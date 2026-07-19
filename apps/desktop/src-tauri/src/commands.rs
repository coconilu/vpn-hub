use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vpn_hub_core::{
    GuardianConfig, GuardianStore, HealthStatus, HistoryExport, HistoryFilter, HistoryOutletKind,
    HistoryOutletSnapshot, HistoryResponse, LatencySample, OutletConfig, OutletKind, OutletSummary,
    ProbeOutletConfig, ProbeResult, RouteMode, RouteSwitchEvent, StateEvent,
    SubscriptionCredentialStatus, UdpCapabilityEvidence, UdpProbeTarget, is_current_udp_evidence,
    probe_local_proxy_udp, probe_outlet, run_controller_guardian_cycle, unknown_udp_evidence,
};

use crate::{
    lifecycle::{self, LifecycleEvent},
    runtime::{
        AppState, CoreStatus, PortSnapshot, RoutingStatus, SettingsApplyRequest,
        SettingsApplyResult, SettingsPreview, SettingsPreviewRequest,
    },
};

#[derive(Debug, Serialize)]
pub struct DashboardSnapshot {
    updated_at: String,
    entry: PortSnapshot,
    mihomo: CoreStatus,
    routing: RoutingStatus,
    summaries: Vec<OutletSummary>,
    samples: Vec<LatencySample>,
    events: Vec<StateEvent>,
    route_switches: Vec<RouteSwitchEvent>,
    udp_capabilities: Vec<UdpCapabilityEvidence>,
}

fn load_dashboard(state: &AppState) -> Result<DashboardSnapshot, String> {
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    let mut store = GuardianStore::open(&guardian.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    store
        .sync_history_outlets(&history_outlets(&private), &Utc::now().to_rfc3339())
        .map_err(|error| format!("无法同步脱敏历史出口目录：{error}"))?;
    for outlet in private.enabled_outlets() {
        store
            .ensure_udp_capability(
                &outlet.id,
                &outlet.label,
                &unknown_udp_evidence(outlet, "not_yet_validated"),
            )
            .map_err(|error| format!("无法初始化 UDP 能力状态：{error}"))?;
    }
    let mut udp_capabilities = store
        .udp_capabilities()
        .map_err(|error| format!("无法读取 UDP 能力状态：{error}"))?;
    udp_capabilities.retain(|evidence| {
        private
            .outlets
            .iter()
            .any(|outlet| outlet.id == evidence.outlet_id)
    });
    for evidence in &mut udp_capabilities {
        let current = private
            .outlets
            .iter()
            .find(|outlet| outlet.id == evidence.outlet_id)
            .is_some_and(|outlet| is_current_udp_evidence(outlet, evidence));
        if !current {
            evidence.status = vpn_hub_core::UdpCapabilityStatus::Unknown;
            evidence.reason_code = "evidence_requires_revalidation".into();
        }
    }
    Ok(DashboardSnapshot {
        updated_at: Utc::now().to_rfc3339(),
        entry: AppState::port_snapshot(&private.entry.host, private.entry.port),
        mihomo: state.core_status()?,
        routing: state.routing_status()?,
        summaries: store
            .summaries()
            .map_err(|error| format!("无法读取出口汇总：{error}"))?,
        samples: store
            .recent_samples(180)
            .map_err(|error| format!("无法读取延迟样本：{error}"))?,
        events: store
            .recent_events(12)
            .map_err(|error| format!("无法读取状态事件：{error}"))?,
        route_switches: store
            .recent_route_switches(12)
            .map_err(|error| format!("无法读取路由切换事件：{error}"))?,
        udp_capabilities,
    })
}

fn history_outlets(private: &vpn_hub_core::PrivateRoutingConfig) -> Vec<HistoryOutletSnapshot> {
    private
        .outlets
        .iter()
        .map(|outlet| HistoryOutletSnapshot {
            outlet_id: outlet.id.clone(),
            label: outlet.label.clone(),
            kind: match outlet.kind {
                OutletKind::Subscription { .. } => HistoryOutletKind::Subscription,
                OutletKind::LocalProxy { .. } => HistoryOutletKind::LocalProxy,
            },
            enabled: outlet.enabled,
        })
        .collect()
}

fn history_context(
    state: &AppState,
) -> Result<(std::path::PathBuf, Vec<HistoryOutletSnapshot>, String), String> {
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    Ok((
        guardian.database_path,
        history_outlets(&private),
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    ))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn get_history(
    state: State<'_, AppState>,
    filter: HistoryFilter,
) -> Result<HistoryResponse, String> {
    let (database_path, outlets, now) = history_context(&state)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut store = GuardianStore::open(database_path)
            .map_err(|error| format!("无法打开历史数据库：{error}"))?;
        store
            .sync_history_outlets(&outlets, &now)
            .map_err(|error| format!("无法同步脱敏历史出口目录：{error}"))?;
        store
            .query_history(&filter, &now)
            .map_err(|error| format!("无法查询历史：{error}"))
    })
    .await
    .map_err(|_| "历史查询后台任务异常退出".to_string())?
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn export_history(
    state: State<'_, AppState>,
    filter: HistoryFilter,
) -> Result<HistoryExport, String> {
    let (database_path, outlets, now) = history_context(&state)?;
    let timestamp = Utc::now().timestamp_millis();
    let destination = state.history_export_path(timestamp);
    let exported_path = destination.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut store = GuardianStore::open(database_path)
            .map_err(|error| format!("无法打开历史数据库：{error}"))?;
        store
            .sync_history_outlets(&outlets, &now)
            .map_err(|error| format!("无法同步脱敏历史出口目录：{error}"))?;
        let rows = store
            .export_history_csv(&destination, &filter, &now)
            .map_err(|error| format!("无法导出脱敏 CSV：{error}"))?;
        Ok(HistoryExport {
            path: exported_path.to_string_lossy().into_owned(),
            rows,
        })
    })
    .await
    .map_err(|_| "CSV 导出后台任务异常退出".to_string())?
}

#[tauri::command]
pub async fn set_history_retention(state: State<'_, AppState>, days: u32) -> Result<u64, String> {
    let (database_path, _, now) = history_context(&state)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut store = GuardianStore::open(database_path)
            .map_err(|error| format!("无法打开历史数据库：{error}"))?;
        store
            .set_retention_days(days, &now)
            .map_err(|error| format!("无法更新历史保留策略：{error}"))
    })
    .await
    .map_err(|_| "历史清理后台任务异常退出".to_string())?
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn get_settings(
    state: State<'_, AppState>,
) -> Result<vpn_hub_core::SafeSettingsView, String> {
    let _transaction = state.lock_routing_transaction().await;
    state.settings_view()
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn preview_settings(
    state: State<'_, AppState>,
    request: SettingsPreviewRequest,
) -> Result<SettingsPreview, String> {
    let _transaction = state.lock_routing_transaction().await;
    state.preview_settings(&request)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn apply_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    request: SettingsApplyRequest,
) -> Result<SettingsApplyResult, String> {
    app.state::<lifecycle::DesktopCoordinator>()
        .prepare_config_reload();
    let _transaction = state.lock_routing_transaction().await;
    let result = state.apply_settings(request)?;
    lifecycle::dispatch(
        &app,
        LifecycleEvent::ConfigReload {
            now_ms: unix_time_ms(),
        },
    );
    Ok(result)
}

async fn record_direct_guardian_cycle(state: &AppState) -> Result<u64, String> {
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    let resolved = state.resolved_subscription_urls(&private)?;
    let mut store = GuardianStore::open(&guardian.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    store
        .sync_history_outlets(&history_outlets(&private), &Utc::now().to_rfc3339())
        .map_err(|error| format!("无法同步脱敏历史出口目录：{error}"))?;

    for outlet in private.enabled_outlets() {
        store
            .ensure_udp_capability(
                &outlet.id,
                &outlet.label,
                &unknown_udp_evidence(outlet, "not_yet_validated"),
            )
            .map_err(|error| format!("无法初始化 UDP 能力状态：{error}"))?;
        let probe_outlet_config = virtual_outlet(outlet, &private.entry);
        let result = match &outlet.kind {
            OutletKind::LocalProxy { endpoint } => {
                let mut direct = probe_outlet_config.clone();
                direct.proxy_url.clone_from(endpoint);
                direct.probe_url.clone_from(&private.probe_targets[0]);
                probe_outlet(&direct, &guardian.monitor).await
            }
            OutletKind::Subscription { secret_ref, .. } => unavailable_result(
                outlet,
                if resolved.contains_key(secret_ref) {
                    ProbeFailureCode::ControllerNotRunning
                } else {
                    ProbeFailureCode::SubscriptionNotConfigured
                },
                private.probe_targets.len(),
            ),
        };
        store
            .record_probe(
                &probe_outlet_config,
                &result,
                guardian.monitor.failure_threshold,
                guardian.monitor.recovery_threshold,
            )
            .map_err(|error| format!("无法写入检测结果：{error}"))?;
    }
    Ok(guardian.monitor.interval_seconds)
}

pub(crate) async fn record_routing_cycle_locked(state: &AppState) -> Result<u64, String> {
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    let Some(controller) = state.controller_client()? else {
        return record_direct_guardian_cycle(state).await;
    };
    let mut store = GuardianStore::open(&guardian.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    store
        .sync_history_outlets(&history_outlets(&private), &Utc::now().to_rfc3339())
        .map_err(|error| format!("无法同步脱敏历史出口目录：{error}"))?;

    run_controller_guardian_cycle(
        &controller,
        &private,
        &state.resolved_subscription_urls(&private)?,
        &guardian.monitor,
        &mut store,
        state,
        unix_time_ms(),
    )
    .await
    .map_err(|error| format!("Guardian 路由周期失败：{error}"))?;
    Ok(guardian.monitor.interval_seconds)
}

fn unavailable_result(
    outlet: &OutletConfig,
    error_code: ProbeFailureCode,
    total_targets: usize,
) -> ProbeResult {
    ProbeResult {
        outlet_id: outlet.id.clone(),
        label: outlet.label.clone(),
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        port_reachable: false,
        status: HealthStatus::Down,
        http_status: None,
        latency_ms: None,
        error_code: Some(error_code.as_str().into()),
        successful_targets: 0,
        total_targets: u32::try_from(total_targets).unwrap_or(u32::MAX),
    }
}

#[derive(Clone, Copy)]
enum ProbeFailureCode {
    SubscriptionNotConfigured,
    ControllerNotRunning,
    #[cfg(test)]
    ProviderFailed,
}

impl ProbeFailureCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SubscriptionNotConfigured => "subscription_not_configured",
            Self::ControllerNotRunning => "controller_not_running",
            #[cfg(test)]
            Self::ProviderFailed => "provider_failed",
        }
    }
}

fn virtual_outlet(outlet: &OutletConfig, entry: &vpn_hub_core::EntryConfig) -> ProbeOutletConfig {
    let url_host = if entry.host.contains(':') {
        format!("[{}]", entry.host)
    } else {
        entry.host.clone()
    };
    ProbeOutletConfig {
        id: outlet.id.clone(),
        label: outlet.label.clone(),
        proxy_url: format!("socks5h://{url_host}:{}", entry.port),
        probe_url: "https://localhost.invalid/".into(),
        degraded_latency_ms: 2_500,
        enabled: outlet.enabled,
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn get_dashboard_snapshot(
    state: State<'_, AppState>,
) -> Result<DashboardSnapshot, String> {
    let _transaction = state.lock_routing_transaction().await;
    load_dashboard(&state)
}

#[tauri::command]
pub async fn refresh_guardian(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    let _transaction = state.lock_routing_transaction().await;
    record_routing_cycle_locked(&state).await?;
    load_dashboard(&state)
}

#[tauri::command]
pub async fn revalidate_udp_capabilities(
    state: State<'_, AppState>,
    authorized_subscription_targets: Vec<String>,
) -> Result<DashboardSnapshot, String> {
    let _transaction = state.lock_routing_transaction().await;
    if state.controller_client()?.is_some() {
        return Err(
            "重新验证 UDP 能力前请先停止由本应用管理的开发核心；避免运行中配置继续使用过期结论"
                .into(),
        );
    }
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    let mut store = GuardianStore::open(&guardian.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    if authorized_subscription_targets.len() > 8 {
        return Err("一次最多允许 8 个受控 UDP 目标".into());
    }
    let mut subscription_targets = authorized_subscription_targets
        .iter()
        .map(|target| {
            target
                .parse::<SocketAddr>()
                .map_err(|_| "受控 UDP 目标格式无效；请使用 IP:端口".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    subscription_targets.sort_unstable();
    subscription_targets.dedup();
    if subscription_targets
        .iter()
        .any(|target| matches!(target.port(), 3_666 | 6_666))
    {
        return Err("受保护端口不能用作 UDP 探测目标".into());
    }
    let echo = OwnedUdpEcho::start()?;

    for outlet in private.enabled_outlets() {
        let evidence = match &outlet.kind {
            OutletKind::Subscription { .. } => {
                state
                    .revalidate_subscription_udp(&private, outlet, &subscription_targets)
                    .await?
            }
            OutletKind::LocalProxy { .. } => {
                let target = UdpProbeTarget {
                    address: echo.address(),
                    request: format!("vpn-hub-udp-probe:{}", outlet.id).into_bytes(),
                    expected_response: format!("vpn-hub-udp-probe:{}", outlet.id).into_bytes(),
                };
                let owned_outlet = outlet.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    probe_local_proxy_udp(&owned_outlet, &[target], Duration::from_millis(1_500))
                })
                .await
                .map_err(|_| "UDP 能力探测任务失败".to_string())?
            }
        };
        store
            .record_udp_capability(&outlet.id, &outlet.label, &evidence)
            .map_err(|error| format!("无法写入 UDP 能力证据：{error}"))?;
    }
    drop(echo);
    load_dashboard(&state)
}

struct OwnedUdpEcho {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl OwnedUdpEcho {
    fn start() -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| "无法创建隔离 UDP 回环目标".to_string())?;
        let address = socket
            .local_addr()
            .map_err(|_| "无法读取隔离 UDP 回环目标".to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|_| "无法配置隔离 UDP 回环目标".to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 2_048];
            while !thread_stop.load(Ordering::Acquire) {
                if let Ok((length, peer)) = socket.recv_from(&mut buffer) {
                    let _ = socket.send_to(&buffer[..length], peer);
                }
            }
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for OwnedUdpEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(wake) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            let _ = wake.send_to(&[0], self.address);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn set_route_mode(
    state: State<'_, AppState>,
    mode: RouteMode,
    manual_outlet: Option<String>,
) -> Result<DashboardSnapshot, String> {
    let _transaction = state.lock_routing_transaction().await;
    if state.controller_client()?.is_none() {
        return Err("请先启动开发核心；未连接 Controller 时不会伪装路由切换".into());
    }
    state.set_route_mode(mode, manual_outlet)?;
    record_routing_cycle_locked(&state).await?;
    load_dashboard(&state)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn list_subscription_credentials(
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionCredentialStatus>, String> {
    state.subscription_credential_statuses()
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_subscription_credential(
    state: State<'_, AppState>,
    subscription_id: String,
    credential: String,
) -> Result<SubscriptionCredentialStatus, String> {
    state.set_subscription_credential(&subscription_id, &credential)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn delete_subscription_credential(
    state: State<'_, AppState>,
    subscription_id: String,
) -> Result<SubscriptionCredentialStatus, String> {
    state.delete_subscription_credential(&subscription_id)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn start_development_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    app.state::<lifecycle::DesktopCoordinator>()
        .prepare_manual_start();
    let _transaction = state.lock_routing_transaction().await;
    let mut status = match state.start_development_core().await {
        Ok(status) => status,
        Err(error) => {
            if state
                .core_status()
                .is_ok_and(|status| status.state == "external")
            {
                lifecycle::dispatch(&app, LifecycleEvent::PortConflictObserved);
            }
            return Err(error);
        }
    };
    if let Err(error) = record_routing_cycle_locked(&state).await {
        let _ = state.stop_development_core();
        return Err(format!(
            "开发核心首次健康决策失败，已停止并保持 Fail Closed：{error}"
        ));
    }
    if let Some(pid) = status.pid {
        lifecycle::dispatch(&app, LifecycleEvent::CoreStarted { pid });
    }
    status.message = "开发核心已启动，并完成首次真实 Controller 健康决策".into();
    Ok(status)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn stop_development_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    app.state::<lifecycle::DesktopCoordinator>().prepare_stop();
    let _transaction = state.lock_routing_transaction().await;
    let status = state.stop_development_core()?;
    lifecycle::dispatch(&app, LifecycleEvent::CoreStopped);
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription() -> OutletConfig {
        OutletConfig {
            id: "subscription-a".into(),
            label: "订阅 A".into(),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: "secret.a".into(),
                provider_update_seconds: 180,
            },
        }
    }

    #[test]
    fn history_catalogue_projects_multiple_subscriptions_without_secret_references() {
        let mut config = vpn_hub_core::PrivateRoutingConfig::default();
        config.outlets = (0..3)
            .map(|index| OutletConfig {
                id: format!("subscription-{index}"),
                label: format!("订阅 {index}"),
                enabled: index != 2,
                kind: OutletKind::Subscription {
                    secret_ref: format!("synthetic-ref-{index}"),
                    provider_update_seconds: 180,
                },
            })
            .chain(std::iter::once(OutletConfig {
                id: "local-synthetic".into(),
                label: "本地出口".into(),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: "socks5://127.0.0.1:45191".into(),
                },
            }))
            .collect();
        let catalogue = history_outlets(&config);
        assert_eq!(catalogue.len(), 4);
        assert_eq!(
            catalogue
                .iter()
                .filter(|outlet| outlet.kind == HistoryOutletKind::Subscription)
                .count(),
            3
        );
        assert!(!catalogue[2].enabled);
        let serialized = serde_json::to_string(&catalogue).expect("serialize safe catalogue");
        assert!(!serialized.contains("synthetic-ref"));
        assert!(!serialized.contains("socks5://"));
    }

    #[test]
    fn unavailable_result_contains_no_target_details() {
        let sensitive_url =
            "https://example.invalid/provider/credential-token-value/node-detail-value";
        let result = unavailable_result(&subscription(), ProbeFailureCode::ProviderFailed, 3);
        let serialized = serde_json::to_string(&result).expect("serialize");
        assert!(!serialized.contains("://"));
        for sensitive_part in [sensitive_url, "credential-token-value", "node-detail-value"] {
            assert!(!serialized.contains(sensitive_part));
        }
        assert_eq!(result.total_targets, 3);
    }

    #[tokio::test]
    async fn clean_data_dashboard_and_refresh_work_without_static_outlets() {
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let data_directory = directory.path().join("clean-app-data");
        let state = AppState::new_for_test(workspace_root, &data_directory);

        let initial = load_dashboard(&state).expect("clean dashboard");
        assert_eq!(initial.entry.host, "127.0.0.1");
        assert_eq!(initial.entry.port, 3_666);
        assert!(initial.routing.outlets.is_empty());

        let interval = record_routing_cycle_locked(&state)
            .await
            .expect("clean refresh");
        assert_eq!(interval, 180);
        let refreshed = load_dashboard(&state).expect("refreshed dashboard");
        assert!(refreshed.routing.outlets.is_empty());
        assert!(refreshed.summaries.is_empty());
    }

    #[test]
    fn dashboard_projects_stale_udp_evidence_as_unknown_without_rewriting_history() {
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let data_directory = directory.path().join("dashboard-stale-evidence");
        let state = AppState::new_for_test(workspace_root, &data_directory);
        let mut config = vpn_hub_core::PrivateRoutingConfig::default();
        config.entry = vpn_hub_core::EntryConfig {
            host: "127.0.0.1".into(),
            port: 45_131,
        };
        config.controller_port = 45_132;
        let outlet = OutletConfig {
            id: "dashboard-local".into(),
            label: "Dashboard local".into(),
            enabled: true,
            kind: OutletKind::LocalProxy {
                endpoint: "socks5://127.0.0.1:45133".into(),
            },
        };
        config.outlets = vec![outlet.clone()];
        config
            .save(state.private_config_path_for_test())
            .expect("save original config");
        let guardian = GuardianConfig::load(state.guardian_config_path()).expect("guardian config");
        let mut store = GuardianStore::open(&guardian.database_path).expect("guardian store");
        let mut evidence = unknown_udp_evidence(&outlet, "test");
        evidence.status = vpn_hub_core::UdpCapabilityStatus::Supported;
        store
            .record_udp_capability(&outlet.id, &outlet.label, &evidence)
            .expect("record current supported evidence");
        drop(store);

        if let OutletKind::LocalProxy { endpoint } = &mut config.outlets[0].kind {
            *endpoint = "socks5://127.0.0.1:45134".into();
        }
        config
            .save(state.private_config_path_for_test())
            .expect("save changed config");
        let dashboard = load_dashboard(&state).expect("dashboard snapshot");
        assert_eq!(dashboard.udp_capabilities.len(), 1);
        assert_eq!(
            dashboard.udp_capabilities[0].status,
            vpn_hub_core::UdpCapabilityStatus::Unknown
        );
        assert_eq!(
            dashboard.udp_capabilities[0].reason_code,
            "evidence_requires_revalidation"
        );

        let store = GuardianStore::open(&guardian.database_path).expect("reopen history");
        let history = store
            .udp_capability_history(&outlet.id, 10)
            .expect("evidence history");
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].status,
            vpn_hub_core::UdpCapabilityStatus::Supported
        );
        assert_eq!(history[0].reason_code, "test");
    }
}
