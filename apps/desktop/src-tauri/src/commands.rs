use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vpn_hub_core::{
    GuardianConfig, GuardianStore, HealthStatus, LOCAL_OUTLET, LatencySample, OutletConfig,
    OutletHealth, OutletSummary, PrivateConfigSummary, ProbeResult, RouteMode, RouteSwitchEvent,
    RoutingPolicy, SUBSCRIPTION_OUTLET, StateEvent, outlet_proxy_name, probe_outlet,
};

use crate::runtime::{AppState, CoreStatus, PortSnapshot, RoutingStatus};

#[derive(Debug, Serialize)]
pub struct DashboardSnapshot {
    updated_at: String,
    protected_entry: PortSnapshot,
    development_entry: PortSnapshot,
    upstream_entry: PortSnapshot,
    mihomo: CoreStatus,
    routing: RoutingStatus,
    summaries: Vec<OutletSummary>,
    samples: Vec<LatencySample>,
    events: Vec<StateEvent>,
    route_switches: Vec<RouteSwitchEvent>,
}

fn load_dashboard(state: &AppState) -> Result<DashboardSnapshot, String> {
    let config = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let store = GuardianStore::open(&config.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    Ok(DashboardSnapshot {
        updated_at: Utc::now().to_rfc3339(),
        protected_entry: AppState::port_snapshot(6_666),
        development_entry: AppState::port_snapshot(36_666),
        upstream_entry: AppState::port_snapshot(16_666),
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
    })
}

async fn record_direct_guardian_cycle(config_path: &Path) -> Result<u64, String> {
    let config = GuardianConfig::load(config_path)
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let mut store = GuardianStore::open(&config.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    for outlet in config.outlets.iter().filter(|outlet| outlet.enabled) {
        let result = probe_outlet(outlet, &config.monitor).await;
        store
            .record_probe(
                outlet,
                &result,
                config.monitor.failure_threshold,
                config.monitor.recovery_threshold,
            )
            .map_err(|error| format!("无法写入检测结果：{error}"))?;
    }
    Ok(config.monitor.interval_seconds)
}

async fn record_routing_cycle(state: &AppState) -> Result<u64, String> {
    let _transaction = state.lock_routing_transaction().await;
    record_routing_cycle_locked(state).await
}

async fn record_routing_cycle_locked(state: &AppState) -> Result<u64, String> {
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    let Some(controller) = state.controller_client()? else {
        return record_direct_guardian_cycle(&state.guardian_config_path()).await;
    };
    let mut store = GuardianStore::open(&guardian.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;

    let observed =
        probe_configured_outlets(&controller, &private, guardian.monitor.request_timeout_ms).await;

    for (outlet, result) in &observed {
        store
            .record_probe(
                outlet,
                result,
                guardian.monitor.failure_threshold,
                guardian.monitor.recovery_threshold,
            )
            .map_err(|error| format!("无法写入多目标检测结果：{error}"))?;
    }

    let summaries = store
        .summaries()
        .map_err(|error| format!("无法读取稳定健康状态：{error}"))?;
    let latest_latency = observed
        .iter()
        .map(|(outlet, result)| (outlet.id.as_str(), result.latency_ms))
        .collect::<BTreeMap<_, _>>();
    let health = summaries
        .into_iter()
        .filter(|item| matches!(item.outlet_id.as_str(), SUBSCRIPTION_OUTLET | LOCAL_OUTLET))
        .map(|item| {
            let latency_ms = latest_latency
                .get(item.outlet_id.as_str())
                .copied()
                .flatten();
            (
                item.outlet_id,
                OutletHealth {
                    status: item.last_status,
                    latency_ms,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let policy = RoutingPolicy {
        priority: private.priority.clone(),
        cooldown_ms: private.cooldown_seconds.saturating_mul(1_000),
        minimum_improvement_ms: private.minimum_improvement_ms,
    };
    let now_ms = unix_time_ms();
    if let Some(decision) = state.evaluate_route(now_ms, &health, &policy)? {
        let proxy_name = outlet_proxy_name(&decision.to_outlet)
            .ok_or_else(|| "路由策略返回未知出口".to_string())?;
        let started = Instant::now();
        controller
            .select(vpn_hub_core::MASTER_SELECTOR, proxy_name)
            .await
            .map_err(|error| format!("Mihomo 真实选择器切换失败：{error}"))?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        state.apply_route(&decision, now_ms)?;
        store
            .record_route_switch(&RouteSwitchEvent {
                occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                from_outlet: decision.from_outlet,
                to_outlet: decision.to_outlet,
                mode: private.route_mode.as_str().into(),
                reason: decision.reason,
                duration_ms,
            })
            .map_err(|error| format!("无法记录真实路由切换：{error}"))?;
    }
    Ok(guardian.monitor.interval_seconds)
}

async fn probe_configured_outlets(
    controller: &vpn_hub_core::ControllerClient,
    private: &vpn_hub_core::PrivateRoutingConfig,
    timeout_ms: u64,
) -> Vec<(OutletConfig, ProbeResult)> {
    let subscription = if private.subscription_configured() {
        probe_controller_outlet(
            controller,
            SUBSCRIPTION_OUTLET,
            &private.probe_targets,
            timeout_ms,
        )
        .await
    } else {
        unavailable_result(
            SUBSCRIPTION_OUTLET,
            "订阅 A",
            ProbeFailureCode::SubscriptionNotConfigured,
            private.probe_targets.len(),
        )
    };
    let local =
        probe_controller_outlet(controller, LOCAL_OUTLET, &private.probe_targets, timeout_ms).await;
    vec![
        (virtual_outlet(SUBSCRIPTION_OUTLET, "订阅 A"), subscription),
        (virtual_outlet(LOCAL_OUTLET, "超实惠"), local),
    ]
}

async fn probe_controller_outlet(
    controller: &vpn_hub_core::ControllerClient,
    outlet_id: &str,
    targets: &[String],
    timeout_ms: u64,
) -> ProbeResult {
    let label = if outlet_id == SUBSCRIPTION_OUTLET {
        "订阅 A"
    } else {
        "超实惠"
    };
    let Some(proxy_name) = outlet_proxy_name(outlet_id) else {
        return unavailable_result(
            outlet_id,
            label,
            ProbeFailureCode::UnknownOutlet,
            targets.len(),
        );
    };
    let mut delays = Vec::new();
    for target in targets {
        if let Ok(delay) = controller.delay(proxy_name, target, timeout_ms).await {
            delays.push(delay);
        }
    }
    delays.sort_unstable();
    let successful_targets = u32::try_from(delays.len()).unwrap_or(u32::MAX);
    let total_targets = u32::try_from(targets.len()).unwrap_or(u32::MAX);
    let (status, latency_ms) = classify_delays(&delays, targets.len());
    ProbeResult {
        outlet_id: outlet_id.into(),
        label: label.into(),
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        port_reachable: true,
        status,
        http_status: None,
        latency_ms,
        error_code: (status == HealthStatus::Down).then(|| "multi_target_quorum_failed".into()),
        successful_targets,
        total_targets,
    }
}

fn classify_delays(delays: &[u64], total_targets: usize) -> (HealthStatus, Option<u64>) {
    let quorum = total_targets / 2 + 1;
    let latency_ms = delays.get(delays.len() / 2).copied();
    let status = if delays.len() < quorum {
        HealthStatus::Down
    } else if latency_ms.is_some_and(|latency| latency > 2_500) || delays.len() < total_targets {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };
    (status, latency_ms)
}

fn unavailable_result(
    outlet_id: &str,
    label: &str,
    error_code: ProbeFailureCode,
    total_targets: usize,
) -> ProbeResult {
    ProbeResult {
        outlet_id: outlet_id.into(),
        label: label.into(),
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
    UnknownOutlet,
    #[cfg(test)]
    ProviderFailed,
}

impl ProbeFailureCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SubscriptionNotConfigured => "subscription_not_configured",
            Self::UnknownOutlet => "unknown_outlet",
            #[cfg(test)]
            Self::ProviderFailed => "provider_failed",
        }
    }
}

fn virtual_outlet(id: &str, label: &str) -> OutletConfig {
    OutletConfig {
        id: id.into(),
        label: label.into(),
        proxy_url: "socks5h://127.0.0.1:36666".into(),
        probe_url: "https://localhost.invalid/".into(),
        degraded_latency_ms: 2_500,
        enabled: true,
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

pub(crate) async fn monitor_guardian(app: AppHandle) {
    loop {
        let interval = {
            let state = app.state::<AppState>();
            match record_routing_cycle(&state).await {
                Ok(interval) => interval,
                Err(error) => {
                    eprintln!("Guardian background cycle failed: {error}");
                    180
                }
            }
        };
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
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
pub async fn save_subscription_url(
    state: State<'_, AppState>,
    subscription_url: String,
) -> Result<PrivateConfigSummary, String> {
    let _transaction = state.lock_routing_transaction().await;
    state.save_subscription_url(&subscription_url)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn start_development_core(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    let _transaction = state.lock_routing_transaction().await;
    let mut status = state.start_development_core()?;
    if let Err(error) = record_routing_cycle_locked(&state).await {
        let _ = state.stop_development_core();
        return Err(format!(
            "开发核心首次健康决策失败，已停止并保持 Fail Closed：{error}"
        ));
    }
    status.message = "开发核心已启动，并完成首次真实 Controller 健康决策".into();
    Ok(status)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn stop_development_core(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    let _transaction = state.lock_routing_transaction().await;
    state.stop_development_core()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_result_contains_no_target_details() {
        let sensitive_url =
            "https://example.invalid/provider/credential-token-value/node-detail-value";
        let result = unavailable_result(
            "subscription-a",
            "订阅 A",
            ProbeFailureCode::ProviderFailed,
            3,
        );
        let serialized = serde_json::to_string(&result).expect("serialize");
        assert!(!serialized.contains("://"));
        for sensitive_part in [sensitive_url, "credential-token-value", "node-detail-value"] {
            assert!(!serialized.contains(sensitive_part));
        }
        assert_eq!(result.total_targets, 3);
    }

    #[test]
    fn multi_target_quorum_avoids_single_target_false_down() {
        assert_eq!(
            classify_delays(&[80, 120], 3),
            (HealthStatus::Degraded, Some(120))
        );
        assert_eq!(classify_delays(&[80], 3).0, HealthStatus::Down);
        assert_eq!(
            classify_delays(&[80, 100, 120], 3),
            (HealthStatus::Healthy, Some(100))
        );
    }
}
