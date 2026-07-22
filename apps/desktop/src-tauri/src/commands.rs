use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vpn_hub_core::{
    DEFAULT_GUARDIAN_CONCURRENCY, DEFAULT_GUARDIAN_CYCLE_BUDGET, GuardianConfig, GuardianStore,
    HealthStatus, HistoryExport, HistoryFilter, HistoryOutletKind, HistoryOutletSnapshot,
    HistoryResponse, LatencySample, OutletConfig, OutletKind, OutletSummary, ProbeOutletConfig,
    ProbeResult, RouteMode, RouteSwitchEvent, StateEvent, SubscriptionCredentialStatus,
    UdpCapabilityEvidence, UdpProbeTarget, ValidationIssue, is_current_udp_evidence,
    probe_local_proxy_udp, probe_outlet, run_controller_guardian_cycle_controlled,
    unknown_udp_evidence,
};

#[cfg(target_os = "windows")]
use crate::{
    entry_switch_windows::{
        ProtectedProxySnapshotWire, compare_then_apply_proxy, snapshot_current_user_proxy,
    },
    runtime::{DeferredSettingsApply, EntrySwitchRuntimeJournal, EntrySwitchRuntimePhase},
};
use crate::{
    lifecycle::{self, LifecycleEvent},
    runtime::{
        AppState, CoreStatus, EntrySwitchApplyRequest, EntrySwitchApplyResult, EntrySwitchPreview,
        EntrySwitchPreviewChecks, FastPathPerformanceReport, FastPathResultCode, FastPathStage,
        NodeLatencyBatchResult, NodeLatencyResult, PortSnapshot, RoutingStatus,
        SettingsApplyRequest, SettingsApplyResult, SettingsPreview, SettingsPreviewRequest,
        SettingsTerminalStatus, SubscriptionNodeCatalog, SubscriptionNodeGroup,
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

async fn load_dashboard(state: &AppState) -> Result<DashboardSnapshot, String> {
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
        mihomo: state.core_status_authoritative().await?,
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

fn ensure_entry_switch_preview_supported(
    settings_terminal_active: bool,
    windows_supported: bool,
) -> Result<(), String> {
    if settings_terminal_active {
        return Err("terminal_recovery_active：设置安全门未解除，拒绝签发入口切换授权".into());
    }
    if !windows_supported {
        return Err("安全入口切换只支持 Windows 当前用户 default-LAN 系统代理".into());
    }
    Ok(())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn preview_entry_switch(
    state: State<'_, AppState>,
    target: vpn_hub_core::EntryConfig,
    apply_system_proxy: bool,
    confirmed: bool,
) -> Result<EntrySwitchPreview, String> {
    let _settings_apply = state.lock_settings_apply().await;
    let _transaction = state.lock_routing_transaction().await;
    ensure_entry_switch_preview_supported(state.settings_terminal_active(), cfg!(windows))?;
    let status = state.core_status_authoritative().await?;
    let managed_core_ready = status.managed
        && status.pid.is_some()
        && status.state == "running"
        && status
            .pid
            .is_some_and(|pid| state.owned_core_controller_is_running(pid));
    let target_available = !AppState::port_snapshot(&target.host, target.port).reachable;
    #[cfg(target_os = "windows")]
    let proxy_scope_supported = !apply_system_proxy || snapshot_current_user_proxy().is_ok();
    #[cfg(not(target_os = "windows"))]
    let proxy_scope_supported = false;
    state.prepare_entry_switch_preview(
        target,
        apply_system_proxy,
        EntrySwitchPreviewChecks {
            confirmed: confirmed.into(),
            managed_core_ready: managed_core_ready.into(),
            target_available: target_available.into(),
            proxy_scope_supported: proxy_scope_supported.into(),
        },
    )
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyRollbackAction {
    RestoreOriginal,
    AlreadyOriginal,
    PreserveThirdParty,
}

#[cfg(target_os = "windows")]
fn classify_proxy_rollback(
    observed: &ProtectedProxySnapshotWire,
    original: &ProtectedProxySnapshotWire,
    desired: &ProtectedProxySnapshotWire,
) -> ProxyRollbackAction {
    if observed == desired {
        ProxyRollbackAction::RestoreOriginal
    } else if observed == original {
        ProxyRollbackAction::AlreadyOriginal
    } else {
        ProxyRollbackAction::PreserveThirdParty
    }
}

#[cfg(target_os = "windows")]
fn owned_core_stop_confirmed(
    stop_result: lifecycle::StopRequestResult,
    authoritative_pid: Option<u32>,
) -> bool {
    stop_result == lifecycle::StopRequestResult::Stopped && authoritative_pid.is_none()
}

#[cfg(target_os = "windows")]
async fn compensate_failed_entry_switch(
    app: &AppHandle,
    state: &AppState,
    pending: Option<&DeferredSettingsApply>,
    journal: &EntrySwitchRuntimeJournal,
    failure: &str,
) -> String {
    if pending.is_some_and(|value| state.deferred_settings_commit_decided(value)) {
        return format!(
            "entry_switch_recovery_pending：{failure}；入口提交决定已持久化，系统代理与配置只允许幂等前滚"
        );
    }
    let stop_result = lifecycle::dispatch_stop_and_wait(app).await;
    let authoritative_pid = match state.owned_core_pid_authoritative().await {
        Ok(pid) => pid,
        Err(error) => {
            return format!(
                "entry_switch_recovery_pending：{failure}；无法确认目标入口核心是否已停止，保留恢复日志：{error}"
            );
        }
    };
    if !owned_core_stop_confirmed(stop_result, authoritative_pid) {
        return format!(
            "entry_switch_recovery_pending：{failure}；目标入口核心停止仍在进行或 PID 仍存在，未回滚配置或系统代理并保留恢复日志"
        );
    }
    let mut notes = Vec::new();
    if let (Some(original), Some(desired)) = (&journal.original_proxy, &journal.desired_proxy) {
        match snapshot_current_user_proxy() {
            Ok(observed) => match classify_proxy_rollback(&observed, original, desired) {
                ProxyRollbackAction::RestoreOriginal => {
                    match compare_then_apply_proxy(desired, original) {
                        Ok(true) => notes.push("Windows 系统代理已恢复"),
                        Ok(false) | Err(_) => {
                            return format!(
                                "entry_switch_recovery_pending：{failure}；系统代理属于本事务但恢复回读失败"
                            );
                        }
                    }
                }
                ProxyRollbackAction::AlreadyOriginal => {}
                ProxyRollbackAction::PreserveThirdParty => {
                    notes.push("检测到并发系统代理变更，未覆盖第三方新值");
                }
            },
            Err(_) => {
                return format!(
                    "entry_switch_recovery_pending：{failure}；无法确认系统代理恢复边界"
                );
            }
        }
    }
    if let Some(pending) = pending
        && let Err(error) = state.rollback_deferred_settings(pending)
    {
        return format!("entry_switch_recovery_pending：{failure}；入口配置回滚未完成：{error}");
    }
    if app
        .state::<lifecycle::DesktopCoordinator>()
        .stop_requested()
    {
        notes.push("停止请求优先，原入口配置已恢复且核心保持停止");
    } else {
        let restart = {
            let _transaction = state.lock_routing_transaction().await;
            start_owned_core_verified(app, state).await
        };
        if let Err(error) = restart {
            return format!(
                "entry_switch_terminal_fail_closed：{failure}；原入口配置已恢复，但旧核心恢复失败：{error}"
            );
        }
        notes.push("原入口与旧核心已恢复");
    }
    if let Err(error) = state.clear_entry_switch_runtime_journal() {
        return format!(
            "entry_switch_recovery_pending：{failure}；状态已恢复但事务日志清理失败：{error}"
        );
    }
    if notes.is_empty() {
        failure.to_string()
    } else {
        format!("{failure}；{}", notes.join("；"))
    }
}

#[cfg(target_os = "windows")]
struct PreparedEntrySwitch {
    settings_fingerprint: String,
    previous_entry: vpn_hub_core::EntryConfig,
    journal: EntrySwitchRuntimeJournal,
}

#[cfg(target_os = "windows")]
async fn prepare_entry_switch_transaction(
    state: &AppState,
    request: &EntrySwitchApplyRequest,
) -> Result<PreparedEntrySwitch, String> {
    let settings_fingerprint = state.consume_entry_switch_ticket(request)?;
    let previous_entry = state.private_config()?.entry;
    if AppState::port_snapshot(&request.target.host, request.target.port).reachable {
        return Err("目标端口已被占用；不会停止或接管未知及第三方进程".into());
    }
    let owned_pid = state
        .owned_core_pid_authoritative()
        .await?
        .ok_or_else(|| "入口切换要求当前 VPN Hub 自管核心正在运行".to_string())?;
    if !state
        .owned_core_controller_is_running_authoritative(owned_pid)
        .await?
    {
        return Err("无法同时证明当前核心 PID 与 Controller ownership".into());
    }
    let (original_proxy, desired_proxy) = if request.apply_system_proxy {
        let original = snapshot_current_user_proxy()?;
        let desired = ProtectedProxySnapshotWire::for_entry(&request.target, &original)?;
        (Some(original), Some(desired))
    } else {
        (None, None)
    };
    let journal = state.prepare_entry_switch_runtime_journal(
        previous_entry.clone(),
        request.target.clone(),
        original_proxy,
        desired_proxy,
    )?;
    Ok(PreparedEntrySwitch {
        settings_fingerprint,
        previous_entry,
        journal,
    })
}

#[cfg(target_os = "windows")]
async fn finalize_entry_switch_transaction(
    app: &AppHandle,
    state: &AppState,
    request: &EntrySwitchApplyRequest,
    previous_entry: vpn_hub_core::EntryConfig,
    mut pending: DeferredSettingsApply,
    mut journal: EntrySwitchRuntimeJournal,
) -> Result<EntrySwitchApplyResult, String> {
    if let Some((original, desired)) = journal
        .original_proxy
        .clone()
        .zip(journal.desired_proxy.clone())
    {
        if let Err(error) = state.set_entry_switch_runtime_phase(
            &mut journal,
            EntrySwitchRuntimePhase::ProxyApplyPending,
        ) {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                &error,
            )
            .await);
        }
        let proxy_apply = compare_then_apply_proxy(&original, &desired);
        let proxy_error = match proxy_apply {
            Ok(true) => None,
            Ok(false) => Some("Windows 系统代理在预览后发生并发变化；未覆盖新值".into()),
            Err(error) => Some(error),
        };
        if let Some(error) = proxy_error {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                &error,
            )
            .await);
        }
        if let Err(error) = state
            .set_entry_switch_runtime_phase(&mut journal, EntrySwitchRuntimePhase::ProxyApplied)
        {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                &error,
            )
            .await);
        }
    }
    let result = match state.finalize_deferred_settings(&mut pending, true) {
        Ok(result) => result,
        Err(error) => {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                &error,
            )
            .await);
        }
    };
    if let Err(error) =
        state.set_entry_switch_runtime_phase(&mut journal, EntrySwitchRuntimePhase::CommitDecided)
    {
        return Err(format!(
            "entry_switch_recovery_pending: settings and runtime committed, but the recovery decision could not be persisted: {error}"
        ));
    }
    if let Err(error) = state.clear_entry_switch_runtime_journal() {
        return Err(format!(
            "entry_switch_recovery_pending: settings and runtime committed, but the recovery journal could not be cleared: {error}"
        ));
    }
    Ok(EntrySwitchApplyResult {
        settings: result.settings,
        previous_entry,
        current_entry: request.target.clone(),
        system_proxy_applied: request.apply_system_proxy,
        managed_core_restarted: result.managed_core_restarted,
    })
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_lines)]
async fn run_entry_switch_transaction(
    app: &AppHandle,
    state: &AppState,
    request: &EntrySwitchApplyRequest,
    prepared: PreparedEntrySwitch,
    operation: &crate::runtime::ForegroundOperation<'_>,
) -> Result<EntrySwitchApplyResult, String> {
    let PreparedEntrySwitch {
        settings_fingerprint,
        previous_entry,
        mut journal,
    } = prepared;
    let owned_pid = state
        .owned_core_pid_authoritative()
        .await?
        .ok_or_else(|| "入口切换前 exact-owned core 已停止".to_string())?;
    let pending = match state
        .apply_entry_switch_settings_deferred(request.target.clone(), settings_fingerprint)
    {
        Ok(pending) => pending,
        Err(error) => {
            let _ = state.clear_entry_switch_runtime_journal();
            return Err(format!("入口候选未提交，owned 核心保持原状态：{error}"));
        }
    };
    if let Err(error) =
        state.set_entry_switch_runtime_phase(&mut journal, EntrySwitchRuntimePhase::SettingsPending)
    {
        return Err(
            compensate_failed_entry_switch(app, state, Some(&pending), &journal, &error).await,
        );
    }
    let hot_reload = {
        let _transaction = state.lock_routing_transaction().await;
        tokio::time::timeout(
            Duration::from_secs(4),
            state.reload_owned_core_config_verified(owned_pid, operation.cancel_flag()),
        )
        .await
        .map_err(|_| "入口同 PID 热重载超过 4 秒预算".to_string())
        .and_then(std::convert::identity)
    };
    let managed_core_restarted = if hot_reload.is_ok() {
        false
    } else {
        if let Err(error) = operation.ensure_active() {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                &error,
            )
            .await);
        }
        let stop_result = lifecycle::dispatch_stop_and_wait(app).await;
        let authoritative_pid = state.owned_core_pid_authoritative().await?;
        if !owned_core_stop_confirmed(stop_result, authoritative_pid) {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                "入口热重载失败，且未能确认 exact-owned core 已停止",
            )
            .await);
        }
        if AppState::port_snapshot(&request.target.host, request.target.port).reachable {
            let error = "停止旧核心后目标端口被并发占用；拒绝接管";
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                error,
            )
            .await);
        }
        let runtime_start = {
            let _transaction = state.lock_routing_transaction().await;
            start_owned_core_verified(app, state).await
        };
        if let Err(error) = runtime_start {
            return Err(compensate_failed_entry_switch(
                app,
                state,
                Some(&pending),
                &journal,
                &error,
            )
            .await);
        }
        true
    };
    if let Err(error) =
        state.set_entry_switch_runtime_phase(&mut journal, EntrySwitchRuntimePhase::RuntimeVerified)
    {
        return Err(
            compensate_failed_entry_switch(app, state, Some(&pending), &journal, &error).await,
        );
    }
    let mut result =
        finalize_entry_switch_transaction(app, state, request, previous_entry, pending, journal)
            .await?;
    result.managed_core_restarted = managed_core_restarted;
    Ok(result)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn apply_entry_switch(
    app: AppHandle,
    state: State<'_, AppState>,
    request: EntrySwitchApplyRequest,
) -> Result<EntrySwitchApplyResult, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (app, state, request);
        Err("安全入口切换只支持 Windows 当前用户 default-LAN 系统代理".into())
    }
    #[cfg(target_os = "windows")]
    {
        let _settings_apply = state.lock_settings_apply().await;
        let operation = state.begin_foreground_operation()?;
        if state.settings_terminal_active() {
            return Err("terminal_recovery_active：设置安全门未解除，拒绝入口切换".into());
        }
        if state.uses_helper_authority() {
            return Err("当前入口切换仅支持 desktop-owned 核心，不会绕过 Helper authority".into());
        }
        app.state::<lifecycle::DesktopCoordinator>()
            .cancel_background_work();
        let prepared = prepare_entry_switch_transaction(&state, &request).await?;
        run_entry_switch_transaction(&app, &state, &request, prepared, &operation).await
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn get_subscription_node_catalog(
    state: State<'_, AppState>,
) -> Result<SubscriptionNodeCatalog, String> {
    let _transaction = state.lock_routing_transaction().await;
    state.subscription_node_catalog().await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn retry_subscription_provider(
    app: AppHandle,
    state: State<'_, AppState>,
    subscription_id: String,
) -> Result<SubscriptionNodeGroup, String> {
    let group = {
        let _transaction = state.lock_routing_transaction().await;
        state.retry_subscription_provider(&subscription_id).await?
    };
    if group.state == crate::runtime::SubscriptionNodeGroupState::ProviderLoading {
        lifecycle::dispatch(
            &app,
            LifecycleEvent::ConfigReload {
                now_ms: unix_time_ms(),
            },
        );
    }
    Ok(group)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn select_subscription_node(
    state: State<'_, AppState>,
    subscription_id: String,
    node_name: String,
) -> Result<SubscriptionNodeGroup, String> {
    let _transaction = state.lock_routing_transaction().await;
    state
        .select_subscription_node(&subscription_id, &node_name)
        .await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn test_subscription_node_latency(
    state: State<'_, AppState>,
    subscription_id: String,
    node_name: String,
) -> Result<NodeLatencyResult, String> {
    let _transaction = state.lock_routing_transaction().await;
    state
        .test_subscription_node_latency(&subscription_id, &node_name)
        .await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn test_subscription_node_latencies(
    state: State<'_, AppState>,
    subscription_id: String,
    operation_id: String,
) -> Result<NodeLatencyBatchResult, String> {
    let _transaction = state.lock_routing_transaction().await;
    state
        .test_subscription_node_latencies(&subscription_id, &operation_id)
        .await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn cancel_subscription_node_latency_batch(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<bool, String> {
    state.cancel_subscription_node_latency_batch(&operation_id)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn preview_settings(
    state: State<'_, AppState>,
    request: SettingsPreviewRequest,
) -> Result<SettingsPreview, String> {
    let _transaction = state.lock_routing_transaction().await;
    let core_status = state.core_status_authoritative().await?;
    let managed_core_running = core_status.managed && core_status.pid.is_some();
    let mut preview = state.preview_settings_with_core_state(&request, managed_core_running)?;
    if core_status.state == "external"
        && (preview.diff.affects_private_routing() || !request.credential_intents.is_empty())
    {
        preview.issues.push(ValidationIssue::new(
            "runtime",
            "external_core_ownership_unproven",
            "入口或 Controller 由未知进程持有；不会停止、重启或改写其运行配置",
        ));
        preview.can_apply = false;
    }
    if helper_settings_deployment_required(
        state.uses_helper_authority(),
        preview.diff.affects_private_routing(),
        !request.credential_intents.is_empty(),
    ) {
        preview.issues.push(ValidationIssue::new(
            "runtime",
            "helper_settings_deployment_required",
            "Helper 核心使用受保护的 ProgramData 配置；当前设置事务不会越权改写该运行配置",
        ));
        preview.can_apply = false;
    }
    if managed_core_running
        && preview.diff.requires_authenticated_controller_apply()
        && state.controller_client()?.is_none()
    {
        preview.issues.push(ValidationIssue::new(
            "runtime",
            "authenticated_controller_required",
            "自管核心未提供受鉴权 Controller；路由策略不会被误报为在线应用",
        ));
        preview.can_apply = false;
    }
    Ok(preview)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_lines)]
pub async fn apply_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    request: SettingsApplyRequest,
) -> Result<SettingsApplyResult, String> {
    let started_at = Instant::now();
    let result = apply_settings_inner(app, &state, request).await;
    let result_code = if result.is_ok() {
        FastPathResultCode::Ok
    } else {
        FastPathResultCode::Error
    };
    state.record_fast_path(FastPathStage::SettingsApply, started_at, result_code);
    result
}

#[allow(clippy::too_many_lines)]
async fn apply_settings_inner(
    app: AppHandle,
    state: &AppState,
    request: SettingsApplyRequest,
) -> Result<SettingsApplyResult, String> {
    let _settings_apply = state.lock_settings_apply().await;
    let operation = state.begin_foreground_operation()?;
    if state.settings_terminal_active() {
        return Err(
            "terminal_recovery_active：设置安全门仍处于 Fail Closed；请先执行显式受鉴权恢复".into(),
        );
    }
    let coordinator = app.state::<lifecycle::DesktopCoordinator>();
    coordinator.cancel_background_work();
    operation.ensure_active()?;
    let (preflight, managed_core_running) = {
        let _transaction = state.lock_routing_transaction().await;
        let core_status = state.core_status_authoritative().await?;
        let managed_core_running = core_status.managed && core_status.pid.is_some();
        let preview = state.preflight_settings_apply(&request, managed_core_running)?;
        if helper_settings_deployment_required(
            state.uses_helper_authority(),
            preview.diff.affects_private_routing(),
            !request.credential_mutations.is_empty(),
        ) {
            return Err(
                "Helper 核心使用受保护的 ProgramData 配置；拒绝把用户设置误报为已应用".into(),
            );
        }
        if core_status.state == "external"
            && (preview.diff.affects_private_routing() || !request.credential_mutations.is_empty())
        {
            return Err(
                "入口或 Controller ownership 不可证明；不会停止、重启或改写未知核心".into(),
            );
        }
        if managed_core_running
            && preview.diff.requires_authenticated_controller_apply()
            && state.controller_client()?.is_none()
        {
            return Err("自管核心未提供受鉴权 Controller；不会把路由策略误报为在线应用".into());
        }
        (preview, managed_core_running)
    };
    if !preflight.requires_managed_core_restart {
        let _transaction = state.lock_routing_transaction().await;
        let requires_controller_confirmation =
            managed_core_running && preflight.diff.requires_authenticated_controller_apply();
        let apply_result = if requires_controller_confirmation {
            state
                .apply_settings_with_runtime_validation(request, || {
                    state.apply_runtime_policy_verified()
                })
                .await
        } else {
            state.apply_settings(request)
        };
        let result = match after_successful_settings_commit(apply_result, || {
            coordinator.prepare_config_reload();
        }) {
            Ok(result) => result,
            Err(error) => {
                if requires_controller_confirmation && !state.settings_terminal_active() {
                    lifecycle::dispatch(
                        &app,
                        LifecycleEvent::ConfigReload {
                            now_ms: unix_time_ms(),
                        },
                    );
                }
                return Err(error);
            }
        };
        lifecycle::dispatch(
            &app,
            LifecycleEvent::ConfigReload {
                now_ms: unix_time_ms(),
            },
        );
        return Ok(result);
    }

    let owned_pid = state
        .owned_core_pid_authoritative()
        .await?
        .ok_or_else(|| "预览中的自管核心已停止，请重新预览后应用".to_string())?;
    if !state
        .owned_core_controller_is_running_authoritative(owned_pid)
        .await?
    {
        return Err("无法同时证明 PID 与 Controller ownership；不会停止或改写未知核心".into());
    }
    operation.ensure_active()?;
    let pending_result = {
        let _transaction = state.lock_routing_transaction().await;
        state.apply_settings_deferred(request)
    };
    let mut pending = match pending_result {
        Ok(pending) => pending,
        Err(error) => {
            if state.settings_recovery_pending() {
                return Err(format!(
                    "设置提交失败且最后有效配置回滚未完成；核心保持原状态并等待下次恢复：{error}"
                ));
            }
            return Err(format!(
                "设置候选提交失败；配置与 owned 核心保持原状态：{error}"
            ));
        }
    };

    let hot_reload = {
        let _transaction = state.lock_routing_transaction().await;
        tokio::time::timeout(
            Duration::from_secs(4),
            state.reload_owned_core_config_verified(owned_pid, operation.cancel_flag()),
        )
        .await
        .map_err(|_| "同 PID 热重载超过 4 秒预算".to_string())
        .and_then(std::convert::identity)
    };
    if hot_reload.is_ok() {
        let finalized = {
            let _transaction = state.lock_routing_transaction().await;
            state.finalize_deferred_settings(&mut pending, false)
        };
        match finalized {
            Ok(result) => {
                coordinator.prepare_config_reload();
                lifecycle::dispatch(
                    &app,
                    LifecycleEvent::ConfigReload {
                        now_ms: unix_time_ms(),
                    },
                );
                return Ok(result);
            }
            Err(error) if state.deferred_settings_commit_decided(&pending) => {
                return Err(format!(
                    "settings_commit_recovery_pending：热重载已生效且提交决定已持久化，收尾将幂等前滚：{error}"
                ));
            }
            Err(error) => {
                let _ = lifecycle::dispatch_stop_and_wait(&app).await;
                let rollback = {
                    let _transaction = state.lock_routing_transaction().await;
                    state.rollback_deferred_settings(&pending)
                };
                if let Err(rollback_error) = rollback {
                    return Err(format!(
                        "热重载已通过但事务收尾和回滚均失败；核心已停止并保持 Fail Closed：{error}；{rollback_error}"
                    ));
                }
                let recovery = {
                    let _transaction = state.lock_routing_transaction().await;
                    start_owned_core_verified(&app, state).await
                };
                return match recovery {
                    Ok(_) => Err(format!("热重载事务收尾失败，旧配置与核心已恢复：{error}")),
                    Err(recovery_error) => Err(format!(
                        "热重载事务收尾失败，旧配置已恢复但旧核心恢复失败：{error}；{recovery_error}"
                    )),
                };
            }
        }
    }

    if let Err(cancelled) = operation.ensure_active() {
        let stopped = lifecycle::dispatch_stop_and_wait(&app).await;
        let rollback = {
            let _transaction = state.lock_routing_transaction().await;
            state.rollback_deferred_settings(&pending)
        };
        if let Err(error) = rollback {
            return Err(format!(
                "{cancelled}；已停止热重载核心，但配置回滚未完成：{error}"
            ));
        }
        if stopped != lifecycle::StopRequestResult::Stopped
            || state.owned_core_pid_authoritative().await?.is_some()
        {
            return Err(format!(
                "{cancelled}；旧配置已恢复，但无法确认 exact-owned core 已停止，保持 Fail Closed"
            ));
        }
        if app
            .state::<lifecycle::DesktopCoordinator>()
            .stop_requested()
        {
            return Err(format!(
                "{cancelled}；旧配置已恢复，停止请求优先，核心保持停止"
            ));
        }
        let recovery = {
            let _transaction = state.lock_routing_transaction().await;
            start_owned_core_verified(&app, state).await
        };
        return match recovery {
            Ok(_) => Err(format!("{cancelled}；旧配置与旧核心已恢复")),
            Err(error) => Err(format!(
                "{cancelled}；旧配置已恢复，但旧核心恢复失败并保持 Fail Closed：{error}"
            )),
        };
    }
    let fallback_started_at = Instant::now();
    if lifecycle::dispatch_stop_and_wait(&app).await != lifecycle::StopRequestResult::Stopped
        || state.owned_core_pid_authoritative().await?.is_some()
    {
        state.record_fast_path(
            FastPathStage::FallbackRestart,
            fallback_started_at,
            FastPathResultCode::Error,
        );
        let rollback = {
            let _transaction = state.lock_routing_transaction().await;
            state.rollback_deferred_settings(&pending)
        };
        return Err(match rollback {
            Ok(()) => "热重载失败且未能确认 exact-owned core 已停止；已恢复最后有效配置".into(),
            Err(error) => format!(
                "热重载失败、exact-owned core 未确认停止且配置回滚失败；保持 Fail Closed：{error}"
            ),
        });
    }

    let reload_epoch_before_start = app
        .state::<lifecycle::DesktopCoordinator>()
        .recovery_epoch();
    let start_result = {
        let _transaction = state.lock_routing_transaction().await;
        start_owned_core_verified(&app, state).await
    };
    state.record_fast_path(
        FastPathStage::FallbackRestart,
        fallback_started_at,
        if start_result.is_ok() {
            FastPathResultCode::Ok
        } else {
            FastPathResultCode::Error
        },
    );
    if let Err(start_error) = start_result {
        let rollback = {
            let _transaction = state.lock_routing_transaction().await;
            state.rollback_deferred_settings(&pending)
        };
        if let Err(rollback_error) = rollback {
            return Err(format!(
                "新核心启动失败且最后有效配置回滚未完成；保持 Fail Closed：{start_error}；{rollback_error}"
            ));
        }
        let coordinator = app.state::<lifecycle::DesktopCoordinator>();
        if coordinator.stop_requested()
            || coordinator.recovery_epoch() != reload_epoch_before_start.saturating_add(1)
        {
            return Err("停止请求优先于设置重载；已恢复最后有效配置并保持核心停止".into());
        }
        let recovery = {
            let _transaction = state.lock_routing_transaction().await;
            start_owned_core_verified(&app, state).await
        };
        return match recovery {
            Ok(_) => Err(format!(
                "新核心未通过权威回读；已恢复最后有效配置和旧核心：{start_error}"
            )),
            Err(recovery_error) => Err(format!(
                "新核心未通过权威回读；已恢复最后有效配置，但旧核心恢复失败并进入 terminal Fail Closed：{start_error}；{recovery_error}"
            )),
        };
    }

    let finalized = {
        let _transaction = state.lock_routing_transaction().await;
        state.finalize_deferred_settings(&mut pending, true)
    };
    match finalized {
        Ok(result) => Ok(result),
        Err(finalize_error) => {
            if state.deferred_settings_commit_decided(&pending) {
                return Err(format!(
                    "settings_commit_recovery_pending：提交决定已持久化；设置与 Controller 保持新状态，剩余收尾只会幂等前滚：{finalize_error}"
                ));
            }
            let _ = lifecycle::dispatch_stop_and_wait(&app).await;
            let rollback = {
                let _transaction = state.lock_routing_transaction().await;
                state.rollback_deferred_settings(&pending)
            };
            if let Err(rollback_error) = rollback {
                return Err(format!(
                    "新核心已通过回读，但设置事务收尾与回滚均失败；核心已停止并保持 Fail Closed：{finalize_error}；{rollback_error}"
                ));
            }
            if app
                .state::<lifecycle::DesktopCoordinator>()
                .stop_requested()
            {
                return Err("停止请求优先于设置收尾；已恢复最后有效配置并保持核心停止".into());
            }
            let recovery = {
                let _transaction = state.lock_routing_transaction().await;
                start_owned_core_verified(&app, state).await
            };
            match recovery {
                Ok(_) => Err(format!(
                    "设置事务收尾失败；已恢复最后有效配置和旧核心：{finalize_error}"
                )),
                Err(recovery_error) => Err(format!(
                    "设置事务收尾失败；已恢复最后有效配置，但旧核心恢复失败并进入 terminal Fail Closed：{finalize_error}；{recovery_error}"
                )),
            }
        }
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn cancel_foreground_operation(app: AppHandle, state: State<'_, AppState>) -> bool {
    let cancelled = state.cancel_foreground_operation();
    app.state::<lifecycle::DesktopCoordinator>()
        .cancel_background_work();
    cancelled
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn get_fast_path_performance(
    state: State<'_, AppState>,
) -> Result<FastPathPerformanceReport, String> {
    state.fast_path_performance_report()
}

fn helper_settings_deployment_required(
    helper_owned: bool,
    private_routing_changed: bool,
    credentials_changed: bool,
) -> bool {
    helper_owned && (private_routing_changed || credentials_changed)
}

fn after_successful_settings_commit<T>(
    result: Result<T, String>,
    on_commit: impl FnOnce(),
) -> Result<T, String> {
    let committed = result?;
    on_commit();
    Ok(committed)
}

fn after_successful_terminal_recovery<T>(
    result: Result<T, String>,
    dispatch_reload: impl FnOnce(),
) -> Result<T, String> {
    let recovered = result?;
    dispatch_reload();
    Ok(recovered)
}

async fn recover_active_settings_terminal(
    current: SettingsTerminalStatus,
    recovery: impl Future<Output = Result<SettingsTerminalStatus, String>>,
    dispatch_reload: impl FnOnce(),
) -> Result<SettingsTerminalStatus, String> {
    if !current.active {
        return Ok(current);
    }
    after_successful_terminal_recovery(recovery.await, dispatch_reload)
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
    record_routing_cycle_controlled(state, true, Arc::new(AtomicBool::new(false))).await
}

#[cfg(test)]
async fn record_owned_controller_cycle_locked(state: &AppState) -> Result<u64, String> {
    record_routing_cycle_controlled(state, false, Arc::new(AtomicBool::new(false))).await
}

pub(crate) async fn record_routing_cycle_controlled(
    state: &AppState,
    allow_direct_fallback: bool,
    cancel: Arc<AtomicBool>,
) -> Result<u64, String> {
    if cancel.load(Ordering::Acquire) {
        return Err("Guardian 路由周期已取消".into());
    }
    if state.settings_terminal_active() {
        state.enforce_settings_terminal_fail_closed().await?;
        return Err(
            "terminal_recovery_active：自动 Guardian/ConfigReload 探测已阻断，MASTER/UDP 保持 Fail Closed"
                .into(),
        );
    }
    let guardian = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let private = state.private_config()?;
    let Some(controller) = state.controller_client()? else {
        return if allow_direct_fallback {
            if cancel.load(Ordering::Acquire) {
                return Err("Guardian 路由周期已取消".into());
            }
            record_direct_guardian_cycle(state).await
        } else {
            Err("应用自管核心未提供可验证 Controller；不会把直连探测降级当作启动成功".into())
        };
    };
    let mut store = GuardianStore::open(&guardian.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
    store
        .sync_history_outlets(&history_outlets(&private), &Utc::now().to_rfc3339())
        .map_err(|error| format!("无法同步脱敏历史出口目录：{error}"))?;

    let guardian_started_at = Instant::now();
    let guardian_result = run_controller_guardian_cycle_controlled(
        &controller,
        &private,
        &state.resolved_subscription_urls(&private)?,
        &guardian.monitor,
        &mut store,
        state,
        unix_time_ms(),
        Arc::clone(&cancel),
        DEFAULT_GUARDIAN_CYCLE_BUDGET,
        DEFAULT_GUARDIAN_CONCURRENCY,
    )
    .await
    .map_err(|error| format!("Guardian 路由周期失败：{error}"));
    state.record_fast_path(
        FastPathStage::GuardianCycle,
        guardian_started_at,
        if guardian_result.is_ok() {
            FastPathResultCode::Ok
        } else if cancel.load(Ordering::Acquire) {
            FastPathResultCode::Cancelled
        } else {
            FastPathResultCode::Error
        },
    );
    guardian_result?;
    Ok(guardian.monitor.interval_seconds)
}

#[tauri::command]
pub async fn get_settings_terminal_status(
    state: State<'_, AppState>,
) -> Result<crate::runtime::SettingsTerminalStatus, String> {
    Ok(state.settings_terminal_status())
}

#[tauri::command]
pub async fn recover_settings_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::runtime::SettingsTerminalStatus, String> {
    let _settings_apply = state.lock_settings_apply().await;
    let _transaction = state.lock_routing_transaction().await;
    let current = state.settings_terminal_status();
    let coordinator = app.state::<lifecycle::DesktopCoordinator>();
    recover_active_settings_terminal(
        current,
        async {
            if state.controller_client()?.is_none() {
                state.recover_settings_transaction_for_terminal()?;
                start_owned_core_for_terminal_recovery(&app, &state).await
            } else {
                state.recover_settings_terminal().await
            }
        },
        || {
            coordinator.prepare_config_reload();
            lifecycle::dispatch(
                &app,
                LifecycleEvent::ConfigReload {
                    now_ms: unix_time_ms(),
                },
            );
        },
    )
    .await
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
    load_dashboard(&state).await
}

#[tauri::command]
pub async fn refresh_guardian(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    let _transaction = state.lock_routing_transaction().await;
    record_routing_cycle_locked(&state).await?;
    load_dashboard(&state).await
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
    load_dashboard(&state).await
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
    app: AppHandle,
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
    lifecycle::dispatch(&app, LifecycleEvent::RouteChanged);
    load_dashboard(&state).await
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
    let _transaction = state.lock_routing_transaction().await;
    start_owned_core_verified(&app, &state).await
}

async fn start_owned_core_verified(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreStatus, String> {
    let started_at = Instant::now();
    let timed = tokio::time::timeout(
        Duration::from_secs(5),
        start_owned_core_verified_inner(app, state),
    )
    .await;
    let (result, result_code) = match timed {
        Ok(result) => {
            let code = if result.is_ok() {
                FastPathResultCode::Ok
            } else {
                FastPathResultCode::Error
            };
            (result, code)
        }
        Err(_) => (
            Err("核心启动超过 5 秒总预算；未发布迟到进程并保持 Fail Closed".to_string()),
            FastPathResultCode::Timeout,
        ),
    };
    state.record_fast_path(FastPathStage::CoreStartup, started_at, result_code);
    result
}

async fn start_owned_core_verified_inner(
    app: &AppHandle,
    state: &AppState,
) -> Result<CoreStatus, String> {
    let coordinator = app.state::<lifecycle::DesktopCoordinator>();
    let cancel = Arc::new(AtomicBool::new(false));
    let start_epoch = coordinator.prepare_manual_start(&cancel)?;
    let mut status = match state.start_development_core_cancellable(&cancel).await {
        Ok(status) => status,
        Err(error) => {
            if state
                .core_status_authoritative()
                .await
                .is_ok_and(|status| status.state == "external")
            {
                lifecycle::dispatch(app, LifecycleEvent::PortConflictObserved);
            }
            coordinator.complete_manual_start_failure(start_epoch);
            return Err(error);
        }
    };
    let Some(pid) = status.pid else {
        coordinator.complete_manual_start_failure(start_epoch);
        return Err("应用自管核心未发布可验证 PID；已保持 Fail Closed".into());
    };
    if state.uses_helper_authority() {
        if !coordinator.complete_manual_start(pid, start_epoch) {
            let _ = state.stop_supervised_core_if_pid(pid).await;
            return Err("停止请求优先于 Helper 启动结果；核心已安全停止".into());
        }
        status.message = "Helper authority 已启动并监督核心".into();
        return Ok(status);
    }
    if !coordinator.manual_start_allowed(start_epoch)
        || !state.owned_core_controller_is_running(pid)
    {
        let _ = state.stop_supervised_core_if_pid(pid).await;
        coordinator.complete_manual_start_failure(start_epoch);
        return Err(
            "应用自管核心未通过 PID、入口与 Controller ownership 复核；已停止并保持 Fail Closed"
                .into(),
        );
    }
    if !coordinator.complete_manual_start(pid, start_epoch)
        || !state.owned_core_controller_is_running(pid)
    {
        let _ = state.stop_supervised_core_if_pid(pid).await;
        return Err("停止请求已优先于迟到的启动结果；应用自管核心已清理".into());
    }
    lifecycle::dispatch(
        app,
        LifecycleEvent::ConfigReload {
            now_ms: unix_time_ms(),
        },
    );
    status.message = "开发核心已启动并验证双 REJECT；出口健康确认正在后台进行".into();
    Ok(status)
}

async fn start_owned_core_for_terminal_recovery(
    app: &AppHandle,
    state: &AppState,
) -> Result<crate::runtime::SettingsTerminalStatus, String> {
    if !state.settings_terminal_active() {
        return Ok(state.settings_terminal_status());
    }
    if state.uses_helper_authority() {
        return Err(
            "terminal 专用恢复当前只允许 desktop-owned 核心；不会借用 Helper 或外部 Controller"
                .into(),
        );
    }
    let coordinator = app.state::<lifecycle::DesktopCoordinator>();
    let cancel = Arc::new(AtomicBool::new(false));
    let start_epoch = coordinator.prepare_manual_start(&cancel)?;
    let status = match state.start_development_core_cancellable(&cancel).await {
        Ok(status) => status,
        Err(error) => {
            coordinator.complete_manual_start_failure(start_epoch);
            return Err(format!(
                "terminal 专用恢复无法启动初始双 REJECT 核心；安全门保持：{error}"
            ));
        }
    };
    let Some(pid) = status.pid else {
        coordinator.complete_manual_start_failure(start_epoch);
        return Err("terminal 专用恢复核心未发布可验证 PID；安全门保持".into());
    };
    if !coordinator.manual_start_allowed(start_epoch)
        || !state.owned_core_controller_is_running(pid)
    {
        let _ = state.stop_supervised_core_if_pid(pid).await;
        coordinator.complete_manual_start_failure(start_epoch);
        return Err(
            "terminal 专用恢复核心未通过 PID/Controller ownership；已停止且安全门保持".into(),
        );
    }
    let recovered = match state.recover_settings_terminal_for_owned_core(pid).await {
        Ok(status) => status,
        Err(error) => {
            let _ = state.stop_supervised_core_if_pid(pid).await;
            coordinator.complete_manual_start_failure(start_epoch);
            return Err(format!(
                "terminal 专用恢复未通过双 REJECT 权威回读；核心已停止且安全门保持：{error}"
            ));
        }
    };
    if !coordinator.complete_manual_start(pid, start_epoch)
        || !state.owned_core_controller_is_running(pid)
    {
        let _ = state.stop_supervised_core_if_pid(pid).await;
        return Err("停止请求优先于 terminal 专用恢复结果；核心已清理".into());
    }
    Ok(recovered)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn stop_development_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatus, String> {
    let resolution = app
        .state::<lifecycle::DesktopCoordinator>()
        .request_stop()
        .await;
    Ok(match resolution {
        lifecycle::StopRequestResult::Stopped => CoreStatus {
            state: "stopped".into(),
            managed: false,
            pid: None,
            started_at: None,
            message: "应用自管核心与待恢复任务已停止".into(),
        },
        lifecycle::StopRequestResult::Pending => {
            let pid = state.owned_core_pid_authoritative().await?;
            CoreStatus {
                state: "stopping".into(),
                managed: pid.is_some(),
                pid,
                started_at: None,
                message: "停止请求处理中；不会报告为已停止，后台将继续有界清理".into(),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_switch_preview_rejects_terminal_and_unsupported_platform() {
        assert!(ensure_entry_switch_preview_supported(false, true).is_ok());
        assert!(
            ensure_entry_switch_preview_supported(true, true)
                .expect_err("terminal")
                .contains("terminal_recovery_active")
        );
        assert!(
            ensure_entry_switch_preview_supported(false, false)
                .expect_err("platform")
                .contains("只支持 Windows")
        );
    }

    #[cfg(target_os = "windows")]
    fn proxy_snapshot(port: u16) -> ProtectedProxySnapshotWire {
        vpn_hub_windows_security::WinInetLanProxySnapshot {
            flags: 2,
            proxy_server: Some(format!("http=127.0.0.1:{port}")),
            proxy_bypass: Some("<local>".into()),
            auto_config_url: None,
        }
        .into()
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn compensation_requires_stopped_result_and_absent_owned_pid() {
        assert!(owned_core_stop_confirmed(
            lifecycle::StopRequestResult::Stopped,
            None
        ));
        assert!(!owned_core_stop_confirmed(
            lifecycle::StopRequestResult::Pending,
            None
        ));
        assert!(!owned_core_stop_confirmed(
            lifecycle::StopRequestResult::Stopped,
            Some(42)
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn compensation_proxy_classification_never_overwrites_third_party_value() {
        let original = proxy_snapshot(31_001);
        let desired = proxy_snapshot(31_002);
        let third_party = proxy_snapshot(31_003);
        assert_eq!(
            classify_proxy_rollback(&desired, &original, &desired),
            ProxyRollbackAction::RestoreOriginal
        );
        assert_eq!(
            classify_proxy_rollback(&original, &original, &desired),
            ProxyRollbackAction::AlreadyOriginal
        );
        assert_eq!(
            classify_proxy_rollback(&third_party, &original, &desired),
            ProxyRollbackAction::PreserveThirdParty
        );
    }

    #[test]
    fn helper_owned_runtime_changes_are_rejected_even_while_stopped() {
        assert!(helper_settings_deployment_required(true, true, false));
        assert!(helper_settings_deployment_required(true, false, true));
        assert!(!helper_settings_deployment_required(true, false, false));
        assert!(!helper_settings_deployment_required(false, true, true));
    }

    #[test]
    fn failed_settings_apply_does_not_cancel_scheduled_recovery() {
        let coordinator = lifecycle::DesktopCoordinator::new();
        let recovery_epoch = coordinator.recovery_epoch();
        let result = after_successful_settings_commit::<()>(Err("stale preview".into()), || {
            coordinator.prepare_config_reload();
        });
        assert!(result.is_err());
        assert_eq!(coordinator.recovery_epoch(), recovery_epoch);

        after_successful_settings_commit(Ok(()), || {
            coordinator.prepare_config_reload();
        })
        .expect("successful commit");
        assert_eq!(coordinator.recovery_epoch(), recovery_epoch + 1);
    }

    #[test]
    fn terminal_recovery_dispatches_reload_only_once_and_only_after_success() {
        let reloads = std::cell::Cell::new(0_u32);
        let failed =
            after_successful_terminal_recovery::<()>(Err("pending journal".into()), || {
                reloads.set(reloads.get() + 1);
            });
        assert!(failed.is_err());
        assert_eq!(reloads.get(), 0);

        after_successful_terminal_recovery(Ok(()), || {
            reloads.set(reloads.get() + 1);
        })
        .expect("terminal recovery");
        assert_eq!(reloads.get(), 1);
    }

    fn terminal_status(active: bool) -> SettingsTerminalStatus {
        SettingsTerminalStatus {
            active,
            state: active.then_some(crate::runtime::SettingsTerminalState::Pending),
        }
    }

    #[tokio::test]
    async fn concurrent_terminal_recovery_transitions_and_reloads_exactly_once() {
        async fn invoke(
            lock: Arc<tokio::sync::Mutex<()>>,
            gate_active: Arc<AtomicBool>,
            clears: Arc<std::sync::atomic::AtomicUsize>,
            reloads: Arc<std::sync::atomic::AtomicUsize>,
            ready: Arc<tokio::sync::Barrier>,
        ) -> Result<SettingsTerminalStatus, String> {
            ready.wait().await;
            let _guard = lock.lock().await;
            let current = terminal_status(gate_active.load(Ordering::SeqCst));
            recover_active_settings_terminal(
                current,
                async {
                    clears.fetch_add(1, Ordering::SeqCst);
                    gate_active.store(false, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    Ok(terminal_status(false))
                },
                || {
                    reloads.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await
        }

        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let gate_active = Arc::new(AtomicBool::new(true));
        let clears = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reloads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ready = Arc::new(tokio::sync::Barrier::new(3));
        let first = tokio::spawn(invoke(
            Arc::clone(&lock),
            Arc::clone(&gate_active),
            Arc::clone(&clears),
            Arc::clone(&reloads),
            Arc::clone(&ready),
        ));
        let second = tokio::spawn(invoke(
            lock,
            Arc::clone(&gate_active),
            Arc::clone(&clears),
            Arc::clone(&reloads),
            Arc::clone(&ready),
        ));
        ready.wait().await;

        let first_status = first.await.expect("first join").expect("first recovery");
        let second_status = second.await.expect("second join").expect("second recovery");
        assert_eq!(first_status, terminal_status(false));
        assert_eq!(second_status, terminal_status(false));
        assert_eq!(clears.load(Ordering::SeqCst), 1);
        assert_eq!(reloads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn successful_terminal_recovery_retry_is_an_inactive_no_op() {
        let gate_active = AtomicBool::new(true);
        let clears = std::sync::atomic::AtomicUsize::new(0);
        let reloads = std::sync::atomic::AtomicUsize::new(0);

        let first = recover_active_settings_terminal(
            terminal_status(gate_active.load(Ordering::SeqCst)),
            async {
                clears.fetch_add(1, Ordering::SeqCst);
                gate_active.store(false, Ordering::SeqCst);
                Ok(terminal_status(false))
            },
            || {
                reloads.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect("first recovery");
        let second = recover_active_settings_terminal(
            terminal_status(gate_active.load(Ordering::SeqCst)),
            async { Err("inactive recovery must not be polled".into()) },
            || {
                reloads.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect("inactive retry");

        assert_eq!(first, terminal_status(false));
        assert_eq!(second, terminal_status(false));
        assert_eq!(clears.load(Ordering::SeqCst), 1);
        assert_eq!(reloads.load(Ordering::SeqCst), 1);
    }

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

        let initial = load_dashboard(&state).await.expect("clean dashboard");
        assert_eq!(initial.entry.host, "127.0.0.1");
        assert_eq!(initial.entry.port, 3_666);
        assert!(initial.routing.outlets.is_empty());

        let interval = record_routing_cycle_locked(&state)
            .await
            .expect("clean refresh");
        assert_eq!(interval, 180);
        let strict_error = record_owned_controller_cycle_locked(&state)
            .await
            .expect_err("manual startup must reject the direct Guardian fallback");
        assert!(strict_error.contains("Controller"));
        let refreshed = load_dashboard(&state).await.expect("refreshed dashboard");
        assert!(refreshed.routing.outlets.is_empty());
        assert!(refreshed.summaries.is_empty());
    }

    #[tokio::test]
    async fn dashboard_projects_stale_udp_evidence_as_unknown_without_rewriting_history() {
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
        let dashboard = load_dashboard(&state).await.expect("dashboard snapshot");
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
