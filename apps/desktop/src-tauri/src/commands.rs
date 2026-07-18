use serde::Serialize;
use std::{path::Path, path::PathBuf, time::Duration};
use tauri::State;
use vpn_hub_core::{
    GuardianConfig, GuardianStore, LatencySample, OutletSummary, StateEvent, probe_outlet,
};

use crate::runtime::{AppState, CoreStatus, PortSnapshot};

#[derive(Debug, Serialize)]
pub struct DashboardSnapshot {
    updated_at: String,
    protected_entry: PortSnapshot,
    development_entry: PortSnapshot,
    upstream_entry: PortSnapshot,
    mihomo: CoreStatus,
    summaries: Vec<OutletSummary>,
    samples: Vec<LatencySample>,
    events: Vec<StateEvent>,
}

fn load_dashboard(state: &AppState) -> Result<DashboardSnapshot, String> {
    let config = GuardianConfig::load(state.guardian_config_path())
        .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
    let store = GuardianStore::open(&config.database_path)
        .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;

    Ok(DashboardSnapshot {
        updated_at: chrono::Utc::now().to_rfc3339(),
        protected_entry: AppState::port_snapshot(6_666),
        development_entry: AppState::port_snapshot(36_666),
        upstream_entry: AppState::port_snapshot(16_666),
        mihomo: state.core_status()?,
        summaries: store
            .summaries()
            .map_err(|error| format!("无法读取出口汇总：{error}"))?,
        samples: store
            .recent_samples(180)
            .map_err(|error| format!("无法读取延迟样本：{error}"))?,
        events: store
            .recent_events(12)
            .map_err(|error| format!("无法读取状态事件：{error}"))?,
    })
}

async fn record_guardian_cycle(config_path: &Path) -> Result<u64, String> {
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

pub(crate) async fn monitor_guardian(config_path: PathBuf) {
    loop {
        let interval = match record_guardian_cycle(&config_path).await {
            Ok(interval) => interval,
            Err(error) => {
                eprintln!("Guardian background cycle failed: {error}");
                180
            }
        };
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn get_dashboard_snapshot(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    load_dashboard(&state)
}

#[tauri::command]
pub async fn refresh_guardian(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    record_guardian_cycle(&state.guardian_config_path()).await?;
    load_dashboard(&state)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn start_development_core(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    state.start_development_core()
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn stop_development_core(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    state.stop_development_core()
}
