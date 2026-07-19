use std::{
    collections::{HashMap, VecDeque, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "windows")]
use std::{
    io::Read as _,
    process::{Command, Stdio},
};

use chrono::Utc;
use serde::Serialize;
use tauri::{
    App, AppHandle, Manager,
    menu::{MenuBuilder, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use vpn_hub_core::{
    FAIL_CLOSED_OUTLET, GuardianConfig, GuardianStore, HealthStatus, RouteSwitchEvent, StateEvent,
};

use crate::{commands, runtime::AppState};

const TRAY_ID: &str = "vpn-hub-main";
const RECOVERY_SIGNAL_COALESCE_MS: u64 = 5_000;
const NETWORK_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const RESUME_GAP: Duration = Duration::from_secs(30);
const NOTIFICATION_WINDOW_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    WindowClose,
    OpenWindow,
    StopCore,
    CoreStarted,
    CoreStopped,
    OwnedCoreUnexpectedExit,
    RestartTimer,
    StartupFailed(StartupFailure),
    PortConflictObserved,
    ConfigReload { now_ms: u64 },
    RecoverySignal { now_ms: u64 },
    ExplicitExit,
    OsShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupFailure {
    PortConflict,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecycleEffect {
    HideWindow,
    ShowAndFocusWindow,
    StopOwnedCore,
    StartOwnedCore,
    ProbeAllEnabled,
    RefreshTray,
    Notify(NotificationKind),
    ScheduleRestart(Duration),
    ExitApplication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationKind {
    OwnedCoreExited,
    CoreRecovered,
    PortConflict,
    ConsecutiveStartupFailures(u32),
}

#[derive(Debug, Default)]
struct LifecycleMachine {
    exiting: bool,
    core_expected: bool,
    restart_pending: bool,
    consecutive_startup_failures: u32,
    last_recovery_signal_ms: Option<u64>,
}

impl LifecycleMachine {
    fn reduce(&mut self, event: LifecycleEvent) -> Vec<LifecycleEffect> {
        if self.exiting {
            return Vec::new();
        }
        match event {
            LifecycleEvent::WindowClose => vec![LifecycleEffect::HideWindow],
            LifecycleEvent::OpenWindow => vec![LifecycleEffect::ShowAndFocusWindow],
            LifecycleEvent::StopCore => {
                self.core_expected = false;
                self.restart_pending = false;
                vec![LifecycleEffect::StopOwnedCore, LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::CoreStarted => {
                let recovered = self.consecutive_startup_failures > 0;
                self.core_expected = true;
                self.restart_pending = false;
                self.consecutive_startup_failures = 0;
                let mut effects = vec![LifecycleEffect::RefreshTray];
                if recovered {
                    effects.push(LifecycleEffect::Notify(NotificationKind::CoreRecovered));
                }
                effects
            }
            LifecycleEvent::CoreStopped => {
                self.core_expected = false;
                self.restart_pending = false;
                vec![LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::OwnedCoreUnexpectedExit => {
                if !self.core_expected || self.restart_pending {
                    return Vec::new();
                }
                self.restart_pending = true;
                let delay = restart_delay(self.consecutive_startup_failures);
                vec![
                    LifecycleEffect::Notify(NotificationKind::OwnedCoreExited),
                    LifecycleEffect::ScheduleRestart(delay),
                    LifecycleEffect::RefreshTray,
                ]
            }
            LifecycleEvent::RestartTimer => {
                if !self.core_expected || !self.restart_pending {
                    return Vec::new();
                }
                self.restart_pending = false;
                vec![LifecycleEffect::StartOwnedCore]
            }
            LifecycleEvent::StartupFailed(kind) => {
                if !self.core_expected {
                    return Vec::new();
                }
                self.consecutive_startup_failures =
                    self.consecutive_startup_failures.saturating_add(1);
                self.restart_pending = true;
                let mut effects = Vec::new();
                if kind == StartupFailure::PortConflict {
                    effects.push(LifecycleEffect::Notify(NotificationKind::PortConflict));
                }
                if self.consecutive_startup_failures >= 2 {
                    effects.push(LifecycleEffect::Notify(
                        NotificationKind::ConsecutiveStartupFailures(
                            self.consecutive_startup_failures,
                        ),
                    ));
                }
                effects.push(LifecycleEffect::ScheduleRestart(restart_delay(
                    self.consecutive_startup_failures,
                )));
                effects
            }
            LifecycleEvent::PortConflictObserved => {
                vec![LifecycleEffect::Notify(NotificationKind::PortConflict)]
            }
            LifecycleEvent::ConfigReload { now_ms } | LifecycleEvent::RecoverySignal { now_ms } => {
                if self
                    .last_recovery_signal_ms
                    .is_some_and(|last| now_ms.saturating_sub(last) < RECOVERY_SIGNAL_COALESCE_MS)
                {
                    return Vec::new();
                }
                self.last_recovery_signal_ms = Some(now_ms);
                vec![
                    LifecycleEffect::ProbeAllEnabled,
                    LifecycleEffect::RefreshTray,
                ]
            }
            LifecycleEvent::ExplicitExit | LifecycleEvent::OsShutdown => {
                self.exiting = true;
                self.core_expected = false;
                self.restart_pending = false;
                vec![
                    LifecycleEffect::StopOwnedCore,
                    LifecycleEffect::ExitApplication,
                ]
            }
        }
    }
}

fn restart_delay(attempts: u32) -> Duration {
    Duration::from_secs(1_u64 << attempts.min(5))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TrayProjection {
    pub entry_host: String,
    pub entry_port: u16,
    pub current_outlet_id: String,
    pub core_managed: bool,
    pub outlets: Vec<TrayOutletProjection>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TrayOutletProjection {
    pub outlet_id: String,
    pub label: String,
    pub enabled: bool,
    pub status: HealthStatus,
}

impl TrayProjection {
    fn load(state: &AppState) -> Result<Self, String> {
        let private = state.private_config()?;
        let guardian = GuardianConfig::load(state.guardian_config_path())
            .map_err(|error| format!("无法加载 Guardian 配置：{error}"))?;
        let summaries = GuardianStore::open(&guardian.database_path)
            .and_then(|store| store.summaries())
            .unwrap_or_default();
        let statuses = summaries
            .into_iter()
            .map(|summary| (summary.outlet_id, summary.last_status))
            .collect::<HashMap<_, _>>();
        let routing = state.routing_status()?;
        let current_outlet_id = routing
            .current_outlet
            .unwrap_or_else(|| FAIL_CLOSED_OUTLET.to_owned());
        let core_managed = state
            .core_status()
            .is_ok_and(|status| status.managed && status.state == "running");
        Ok(Self {
            entry_host: private.entry.host,
            entry_port: private.entry.port,
            current_outlet_id,
            core_managed,
            outlets: private
                .outlets
                .into_iter()
                .map(|outlet| TrayOutletProjection {
                    status: statuses
                        .get(&outlet.id)
                        .copied()
                        .unwrap_or(HealthStatus::Unknown),
                    outlet_id: outlet.id.clone(),
                    label: safe_label(&outlet.label, &outlet.id),
                    enabled: outlet.enabled,
                })
                .collect(),
        })
    }

    fn tooltip(&self) -> String {
        format!(
            "VPN Hub · {}:{} · {}",
            self.entry_host, self.entry_port, self.current_outlet_id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SafeNotification {
    key: String,
    title: String,
    body: String,
}

#[derive(Debug, Default)]
struct NotificationDeduper {
    last_sent: HashMap<String, u64>,
}

impl NotificationDeduper {
    fn allow(&mut self, notification: &SafeNotification, now_ms: u64) -> bool {
        if self
            .last_sent
            .get(&notification.key)
            .is_some_and(|last| now_ms.saturating_sub(*last) < NOTIFICATION_WINDOW_MS)
        {
            return false;
        }
        self.last_sent.insert(notification.key.clone(), now_ms);
        true
    }
}

trait NotificationSink {
    fn send(&self, notification: &SafeNotification);
}

struct TauriNotificationSink<'a> {
    app: &'a AppHandle,
}

impl NotificationSink for TauriNotificationSink<'_> {
    fn send(&self, notification: &SafeNotification) {
        let _ = self
            .app
            .notification()
            .builder()
            .title(&notification.title)
            .body(&notification.body)
            .show();
    }
}

#[derive(Default)]
struct TransitionNotifications {
    initialized: bool,
    seen: VecDeque<String>,
}

impl TransitionNotifications {
    fn collect(&mut self, state: &AppState) -> Vec<SafeNotification> {
        let Ok(guardian) = GuardianConfig::load(state.guardian_config_path()) else {
            return Vec::new();
        };
        let Ok(store) = GuardianStore::open(&guardian.database_path) else {
            return Vec::new();
        };
        let states = store.recent_events(32).unwrap_or_default();
        let switches = store.recent_route_switches(32).unwrap_or_default();
        let mut candidates = Vec::new();
        for event in states.into_iter().rev() {
            let event_key = format!(
                "state:{}:{}:{}:{}",
                event.occurred_at,
                event.outlet_id,
                event.from_status.as_str(),
                event.to_status.as_str()
            );
            if !self.initialized || self.seen.contains(&event_key) {
                self.remember(event_key);
                continue;
            }
            let notification = state_transition_notification(&event);
            self.remember(event_key);
            if let Some(notification) = notification {
                candidates.push(notification);
            }
        }
        for event in switches.into_iter().rev() {
            let event_key = format!(
                "switch:{}:{}:{}",
                event.occurred_at,
                event.from_outlet.as_deref().unwrap_or("none"),
                event.to_outlet
            );
            if !self.initialized || self.seen.contains(&event_key) {
                self.remember(event_key);
                continue;
            }
            candidates.push(route_switch_notification(&event));
            self.remember(event_key);
        }
        self.initialized = true;
        candidates
    }

    fn remember(&mut self, key: String) {
        if self.seen.contains(&key) {
            return;
        }
        self.seen.push_back(key);
        while self.seen.len() > 256 {
            self.seen.pop_front();
        }
    }
}

fn state_transition_notification(event: &StateEvent) -> Option<SafeNotification> {
    let outlet_id = safe_id(&event.outlet_id);
    match event.to_status {
        HealthStatus::Down => Some(SafeNotification {
            key: format!("outlet-down:{outlet_id}"),
            title: "出口故障".into(),
            body: format!("逻辑出口 {outlet_id} 已进入不可用状态。"),
        }),
        HealthStatus::Healthy
            if matches!(
                event.from_status,
                HealthStatus::Down | HealthStatus::Degraded
            ) =>
        {
            Some(SafeNotification {
                key: format!("outlet-recovered:{outlet_id}"),
                title: "出口已恢复".into(),
                body: format!("逻辑出口 {outlet_id} 已恢复可用。"),
            })
        }
        _ => None,
    }
}

fn route_switch_notification(event: &RouteSwitchEvent) -> SafeNotification {
    let from = safe_id(event.from_outlet.as_deref().unwrap_or("none"));
    let to = safe_id(&event.to_outlet);
    if to == FAIL_CLOSED_OUTLET {
        SafeNotification {
            key: "route-fail-closed".into(),
            title: "已进入 Fail Closed".into(),
            body: format!("当前逻辑路由已从 {from} 切换到 Fail Closed。"),
        }
    } else {
        SafeNotification {
            key: format!("route-switch:{from}:{to}"),
            title: "出口已切换".into(),
            body: format!("当前逻辑出口已从 {from} 切换到 {to}。"),
        }
    }
}

pub struct DesktopCoordinator {
    sender: UnboundedSender<LifecycleEvent>,
    receiver: Mutex<Option<UnboundedReceiver<LifecycleEvent>>>,
    started: AtomicBool,
    exit_permitted: AtomicBool,
}

impl DesktopCoordinator {
    #[must_use]
    pub fn new() -> Self {
        let (sender, receiver) = unbounded_channel();
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            started: AtomicBool::new(false),
            exit_permitted: AtomicBool::new(false),
        }
    }

    pub fn dispatch(&self, event: LifecycleEvent) {
        let _ = self.sender.send(event);
    }

    pub fn start(&self, app: AppHandle) -> Result<(), String> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| "桌面生命周期队列锁已损坏".to_string())?
            .take()
            .ok_or_else(|| "桌面生命周期队列已启动".to_string())?;
        tauri::async_runtime::spawn(run_coordinator(app, receiver));
        Ok(())
    }

    #[must_use]
    pub fn exit_permitted(&self) -> bool {
        self.exit_permitted.load(Ordering::Acquire)
    }

    fn permit_exit(&self) {
        self.exit_permitted.store(true, Ordering::Release);
    }
}

impl Default for DesktopCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn dispatch(app: &AppHandle, event: LifecycleEvent) {
    app.state::<DesktopCoordinator>().dispatch(event);
}

pub fn install_tray(app: &App) -> tauri::Result<()> {
    let projection =
        TrayProjection::load(&app.state::<AppState>()).unwrap_or_else(|_| TrayProjection {
            entry_host: "127.0.0.1".into(),
            entry_port: 0,
            current_outlet_id: FAIL_CLOSED_OUTLET.into(),
            core_managed: false,
            outlets: Vec::new(),
        });
    let menu = tray_menu(app.handle(), &projection)?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip(projection.tooltip())
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => dispatch(app, LifecycleEvent::OpenWindow),
            "stop_core" => dispatch(app, LifecycleEvent::StopCore),
            "quit" => dispatch(app, LifecycleEvent::ExplicitExit),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                dispatch(tray.app_handle(), LifecycleEvent::OpenWindow);
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn tray_menu(
    app: &AppHandle,
    projection: &TrayProjection,
) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    let entry = MenuItem::with_id(
        app,
        "summary_entry",
        format!("入口  {}:{}", projection.entry_host, projection.entry_port),
        false,
        None::<&str>,
    )?;
    let current = MenuItem::with_id(
        app,
        "summary_current",
        format!("当前  {}", projection.current_outlet_id),
        false,
        None::<&str>,
    )?;
    let stop = MenuItem::with_id(
        app,
        "stop_core",
        "停止应用自管核心",
        projection.core_managed,
        None::<&str>,
    )?;
    let mut builder = MenuBuilder::new(app)
        .item(&entry)
        .item(&current)
        .separator();
    for (index, outlet) in projection.outlets.iter().enumerate() {
        let state = if outlet.enabled {
            outlet.status.as_str()
        } else {
            "disabled"
        };
        let item = MenuItem::with_id(
            app,
            format!("summary_outlet_{index}"),
            format!("{} · {} · {state}", outlet.outlet_id, outlet.label),
            false,
            None::<&str>,
        )?;
        builder = builder.item(&item);
    }
    builder
        .separator()
        .text("open", "打开 VPN Hub")
        .item(&stop)
        .text("quit", "退出 VPN Hub")
        .build()
}

async fn run_coordinator(app: AppHandle, mut receiver: UnboundedReceiver<LifecycleEvent>) {
    let mut machine = LifecycleMachine::default();
    let initial_running = app
        .state::<AppState>()
        .core_status()
        .is_ok_and(|status| status.managed && status.state == "running");
    machine.core_expected = initial_running;
    let mut deduper = NotificationDeduper::default();
    let mut transitions = TransitionNotifications::default();
    let mut next_guardian = Instant::now();
    let mut next_network_sample = Instant::now() + NETWORK_SAMPLE_INTERVAL;
    let mut last_network_fingerprint = sample_network_fingerprint().await;
    let mut last_network_sample = Instant::now();
    let mut restart_at: Option<Instant> = None;
    let mut previously_owned_running = initial_running;

    loop {
        let restart_deadline =
            restart_at.unwrap_or_else(|| Instant::now() + Duration::from_hours(24));
        tokio::select! {
            event = receiver.recv() => {
                let Some(event) = event else { break };
                if handle_event(&app, &mut machine, &mut deduper, &mut transitions, event, &mut restart_at).await {
                    break;
                }
            }
            () = tokio::time::sleep_until(next_guardian.into()) => {
                let interval = commands::record_routing_cycle(&app.state::<AppState>()).await.unwrap_or(180);
                next_guardian = Instant::now() + Duration::from_secs(interval.max(1));
                publish_transition_notifications(&app, &mut transitions, &mut deduper);
                refresh_tray(&app);
                let owned_running = app.state::<AppState>().core_status().is_ok_and(|status| status.managed && status.state == "running");
                if previously_owned_running && !owned_running {
                    let _ = handle_event(&app, &mut machine, &mut deduper, &mut transitions, LifecycleEvent::OwnedCoreUnexpectedExit, &mut restart_at).await;
                }
                previously_owned_running = owned_running;
            }
            () = tokio::time::sleep_until(next_network_sample.into()) => {
                let now = Instant::now();
                let fingerprint = sample_network_fingerprint().await;
                let resumed = now.duration_since(last_network_sample) >= RESUME_GAP;
                let network_changed = fingerprint != last_network_fingerprint;
                last_network_sample = now;
                last_network_fingerprint = fingerprint;
                next_network_sample = now + NETWORK_SAMPLE_INTERVAL;
                if resumed || network_changed {
                    let event = LifecycleEvent::RecoverySignal { now_ms: unix_time_ms() };
                    let _ = handle_event(&app, &mut machine, &mut deduper, &mut transitions, event, &mut restart_at).await;
                    next_guardian = Instant::now() + Duration::from_secs(1);
                }
            }
            () = tokio::time::sleep_until(restart_deadline.into()), if restart_at.is_some() => {
                restart_at = None;
                let _ = handle_event(&app, &mut machine, &mut deduper, &mut transitions, LifecycleEvent::RestartTimer, &mut restart_at).await;
            }
        }
    }
}

async fn handle_event(
    app: &AppHandle,
    machine: &mut LifecycleMachine,
    deduper: &mut NotificationDeduper,
    transitions: &mut TransitionNotifications,
    event: LifecycleEvent,
    restart_at: &mut Option<Instant>,
) -> bool {
    let effects = machine.reduce(event);
    for effect in effects {
        match effect {
            LifecycleEffect::HideWindow => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            LifecycleEffect::ShowAndFocusWindow => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.unminimize();
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            LifecycleEffect::StopOwnedCore => {
                let status = app.state::<AppState>().core_status();
                if status.is_ok_and(|status| status.managed) {
                    let _ = app.state::<AppState>().stop_development_core();
                }
                *restart_at = None;
            }
            LifecycleEffect::StartOwnedCore => {
                let started = app
                    .state::<AppState>()
                    .start_development_core()
                    .await
                    .is_ok();
                let healthy = started
                    && commands::record_routing_cycle(&app.state::<AppState>())
                        .await
                        .is_ok();
                if healthy {
                    let recovered = machine.reduce(LifecycleEvent::CoreStarted);
                    for effect in recovered {
                        if let LifecycleEffect::Notify(kind) = effect {
                            send_lifecycle_notification(app, deduper, kind);
                        }
                    }
                } else {
                    if started {
                        let _ = app.state::<AppState>().stop_development_core();
                    }
                    let occupied = app
                        .state::<AppState>()
                        .core_status()
                        .is_ok_and(|status| status.state == "external");
                    let kind = if occupied {
                        StartupFailure::PortConflict
                    } else {
                        StartupFailure::Other
                    };
                    for effect in machine.reduce(LifecycleEvent::StartupFailed(kind)) {
                        match effect {
                            LifecycleEffect::Notify(kind) => {
                                send_lifecycle_notification(app, deduper, kind);
                            }
                            LifecycleEffect::ScheduleRestart(delay) => {
                                *restart_at = Some(Instant::now() + delay);
                            }
                            _ => {}
                        }
                    }
                }
                refresh_tray(app);
            }
            LifecycleEffect::ProbeAllEnabled => {
                let _ = commands::record_routing_cycle(&app.state::<AppState>()).await;
                publish_transition_notifications(app, transitions, deduper);
            }
            LifecycleEffect::RefreshTray => refresh_tray(app),
            LifecycleEffect::Notify(kind) => send_lifecycle_notification(app, deduper, kind),
            LifecycleEffect::ScheduleRestart(delay) => {
                *restart_at = Some(Instant::now() + delay);
            }
            LifecycleEffect::ExitApplication => {
                app.state::<DesktopCoordinator>().permit_exit();
                app.exit(0);
                return true;
            }
        }
    }
    false
}

fn refresh_tray(app: &AppHandle) {
    let Ok(projection) = TrayProjection::load(&app.state::<AppState>()) else {
        return;
    };
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    if let Ok(menu) = tray_menu(app, &projection) {
        let _ = tray.set_menu(Some(menu));
    }
    let _ = tray.set_tooltip(Some(projection.tooltip()));
}

fn publish_transition_notifications(
    app: &AppHandle,
    transitions: &mut TransitionNotifications,
    deduper: &mut NotificationDeduper,
) {
    let sink = TauriNotificationSink { app };
    for notification in transitions.collect(&app.state::<AppState>()) {
        if deduper.allow(&notification, unix_time_ms()) {
            sink.send(&notification);
        }
    }
}

fn send_lifecycle_notification(
    app: &AppHandle,
    deduper: &mut NotificationDeduper,
    kind: NotificationKind,
) {
    let projection = TrayProjection::load(&app.state::<AppState>()).ok();
    let entry = projection.as_ref().map_or_else(
        || "configured loopback entry".into(),
        |projection| format!("{}:{}", projection.entry_host, projection.entry_port),
    );
    let notification = match kind {
        NotificationKind::OwnedCoreExited => SafeNotification {
            key: "owned-core-exited".into(),
            title: "应用自管核心意外退出".into(),
            body: "VPN Hub 将按有界退避尝试恢复自管核心。".into(),
        },
        NotificationKind::CoreRecovered => SafeNotification {
            key: "owned-core-recovered".into(),
            title: "应用自管核心已恢复".into(),
            body: format!("自管核心已在 {entry} 恢复。"),
        },
        NotificationKind::PortConflict => SafeNotification {
            key: "entry-port-conflict".into(),
            title: "入口端口冲突".into(),
            body: format!("配置入口 {entry} 已被未知进程占用；VPN Hub 不会接管或停止它。"),
        },
        NotificationKind::ConsecutiveStartupFailures(count) => SafeNotification {
            key: "consecutive-core-startup-failures".into(),
            title: "自管核心连续启动失败".into(),
            body: format!("自管核心已连续失败 {count} 次，将继续按有界退避重试。"),
        },
    };
    if deduper.allow(&notification, unix_time_ms()) {
        TauriNotificationSink { app }.send(&notification);
    }
}

fn safe_id(value: &str) -> String {
    let safe = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(64)
        .collect::<String>();
    if safe.is_empty() {
        "unknown".into()
    } else {
        safe
    }
}

fn safe_label(label: &str, outlet_id: &str) -> String {
    let lower = label.to_ascii_lowercase();
    if label.contains("://")
        || label.contains('@')
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("subscription")
    {
        return safe_id(outlet_id);
    }
    let safe = label
        .chars()
        .filter(|character| {
            character.is_alphanumeric()
                || character.is_whitespace()
                || matches!(character, '-' | '_' | '.')
        })
        .take(48)
        .collect::<String>();
    if safe.trim().is_empty() {
        safe_id(outlet_id)
    } else {
        safe
    }
}

fn unix_time_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default()
}

fn network_fingerprint() -> u64 {
    let mut hasher = DefaultHasher::new();
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if let Ok(mut child) = Command::new("ipconfig")
            .arg("/all")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        let mut bytes = Vec::new();
                        if let Some(mut stdout) = child.stdout.take() {
                            let _ = stdout.read_to_end(&mut bytes);
                        }
                        bytes.hash(&mut hasher);
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        "network-monitor-unavailable".hash(&mut hasher);
    }
    hasher.finish()
}

async fn sample_network_fingerprint() -> u64 {
    tokio::task::spawn_blocking(network_fingerprint)
        .await
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_hides_but_explicit_exit_stops_owned_core_once() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            ..LifecycleMachine::default()
        };
        assert_eq!(
            machine.reduce(LifecycleEvent::WindowClose),
            vec![LifecycleEffect::HideWindow]
        );
        assert_eq!(
            machine.reduce(LifecycleEvent::ExplicitExit),
            vec![
                LifecycleEffect::StopOwnedCore,
                LifecycleEffect::ExitApplication
            ]
        );
        assert!(machine.reduce(LifecycleEvent::ExplicitExit).is_empty());
        assert!(machine.reduce(LifecycleEvent::WindowClose).is_empty());
    }

    #[test]
    fn stop_core_does_not_exit_and_disables_unexpected_restart() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            ..LifecycleMachine::default()
        };
        assert_eq!(
            machine.reduce(LifecycleEvent::StopCore),
            vec![LifecycleEffect::StopOwnedCore, LifecycleEffect::RefreshTray]
        );
        assert!(
            machine
                .reduce(LifecycleEvent::OwnedCoreUnexpectedExit)
                .is_empty()
        );
    }

    #[test]
    fn unexpected_exit_is_idempotent_and_uses_bounded_backoff() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            ..LifecycleMachine::default()
        };
        let first = machine.reduce(LifecycleEvent::OwnedCoreUnexpectedExit);
        assert!(first.contains(&LifecycleEffect::ScheduleRestart(Duration::from_secs(1))));
        assert!(
            machine
                .reduce(LifecycleEvent::OwnedCoreUnexpectedExit)
                .is_empty()
        );
        assert_eq!(
            machine.reduce(LifecycleEvent::RestartTimer),
            vec![LifecycleEffect::StartOwnedCore]
        );
        let failed = machine.reduce(LifecycleEvent::StartupFailed(StartupFailure::Other));
        assert!(failed.contains(&LifecycleEffect::ScheduleRestart(Duration::from_secs(2))));
        let failed_again = machine.reduce(LifecycleEvent::StartupFailed(StartupFailure::Other));
        assert!(failed_again.contains(&LifecycleEffect::Notify(
            NotificationKind::ConsecutiveStartupFailures(2)
        )));
    }

    #[test]
    fn observed_manual_port_conflict_notifies_without_taking_ownership_or_retrying() {
        let mut machine = LifecycleMachine::default();
        assert_eq!(
            machine.reduce(LifecycleEvent::PortConflictObserved),
            vec![LifecycleEffect::Notify(NotificationKind::PortConflict)]
        );
        assert!(!machine.core_expected);
        assert!(!machine.restart_pending);
        assert!(machine.reduce(LifecycleEvent::RestartTimer).is_empty());
    }

    #[test]
    fn config_and_network_bursts_coalesce_to_one_full_probe() {
        let mut machine = LifecycleMachine::default();
        assert!(
            machine
                .reduce(LifecycleEvent::ConfigReload { now_ms: 10_000 })
                .contains(&LifecycleEffect::ProbeAllEnabled)
        );
        assert!(
            machine
                .reduce(LifecycleEvent::RecoverySignal { now_ms: 12_000 })
                .is_empty()
        );
        assert!(
            machine
                .reduce(LifecycleEvent::RecoverySignal { now_ms: 16_000 })
                .contains(&LifecycleEffect::ProbeAllEnabled)
        );
    }

    #[test]
    fn notification_deduper_suppresses_probe_floods_until_window_expires() {
        let notification = SafeNotification {
            key: "outlet-down:outlet-a".into(),
            title: "出口故障".into(),
            body: "逻辑出口 outlet-a 已进入不可用状态。".into(),
        };
        let mut deduper = NotificationDeduper::default();
        assert!(deduper.allow(&notification, 10_000));
        assert!(!deduper.allow(&notification, 10_100));
        assert!(deduper.allow(&notification, 70_001));
    }

    #[test]
    fn notifications_are_transition_only_and_sanitize_identifiers() {
        let repeated_probe = StateEvent {
            outlet_id: "safe-outlet".into(),
            occurred_at: "2026-07-20T00:00:00Z".into(),
            from_status: HealthStatus::Healthy,
            to_status: HealthStatus::Healthy,
            reason: "probe".into(),
        };
        assert!(state_transition_notification(&repeated_probe).is_none());

        let failure = StateEvent {
            outlet_id: "unsafe://token@example.invalid".into(),
            occurred_at: "2026-07-20T00:00:01Z".into(),
            from_status: HealthStatus::Healthy,
            to_status: HealthStatus::Down,
            reason: "probe".into(),
        };
        let notification = state_transition_notification(&failure).expect("down transition");
        assert!(!notification.body.contains("://"));
        assert!(!notification.body.contains('@'));
        assert!(!notification.body.contains("example.invalid"));

        let fail_closed = route_switch_notification(&RouteSwitchEvent {
            occurred_at: "2026-07-20T00:00:02Z".into(),
            from_outlet: Some("outlet-a".into()),
            to_outlet: FAIL_CLOSED_OUTLET.into(),
            mode: "priority".into(),
            reason: "all_unavailable".into(),
            duration_ms: 3,
        });
        assert_eq!(fail_closed.title, "已进入 Fail Closed");
        assert!(!fail_closed.body.contains("all_unavailable"));
    }

    #[test]
    fn tray_projection_is_dynamic_and_contains_no_endpoints_or_secrets() {
        let projection = TrayProjection {
            entry_host: "127.0.0.9".into(),
            entry_port: 42_137,
            current_outlet_id: "subscription-c".into(),
            core_managed: true,
            outlets: vec![
                TrayOutletProjection {
                    outlet_id: "subscription-c".into(),
                    label: safe_label("https://secret.invalid/token", "subscription-c"),
                    enabled: true,
                    status: HealthStatus::Healthy,
                },
                TrayOutletProjection {
                    outlet_id: "local-b".into(),
                    label: "本机出口".into(),
                    enabled: false,
                    status: HealthStatus::Unknown,
                },
            ],
        };
        let serialized = serde_json::to_string(&projection).expect("serialize");
        assert!(serialized.contains("42137"));
        assert!(serialized.contains("subscription-c"));
        assert!(!serialized.contains("secret.invalid"));
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("://"));
    }

    #[test]
    fn tray_projection_reloads_add_remove_disable_and_reorder_from_disk() {
        use vpn_hub_core::{EntryConfig, OutletConfig, OutletKind, PrivateRoutingConfig};

        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_test(workspace_root, directory.path());
        let mut config = PrivateRoutingConfig::default();
        config.entry = EntryConfig {
            host: "127.0.0.9".into(),
            port: 45_731,
        };
        config.controller_port = 45_732;
        config.outlets = vec![
            OutletConfig {
                id: "local-a".into(),
                label: "本机 A".into(),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: "socks5://127.0.0.1:45733".into(),
                },
            },
            OutletConfig {
                id: "local-b".into(),
                label: "本机 B".into(),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: "http://127.0.0.1:45734".into(),
                },
            },
        ];
        config
            .save(state.private_config_path_for_test())
            .expect("save first dynamic config");
        let first = TrayProjection::load(&state).expect("first projection");
        assert_eq!(first.entry_port, 45_731);
        assert_eq!(
            first
                .outlets
                .iter()
                .map(|outlet| outlet.outlet_id.as_str())
                .collect::<Vec<_>>(),
            vec!["local-a", "local-b"]
        );

        config.entry.port = 45_735;
        config.outlets.remove(0);
        config.outlets[0].enabled = false;
        config.outlets.insert(
            0,
            OutletConfig {
                id: "local-c".into(),
                label: "本机 C".into(),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: "socks5h://127.0.0.1:45736".into(),
                },
            },
        );
        config
            .save(state.private_config_path_for_test())
            .expect("save changed dynamic config");
        let changed = TrayProjection::load(&state).expect("changed projection");
        assert_eq!(changed.entry_port, 45_735);
        assert_eq!(changed.outlets[0].outlet_id, "local-c");
        assert_eq!(changed.outlets[1].outlet_id, "local-b");
        assert!(!changed.outlets[1].enabled);
        assert!(
            changed
                .outlets
                .iter()
                .all(|outlet| outlet.outlet_id != "local-a")
        );
    }

    #[test]
    fn os_shutdown_and_duplicate_multi_window_events_are_idempotent() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            ..LifecycleMachine::default()
        };
        assert_eq!(
            machine.reduce(LifecycleEvent::OsShutdown),
            vec![
                LifecycleEffect::StopOwnedCore,
                LifecycleEffect::ExitApplication
            ]
        );
        assert!(machine.reduce(LifecycleEvent::WindowClose).is_empty());
        assert!(machine.reduce(LifecycleEvent::OsShutdown).is_empty());
    }
}
