use std::{
    collections::{HashMap, VecDeque, hash_map::DefaultHasher},
    hash::Hasher,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
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
use tokio::sync::{Notify, mpsc, oneshot};
use vpn_hub_core::{
    FAIL_CLOSED_OUTLET, GuardianConfig, GuardianStore, HealthStatus, RouteSwitchEvent, StateEvent,
};

use crate::{commands, runtime::AppState};

const TRAY_ID: &str = "vpn-hub-main";
const RECOVERY_SIGNAL_COALESCE_MS: u64 = 5_000;
const NETWORK_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const RESUME_GAP: Duration = Duration::from_secs(30);
const NOTIFICATION_WINDOW_MS: u64 = 60_000;
const MAX_RECOVERY_ATTEMPTS: u32 = 5;
const CONTROL_JOIN_TIMEOUT: Duration = Duration::from_secs(3);
const OWNED_CORE_WATCH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    WindowClose,
    OpenWindow,
    StopCore,
    ManualStartRequested,
    ManualStartFailed,
    CoreStarted { pid: u32 },
    CoreStopped,
    OwnedCoreUnexpectedExit,
    RestartTimer,
    StartupFailed(StartupFailure),
    PortConflictObserved,
    RecoveryChildPublished { pid: u32 },
    RecoverySucceeded { pid: u32 },
    RouteChanged,
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
    RecoveryTerminal,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct LifecycleMachine {
    exiting: bool,
    core_expected: bool,
    expected_pid: Option<u32>,
    recovering_from_owned_exit: bool,
    recovery_terminal: bool,
    restart_pending: bool,
    consecutive_startup_failures: u32,
    last_recovery_signal_ms: Option<u64>,
}

impl LifecycleMachine {
    #[allow(clippy::too_many_lines)]
    fn reduce(&mut self, event: LifecycleEvent) -> Vec<LifecycleEffect> {
        if self.exiting {
            return Vec::new();
        }
        match event {
            LifecycleEvent::WindowClose => vec![LifecycleEffect::HideWindow],
            LifecycleEvent::OpenWindow => vec![LifecycleEffect::ShowAndFocusWindow],
            LifecycleEvent::StopCore => {
                self.core_expected = false;
                self.expected_pid = None;
                self.recovering_from_owned_exit = false;
                self.recovery_terminal = true;
                self.restart_pending = false;
                vec![LifecycleEffect::StopOwnedCore, LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::ManualStartRequested => {
                self.recovery_terminal = false;
                self.consecutive_startup_failures = 0;
                self.restart_pending = false;
                Vec::new()
            }
            LifecycleEvent::ManualStartFailed => {
                self.core_expected = false;
                self.expected_pid = None;
                self.recovering_from_owned_exit = false;
                self.recovery_terminal = true;
                self.restart_pending = false;
                vec![LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::CoreStarted { pid } => {
                self.core_expected = true;
                self.expected_pid = Some(pid);
                self.recovering_from_owned_exit = false;
                self.recovery_terminal = false;
                self.restart_pending = false;
                self.consecutive_startup_failures = 0;
                vec![LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::CoreStopped => {
                self.core_expected = false;
                self.expected_pid = None;
                self.recovering_from_owned_exit = false;
                self.recovery_terminal = false;
                self.restart_pending = false;
                vec![LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::OwnedCoreUnexpectedExit => {
                if !self.core_expected || self.restart_pending || self.recovery_terminal {
                    return Vec::new();
                }
                self.expected_pid = None;
                self.recovering_from_owned_exit = true;
                self.restart_pending = true;
                let delay = restart_delay(self.consecutive_startup_failures);
                vec![
                    LifecycleEffect::Notify(NotificationKind::OwnedCoreExited),
                    LifecycleEffect::ScheduleRestart(delay),
                    LifecycleEffect::RefreshTray,
                ]
            }
            LifecycleEvent::RestartTimer => {
                if !self.core_expected || !self.restart_pending || self.recovery_terminal {
                    return Vec::new();
                }
                self.restart_pending = false;
                self.consecutive_startup_failures =
                    self.consecutive_startup_failures.saturating_add(1);
                vec![LifecycleEffect::StartOwnedCore]
            }
            LifecycleEvent::RecoveryChildPublished { pid } => {
                if !self.recovering_from_owned_exit || self.recovery_terminal {
                    return Vec::new();
                }
                self.expected_pid = Some(pid);
                vec![LifecycleEffect::RefreshTray]
            }
            LifecycleEvent::RecoverySucceeded { pid } => {
                if !self.recovering_from_owned_exit || self.recovery_terminal {
                    return Vec::new();
                }
                self.expected_pid = Some(pid);
                self.recovering_from_owned_exit = false;
                self.restart_pending = false;
                self.consecutive_startup_failures = 0;
                vec![
                    LifecycleEffect::Notify(NotificationKind::CoreRecovered),
                    LifecycleEffect::RefreshTray,
                ]
            }
            LifecycleEvent::StartupFailed(kind) => {
                if !self.core_expected {
                    return Vec::new();
                }
                self.expected_pid = None;
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
                if self.consecutive_startup_failures >= MAX_RECOVERY_ATTEMPTS {
                    self.recovery_terminal = true;
                    self.restart_pending = false;
                    effects.push(LifecycleEffect::Notify(NotificationKind::RecoveryTerminal));
                    return effects;
                }
                self.restart_pending = true;
                effects.push(LifecycleEffect::ScheduleRestart(restart_delay(
                    self.consecutive_startup_failures,
                )));
                effects
            }
            LifecycleEvent::PortConflictObserved => {
                vec![LifecycleEffect::Notify(NotificationKind::PortConflict)]
            }
            LifecycleEvent::RouteChanged => vec![LifecycleEffect::RefreshTray],
            LifecycleEvent::ConfigReload { now_ms } => {
                self.last_recovery_signal_ms = Some(now_ms);
                let deliberate_recovery = self.recovery_terminal
                    || (self.core_expected && self.recovering_from_owned_exit);
                if deliberate_recovery {
                    self.core_expected = true;
                    self.expected_pid = None;
                    self.recovery_terminal = false;
                    self.recovering_from_owned_exit = true;
                    self.consecutive_startup_failures = 0;
                    self.restart_pending = true;
                }
                let mut effects = vec![LifecycleEffect::RefreshTray];
                if deliberate_recovery {
                    effects.push(LifecycleEffect::ScheduleRestart(Duration::ZERO));
                }
                effects.push(LifecycleEffect::ProbeAllEnabled);
                effects
            }
            LifecycleEvent::RecoverySignal { now_ms } => {
                if self
                    .last_recovery_signal_ms
                    .is_some_and(|last| now_ms.saturating_sub(last) < RECOVERY_SIGNAL_COALESCE_MS)
                {
                    return Vec::new();
                }
                self.last_recovery_signal_ms = Some(now_ms);
                let deliberate_recovery = self.core_expected
                    && (self.recovery_terminal || self.recovering_from_owned_exit);
                if deliberate_recovery {
                    self.expected_pid = None;
                    self.recovery_terminal = false;
                    self.recovering_from_owned_exit = true;
                    self.consecutive_startup_failures = 0;
                    self.restart_pending = true;
                }
                let mut effects = vec![LifecycleEffect::RefreshTray];
                if deliberate_recovery {
                    effects.push(LifecycleEffect::ScheduleRestart(Duration::ZERO));
                }
                effects.push(LifecycleEffect::ProbeAllEnabled);
                effects
            }
            LifecycleEvent::ExplicitExit | LifecycleEvent::OsShutdown => {
                self.exiting = true;
                self.core_expected = false;
                self.expected_pid = None;
                self.recovering_from_owned_exit = false;
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
    pub stop_available: bool,
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
            stop_available: core_managed,
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

const SIGNAL_EXIT: u32 = 1 << 0;
const SIGNAL_STOP: u32 = 1 << 1;
const SIGNAL_CONFIG_RELOAD: u32 = 1 << 2;
const SIGNAL_RECOVERY: u32 = 1 << 3;
const SIGNAL_OPEN: u32 = 1 << 4;
const SIGNAL_HIDE: u32 = 1 << 5;
const SIGNAL_CORE_STARTED: u32 = 1 << 6;
const SIGNAL_CORE_STOPPED: u32 = 1 << 7;
const SIGNAL_PORT_CONFLICT: u32 = 1 << 8;
const SIGNAL_MANUAL_START: u32 = 1 << 9;
const SIGNAL_ROUTE_CHANGED: u32 = 1 << 10;
const SIGNAL_MANUAL_FAILED: u32 = 1 << 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopRequestResult {
    Stopped,
    Pending,
}

#[derive(Default)]
struct ControlMailbox {
    signals: AtomicU32,
    core_pid: AtomicU32,
    core_epoch: AtomicU64,
    core_stop_epoch: AtomicU64,
    manual_epoch: AtomicU64,
    notify: Notify,
}

impl ControlMailbox {
    fn post(&self, signal: u32) {
        self.signals.fetch_or(signal, Ordering::AcqRel);
        self.notify.notify_one();
    }

    fn post_core_started(&self, pid: u32, epoch: u64) {
        self.core_pid.store(pid, Ordering::Release);
        self.core_epoch.store(epoch, Ordering::Release);
        self.post(SIGNAL_CORE_STARTED);
    }

    fn post_core_stopped(&self, epoch: u64) {
        self.core_stop_epoch.store(epoch, Ordering::Release);
        self.post(SIGNAL_CORE_STOPPED);
    }

    fn post_manual_failed(&self, epoch: u64) {
        self.manual_epoch.store(epoch, Ordering::Release);
        self.post(SIGNAL_MANUAL_FAILED);
    }

    fn take(&self) -> (u32, u32, u64, u64, u64) {
        let signals = self.signals.swap(0, Ordering::AcqRel);
        let pid = self.core_pid.load(Ordering::Acquire);
        let epoch = self.core_epoch.load(Ordering::Acquire);
        let stop_epoch = self.core_stop_epoch.load(Ordering::Acquire);
        let manual_epoch = self.manual_epoch.load(Ordering::Acquire);
        (signals, pid, epoch, stop_epoch, manual_epoch)
    }
}

pub struct DesktopCoordinator {
    mailbox: Arc<ControlMailbox>,
    started: AtomicBool,
    exit_permitted: AtomicBool,
    recovery_epoch: AtomicU64,
    active_cancel: Mutex<Option<Arc<AtomicBool>>>,
    manual_cancel: Mutex<Option<(u64, Arc<AtomicBool>)>>,
    pending_stop: AtomicBool,
    stop_available: AtomicBool,
    exit_requested: AtomicBool,
    stop_waiters: Mutex<Vec<oneshot::Sender<StopRequestResult>>>,
}

impl DesktopCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mailbox: Arc::new(ControlMailbox::default()),
            started: AtomicBool::new(false),
            exit_permitted: AtomicBool::new(false),
            recovery_epoch: AtomicU64::new(0),
            active_cancel: Mutex::new(None),
            manual_cancel: Mutex::new(None),
            pending_stop: AtomicBool::new(false),
            stop_available: AtomicBool::new(false),
            exit_requested: AtomicBool::new(false),
            stop_waiters: Mutex::new(Vec::new()),
        }
    }

    pub fn dispatch(&self, event: LifecycleEvent) {
        match event {
            LifecycleEvent::ExplicitExit | LifecycleEvent::OsShutdown => {
                self.exit_requested.store(true, Ordering::Release);
                self.begin_stop(None);
                self.mailbox.post(SIGNAL_EXIT);
            }
            LifecycleEvent::StopCore => {
                self.begin_stop(None);
            }
            LifecycleEvent::ConfigReload { .. } => self.mailbox.post(SIGNAL_CONFIG_RELOAD),
            LifecycleEvent::RecoverySignal { .. } => self.mailbox.post(SIGNAL_RECOVERY),
            LifecycleEvent::OpenWindow => self.mailbox.post(SIGNAL_OPEN),
            LifecycleEvent::WindowClose => self.mailbox.post(SIGNAL_HIDE),
            LifecycleEvent::CoreStarted { pid } => {
                self.stop_available.store(true, Ordering::Release);
                self.mailbox.post_core_started(pid, self.recovery_epoch());
            }
            LifecycleEvent::CoreStopped => {
                self.stop_available.store(false, Ordering::Release);
                self.mailbox.post_core_stopped(self.recovery_epoch());
            }
            LifecycleEvent::PortConflictObserved => self.mailbox.post(SIGNAL_PORT_CONFLICT),
            LifecycleEvent::RouteChanged => self.mailbox.post(SIGNAL_ROUTE_CHANGED),
            LifecycleEvent::ManualStartRequested => {
                self.invalidate_recovery();
                self.mailbox.post(SIGNAL_MANUAL_START);
            }
            LifecycleEvent::ManualStartFailed => {
                self.mailbox.post_manual_failed(self.recovery_epoch());
            }
            LifecycleEvent::OwnedCoreUnexpectedExit
            | LifecycleEvent::RestartTimer
            | LifecycleEvent::StartupFailed(_)
            | LifecycleEvent::RecoveryChildPublished { .. }
            | LifecycleEvent::RecoverySucceeded { .. } => {}
        }
    }

    pub fn start(&self, app: AppHandle) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        tauri::async_runtime::spawn(run_coordinator(app, Arc::clone(&self.mailbox)));
    }

    pub fn prepare_config_reload(&self) {
        self.invalidate_recovery();
    }

    pub fn prepare_manual_start(&self, cancel: &Arc<AtomicBool>) -> Result<u64, String> {
        if self.pending_stop.load(Ordering::Acquire) {
            return Err("停止请求尚未完成；不会启动迟到的应用自管核心".into());
        }
        let epoch = self.invalidate_recovery();
        if let Ok(mut manual) = self.manual_cancel.lock() {
            *manual = Some((epoch, Arc::clone(cancel)));
        }
        if self.pending_stop.load(Ordering::Acquire) || self.recovery_epoch() != epoch {
            cancel.store(true, Ordering::Release);
            self.finish_manual_start(epoch);
            return Err("停止请求已优先于启动；不会发布应用自管核心".into());
        }
        self.stop_available.store(true, Ordering::Release);
        self.mailbox.post(SIGNAL_MANUAL_START);
        Ok(epoch)
    }

    pub fn complete_manual_start(&self, pid: u32, epoch: u64) -> bool {
        let accepted = self.manual_start_allowed(epoch);
        if accepted {
            self.mailbox.post_core_started(pid, epoch);
        }
        self.finish_manual_start(epoch);
        accepted && self.manual_start_allowed(epoch)
    }

    pub fn complete_manual_start_failure(&self, epoch: u64) {
        if self.recovery_epoch() == epoch && !self.pending_stop.load(Ordering::Acquire) {
            self.stop_available.store(true, Ordering::Release);
            self.mailbox.post_manual_failed(epoch);
        }
        self.finish_manual_start(epoch);
    }

    #[must_use]
    pub fn manual_start_allowed(&self, epoch: u64) -> bool {
        self.recovery_epoch() == epoch && !self.pending_stop.load(Ordering::Acquire)
    }

    fn finish_manual_start(&self, epoch: u64) {
        if let Ok(mut manual) = self.manual_cancel.lock()
            && manual
                .as_ref()
                .is_some_and(|(current, _)| *current == epoch)
        {
            *manual = None;
        }
    }

    pub async fn request_stop(&self) -> StopRequestResult {
        let (sender, receiver) = oneshot::channel();
        self.begin_stop(Some(sender));
        await_stop_result(receiver, CONTROL_JOIN_TIMEOUT).await
    }

    fn begin_stop(&self, waiter: Option<oneshot::Sender<StopRequestResult>>) {
        if let Some(waiter) = waiter
            && let Ok(mut waiters) = self.stop_waiters.lock()
        {
            waiters.push(waiter);
        }
        if !self.pending_stop.swap(true, Ordering::AcqRel) {
            self.invalidate_recovery();
        }
        self.stop_available.store(true, Ordering::Release);
        self.mailbox.post(SIGNAL_STOP);
    }

    fn resolve_stop(&self) {
        self.pending_stop.store(false, Ordering::Release);
        self.stop_available.store(false, Ordering::Release);
        if let Ok(mut waiters) = self.stop_waiters.lock() {
            for waiter in waiters.drain(..) {
                let _ = waiter.send(StopRequestResult::Stopped);
            }
        }
    }

    #[must_use]
    fn pending_stop(&self) -> bool {
        self.pending_stop.load(Ordering::Acquire)
    }

    #[must_use]
    fn stop_available(&self) -> bool {
        self.stop_available.load(Ordering::Acquire)
    }

    fn invalidate_recovery(&self) -> u64 {
        let epoch = self.recovery_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        if let Ok(active) = self.active_cancel.lock()
            && let Some(cancel) = active.as_ref()
        {
            cancel.store(true, Ordering::Release);
        }
        if let Ok(manual) = self.manual_cancel.lock()
            && let Some((_, cancel)) = manual.as_ref()
        {
            cancel.store(true, Ordering::Release);
        }
        self.mailbox.notify.notify_one();
        epoch
    }

    pub(crate) fn recovery_epoch(&self) -> u64 {
        self.recovery_epoch.load(Ordering::Acquire)
    }

    fn set_active_cancel(&self, cancel: Option<Arc<AtomicBool>>) {
        if let Ok(mut active) = self.active_cancel.lock() {
            *active = cancel;
        }
    }

    #[must_use]
    pub fn exit_permitted(&self) -> bool {
        self.exit_permitted.load(Ordering::Acquire)
    }

    fn permit_exit(&self) {
        self.exit_permitted.store(true, Ordering::Release);
    }
}

async fn await_stop_result(
    receiver: oneshot::Receiver<StopRequestResult>,
    timeout: Duration,
) -> StopRequestResult {
    tokio::time::timeout(timeout, receiver)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(StopRequestResult::Pending)
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
    let mut projection =
        TrayProjection::load(&app.state::<AppState>()).unwrap_or_else(|_| TrayProjection {
            entry_host: "127.0.0.1".into(),
            entry_port: 0,
            current_outlet_id: FAIL_CLOSED_OUTLET.into(),
            core_managed: false,
            stop_available: false,
            outlets: Vec::new(),
        });
    projection.stop_available |= app.state::<DesktopCoordinator>().stop_available();
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
        "停止核心 / 取消恢复",
        projection.stop_available,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkKind {
    Probe,
    Restart,
}

#[derive(Debug)]
enum WorkMessage {
    ProbeFinished {
        id: u64,
        interval_seconds: u64,
        succeeded: bool,
    },
    RestartPublished {
        id: u64,
        pid: u32,
    },
    RestartFinished {
        id: u64,
        pid: Option<u32>,
        outcome: RestartOutcome,
    },
    StopFinished {
        confirmed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartOutcome {
    Succeeded,
    Failed(StartupFailure),
    Cancelled,
}

struct ActiveWork {
    id: u64,
    kind: WorkKind,
    cancel: Arc<AtomicBool>,
    owned_child_exited: Arc<AtomicBool>,
    published_pid: Arc<AtomicU32>,
    handle: tokio::task::JoinHandle<()>,
}

impl ActiveWork {
    async fn cancel_and_join(mut self, app: &AppHandle, clean_published_restart: bool) {
        self.cancel.store(true, Ordering::Release);
        cancel_and_join_handle(&mut self.handle, CONTROL_JOIN_TIMEOUT).await;
        if clean_published_restart && self.kind == WorkKind::Restart {
            let published_pid = self.published_pid.load(Ordering::Acquire);
            if published_pid != 0 {
                let _ = app
                    .state::<AppState>()
                    .stop_supervised_core_if_pid(published_pid)
                    .await;
            }
        }
        app.state::<DesktopCoordinator>().set_active_cancel(None);
    }
}

async fn cancel_and_join_handle(handle: &mut tokio::task::JoinHandle<()>, timeout: Duration) {
    if tokio::time::timeout(timeout, &mut *handle).await.is_err() {
        handle.abort();
        let _ = tokio::time::timeout(timeout, handle).await;
    }
}

async fn stop_owned_core_bounded(app: &AppHandle) -> bool {
    let state = app.state::<AppState>();
    stop_owned_core_with_timeout(&state, CONTROL_JOIN_TIMEOUT).await
}

async fn stop_owned_core_with_timeout(state: &AppState, timeout: Duration) -> bool {
    let cleanup = async {
        let _transaction = state.lock_routing_transaction().await;
        state.stop_supervised_core().await?;
        Ok::<bool, String>(state.owned_core_pid().is_none())
    };
    tokio::time::timeout(timeout, cleanup)
        .await
        .is_ok_and(|result| result.unwrap_or(false))
}

fn start_stop_work(
    app: &AppHandle,
    active: Option<ActiveWork>,
    sender: mpsc::Sender<WorkMessage>,
) -> tokio::task::JoinHandle<()> {
    let task_app = app.clone();
    tokio::spawn(async move {
        if let Some(work) = active {
            work.cancel_and_join(&task_app, true).await;
        }
        let confirmed = stop_owned_core_bounded(&task_app).await;
        let _ = sender.send(WorkMessage::StopFinished { confirmed }).await;
    })
}

fn start_probe_work(app: &AppHandle, id: u64, sender: mpsc::Sender<WorkMessage>) -> ActiveWork {
    let cancel = Arc::new(AtomicBool::new(false));
    let owned_child_exited = Arc::new(AtomicBool::new(false));
    let published_pid = Arc::new(AtomicU32::new(0));
    let task_cancel = Arc::clone(&cancel);
    let task_app = app.clone();
    let handle = tokio::spawn(async move {
        let state = task_app.state::<AppState>();
        let _transaction = state.lock_routing_transaction().await;
        if task_cancel.load(Ordering::Acquire) {
            let _ = sender
                .send(WorkMessage::ProbeFinished {
                    id,
                    interval_seconds: 180,
                    succeeded: false,
                })
                .await;
            return;
        }
        let result = commands::record_routing_cycle_locked(&state).await;
        let succeeded = result.is_ok() && !task_cancel.load(Ordering::Acquire);
        let _ = sender
            .send(WorkMessage::ProbeFinished {
                id,
                interval_seconds: result.unwrap_or(180),
                succeeded,
            })
            .await;
    });
    ActiveWork {
        id,
        kind: WorkKind::Probe,
        cancel,
        owned_child_exited,
        published_pid,
        handle,
    }
}

fn start_restart_work(
    app: &AppHandle,
    id: u64,
    epoch: u64,
    sender: mpsc::Sender<WorkMessage>,
) -> ActiveWork {
    let cancel = Arc::new(AtomicBool::new(false));
    let owned_child_exited = Arc::new(AtomicBool::new(false));
    let published_pid = Arc::new(AtomicU32::new(0));
    let task_cancel = Arc::clone(&cancel);
    let task_owned_child_exited = Arc::clone(&owned_child_exited);
    let task_published_pid = Arc::clone(&published_pid);
    let task_app = app.clone();
    let handle = tokio::spawn(run_restart_task(
        task_app,
        id,
        epoch,
        sender,
        task_cancel,
        task_owned_child_exited,
        task_published_pid,
    ));
    ActiveWork {
        id,
        kind: WorkKind::Restart,
        cancel,
        owned_child_exited,
        published_pid,
        handle,
    }
}

async fn run_restart_task(
    app: AppHandle,
    id: u64,
    epoch: u64,
    sender: mpsc::Sender<WorkMessage>,
    cancel: Arc<AtomicBool>,
    owned_child_exited: Arc<AtomicBool>,
    published_pid: Arc<AtomicU32>,
) {
    let state = app.state::<AppState>();
    let _transaction = state.lock_routing_transaction().await;
    if cancel.load(Ordering::Acquire) || app.state::<DesktopCoordinator>().recovery_epoch() != epoch
    {
        send_restart_finished(&sender, id, None, RestartOutcome::Cancelled).await;
        return;
    }
    let status = state.start_development_core_cancellable(&cancel).await;
    let Ok(status) = status else {
        if cancel.load(Ordering::Acquire)
            || app.state::<DesktopCoordinator>().recovery_epoch() != epoch
        {
            send_restart_finished(&sender, id, None, RestartOutcome::Cancelled).await;
            return;
        }
        let failure = if state
            .core_status()
            .is_ok_and(|status| status.state == "external")
        {
            StartupFailure::PortConflict
        } else {
            StartupFailure::Other
        };
        send_restart_finished(&sender, id, None, RestartOutcome::Failed(failure)).await;
        return;
    };
    let Some(pid) = status.pid else {
        send_restart_finished(
            &sender,
            id,
            None,
            RestartOutcome::Failed(StartupFailure::Other),
        )
        .await;
        return;
    };
    published_pid.store(pid, Ordering::Release);
    let _ = sender.send(WorkMessage::RestartPublished { id, pid }).await;
    let still_current = app.state::<DesktopCoordinator>().recovery_epoch() == epoch;
    let child_alive = state.owned_core_controller_is_running(pid);
    if cancel.load(Ordering::Acquire) || !still_current || !child_alive {
        let _ = state.stop_supervised_core_if_pid(pid).await;
        let outcome = if owned_child_exited.load(Ordering::Acquire) || !child_alive {
            RestartOutcome::Failed(StartupFailure::Other)
        } else {
            RestartOutcome::Cancelled
        };
        send_restart_finished(&sender, id, Some(pid), outcome).await;
        return;
    }
    let guardian_succeeded = state.uses_helper_authority()
        || commands::record_routing_cycle_locked(&state).await.is_ok();
    let child_alive = state.owned_core_controller_is_running(pid);
    let epoch_current = app.state::<DesktopCoordinator>().recovery_epoch() == epoch;
    let deliberately_cancelled = cancel.load(Ordering::Acquire)
        && !owned_child_exited.load(Ordering::Acquire)
        || !epoch_current;
    let committed = guardian_succeeded && !deliberately_cancelled && child_alive;
    if !committed {
        let _ = state.stop_supervised_core_if_pid(pid).await;
    }
    let outcome = if committed {
        RestartOutcome::Succeeded
    } else if deliberately_cancelled {
        RestartOutcome::Cancelled
    } else {
        RestartOutcome::Failed(StartupFailure::Other)
    };
    send_restart_finished(&sender, id, Some(pid), outcome).await;
}

async fn send_restart_finished(
    sender: &mpsc::Sender<WorkMessage>,
    id: u64,
    pid: Option<u32>,
    outcome: RestartOutcome,
) {
    let _ = sender
        .send(WorkMessage::RestartFinished { id, pid, outcome })
        .await;
}

#[allow(clippy::too_many_lines)]
async fn run_coordinator(app: AppHandle, mailbox: Arc<ControlMailbox>) {
    let mut machine = LifecycleMachine::default();
    if let Some(pid) = app.state::<AppState>().owned_core_pid() {
        let _ = machine.reduce(LifecycleEvent::CoreStarted { pid });
        app.state::<DesktopCoordinator>()
            .stop_available
            .store(true, Ordering::Release);
    }
    let mut deduper = NotificationDeduper::default();
    let mut transitions = TransitionNotifications::default();
    let _ = transitions.collect(&app.state::<AppState>());
    let (work_sender, mut work_receiver) = mpsc::channel(8);
    let (network_sender, mut network_receiver) = mpsc::channel(2);
    let mut active: Option<ActiveWork> = None;
    let mut network_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut stop_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut stop_retry_at: Option<Instant> = None;
    let mut pending_probe = true;
    let mut next_work_id = 1_u64;
    let mut next_guardian = Instant::now();
    let mut next_network_sample = Instant::now();
    let mut last_network_fingerprint: Option<u64> = None;
    let mut last_network_sample = Instant::now();
    let mut restart_at: Option<(Instant, u64)> = None;
    let mut watcher = tokio::time::interval(OWNED_CORE_WATCH_INTERVAL);

    loop {
        let coordinator = app.state::<DesktopCoordinator>();
        if coordinator.pending_stop()
            && stop_handle.is_none()
            && stop_retry_at.is_none_or(|deadline| deadline <= Instant::now())
        {
            stop_retry_at = None;
            stop_handle = Some(start_stop_work(&app, active.take(), work_sender.clone()));
        }
        if active.is_none() && !coordinator.pending_stop() {
            let due_restart = restart_at.is_some_and(|(deadline, _)| deadline <= Instant::now());
            if due_restart {
                let Some((_, epoch)) = restart_at.take() else {
                    continue;
                };
                if epoch == app.state::<DesktopCoordinator>().recovery_epoch() {
                    let effects = machine.reduce(LifecycleEvent::RestartTimer);
                    if effects.contains(&LifecycleEffect::StartOwnedCore) {
                        let work =
                            start_restart_work(&app, next_work_id, epoch, work_sender.clone());
                        next_work_id = next_work_id.saturating_add(1);
                        app.state::<DesktopCoordinator>()
                            .set_active_cancel(Some(Arc::clone(&work.cancel)));
                        active = Some(work);
                    }
                }
            } else if pending_probe {
                let work = start_probe_work(&app, next_work_id, work_sender.clone());
                next_work_id = next_work_id.saturating_add(1);
                app.state::<DesktopCoordinator>()
                    .set_active_cancel(Some(Arc::clone(&work.cancel)));
                active = Some(work);
                pending_probe = false;
            }
        }
        let restart_deadline =
            restart_at.map_or_else(|| Instant::now() + Duration::from_hours(24), |item| item.0);
        let stop_retry_deadline =
            stop_retry_at.unwrap_or_else(|| Instant::now() + Duration::from_hours(24));
        tokio::select! {
            () = mailbox.notify.notified() => {
                let (signals, core_pid, core_epoch, core_stop_epoch, manual_epoch) = mailbox.take();
                if signals & SIGNAL_EXIT != 0
                    && let Some(mut handle) = network_handle.take()
                    && tokio::time::timeout(CONTROL_JOIN_TIMEOUT, &mut handle).await.is_err()
                {
                    handle.abort();
                    let _ = tokio::time::timeout(CONTROL_JOIN_TIMEOUT, &mut handle).await;
                }
                if signals & SIGNAL_STOP != 0 {
                    restart_at = None;
                    pending_probe = false;
                }
                if signals & SIGNAL_MANUAL_START != 0 {
                    restart_at = None;
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::ManualStartRequested), &mut pending_probe, &mut restart_at);
                }
                let current_epoch = app.state::<DesktopCoordinator>().recovery_epoch();
                if signals & SIGNAL_MANUAL_FAILED != 0
                    && manual_epoch == current_epoch
                    && !app.state::<DesktopCoordinator>().pending_stop()
                {
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::ManualStartFailed), &mut pending_probe, &mut restart_at);
                }
                let accepted_core_stopped = signals & SIGNAL_CORE_STOPPED != 0
                    && core_stop_epoch == current_epoch;
                if accepted_core_stopped {
                    restart_at = None;
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::CoreStopped), &mut pending_probe, &mut restart_at);
                }
                let owns_started_pid = core_pid != 0
                    && app.state::<AppState>().owned_core_is_running(core_pid);
                if should_accept_core_started(
                    signals,
                    accepted_core_stopped,
                    core_pid,
                    core_epoch,
                    current_epoch,
                    owns_started_pid,
                ) {
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::CoreStarted { pid: core_pid }), &mut pending_probe, &mut restart_at);
                }
                if signals & SIGNAL_PORT_CONFLICT != 0 {
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::PortConflictObserved), &mut pending_probe, &mut restart_at);
                }
                if signals & SIGNAL_CONFIG_RELOAD != 0
                    && !app.state::<DesktopCoordinator>().pending_stop()
                {
                    if let Some(work) = active.take() {
                        work.cancel_and_join(&app, true).await;
                    }
                    let effects = machine.reduce(LifecycleEvent::ConfigReload { now_ms: unix_time_ms() });
                    if effects.iter().any(|effect| matches!(effect, LifecycleEffect::ScheduleRestart(_))) {
                        app.state::<DesktopCoordinator>().stop_available.store(true, Ordering::Release);
                    }
                    consume_effects(&app, &mut deduper, effects, &mut pending_probe, &mut restart_at);
                }
                if signals & SIGNAL_RECOVERY != 0
                    && !app.state::<DesktopCoordinator>().pending_stop()
                {
                    let effects = machine.reduce(LifecycleEvent::RecoverySignal { now_ms: unix_time_ms() });
                    consume_effects(&app, &mut deduper, effects, &mut pending_probe, &mut restart_at);
                }
                if signals & SIGNAL_ROUTE_CHANGED != 0 {
                    let effects = machine.reduce(LifecycleEvent::RouteChanged);
                    consume_effects(&app, &mut deduper, effects, &mut pending_probe, &mut restart_at);
                    publish_transition_notifications(&app, &mut transitions, &mut deduper);
                }
                if signals & SIGNAL_OPEN != 0 {
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::OpenWindow), &mut pending_probe, &mut restart_at);
                } else if signals & SIGNAL_HIDE != 0 {
                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::WindowClose), &mut pending_probe, &mut restart_at);
                }
            }
            message = work_receiver.recv() => {
                let Some(message) = message else { break };
                match message {
                    WorkMessage::RestartPublished { id, pid } if active.as_ref().is_some_and(|work| work.id == id) => {
                        consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::RecoveryChildPublished { pid }), &mut pending_probe, &mut restart_at);
                    }
                    WorkMessage::RestartFinished { id, pid, outcome } if active.as_ref().is_some_and(|work| work.id == id) => {
                        if let Some(mut work) = active.take() {
                            let _ = (&mut work.handle).await;
                        }
                        app.state::<DesktopCoordinator>().set_active_cancel(None);
                        match outcome {
                            RestartOutcome::Succeeded => {
                                if let Some(pid) = pid {
                                    pending_probe = false;
                                    consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::RecoverySucceeded { pid }), &mut pending_probe, &mut restart_at);
                                    publish_transition_notifications(&app, &mut transitions, &mut deduper);
                                }
                            }
                            RestartOutcome::Failed(failure) => {
                                consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::StartupFailed(failure)), &mut pending_probe, &mut restart_at);
                            }
                            RestartOutcome::Cancelled => {}
                        }
                    }
                    WorkMessage::ProbeFinished { id, interval_seconds, succeeded } if active.as_ref().is_some_and(|work| work.id == id) => {
                        if let Some(mut work) = active.take() {
                            let _ = (&mut work.handle).await;
                        }
                        app.state::<DesktopCoordinator>().set_active_cancel(None);
                        next_guardian = Instant::now() + Duration::from_secs(interval_seconds.max(1));
                        if succeeded {
                            publish_transition_notifications(&app, &mut transitions, &mut deduper);
                            refresh_tray(&app);
                        }
                    }
                    WorkMessage::StopFinished { confirmed } => {
                        if let Some(mut handle) = stop_handle.take() {
                            let _ = tokio::time::timeout(CONTROL_JOIN_TIMEOUT, &mut handle).await;
                        }
                        if confirmed && app.state::<AppState>().owned_core_pid().is_none() {
                            stop_retry_at = None;
                            consume_effects(&app, &mut deduper, machine.reduce(LifecycleEvent::StopCore), &mut pending_probe, &mut restart_at);
                            app.state::<DesktopCoordinator>().resolve_stop();
                            refresh_tray(&app);
                            if app.state::<DesktopCoordinator>().exit_requested.swap(false, Ordering::AcqRel) {
                                app.state::<DesktopCoordinator>().permit_exit();
                                app.exit(0);
                                break;
                            }
                        } else {
                            stop_retry_at = Some(Instant::now() + OWNED_CORE_WATCH_INTERVAL);
                        }
                    }
                    _ => {}
                }
            }
            _ = watcher.tick() => {
                if let Some(pid) = machine.expected_pid {
                    let alive = app.state::<AppState>().owned_core_is_running(pid);
                    if !alive && !machine.recovery_terminal {
                        if active.as_ref().is_some_and(|work| work.kind == WorkKind::Restart) {
                            if let Some(work) = active.as_ref() {
                                work.owned_child_exited.store(true, Ordering::Release);
                                work.cancel.store(true, Ordering::Release);
                            }
                        } else {
                            let effects = machine.reduce(LifecycleEvent::OwnedCoreUnexpectedExit);
                            consume_effects(&app, &mut deduper, effects, &mut pending_probe, &mut restart_at);
                        }
                    }
                }
            }
            () = tokio::time::sleep_until(next_guardian.into()) => {
                next_guardian = Instant::now() + Duration::from_mins(3);
                pending_probe = true;
            }
            () = tokio::time::sleep_until(next_network_sample.into()) => {
                let now = Instant::now();
                let resumed = now.duration_since(last_network_sample) >= RESUME_GAP;
                last_network_sample = now;
                next_network_sample = now + NETWORK_SAMPLE_INTERVAL;
                if network_handle.is_none() {
                    let sender = network_sender.clone();
                    network_handle = Some(tokio::spawn(async move {
                        let sample = sample_network_fingerprint().await;
                        let _ = sender.send(sample).await;
                    }));
                }
                if resumed {
                    mailbox.post(SIGNAL_RECOVERY);
                }
            }
            sample = network_receiver.recv() => {
                if let Some(mut handle) = network_handle.take() {
                    let _ = (&mut handle).await;
                }
                if update_network_fingerprint(&mut last_network_fingerprint, sample.flatten()) {
                    mailbox.post(SIGNAL_RECOVERY);
                }
            }
            () = tokio::time::sleep_until(restart_deadline.into()), if restart_at.is_some() && active.is_none() && !app.state::<DesktopCoordinator>().pending_stop() => {
                let Some((_, epoch)) = restart_at.take() else { continue };
                if epoch == app.state::<DesktopCoordinator>().recovery_epoch() {
                    let effects = machine.reduce(LifecycleEvent::RestartTimer);
                    if effects.contains(&LifecycleEffect::StartOwnedCore) {
                        let work = start_restart_work(&app, next_work_id, epoch, work_sender.clone());
                        next_work_id = next_work_id.saturating_add(1);
                        app.state::<DesktopCoordinator>().set_active_cancel(Some(Arc::clone(&work.cancel)));
                        active = Some(work);
                    }
                }
            }
            () = tokio::time::sleep_until(stop_retry_deadline.into()), if stop_retry_at.is_some() && stop_handle.is_none() => {
                stop_retry_at = None;
            }
        }
    }
}

fn should_accept_core_started(
    signals: u32,
    accepted_core_stopped: bool,
    pid: u32,
    event_epoch: u64,
    current_epoch: u64,
    owns_pid: bool,
) -> bool {
    signals & SIGNAL_STOP == 0
        && !accepted_core_stopped
        && pid != 0
        && event_epoch == current_epoch
        && owns_pid
}

fn update_network_fingerprint(previous: &mut Option<u64>, sample: Option<u64>) -> bool {
    let Some(sample) = sample else {
        return false;
    };
    let changed = previous.is_some_and(|value| value != sample);
    *previous = Some(sample);
    changed
}

fn consume_effects(
    app: &AppHandle,
    deduper: &mut NotificationDeduper,
    effects: Vec<LifecycleEffect>,
    pending_probe: &mut bool,
    restart_at: &mut Option<(Instant, u64)>,
) {
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
            LifecycleEffect::ProbeAllEnabled => *pending_probe = true,
            LifecycleEffect::RefreshTray => refresh_tray(app),
            LifecycleEffect::Notify(kind) => send_lifecycle_notification(app, deduper, kind),
            LifecycleEffect::ScheduleRestart(delay) => {
                let epoch = app.state::<DesktopCoordinator>().recovery_epoch();
                *restart_at = Some((Instant::now() + delay, epoch));
            }
            LifecycleEffect::StopOwnedCore
            | LifecycleEffect::StartOwnedCore
            | LifecycleEffect::ExitApplication => {}
        }
    }
}

fn refresh_tray(app: &AppHandle) {
    let Ok(mut projection) = TrayProjection::load(&app.state::<AppState>()) else {
        return;
    };
    projection.stop_available |= app.state::<DesktopCoordinator>().stop_available();
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
        NotificationKind::RecoveryTerminal => SafeNotification {
            key: "owned-core-recovery-terminal".into(),
            title: "自管核心自动恢复已暂停".into(),
            body: format!(
                "自管核心连续 {MAX_RECOVERY_ATTEMPTS} 次恢复失败，当前保持 Fail Closed；请手动启动或等待配置、网络变化后重试。"
            ),
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

#[derive(Debug)]
struct CommandSample {
    fingerprint: Option<u64>,
    pid: u32,
    reader_joined: bool,
}

#[cfg(target_os = "windows")]
fn sample_command_output(mut command: Command, timeout: Duration) -> CommandSample {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return CommandSample {
            fingerprint: None,
            pid: 0,
            reader_joined: true,
        };
    };
    let pid = child.id();
    let reader = child.stdout.take().map(|mut stdout| {
        std::thread::spawn(move || {
            let mut hasher = DefaultHasher::new();
            let mut buffer = [0_u8; 8_192];
            loop {
                let length = stdout.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                hasher.write(&buffer[..length]);
            }
            std::io::Result::Ok(hasher.finish())
        })
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let reader_result = reader.map(std::thread::JoinHandle::join);
    let reader_joined = reader_result.as_ref().is_none_or(Result::is_ok);
    let fingerprint = match (status, reader_result) {
        (Some(status), Some(Ok(Ok(fingerprint)))) if status.success() => Some(fingerprint),
        _ => None,
    };
    CommandSample {
        fingerprint,
        pid,
        reader_joined,
    }
}

fn network_fingerprint() -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut command = Command::new("ipconfig");
        command.arg("/all").creation_flags(CREATE_NO_WINDOW);
        let sample = sample_command_output(command, Duration::from_secs(2));
        debug_assert!(sample.reader_joined || sample.pid == 0);
        sample.fingerprint
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

async fn sample_network_fingerprint() -> Option<u64> {
    tokio::task::spawn_blocking(network_fingerprint)
        .await
        .unwrap_or(None)
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
        assert_eq!(
            machine.reduce(LifecycleEvent::RestartTimer),
            vec![LifecycleEffect::StartOwnedCore]
        );
        let failed_again = machine.reduce(LifecycleEvent::StartupFailed(StartupFailure::Other));
        assert!(failed_again.contains(&LifecycleEffect::Notify(
            NotificationKind::ConsecutiveStartupFailures(2)
        )));
    }

    #[test]
    fn recovery_has_five_attempt_terminal_limit_and_deliberate_reset_only() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            ..LifecycleMachine::default()
        };
        machine.reduce(LifecycleEvent::OwnedCoreUnexpectedExit);
        for attempt in 1..=MAX_RECOVERY_ATTEMPTS {
            assert_eq!(
                machine.reduce(LifecycleEvent::RestartTimer),
                vec![LifecycleEffect::StartOwnedCore]
            );
            machine.reduce(LifecycleEvent::RecoveryChildPublished { pid: 100 + attempt });
            let effects = machine.reduce(LifecycleEvent::StartupFailed(StartupFailure::Other));
            assert_eq!(machine.expected_pid, None);
            if attempt < MAX_RECOVERY_ATTEMPTS {
                assert!(
                    effects
                        .iter()
                        .any(|effect| matches!(effect, LifecycleEffect::ScheduleRestart(_)))
                );
            } else {
                assert!(
                    effects.contains(&LifecycleEffect::Notify(NotificationKind::RecoveryTerminal))
                );
                assert!(
                    effects
                        .iter()
                        .all(|effect| !matches!(effect, LifecycleEffect::ScheduleRestart(_)))
                );
            }
        }
        assert!(machine.recovery_terminal);
        assert!(machine.reduce(LifecycleEvent::RestartTimer).is_empty());
        let deliberate = machine.reduce(LifecycleEvent::RecoverySignal { now_ms: 50_000 });
        assert!(!machine.recovery_terminal);
        assert!(deliberate.contains(&LifecycleEffect::ScheduleRestart(Duration::ZERO)));
    }

    #[test]
    fn first_automatic_replacement_emits_recovered_after_publish_and_guardian_commit() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            expected_pid: Some(10),
            ..LifecycleMachine::default()
        };
        machine.reduce(LifecycleEvent::OwnedCoreUnexpectedExit);
        machine.reduce(LifecycleEvent::RestartTimer);
        let published = machine.reduce(LifecycleEvent::RecoveryChildPublished { pid: 11 });
        assert_eq!(machine.expected_pid, Some(11));
        assert!(!published.contains(&LifecycleEffect::Notify(NotificationKind::CoreRecovered)));
        let committed = machine.reduce(LifecycleEvent::RecoverySucceeded { pid: 11 });
        assert!(committed.contains(&LifecycleEffect::Notify(NotificationKind::CoreRecovered)));
        assert!(!machine.recovering_from_owned_exit);
    }

    #[test]
    fn config_reload_refreshes_structure_before_scheduling_probe() {
        let mut machine = LifecycleMachine::default();
        let effects = machine.reduce(LifecycleEvent::ConfigReload { now_ms: 100_000 });
        let refresh = effects
            .iter()
            .position(|effect| *effect == LifecycleEffect::RefreshTray)
            .expect("refresh effect");
        let probe = effects
            .iter()
            .position(|effect| *effect == LifecycleEffect::ProbeAllEnabled)
            .expect("probe effect");
        assert!(refresh < probe);
        let repeated = machine.reduce(LifecycleEvent::ConfigReload { now_ms: 100_001 });
        assert_eq!(repeated.first(), Some(&LifecycleEffect::RefreshTray));
        assert!(repeated.contains(&LifecycleEffect::ProbeAllEnabled));
    }

    #[test]
    fn fixed_mailbox_coalesces_flood_without_losing_exit_or_stop() {
        let mailbox = ControlMailbox::default();
        for _ in 0..100_000 {
            mailbox.post(SIGNAL_CONFIG_RELOAD);
            mailbox.post(SIGNAL_RECOVERY);
        }
        mailbox.post(SIGNAL_STOP);
        mailbox.post(SIGNAL_EXIT);
        let (signals, _, _, _, _) = mailbox.take();
        assert_ne!(signals & SIGNAL_EXIT, 0);
        assert_ne!(signals & SIGNAL_STOP, 0);
        assert_ne!(signals & SIGNAL_CONFIG_RELOAD, 0);
        assert_ne!(signals & SIGNAL_RECOVERY, 0);
        assert_eq!(mailbox.take().0, 0);
    }

    #[test]
    fn stop_epoch_rejects_a_stale_manual_start_completion() {
        let coordinator = DesktopCoordinator::new();
        let stale_epoch = coordinator
            .prepare_manual_start(&Arc::new(AtomicBool::new(false)))
            .expect("manual epoch");
        coordinator.begin_stop(None);
        assert!(!coordinator.complete_manual_start(4_242, stale_epoch));

        let (signals, pid, _, _, _) = coordinator.mailbox.take();
        assert_ne!(signals & SIGNAL_MANUAL_START, 0);
        assert_eq!(signals & SIGNAL_CORE_STARTED, 0);
        assert_eq!(pid, 0);
    }

    #[test]
    fn pending_stop_rejects_a_new_manual_start() {
        let coordinator = DesktopCoordinator::new();
        coordinator.begin_stop(None);
        let start = coordinator.prepare_manual_start(&Arc::new(AtomicBool::new(false)));

        assert!(start.is_err());
        let (signals, pid, _, _, _) = coordinator.mailbox.take();
        assert_ne!(signals & SIGNAL_STOP, 0);
        assert_eq!(signals & (SIGNAL_MANUAL_START | SIGNAL_CORE_STARTED), 0);
        assert_eq!(pid, 0);
    }

    #[test]
    fn failed_manual_start_keeps_terminal_stop_action_available() {
        let coordinator = DesktopCoordinator::new();
        let cancel = Arc::new(AtomicBool::new(false));
        let epoch = coordinator
            .prepare_manual_start(&cancel)
            .expect("manual epoch");
        coordinator.complete_manual_start_failure(epoch);

        assert!(coordinator.stop_available());
        let (signals, _, _, _, manual_epoch) = coordinator.mailbox.take();
        assert_ne!(signals & SIGNAL_MANUAL_FAILED, 0);
        assert_eq!(manual_epoch, epoch);
    }

    #[tokio::test]
    async fn stop_timeout_returns_pending_without_resolving_the_durable_intent() {
        let coordinator = DesktopCoordinator::new();
        let (sender, receiver) = oneshot::channel();
        coordinator.begin_stop(Some(sender));

        assert_eq!(
            await_stop_result(receiver, Duration::from_millis(20)).await,
            StopRequestResult::Pending
        );
        assert!(coordinator.pending_stop());
        assert!(coordinator.stop_available());
    }

    #[tokio::test]
    async fn repeated_stop_waiters_resolve_together_and_already_stopped_is_safe() {
        let coordinator = DesktopCoordinator::new();
        let initial_epoch = coordinator.recovery_epoch();
        let (first_sender, first_receiver) = oneshot::channel();
        let (second_sender, second_receiver) = oneshot::channel();
        coordinator.begin_stop(Some(first_sender));
        let stop_epoch = coordinator.recovery_epoch();
        coordinator.begin_stop(Some(second_sender));

        assert!(stop_epoch > initial_epoch);
        assert_eq!(coordinator.recovery_epoch(), stop_epoch);
        coordinator.resolve_stop();
        assert_eq!(first_receiver.await, Ok(StopRequestResult::Stopped));
        assert_eq!(second_receiver.await, Ok(StopRequestResult::Stopped));
        assert!(!coordinator.pending_stop());

        let (already_sender, already_receiver) = oneshot::channel();
        coordinator.begin_stop(Some(already_sender));
        coordinator.resolve_stop();
        assert_eq!(already_receiver.await, Ok(StopRequestResult::Stopped));
    }

    #[tokio::test]
    async fn busy_routing_transaction_never_projects_stopped_and_eventually_confirms() {
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_test(workspace_root, directory.path());
        let transaction = state.lock_routing_transaction().await;
        let coordinator = DesktopCoordinator::new();
        coordinator.begin_stop(None);
        let mut machine = LifecycleMachine {
            core_expected: true,
            recovering_from_owned_exit: true,
            restart_pending: true,
            ..LifecycleMachine::default()
        };

        assert!(!stop_owned_core_with_timeout(&state, Duration::from_millis(20)).await);
        assert!(coordinator.pending_stop());
        assert!(machine.core_expected);
        assert!(machine.recovering_from_owned_exit);
        assert!(machine.restart_pending);

        drop(transaction);
        assert!(stop_owned_core_with_timeout(&state, Duration::from_secs(1)).await);
        let effects = machine.reduce(LifecycleEvent::StopCore);
        coordinator.resolve_stop();
        assert!(effects.contains(&LifecycleEffect::StopOwnedCore));
        assert!(!machine.core_expected);
        assert!(machine.recovery_terminal);
        assert!(!machine.restart_pending);
        assert!(!coordinator.pending_stop());
    }

    #[test]
    fn stop_cancels_backoff_and_network_signals_until_explicit_reload() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            expected_pid: Some(42),
            ..LifecycleMachine::default()
        };
        let unexpected = machine.reduce(LifecycleEvent::OwnedCoreUnexpectedExit);
        assert!(
            unexpected
                .iter()
                .any(|effect| { matches!(effect, LifecycleEffect::ScheduleRestart(_)) })
        );
        machine.reduce(LifecycleEvent::StopCore);

        assert!(machine.reduce(LifecycleEvent::RestartTimer).is_empty());
        let network_tick = machine.reduce(LifecycleEvent::RecoverySignal { now_ms: 10_000 });
        assert!(network_tick.contains(&LifecycleEffect::ProbeAllEnabled));
        assert!(network_tick.iter().all(|effect| {
            !matches!(
                effect,
                LifecycleEffect::ScheduleRestart(_) | LifecycleEffect::StartOwnedCore
            )
        }));
        assert!(!machine.core_expected);
        assert!(machine.recovery_terminal);

        let explicit = machine.reduce(LifecycleEvent::ConfigReload { now_ms: 20_000 });
        assert!(explicit.contains(&LifecycleEffect::ScheduleRestart(Duration::ZERO)));
        assert!(machine.core_expected);
        assert!(!machine.recovery_terminal);
    }

    #[test]
    fn stop_and_exact_ownership_take_precedence_over_started_mail() {
        assert!(!should_accept_core_started(
            SIGNAL_STOP | SIGNAL_CORE_STARTED,
            false,
            42,
            7,
            7,
            true
        ));
        assert!(!should_accept_core_started(
            SIGNAL_CORE_STARTED,
            false,
            42,
            6,
            7,
            true
        ));
        assert!(!should_accept_core_started(
            SIGNAL_CORE_STARTED,
            false,
            42,
            7,
            7,
            false
        ));
        assert!(should_accept_core_started(
            SIGNAL_CORE_STARTED,
            false,
            42,
            7,
            7,
            true
        ));
        assert!(should_accept_core_started(
            SIGNAL_CORE_STOPPED | SIGNAL_CORE_STARTED,
            false,
            42,
            7,
            7,
            true
        ));
        assert!(!should_accept_core_started(
            SIGNAL_CORE_STOPPED | SIGNAL_CORE_STARTED,
            true,
            42,
            7,
            7,
            true
        ));
    }

    #[test]
    fn published_recovery_child_exit_continues_the_bounded_retry_chain() {
        let mut machine = LifecycleMachine {
            core_expected: true,
            expected_pid: Some(10),
            ..LifecycleMachine::default()
        };
        machine.reduce(LifecycleEvent::OwnedCoreUnexpectedExit);
        machine.reduce(LifecycleEvent::RestartTimer);
        machine.reduce(LifecycleEvent::RecoveryChildPublished { pid: 11 });

        let effects = machine.reduce(LifecycleEvent::StartupFailed(StartupFailure::Other));
        assert_eq!(machine.expected_pid, None);
        assert!(machine.restart_pending);
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, LifecycleEffect::ScheduleRestart(_)))
        );
    }

    #[test]
    fn route_change_refreshes_immediately_without_scheduling_a_probe() {
        let mut machine = LifecycleMachine::default();
        assert_eq!(
            machine.reduce(LifecycleEvent::RouteChanged),
            vec![LifecycleEffect::RefreshTray]
        );
        let coordinator = DesktopCoordinator::new();
        coordinator.dispatch(LifecycleEvent::RouteChanged);
        coordinator.dispatch(LifecycleEvent::RouteChanged);
        let (signals, _, _, _, _) = coordinator.mailbox.take();
        assert_ne!(signals & SIGNAL_ROUTE_CHANGED, 0);
        assert_eq!(signals & (SIGNAL_CONFIG_RELOAD | SIGNAL_RECOVERY), 0);
    }

    #[test]
    fn route_change_transition_is_collected_once_after_startup_baseline() {
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_test(workspace_root, directory.path());
        let guardian = GuardianConfig::load(state.guardian_config_path()).expect("guardian");
        let store = GuardianStore::open(&guardian.database_path).expect("history");
        let mut transitions = TransitionNotifications::default();
        assert!(transitions.collect(&state).is_empty());
        store
            .record_route_switch(&RouteSwitchEvent {
                occurred_at: "2026-07-20T12:34:56Z".into(),
                from_outlet: Some("local-a".into()),
                to_outlet: "local-b".into(),
                mode: "manual".into(),
                reason: "manual_selection".into(),
                duration_ms: 1,
            })
            .expect("route transition");

        let first = transitions.collect(&state);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].key, "route-switch:local-a:local-b");
        assert!(transitions.collect(&state).is_empty());
    }

    #[test]
    fn failed_network_sample_preserves_previous_without_false_change() {
        let mut previous = Some(41);
        assert!(!update_network_fingerprint(&mut previous, None));
        assert_eq!(previous, Some(41));
        assert!(!update_network_fingerprint(&mut previous, Some(41)));
        assert!(update_network_fingerprint(&mut previous, Some(42)));
        assert_eq!(previous, Some(42));
    }

    #[tokio::test]
    async fn slow_background_task_is_cancelled_and_joined_within_control_bound() {
        let cancel = Arc::new(AtomicBool::new(false));
        let task_cancel = Arc::clone(&cancel);
        let joined = Arc::new(AtomicBool::new(false));
        let task_joined = Arc::clone(&joined);
        let mut handle = tokio::spawn(async move {
            while !task_cancel.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            task_joined.store(true, Ordering::Release);
        });
        let started = Instant::now();
        cancel.store(true, Ordering::Release);
        cancel_and_join_handle(&mut handle, Duration::from_millis(250)).await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(joined.load(Ordering::Acquire));
        assert!(handle.is_finished());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_join_has_a_second_bound_for_an_uncooperative_task() {
        let mut handle = tokio::spawn(async {
            std::thread::sleep(Duration::from_millis(250));
        });
        let started = Instant::now();
        cancel_and_join_handle(&mut handle, Duration::from_millis(20)).await;
        assert!(started.elapsed() < Duration::from_millis(150));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(handle.is_finished());
    }

    #[cfg(target_os = "windows")]
    fn powershell_command(script: &str) -> Command {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut command = Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .creation_flags(CREATE_NO_WINDOW);
        command
    }

    #[cfg(target_os = "windows")]
    fn process_exists(pid: u32) -> bool {
        powershell_command(&format!(
            "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
        ))
        .status()
        .is_ok_and(|status| status.success())
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn network_sampler_drains_large_output_and_hashes_changes_without_leaking_child() {
        let large = sample_command_output(
            powershell_command("[Console]::Out.Write(('A' * 262144))"),
            Duration::from_secs(5),
        );
        assert!(large.fingerprint.is_some());
        assert!(large.reader_joined);
        assert!(!process_exists(large.pid));

        let changed = sample_command_output(
            powershell_command("[Console]::Out.Write(('B' * 262144))"),
            Duration::from_secs(5),
        );
        assert!(changed.fingerprint.is_some());
        assert_ne!(large.fingerprint, changed.fingerprint);
        assert!(changed.reader_joined);
        assert!(!process_exists(changed.pid));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn network_sampler_timeout_kills_only_its_child_and_joins_reader() {
        let sample = sample_command_output(
            powershell_command("Start-Sleep -Seconds 5; [Console]::Out.Write('late')"),
            Duration::from_millis(150),
        );
        assert!(sample.fingerprint.is_none());
        assert!(sample.reader_joined);
        assert!(!process_exists(sample.pid));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn network_sampler_rejects_failed_or_incomplete_samples() {
        let failed = sample_command_output(
            powershell_command("[Console]::Out.Write('partial'); exit 7"),
            Duration::from_secs(2),
        );
        assert!(failed.fingerprint.is_none());
        assert!(failed.reader_joined);
        assert!(!process_exists(failed.pid));
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
            stop_available: true,
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
