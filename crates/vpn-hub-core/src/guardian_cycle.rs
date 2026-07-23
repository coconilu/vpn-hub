use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
use thiserror::Error;
use tokio::{sync::Semaphore, task::JoinSet, time::Instant as TokioInstant};

use crate::{
    ControllerClient, ControllerError, GuardianStore, HealthStatus, MonitorConfig, OutletConfig,
    OutletHealth, PrivateRoutingConfig, ProbeOutletConfig, ProbeResult, RouteDecision,
    RouteSwitchEvent, RoutingEngine, RoutingPolicy, StoreError, UDP_SELECTOR, UdpCapabilityStatus,
    current_udp_status, outlet_proxy_name, unknown_udp_evidence,
};

#[derive(Debug, Error)]
pub enum RoutingStateError {
    #[error("routing state is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianCommitStatus {
    Busy,
    Stale,
    Committed,
}

pub trait RoutingSession {
    /// Returns the current monotonic configuration generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation cannot be read atomically.
    fn config_generation(&self) -> Result<u64, RoutingStateError>;

    /// Returns the currently applied outlet, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when the session state cannot be read.
    fn current_outlet(&self) -> Result<Option<String>, RoutingStateError>;

    /// Evaluates the next route without mutating session state.
    ///
    /// # Errors
    ///
    /// Returns an error when the session state cannot be read.
    fn evaluate_route(
        &self,
        now_ms: u64,
        health: &BTreeMap<String, OutletHealth>,
        policy: &RoutingPolicy,
    ) -> Result<Option<RouteDecision>, RoutingStateError>;

    /// Applies a selector decision after the Controller confirms the switch.
    ///
    /// # Errors
    ///
    /// Returns an error when the session state cannot be updated.
    fn apply_route(&self, decision: &RouteDecision, now_ms: u64) -> Result<(), RoutingStateError>;

    /// Commits the durable cycle and in-memory route under the same
    /// generation synchronization boundary. Returns `false` when a newer
    /// configuration won before the boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable commit or routing update fails.
    fn try_commit_cycle_if_current<F>(
        &self,
        expected_generation: u64,
        decision: Option<&RouteDecision>,
        now_ms: u64,
        durable_commit: &mut F,
    ) -> Result<GuardianCommitStatus, GuardianCycleError>
    where
        F: FnMut() -> Result<(), GuardianCycleError>;

    /// Persists an application-level terminal gate when the Controller cannot
    /// authoritatively confirm both fail-closed selectors.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal state cannot be durably recorded.
    fn persist_fail_closed_unconfirmed(&self) -> Result<(), RoutingStateError>;
}

impl RoutingSession for std::sync::Mutex<RoutingEngine> {
    fn config_generation(&self) -> Result<u64, RoutingStateError> {
        Ok(0)
    }

    fn current_outlet(&self) -> Result<Option<String>, RoutingStateError> {
        self.lock()
            .map_err(|_| RoutingStateError::Unavailable)
            .map(|engine| engine.current_outlet().map(str::to_owned))
    }

    fn evaluate_route(
        &self,
        now_ms: u64,
        health: &BTreeMap<String, OutletHealth>,
        policy: &RoutingPolicy,
    ) -> Result<Option<RouteDecision>, RoutingStateError> {
        self.lock()
            .map_err(|_| RoutingStateError::Unavailable)
            .map(|engine| engine.evaluate(now_ms, health, policy))
    }

    fn apply_route(&self, decision: &RouteDecision, now_ms: u64) -> Result<(), RoutingStateError> {
        self.lock()
            .map_err(|_| RoutingStateError::Unavailable)?
            .apply(decision, now_ms);
        Ok(())
    }

    fn try_commit_cycle_if_current<F>(
        &self,
        expected_generation: u64,
        decision: Option<&RouteDecision>,
        now_ms: u64,
        durable_commit: &mut F,
    ) -> Result<GuardianCommitStatus, GuardianCycleError>
    where
        F: FnMut() -> Result<(), GuardianCycleError>,
    {
        if expected_generation != 0 {
            return Ok(GuardianCommitStatus::Stale);
        }
        durable_commit()?;
        if let Some(decision) = decision {
            self.apply_route(decision, now_ms)?;
        }
        Ok(GuardianCommitStatus::Committed)
    }

    fn persist_fail_closed_unconfirmed(&self) -> Result<(), RoutingStateError> {
        self.lock()
            .map_err(|_| RoutingStateError::Unavailable)?
            .restore_current(None, None);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum GuardianCycleError {
    #[error("Controller operation failed: {0}")]
    Controller(#[from] ControllerError),
    #[error("Guardian storage operation failed: {0}")]
    Store(#[from] StoreError),
    #[error("routing state operation failed: {0}")]
    RoutingState(#[from] RoutingStateError),
    #[error("Guardian cycle was cancelled before commit")]
    Cancelled,
    #[error("Guardian cycle exceeded its end-to-end deadline")]
    Deadline,
    #[error(
        "Guardian could not authoritatively confirm both fail-closed selectors; terminal gate persisted"
    )]
    FailClosedUnconfirmed,
}

pub const DEFAULT_GUARDIAN_CYCLE_BUDGET: Duration = Duration::from_secs(8);
pub const DEFAULT_GUARDIAN_CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct GuardianCycleOutcome {
    pub observed: Vec<ProbeResult>,
    pub decision: Option<RouteDecision>,
}

/// Executes the production Controller-backed Guardian routing cycle.
///
/// The order is deliberate: selected-member Controller delays are collected,
/// sanitized probes are committed, a decision is evaluated from stable state,
/// the real selector is changed, in-memory state is applied, and only then is
/// the sanitized route event recorded.
///
/// # Errors
///
/// Returns sanitized Controller, `SQLite`, or routing-state failures.
#[allow(clippy::too_many_lines)]
pub async fn run_controller_guardian_cycle(
    controller: &ControllerClient,
    private: &PrivateRoutingConfig,
    resolved: &crate::ResolvedSubscriptionUrls,
    monitor: &MonitorConfig,
    store: &mut GuardianStore,
    routing: &impl RoutingSession,
    now_ms: u64,
) -> Result<GuardianCycleOutcome, GuardianCycleError> {
    run_controller_guardian_cycle_controlled(
        controller,
        private,
        resolved,
        monitor,
        store,
        routing,
        now_ms,
        Arc::new(AtomicBool::new(false)),
        DEFAULT_GUARDIAN_CYCLE_BUDGET,
        DEFAULT_GUARDIAN_CONCURRENCY,
    )
    .await
}

/// Executes a cancellable, globally bounded Guardian cycle. Probes run with a
/// shared concurrency limit; cancellation is checked before any durable or
/// Controller routing mutation so an obsolete configuration generation cannot
/// overwrite a newer one.
///
/// # Errors
///
/// Returns `Cancelled` without committing probe or selector state when the
/// caller invalidates this cycle, plus the same sanitized errors as the normal
/// Guardian entry point.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_controller_guardian_cycle_controlled(
    controller: &ControllerClient,
    private: &PrivateRoutingConfig,
    resolved: &crate::ResolvedSubscriptionUrls,
    monitor: &MonitorConfig,
    store: &mut GuardianStore,
    routing: &impl RoutingSession,
    now_ms: u64,
    cancel: Arc<AtomicBool>,
    budget: Duration,
    concurrency: usize,
) -> Result<GuardianCycleOutcome, GuardianCycleError> {
    let cycle_started = Instant::now();
    let deadline = TokioInstant::now() + budget;
    let cleanup_reserve = FAIL_CLOSED_CLEANUP_BUDGET.min(budget / 3);
    let work_deadline = deadline - cleanup_reserve;
    let expected_generation = routing.config_generation()?;
    let observed = probe_configured_outlets(
        controller,
        private,
        resolved,
        monitor.request_timeout_ms,
        Arc::clone(&cancel),
        work_deadline,
        concurrency,
    )
    .await;

    if cancel.load(Ordering::Acquire) || routing.config_generation()? != expected_generation {
        return abort_cycle_fail_closed(
            controller,
            routing,
            deadline,
            GuardianCycleError::Cancelled,
        )
        .await;
    }
    if TokioInstant::now() >= work_deadline {
        return abort_cycle_fail_closed(
            controller,
            routing,
            deadline,
            GuardianCycleError::Deadline,
        )
        .await;
    }

    let health = store.project_probe_health(
        &observed,
        monitor.failure_threshold,
        monitor.recovery_threshold,
    )?;
    let policy = RoutingPolicy {
        priority: private.priority(),
        cooldown_ms: private.cooldown_seconds.saturating_mul(1_000),
        minimum_improvement_ms: private.minimum_improvement_ms,
    };
    let decision = routing.evaluate_route(now_ms, &health, &policy)?;
    if cycle_invalid(routing, expected_generation, &cancel)? {
        return abort_cycle_fail_closed(
            controller,
            routing,
            deadline,
            GuardianCycleError::Cancelled,
        )
        .await;
    }
    if let Some(decision) = &decision
        && let Err(error) = select_before_deadline(
            controller,
            work_deadline,
            crate::MASTER_SELECTOR,
            &outlet_proxy_name(&decision.to_outlet),
        )
        .await
    {
        return abort_cycle_fail_closed(controller, routing, deadline, error).await;
    }
    if cycle_invalid(routing, expected_generation, &cancel)? {
        return abort_cycle_fail_closed(
            controller,
            routing,
            deadline,
            GuardianCycleError::Cancelled,
        )
        .await;
    }
    let selected_outlet = decision
        .as_ref()
        .map(|decision| decision.to_outlet.clone())
        .or(routing.current_outlet()?);
    let udp_capabilities = store.udp_capabilities()?;
    let udp_target = udp_selector_target(private, selected_outlet.as_deref(), &udp_capabilities);
    if let Err(error) =
        select_before_deadline(controller, work_deadline, UDP_SELECTOR, &udp_target).await
    {
        return abort_cycle_fail_closed(controller, routing, deadline, error).await;
    }
    if cycle_invalid(routing, expected_generation, &cancel)? {
        return abort_cycle_fail_closed(
            controller,
            routing,
            deadline,
            GuardianCycleError::Cancelled,
        )
        .await;
    }

    let duration_ms = u64::try_from(cycle_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let initial_udp = private
        .enabled_outlets()
        .map(|outlet| {
            (
                outlet.id.clone(),
                outlet.label.clone(),
                unknown_udp_evidence(outlet, "not_yet_validated"),
            )
        })
        .collect::<Vec<_>>();
    let route_event = decision.as_ref().map(|decision| RouteSwitchEvent {
        occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        from_outlet: decision.from_outlet.clone(),
        to_outlet: decision.to_outlet.clone(),
        mode: private.route_mode.as_str().into(),
        reason: decision.reason.clone(),
        duration_ms,
    });
    let durable_deadline = work_deadline.into_std();
    let mut durable_commit = || {
        store
            .commit_guardian_cycle_batch(
                &initial_udp,
                &observed,
                monitor.failure_threshold,
                monitor.recovery_threshold,
                route_event.as_ref(),
                durable_deadline,
            )
            .map_err(|error| match error {
                StoreError::Deadline => GuardianCycleError::Deadline,
                other => GuardianCycleError::Store(other),
            })
    };
    loop {
        if cycle_invalid(routing, expected_generation, &cancel)? {
            return abort_cycle_fail_closed(
                controller,
                routing,
                deadline,
                GuardianCycleError::Cancelled,
            )
            .await;
        }
        if TokioInstant::now() >= work_deadline {
            return abort_cycle_fail_closed(
                controller,
                routing,
                deadline,
                GuardianCycleError::Deadline,
            )
            .await;
        }
        match routing.try_commit_cycle_if_current(
            expected_generation,
            decision.as_ref(),
            now_ms,
            &mut durable_commit,
        ) {
            Ok(GuardianCommitStatus::Committed) => break,
            Ok(GuardianCommitStatus::Stale) => {
                return abort_cycle_fail_closed(
                    controller,
                    routing,
                    deadline,
                    GuardianCycleError::Cancelled,
                )
                .await;
            }
            Ok(GuardianCommitStatus::Busy) => {
                tokio::time::sleep_until(
                    (TokioInstant::now() + Duration::from_millis(5)).min(work_deadline),
                )
                .await;
            }
            Err(error) => {
                return abort_cycle_fail_closed(controller, routing, deadline, error).await;
            }
        }
    }

    Ok(GuardianCycleOutcome {
        observed: observed.into_iter().map(|(_, result)| result).collect(),
        decision,
    })
}

fn cycle_invalid(
    routing: &impl RoutingSession,
    expected_generation: u64,
    cancel: &AtomicBool,
) -> Result<bool, RoutingStateError> {
    Ok(cancel.load(Ordering::Acquire) || routing.config_generation()? != expected_generation)
}

async fn select_before_deadline(
    controller: &ControllerClient,
    deadline: TokioInstant,
    selector: &str,
    target: &str,
) -> Result<(), GuardianCycleError> {
    if TokioInstant::now() >= deadline {
        return Err(GuardianCycleError::Deadline);
    }
    tokio::time::timeout_at(deadline, controller.select(selector, target))
        .await
        .map_err(|_| GuardianCycleError::Deadline)?
        .map_err(GuardianCycleError::Controller)
}

const FAIL_CLOSED_CLEANUP_BUDGET: Duration = Duration::from_millis(500);

async fn abort_cycle_fail_closed<T>(
    controller: &ControllerClient,
    routing: &impl RoutingSession,
    deadline: TokioInstant,
    original: GuardianCycleError,
) -> Result<T, GuardianCycleError> {
    if force_controller_fail_closed_confirmed(controller, deadline).await {
        return Err(original);
    }
    routing.persist_fail_closed_unconfirmed()?;
    Err(GuardianCycleError::FailClosedUnconfirmed)
}

async fn force_controller_fail_closed_confirmed(
    controller: &ControllerClient,
    deadline: TokioInstant,
) -> bool {
    let now = TokioInstant::now();
    if now >= deadline {
        return false;
    }
    let put_deadline = now + deadline.duration_since(now) / 2;
    let (master_put, udp_put) = tokio::join!(
        tokio::time::timeout_at(
            put_deadline,
            controller.select(crate::MASTER_SELECTOR, crate::FAIL_CLOSED_PROXY),
        ),
        tokio::time::timeout_at(
            put_deadline,
            controller.select(UDP_SELECTOR, crate::FAIL_CLOSED_PROXY),
        ),
    );
    let _ = (master_put, udp_put);
    if TokioInstant::now() >= deadline {
        return false;
    }
    let (master, udp) = tokio::join!(
        tokio::time::timeout_at(
            deadline,
            controller.is_selected(crate::MASTER_SELECTOR, crate::FAIL_CLOSED_PROXY),
        ),
        tokio::time::timeout_at(
            deadline,
            controller.is_selected(UDP_SELECTOR, crate::FAIL_CLOSED_PROXY),
        ),
    );
    matches!(master, Ok(Ok(true))) && matches!(udp, Ok(Ok(true)))
}

pub(crate) fn udp_selector_target(
    private: &PrivateRoutingConfig,
    selected_outlet: Option<&str>,
    udp_capabilities: &[crate::UdpCapabilityEvidence],
) -> String {
    let Some(selected_outlet) = selected_outlet else {
        return crate::FAIL_CLOSED_PROXY.to_string();
    };
    let supported = private
        .outlets
        .iter()
        .find(|outlet| outlet.id == selected_outlet)
        .is_some_and(|outlet| {
            current_udp_status(
                outlet,
                udp_capabilities
                    .iter()
                    .find(|evidence| evidence.outlet_id == selected_outlet),
            ) == UdpCapabilityStatus::Supported
        });
    if supported {
        outlet_proxy_name(selected_outlet)
    } else {
        crate::FAIL_CLOSED_PROXY.to_string()
    }
}

async fn probe_configured_outlets(
    controller: &ControllerClient,
    private: &PrivateRoutingConfig,
    resolved: &crate::ResolvedSubscriptionUrls,
    timeout_ms: u64,
    cancel: Arc<AtomicBool>,
    deadline: TokioInstant,
    concurrency: usize,
) -> Vec<(ProbeOutletConfig, ProbeResult)> {
    let outlets = private.enabled_outlets().cloned().collect::<Vec<_>>();
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let targets = Arc::new(private.probe_targets.clone());
    let mut tasks = JoinSet::new();
    for (index, outlet) in outlets.iter().cloned().enumerate() {
        let configured = outlet
            .secret_ref()
            .is_none_or(|secret_ref| resolved.contains_key(secret_ref));
        let controller = controller.clone();
        let targets = Arc::clone(&targets);
        let semaphore = Arc::clone(&semaphore);
        let cancel = Arc::clone(&cancel);
        tasks.spawn(async move {
            let result = if configured {
                probe_controller_outlet(
                    &controller,
                    &outlet,
                    &targets,
                    timeout_ms,
                    deadline,
                    semaphore,
                    cancel,
                )
                .await
            } else {
                unavailable_result(&outlet, "subscription_not_configured", targets.len())
            };
            (index, result)
        });
    }

    let mut results = BTreeMap::new();
    while !tasks.is_empty() && !cancel.load(Ordering::Acquire) {
        let next = tokio::time::timeout_at(deadline, tasks.join_next()).await;
        let Ok(Some(Ok((index, result)))) = next else {
            break;
        };
        results.insert(index, result);
    }
    tasks.abort_all();

    outlets
        .iter()
        .enumerate()
        .map(|(index, outlet)| {
            let result = results.remove(&index).unwrap_or_else(|| {
                unavailable_result(outlet, "guardian_cycle_deadline", targets.len())
            });
            (virtual_outlet(outlet, &private.entry), result)
        })
        .collect()
}

async fn probe_controller_outlet(
    controller: &ControllerClient,
    outlet: &OutletConfig,
    targets: &[String],
    timeout_ms: u64,
    deadline: TokioInstant,
    semaphore: Arc<Semaphore>,
    cancel: Arc<AtomicBool>,
) -> ProbeResult {
    let proxy_name = outlet_proxy_name(&outlet.id);
    let mut tasks = JoinSet::new();
    for target in targets {
        let target = target.clone();
        let controller = controller.clone();
        let proxy_name = proxy_name.clone();
        let semaphore = Arc::clone(&semaphore);
        let cancel = Arc::clone(&cancel);
        tasks.spawn(async move {
            if cancel.load(Ordering::Acquire) {
                return None;
            }
            let permit = tokio::select! {
                permit = semaphore.acquire_owned() => permit.ok()?,
                () = wait_for_cancel(Arc::clone(&cancel)) => return None,
                () = tokio::time::sleep_until(deadline) => return None,
            };
            let _permit = permit;
            tokio::select! {
                result = controller.delay(&proxy_name, &target, timeout_ms) => result.ok(),
                () = wait_for_cancel(cancel) => None,
                () = tokio::time::sleep_until(deadline) => None,
            }
        });
    }
    let mut delays = Vec::new();
    while !tasks.is_empty() && !cancel.load(Ordering::Acquire) {
        let Ok(Some(Ok(delay))) = tokio::time::timeout_at(deadline, tasks.join_next()).await else {
            break;
        };
        if let Some(delay) = delay {
            delays.push(delay);
        }
    }
    tasks.abort_all();
    delays.sort_unstable();
    let successful_targets = u32::try_from(delays.len()).unwrap_or(u32::MAX);
    let total_targets = u32::try_from(targets.len()).unwrap_or(u32::MAX);
    let (status, latency_ms) = classify_delays(&delays, targets.len());
    ProbeResult {
        outlet_id: outlet.id.clone(),
        label: outlet.label.clone(),
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

async fn wait_for_cancel(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(20)).await;
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
    outlet: &OutletConfig,
    error_code: &str,
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
        error_code: Some(error_code.into()),
        successful_targets: 0,
        total_targets: u32::try_from(total_targets).unwrap_or(u32::MAX),
    }
}

fn virtual_outlet(outlet: &OutletConfig, entry: &crate::EntryConfig) -> ProbeOutletConfig {
    ProbeOutletConfig {
        id: outlet.id.clone(),
        label: outlet.label.clone(),
        proxy_url: format!("http://{}:{}", entry.host, entry.port),
        probe_url: "controller://selected-member".into(),
        degraded_latency_ms: 2_500,
        enabled: outlet.enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OutletKind, RouteMode};
    use std::{
        net::Ipv4Addr,
        sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize},
        },
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn delayed_controller(
        delay: Duration,
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    ) -> (ControllerClient, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("controller listener");
        let address = listener.local_addr().expect("controller address");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let active = Arc::clone(&active);
                let maximum = Arc::clone(&maximum);
                tokio::spawn(async move {
                    let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                    maximum.fetch_max(current, Ordering::AcqRel);
                    let mut request = [0_u8; 2_048];
                    let _ = stream.read(&mut request).await;
                    tokio::time::sleep(delay).await;
                    let body = br#"{"delay":42}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    active.fetch_sub(1, Ordering::AcqRel);
                });
            }
        });
        let controller = ControllerClient::new(
            &format!("http://{address}"),
            "synthetic-secret".into(),
            2_000,
        )
        .expect("controller client");
        (controller, handle)
    }

    async fn tracking_controller(
        partial_probe: bool,
        slow_next_put: Arc<AtomicBool>,
    ) -> (
        ControllerClient,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<(String, String)>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("controller listener");
        let address = listener.local_addr().expect("controller address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let selected = Arc::new(Mutex::new((
            "vpn-hub-outlet-old".to_string(),
            "vpn-hub-outlet-old".to_string(),
        )));
        let selected_view = Arc::clone(&selected);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let captured = Arc::clone(&captured);
                let slow_next_put = Arc::clone(&slow_next_put);
                let selected = Arc::clone(&selected);
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 8_192];
                    let Ok(read) = stream.read(&mut request).await else {
                        return;
                    };
                    request.truncate(read);
                    let request = String::from_utf8_lossy(&request).into_owned();
                    captured.lock().expect("requests").push(request.clone());
                    let is_put = request.starts_with("PUT ");
                    if is_put && slow_next_put.swap(false, Ordering::AcqRel) {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                    let body_text = request.split("\r\n\r\n").nth(1).unwrap_or_default();
                    let target = body_text
                        .split("\"name\":\"")
                        .nth(1)
                        .and_then(|tail| tail.split('"').next());
                    if is_put && let Some(target) = target {
                        let mut selected = selected.lock().expect("selected");
                        if request.contains(UDP_SELECTOR) {
                            selected.1 = target.into();
                        } else if request.contains(crate::MASTER_SELECTOR) {
                            selected.0 = target.into();
                        }
                    }
                    let (status, body): (&str, String) = if partial_probe
                        && request.starts_with("GET ")
                        && request.contains("probe-b.invalid")
                    {
                        ("503 Service Unavailable", String::new())
                    } else if request.starts_with("GET ") && request.contains("/delay?") {
                        ("200 OK", r#"{"delay":42}"#.into())
                    } else if request.starts_with("GET ") && request.contains(UDP_SELECTOR) {
                        let current = selected.lock().expect("selected").1.clone();
                        ("200 OK", format!(r#"{{"now":"{current}"}}"#))
                    } else if request.starts_with("GET ")
                        && request.contains(crate::MASTER_SELECTOR)
                    {
                        let current = selected.lock().expect("selected").0.clone();
                        ("200 OK", format!(r#"{{"now":"{current}"}}"#))
                    } else {
                        ("204 No Content", String::new())
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let controller = ControllerClient::new(
            &format!("http://{address}"),
            "synthetic-secret".into(),
            3_000,
        )
        .expect("controller client");
        (controller, requests, selected_view, handle)
    }

    struct GenerationRoutingSession {
        generation: AtomicU64,
        invalidate_on_commit: AtomicBool,
        terminal_unconfirmed: AtomicBool,
        busy_until: Mutex<Option<TokioInstant>>,
        engine: Mutex<RoutingEngine>,
    }

    impl GenerationRoutingSession {
        fn new(invalidate_on_commit: bool, current: Option<String>) -> Self {
            let mut engine = RoutingEngine::new(RouteMode::Priority, None);
            engine.restore_current(current, None);
            Self {
                generation: AtomicU64::new(7),
                invalidate_on_commit: AtomicBool::new(invalidate_on_commit),
                terminal_unconfirmed: AtomicBool::new(false),
                busy_until: Mutex::new(None),
                engine: Mutex::new(engine),
            }
        }

        fn hold_commit_gate_for(&self, duration: Duration) {
            *self.busy_until.lock().expect("busy gate") = Some(TokioInstant::now() + duration);
        }
    }

    impl RoutingSession for GenerationRoutingSession {
        fn config_generation(&self) -> Result<u64, RoutingStateError> {
            Ok(self.generation.load(Ordering::Acquire))
        }

        fn current_outlet(&self) -> Result<Option<String>, RoutingStateError> {
            Ok(self
                .engine
                .lock()
                .map_err(|_| RoutingStateError::Unavailable)?
                .current_outlet()
                .map(str::to_owned))
        }

        fn evaluate_route(
            &self,
            now_ms: u64,
            health: &BTreeMap<String, OutletHealth>,
            policy: &RoutingPolicy,
        ) -> Result<Option<RouteDecision>, RoutingStateError> {
            Ok(self
                .engine
                .lock()
                .map_err(|_| RoutingStateError::Unavailable)?
                .evaluate(now_ms, health, policy))
        }

        fn apply_route(
            &self,
            decision: &RouteDecision,
            now_ms: u64,
        ) -> Result<(), RoutingStateError> {
            self.engine
                .lock()
                .map_err(|_| RoutingStateError::Unavailable)?
                .apply(decision, now_ms);
            Ok(())
        }

        fn try_commit_cycle_if_current<F>(
            &self,
            expected_generation: u64,
            decision: Option<&RouteDecision>,
            now_ms: u64,
            durable_commit: &mut F,
        ) -> Result<GuardianCommitStatus, GuardianCycleError>
        where
            F: FnMut() -> Result<(), GuardianCycleError>,
        {
            if self
                .busy_until
                .lock()
                .map_err(|_| RoutingStateError::Unavailable)?
                .is_some_and(|deadline| TokioInstant::now() < deadline)
            {
                return Ok(GuardianCommitStatus::Busy);
            }
            if self.invalidate_on_commit.swap(false, Ordering::AcqRel) {
                self.generation.fetch_add(1, Ordering::AcqRel);
            }
            if self.generation.load(Ordering::Acquire) != expected_generation {
                return Ok(GuardianCommitStatus::Stale);
            }
            durable_commit()?;
            if let Some(decision) = decision {
                self.apply_route(decision, now_ms)?;
            }
            Ok(GuardianCommitStatus::Committed)
        }

        fn persist_fail_closed_unconfirmed(&self) -> Result<(), RoutingStateError> {
            self.terminal_unconfirmed.store(true, Ordering::Release);
            self.engine
                .lock()
                .map_err(|_| RoutingStateError::Unavailable)?
                .restore_current(None, None);
            Ok(())
        }
    }

    fn concurrent_fixture() -> PrivateRoutingConfig {
        let mut private = PrivateRoutingConfig::default();
        private.probe_targets = vec![
            "https://probe-a.invalid/".into(),
            "https://probe-b.invalid/".into(),
            "https://probe-c.invalid/".into(),
        ];
        private.outlets = (0..3)
            .map(|index| OutletConfig {
                id: format!("local-{index}"),
                label: format!("Local {index}"),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: format!("socks5://127.0.0.1:{}", 45_000 + index),
                },
            })
            .collect();
        private
    }

    fn monitor_fixture() -> MonitorConfig {
        MonitorConfig {
            interval_seconds: 30,
            connect_timeout_ms: 500,
            request_timeout_ms: 500,
            failure_threshold: 2,
            recovery_threshold: 2,
        }
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

    #[tokio::test]
    async fn outlet_target_matrix_is_bounded_and_concurrent() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let (controller, server) = delayed_controller(
            Duration::from_millis(120),
            Arc::clone(&active),
            Arc::clone(&maximum),
        )
        .await;
        let private = concurrent_fixture();
        let started = TokioInstant::now();
        let observed = probe_configured_outlets(
            &controller,
            &private,
            &crate::ResolvedSubscriptionUrls::new(),
            1_000,
            Arc::new(AtomicBool::new(false)),
            TokioInstant::now() + Duration::from_millis(700),
            4,
        )
        .await;
        server.abort();

        assert_eq!(observed.len(), 3);
        assert!(
            observed
                .iter()
                .all(|(_, result)| result.successful_targets == 3)
        );
        assert!(maximum.load(Ordering::Acquire) <= 4);
        assert!(maximum.load(Ordering::Acquire) > 1);
        assert!(started.elapsed() < Duration::from_millis(650));
    }

    #[tokio::test]
    async fn global_deadline_retains_partial_results_without_waiting_per_target() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let (controller, server) =
            delayed_controller(Duration::from_secs(2), active, maximum).await;
        let private = concurrent_fixture();
        let started = TokioInstant::now();
        let observed = probe_configured_outlets(
            &controller,
            &private,
            &crate::ResolvedSubscriptionUrls::new(),
            5_000,
            Arc::new(AtomicBool::new(false)),
            TokioInstant::now() + Duration::from_millis(100),
            4,
        )
        .await;
        server.abort();

        assert!(started.elapsed() < Duration::from_millis(400));
        assert_eq!(observed.len(), 3);
        assert!(observed.iter().all(|(_, result)| {
            result.status == HealthStatus::Down
                && result.error_code.as_deref() == Some("guardian_cycle_deadline")
        }));
    }

    #[tokio::test]
    async fn generation_change_at_final_commit_discards_cycle_and_restores_reject() {
        let (controller, requests, _selected, server) =
            tracking_controller(false, Arc::new(AtomicBool::new(false))).await;
        let mut private = concurrent_fixture();
        private.outlets.truncate(1);
        private.probe_targets.truncate(1);
        let directory = tempfile::tempdir().expect("tempdir");
        let mut store = GuardianStore::open(directory.path().join("guardian.db")).expect("store");
        let routing = GenerationRoutingSession::new(true, None);

        let result = run_controller_guardian_cycle_controlled(
            &controller,
            &private,
            &crate::ResolvedSubscriptionUrls::new(),
            &monitor_fixture(),
            &mut store,
            &routing,
            1_000,
            Arc::new(AtomicBool::new(false)),
            Duration::from_secs(1),
            2,
        )
        .await;
        server.abort();

        assert!(matches!(result, Err(GuardianCycleError::Cancelled)));
        assert!(store.recent_samples(10).expect("samples").is_empty());
        assert!(store.recent_events(10).expect("events").is_empty());
        assert!(store.recent_route_switches(10).expect("routes").is_empty());
        assert!(store.udp_capabilities().expect("udp").is_empty());
        assert_eq!(routing.current_outlet().expect("route"), None);
        let requests = requests.lock().expect("requests");
        for selector in [crate::MASTER_SELECTOR, UDP_SELECTOR] {
            let last = requests
                .iter()
                .rev()
                .find(|request| request.starts_with("PUT ") && request.contains(selector))
                .expect("selector request");
            assert!(last.contains(r#""name":"REJECT""#), "{last}");
        }
    }

    #[tokio::test]
    async fn selector_timeout_shares_cycle_deadline_after_partial_probe_and_is_bounded() {
        let (controller, requests, _selected, server) =
            tracking_controller(true, Arc::new(AtomicBool::new(true))).await;
        let mut private = concurrent_fixture();
        private.outlets.truncate(1);
        private.probe_targets.truncate(2);
        let directory = tempfile::tempdir().expect("tempdir");
        let mut store = GuardianStore::open(directory.path().join("guardian.db")).expect("store");
        let routing = GenerationRoutingSession::new(false, Some("fail-closed".into()));
        let started = TokioInstant::now();

        let result = run_controller_guardian_cycle_controlled(
            &controller,
            &private,
            &crate::ResolvedSubscriptionUrls::new(),
            &monitor_fixture(),
            &mut store,
            &routing,
            1_000,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(150),
            2,
        )
        .await;
        let elapsed = started.elapsed();
        server.abort();

        assert!(matches!(result, Err(GuardianCycleError::Deadline)));
        assert!(elapsed < Duration::from_millis(700), "elapsed={elapsed:?}");
        assert!(store.recent_samples(10).expect("samples").is_empty());
        let requests = requests.lock().expect("requests");
        assert!(
            requests
                .iter()
                .any(|request| request.contains("probe-a.invalid"))
        );
        assert!(
            requests
                .iter()
                .any(|request| request.contains("probe-b.invalid"))
        );
        for selector in [crate::MASTER_SELECTOR, UDP_SELECTOR] {
            let last = requests
                .iter()
                .rev()
                .find(|request| request.starts_with("PUT ") && request.contains(selector))
                .expect("selector request");
            assert!(last.contains(r#""name":"REJECT""#), "{last}");
        }
    }

    #[tokio::test]
    async fn one_stalled_fail_closed_selector_persists_terminal_gate_even_if_it_applies_late() {
        let (controller, requests, selected, server) =
            tracking_controller(false, Arc::new(AtomicBool::new(true))).await;
        let mut private = concurrent_fixture();
        private.outlets.clear();
        private.probe_targets.clear();
        let directory = tempfile::tempdir().expect("tempdir");
        let mut store = GuardianStore::open(directory.path().join("guardian.db")).expect("store");
        let routing = GenerationRoutingSession::new(false, Some("local-old".into()));
        let started = TokioInstant::now();

        let result = run_controller_guardian_cycle_controlled(
            &controller,
            &private,
            &crate::ResolvedSubscriptionUrls::new(),
            &monitor_fixture(),
            &mut store,
            &routing,
            1_000,
            Arc::new(AtomicBool::new(true)),
            Duration::from_millis(300),
            2,
        )
        .await;
        let elapsed = started.elapsed();

        assert!(matches!(
            result,
            Err(GuardianCycleError::FailClosedUnconfirmed)
        ));
        assert!(elapsed < Duration::from_millis(450), "elapsed={elapsed:?}");
        assert!(routing.terminal_unconfirmed.load(Ordering::Acquire));
        assert_eq!(routing.current_outlet().expect("route"), None);
        {
            let captured = requests.lock().expect("requests");
            for selector in [crate::MASTER_SELECTOR, UDP_SELECTOR] {
                assert!(captured.iter().any(|request| {
                    request.starts_with("PUT ")
                        && request.contains(selector)
                        && request.contains("\"name\":\"REJECT\"")
                }));
            }
        }

        tokio::time::sleep(Duration::from_millis(450)).await;
        let selected = selected.lock().expect("selected");
        assert!(selected.0 == crate::FAIL_CLOSED_PROXY || selected.1 == crate::FAIL_CLOSED_PROXY);
        drop(selected);
        assert!(
            routing.terminal_unconfirmed.load(Ordering::Acquire),
            "a late Controller application cannot clear the durable terminal intent"
        );
        server.abort();
    }

    #[tokio::test]
    async fn busy_generation_gate_consumes_cycle_deadline_and_discards_the_atomic_batch() {
        let (controller, _requests, _selected, server) =
            tracking_controller(false, Arc::new(AtomicBool::new(false))).await;
        let mut private = concurrent_fixture();
        private.outlets.truncate(1);
        private.probe_targets.truncate(1);
        let directory = tempfile::tempdir().expect("tempdir");
        let mut store = GuardianStore::open(directory.path().join("guardian.db")).expect("store");
        let routing = GenerationRoutingSession::new(false, None);
        routing.hold_commit_gate_for(Duration::from_millis(500));
        let started = TokioInstant::now();

        let result = run_controller_guardian_cycle_controlled(
            &controller,
            &private,
            &crate::ResolvedSubscriptionUrls::new(),
            &monitor_fixture(),
            &mut store,
            &routing,
            1_000,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(240),
            2,
        )
        .await;
        let elapsed = started.elapsed();
        server.abort();

        assert!(matches!(result, Err(GuardianCycleError::Deadline)));
        assert!(elapsed < Duration::from_millis(350), "elapsed={elapsed:?}");
        assert!(store.recent_samples(10).expect("samples").is_empty());
        assert!(store.recent_events(10).expect("events").is_empty());
        assert!(store.recent_route_switches(10).expect("routes").is_empty());
        assert!(store.udp_capabilities().expect("udp").is_empty());
        assert_eq!(routing.current_outlet().expect("route"), None);
        assert!(!routing.terminal_unconfirmed.load(Ordering::Acquire));
    }
}
