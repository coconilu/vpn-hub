use std::{
    collections::{BTreeMap, HashSet},
    time::Instant,
};

use chrono::{SecondsFormat, Utc};
use thiserror::Error;

use crate::{
    ControllerClient, ControllerError, GuardianStore, HealthStatus, MonitorConfig, OutletConfig,
    OutletHealth, OutletKind, PrivateRoutingConfig, ProbeOutletConfig, ProbeResult, RouteDecision,
    RouteSwitchEvent, RoutingEngine, RoutingPolicy, StoreError, UDP_SELECTOR, UdpCapabilityStatus,
    current_udp_status, outlet_proxy_name, unknown_udp_evidence,
};

#[derive(Debug, Error)]
pub enum RoutingStateError {
    #[error("routing state is unavailable")]
    Unavailable,
}

pub trait RoutingSession {
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
}

impl RoutingSession for std::sync::Mutex<RoutingEngine> {
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
}

#[derive(Debug, Error)]
pub enum GuardianCycleError {
    #[error("Controller operation failed: {0}")]
    Controller(#[from] ControllerError),
    #[error("Guardian storage operation failed: {0}")]
    Store(#[from] StoreError),
    #[error("routing state operation failed: {0}")]
    RoutingState(#[from] RoutingStateError),
}

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
    for outlet in private.enabled_outlets() {
        store.ensure_udp_capability(
            &outlet.id,
            &outlet.label,
            &unknown_udp_evidence(outlet, "not_yet_validated"),
        )?;
    }
    let observed =
        probe_configured_outlets(controller, private, resolved, monitor.request_timeout_ms).await;

    for (outlet, result) in &observed {
        store.record_probe(
            outlet,
            result,
            monitor.failure_threshold,
            monitor.recovery_threshold,
        )?;
    }

    let enabled_ids = private
        .enabled_outlets()
        .map(|outlet| outlet.id.as_str())
        .collect::<HashSet<_>>();
    let latest_latency = observed
        .iter()
        .map(|(outlet, result)| (outlet.id.as_str(), result.latency_ms))
        .collect::<BTreeMap<_, _>>();
    let health = store
        .summaries()?
        .into_iter()
        .filter(|item| enabled_ids.contains(item.outlet_id.as_str()))
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
        priority: private.priority(),
        cooldown_ms: private.cooldown_seconds.saturating_mul(1_000),
        minimum_improvement_ms: private.minimum_improvement_ms,
    };
    let decision = routing.evaluate_route(now_ms, &health, &policy)?;
    let started = Instant::now();
    if let Some(decision) = &decision {
        controller
            .select(
                crate::MASTER_SELECTOR,
                &outlet_proxy_name(&decision.to_outlet),
            )
            .await?;
    }
    let selected_outlet = decision
        .as_ref()
        .map(|decision| decision.to_outlet.clone())
        .or(routing.current_outlet()?);
    let udp_capabilities = store.udp_capabilities()?;
    let udp_target = udp_selector_target(private, selected_outlet.as_deref(), &udp_capabilities);
    if let Err(error) = controller.select(UDP_SELECTOR, &udp_target).await {
        let _ = controller
            .select(UDP_SELECTOR, crate::FAIL_CLOSED_PROXY)
            .await;
        return Err(error.into());
    }
    if let Some(decision) = &decision {
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        routing.apply_route(decision, now_ms)?;
        store.record_route_switch(&RouteSwitchEvent {
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            from_outlet: decision.from_outlet.clone(),
            to_outlet: decision.to_outlet.clone(),
            mode: private.route_mode.as_str().into(),
            reason: decision.reason.clone(),
            duration_ms,
        })?;
    }

    Ok(GuardianCycleOutcome {
        observed: observed.into_iter().map(|(_, result)| result).collect(),
        decision,
    })
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
) -> Vec<(ProbeOutletConfig, ProbeResult)> {
    let mut observed = Vec::new();
    for outlet in private.enabled_outlets() {
        let result = match &outlet.kind {
            OutletKind::Subscription { secret_ref, .. } if !resolved.contains_key(secret_ref) => {
                unavailable_result(
                    outlet,
                    "subscription_not_configured",
                    private.probe_targets.len(),
                )
            }
            _ => {
                probe_controller_outlet(controller, outlet, &private.probe_targets, timeout_ms)
                    .await
            }
        };
        observed.push((virtual_outlet(outlet, &private.entry), result));
    }
    observed
}

async fn probe_controller_outlet(
    controller: &ControllerClient,
    outlet: &OutletConfig,
    targets: &[String],
    timeout_ms: u64,
) -> ProbeResult {
    let proxy_name = outlet_proxy_name(&outlet.id);
    let mut delays = Vec::new();
    for target in targets {
        let delay = controller.delay(&proxy_name, target, timeout_ms).await;
        if let Ok(delay) = delay {
            delays.push(delay);
        }
    }
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
