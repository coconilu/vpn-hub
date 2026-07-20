use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::HealthStatus;

pub const FAIL_CLOSED_OUTLET: &str = "fail-closed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    Priority,
    Fastest,
    Manual,
}

impl RouteMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Fastest => "fastest",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutletHealth {
    pub status: HealthStatus,
    pub latency_ms: Option<u64>,
}

impl OutletHealth {
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

#[derive(Debug, Clone)]
pub struct RoutingPolicy {
    pub priority: Vec<String>,
    pub cooldown_ms: u64,
    pub minimum_improvement_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub from_outlet: Option<String>,
    pub to_outlet: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RoutingEngine {
    mode: RouteMode,
    manual_outlet: Option<String>,
    current_outlet: Option<String>,
    last_switch_ms: Option<u64>,
}

impl RoutingEngine {
    #[must_use]
    pub const fn new(mode: RouteMode, manual_outlet: Option<String>) -> Self {
        Self {
            mode,
            manual_outlet,
            current_outlet: None,
            last_switch_ms: None,
        }
    }

    pub fn set_mode(&mut self, mode: RouteMode, manual_outlet: Option<String>) {
        self.mode = mode;
        self.manual_outlet = manual_outlet;
    }

    #[must_use]
    pub const fn mode(&self) -> RouteMode {
        self.mode
    }

    #[must_use]
    pub fn manual_outlet(&self) -> Option<&str> {
        self.manual_outlet.as_deref()
    }

    #[must_use]
    pub fn current_outlet(&self) -> Option<&str> {
        self.current_outlet.as_deref()
    }

    pub fn restore_current(&mut self, outlet: Option<String>, last_switch_ms: Option<u64>) {
        self.current_outlet = outlet;
        self.last_switch_ms = last_switch_ms;
    }

    #[must_use]
    pub fn evaluate(
        &self,
        now_ms: u64,
        health: &BTreeMap<String, OutletHealth>,
        policy: &RoutingPolicy,
    ) -> Option<RouteDecision> {
        let (desired, reason) = match self.mode {
            RouteMode::Priority => (
                policy
                    .priority
                    .iter()
                    .find(|id| is_available(health, id))
                    .cloned()
                    .unwrap_or_else(|| FAIL_CLOSED_OUTLET.to_owned()),
                "priority_policy",
            ),
            RouteMode::Fastest => {
                let desired = fastest_available(health)
                    .or_else(|| {
                        self.current_outlet
                            .as_ref()
                            .filter(|id| is_available(health, id))
                            .cloned()
                    })
                    .unwrap_or_else(|| FAIL_CLOSED_OUTLET.to_owned());
                (desired, "lowest_latency_policy")
            }
            RouteMode::Manual => {
                let manual = self.manual_outlet.as_deref();
                if manual.is_some_and(|id| is_available(health, id)) {
                    (manual.unwrap_or_default().to_owned(), "manual_selection")
                } else {
                    (FAIL_CLOSED_OUTLET.to_owned(), "manual_outlet_unavailable")
                }
            }
        };

        if self.current_outlet.as_deref() == Some(desired.as_str()) {
            return None;
        }

        let current_available = self
            .current_outlet
            .as_deref()
            .is_some_and(|id| is_available(health, id));
        let emergency = !current_available || desired == FAIL_CLOSED_OUTLET;
        if !emergency
            && self
                .last_switch_ms
                .is_some_and(|last| now_ms.saturating_sub(last) < policy.cooldown_ms)
        {
            return None;
        }

        if self.mode == RouteMode::Fastest && current_available {
            let current_latency = self
                .current_outlet
                .as_deref()
                .and_then(|id| health.get(id))
                .and_then(|item| item.latency_ms);
            let desired_latency = health.get(&desired).and_then(|item| item.latency_ms);
            let (Some(current_latency), Some(desired_latency)) = (current_latency, desired_latency)
            else {
                return None;
            };
            if desired_latency.saturating_add(policy.minimum_improvement_ms) >= current_latency {
                return None;
            }
        }

        Some(RouteDecision {
            from_outlet: self.current_outlet.clone(),
            to_outlet: desired,
            reason: reason.to_owned(),
        })
    }

    pub fn apply(&mut self, decision: &RouteDecision, switched_at_ms: u64) {
        self.current_outlet = Some(decision.to_outlet.clone());
        self.last_switch_ms = Some(switched_at_ms);
    }
}

fn is_available(health: &BTreeMap<String, OutletHealth>, id: &str) -> bool {
    health.get(id).is_some_and(OutletHealth::is_available)
}

fn fastest_available(health: &BTreeMap<String, OutletHealth>) -> Option<String> {
    health
        .iter()
        .filter(|(_, item)| item.is_available())
        .filter_map(|(id, item)| item.latency_ms.map(|latency| (id, latency)))
        .min_by_key(|(_, latency)| *latency)
        .map(|(id, _)| id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: &str = "outlet-primary";
    const SECONDARY: &str = "outlet-secondary";

    fn health(items: &[(&str, HealthStatus, Option<u64>)]) -> BTreeMap<String, OutletHealth> {
        items
            .iter()
            .map(|(id, status, latency_ms)| {
                (
                    (*id).to_owned(),
                    OutletHealth {
                        status: *status,
                        latency_ms: *latency_ms,
                    },
                )
            })
            .collect()
    }

    fn policy() -> RoutingPolicy {
        RoutingPolicy {
            priority: vec![PRIMARY.into(), SECONDARY.into()],
            cooldown_ms: 60_000,
            minimum_improvement_ms: 100,
        }
    }

    #[test]
    fn priority_fails_over_immediately_and_recovers_after_cooldown() {
        let mut engine = RoutingEngine::new(RouteMode::Priority, None);
        let both = health(&[
            (PRIMARY, HealthStatus::Healthy, Some(100)),
            (SECONDARY, HealthStatus::Healthy, Some(200)),
        ]);
        let first = engine.evaluate(0, &both, &policy()).expect("initial");
        assert_eq!(first.to_outlet, PRIMARY);
        engine.apply(&first, 0);

        let fallback = health(&[
            (PRIMARY, HealthStatus::Down, None),
            (SECONDARY, HealthStatus::Healthy, Some(200)),
        ]);
        let failover = engine.evaluate(1, &fallback, &policy()).expect("failover");
        assert_eq!(failover.to_outlet, SECONDARY);
        engine.apply(&failover, 1);

        assert!(engine.evaluate(30_000, &both, &policy()).is_none());
        assert_eq!(
            engine
                .evaluate(60_001, &both, &policy())
                .expect("recover")
                .to_outlet,
            PRIMARY
        );
    }

    #[test]
    fn fastest_uses_hysteresis_and_cooldown() {
        let mut engine = RoutingEngine::new(RouteMode::Fastest, None);
        let initial = health(&[
            (PRIMARY, HealthStatus::Healthy, Some(300)),
            (SECONDARY, HealthStatus::Healthy, Some(200)),
        ]);
        let first = engine.evaluate(0, &initial, &policy()).expect("initial");
        engine.apply(&first, 0);
        assert_eq!(first.to_outlet, SECONDARY);

        let small_gain = health(&[
            (PRIMARY, HealthStatus::Healthy, Some(150)),
            (SECONDARY, HealthStatus::Healthy, Some(200)),
        ]);
        assert!(engine.evaluate(70_000, &small_gain, &policy()).is_none());

        let large_gain = health(&[
            (PRIMARY, HealthStatus::Healthy, Some(80)),
            (SECONDARY, HealthStatus::Healthy, Some(200)),
        ]);
        assert_eq!(
            engine
                .evaluate(70_000, &large_gain, &policy())
                .expect("switch")
                .to_outlet,
            PRIMARY
        );
    }

    #[test]
    fn fastest_keeps_healthy_current_when_current_latency_is_missing() {
        let mut engine = RoutingEngine::new(RouteMode::Fastest, None);
        let initial = health(&[
            (PRIMARY, HealthStatus::Healthy, Some(100)),
            (SECONDARY, HealthStatus::Healthy, Some(200)),
        ]);
        let first = engine.evaluate(0, &initial, &policy()).expect("initial");
        engine.apply(&first, 0);
        assert_eq!(first.to_outlet, PRIMARY);

        let missing_current_sample = health(&[
            (PRIMARY, HealthStatus::Healthy, None),
            (SECONDARY, HealthStatus::Healthy, Some(50)),
        ]);
        assert!(
            engine
                .evaluate(120_000, &missing_current_sample, &policy())
                .is_none()
        );

        let current_is_down = health(&[
            (PRIMARY, HealthStatus::Down, None),
            (SECONDARY, HealthStatus::Healthy, Some(50)),
        ]);
        assert_eq!(
            engine
                .evaluate(120_001, &current_is_down, &policy())
                .expect("failover")
                .to_outlet,
            SECONDARY
        );
    }

    #[test]
    fn manual_unavailable_is_fail_closed() {
        let engine = RoutingEngine::new(RouteMode::Manual, Some(PRIMARY.into()));
        let health = health(&[(PRIMARY, HealthStatus::Down, None)]);
        let decision = engine.evaluate(0, &health, &policy()).expect("decision");
        assert_eq!(decision.to_outlet, FAIL_CLOSED_OUTLET);
        assert_eq!(decision.reason, "manual_outlet_unavailable");
    }

    #[test]
    fn all_unavailable_is_fail_closed() {
        let engine = RoutingEngine::new(RouteMode::Priority, None);
        let health = health(&[
            (PRIMARY, HealthStatus::Down, None),
            (SECONDARY, HealthStatus::Down, None),
        ]);
        assert_eq!(
            engine
                .evaluate(0, &health, &policy())
                .expect("decision")
                .to_outlet,
            FAIL_CLOSED_OUTLET
        );
    }

    #[test]
    fn modes_operate_on_a_dynamic_five_outlet_collection() {
        let health = health(&[
            ("sub-a", HealthStatus::Healthy, Some(300)),
            ("sub-b", HealthStatus::Down, None),
            ("sub-c", HealthStatus::Healthy, Some(90)),
            ("local-a", HealthStatus::Healthy, Some(180)),
            ("local-b", HealthStatus::Degraded, Some(120)),
        ]);
        let policy = RoutingPolicy {
            priority: vec![
                "sub-b".into(),
                "local-a".into(),
                "sub-a".into(),
                "sub-c".into(),
                "local-b".into(),
            ],
            cooldown_ms: 60_000,
            minimum_improvement_ms: 25,
        };

        let priority = RoutingEngine::new(RouteMode::Priority, None)
            .evaluate(0, &health, &policy)
            .expect("priority decision");
        assert_eq!(priority.to_outlet, "local-a");

        let fastest = RoutingEngine::new(RouteMode::Fastest, None)
            .evaluate(0, &health, &policy)
            .expect("fastest decision");
        assert_eq!(fastest.to_outlet, "sub-c");

        let manual = RoutingEngine::new(RouteMode::Manual, Some("local-b".into()))
            .evaluate(0, &health, &policy)
            .expect("manual decision");
        assert_eq!(manual.to_outlet, "local-b");
    }
}
