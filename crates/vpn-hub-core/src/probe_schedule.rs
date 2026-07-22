use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

const ACTIVE_HEALTHY_SECONDS: u64 = 15;
const STANDBY_HEALTHY_SECONDS: u64 = 60;
const WAITING_RECHECK_SECONDS: u64 = 60;
const FAILURE_BACKOFF_SECONDS: [u64; 7] = [3, 3, 6, 12, 30, 60, 180];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeReadiness {
    Ready,
    NotConfigured,
    WaitingForRuntime,
    TerminalGate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCompletion {
    Healthy,
    Degraded,
    RecoverableFailure,
    RecoveryPending,
    NotConfigured,
    WaitingForRuntime,
    TerminalGate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmediateProbeReason {
    Startup,
    NetworkChanged,
    Resumed,
    ConfigurationChanged,
    Manual,
    RuntimeReady,
    TerminalRecovered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledProbe {
    pub outlet_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone)]
struct OutletSchedule {
    generation: u64,
    readiness: ProbeReadiness,
    next_due_ms: Option<u64>,
    failure_index: usize,
    in_flight: bool,
}

/// Deterministic, per-outlet Guardian scheduler.
///
/// The scheduler owns no tasks. Callers ask for due work and must complete each
/// lease with the matching generation. This keeps task bounds and stale-result
/// rejection explicit at the desktop lifecycle boundary.
#[derive(Debug, Default)]
pub struct ProbeScheduler {
    outlets: BTreeMap<String, OutletSchedule>,
    generation: u64,
}

impl ProbeScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reconcile(
        &mut self,
        outlets: impl IntoIterator<Item = (String, ProbeReadiness)>,
        now_ms: u64,
    ) {
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        let mut retained = BTreeSet::new();
        for (outlet_id, readiness) in outlets {
            retained.insert(outlet_id.clone());
            self.outlets.insert(
                outlet_id,
                OutletSchedule {
                    generation,
                    readiness,
                    next_due_ms: initial_due(readiness, now_ms),
                    failure_index: 0,
                    in_flight: false,
                },
            );
        }
        self.outlets.retain(|id, _| retained.contains(id));
    }

    pub fn trigger_all(&mut self, reason: ImmediateProbeReason, now_ms: u64) {
        if reason == ImmediateProbeReason::ConfigurationChanged {
            self.generation = self.generation.saturating_add(1);
        }
        for schedule in self.outlets.values_mut() {
            if reason == ImmediateProbeReason::ConfigurationChanged {
                schedule.generation = self.generation;
                schedule.in_flight = false;
            }
            if matches!(
                reason,
                ImmediateProbeReason::NetworkChanged
                    | ImmediateProbeReason::Resumed
                    | ImmediateProbeReason::ConfigurationChanged
                    | ImmediateProbeReason::Manual
            ) {
                schedule.failure_index = 0;
            }
            if matches!(
                schedule.readiness,
                ProbeReadiness::Ready | ProbeReadiness::WaitingForRuntime
            ) {
                schedule.next_due_ms = Some(now_ms);
            }
        }
    }

    pub fn mark_ready(&mut self, outlet_id: &str, reason: ImmediateProbeReason, now_ms: u64) {
        let Some(schedule) = self.outlets.get_mut(outlet_id) else {
            return;
        };
        schedule.readiness = ProbeReadiness::Ready;
        if matches!(
            reason,
            ImmediateProbeReason::RuntimeReady | ImmediateProbeReason::TerminalRecovered
        ) {
            schedule.next_due_ms = Some(now_ms);
        }
    }

    #[must_use]
    pub fn take_due(&mut self, now_ms: u64) -> Vec<ScheduledProbe> {
        self.outlets
            .iter_mut()
            .filter_map(|(outlet_id, schedule)| {
                let due = matches!(
                    schedule.readiness,
                    ProbeReadiness::Ready | ProbeReadiness::WaitingForRuntime
                ) && !schedule.in_flight
                    && schedule.next_due_ms.is_some_and(|due| due <= now_ms);
                if !due {
                    return None;
                }
                schedule.in_flight = true;
                schedule.next_due_ms = None;
                Some(ScheduledProbe {
                    outlet_id: outlet_id.clone(),
                    generation: schedule.generation,
                })
            })
            .collect()
    }

    /// Completes a leased probe. Returns false for a cancelled/old generation.
    pub fn complete(
        &mut self,
        probe: &ScheduledProbe,
        completion: ProbeCompletion,
        active: bool,
        now_ms: u64,
    ) -> bool {
        let Some(schedule) = self.outlets.get_mut(&probe.outlet_id) else {
            return false;
        };
        if !schedule.in_flight || schedule.generation != probe.generation {
            return false;
        }
        schedule.in_flight = false;
        match completion {
            ProbeCompletion::Healthy | ProbeCompletion::Degraded => {
                schedule.readiness = ProbeReadiness::Ready;
                schedule.failure_index = 0;
                let base = if active {
                    ACTIVE_HEALTHY_SECONDS
                } else {
                    STANDBY_HEALTHY_SECONDS
                };
                schedule.next_due_ms = Some(now_ms.saturating_add(jitter_ms(
                    base,
                    &probe.outlet_id,
                    probe.generation,
                    0,
                )));
            }
            ProbeCompletion::RecoverableFailure => {
                schedule.readiness = ProbeReadiness::Ready;
                let index = schedule
                    .failure_index
                    .min(FAILURE_BACKOFF_SECONDS.len() - 1);
                let base = FAILURE_BACKOFF_SECONDS[index];
                schedule.failure_index = schedule.failure_index.saturating_add(1);
                schedule.next_due_ms = Some(now_ms.saturating_add(jitter_ms(
                    base,
                    &probe.outlet_id,
                    probe.generation,
                    index,
                )));
            }
            ProbeCompletion::RecoveryPending => {
                schedule.readiness = ProbeReadiness::Ready;
                schedule.failure_index = 0;
                schedule.next_due_ms = Some(now_ms.saturating_add(jitter_ms(
                    FAILURE_BACKOFF_SECONDS[0],
                    &probe.outlet_id,
                    probe.generation,
                    0,
                )));
            }
            ProbeCompletion::NotConfigured => {
                schedule.readiness = ProbeReadiness::NotConfigured;
                schedule.failure_index = 0;
                schedule.next_due_ms = None;
            }
            ProbeCompletion::WaitingForRuntime => {
                schedule.readiness = ProbeReadiness::WaitingForRuntime;
                schedule.failure_index = 0;
                schedule.next_due_ms =
                    Some(now_ms.saturating_add(WAITING_RECHECK_SECONDS.saturating_mul(1_000)));
            }
            ProbeCompletion::TerminalGate => {
                schedule.readiness = ProbeReadiness::TerminalGate;
                schedule.failure_index = 0;
                schedule.next_due_ms = None;
            }
        }
        true
    }

    #[must_use]
    pub fn next_due_ms(&self) -> Option<u64> {
        self.outlets
            .values()
            .filter(|schedule| !schedule.in_flight)
            .filter_map(|schedule| schedule.next_due_ms)
            .min()
    }

    #[must_use]
    pub fn readiness(&self, outlet_id: &str) -> Option<ProbeReadiness> {
        self.outlets.get(outlet_id).map(|item| item.readiness)
    }
}

const fn initial_due(readiness: ProbeReadiness, now_ms: u64) -> Option<u64> {
    match readiness {
        ProbeReadiness::Ready => Some(now_ms),
        ProbeReadiness::WaitingForRuntime => {
            Some(now_ms.saturating_add(WAITING_RECHECK_SECONDS * 1_000))
        }
        ProbeReadiness::NotConfigured | ProbeReadiness::TerminalGate => None,
    }
}

fn jitter_ms(base_seconds: u64, outlet_id: &str, generation: u64, attempt: usize) -> u64 {
    let mut hash = generation ^ u64::try_from(attempt).unwrap_or(u64::MAX);
    for byte in outlet_id.bytes() {
        hash = hash
            .wrapping_mul(1_099_511_628_211)
            .wrapping_add(u64::from(byte));
    }
    let base_ms = base_seconds.saturating_mul(1_000);
    let spread = base_ms / 10;
    if spread == 0 {
        return base_ms;
    }
    let width = spread.saturating_mul(2).saturating_add(1);
    base_ms.saturating_sub(spread).saturating_add(hash % width)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn due_one(scheduler: &mut ProbeScheduler, now_ms: u64, id: &str) -> ScheduledProbe {
        let due = scheduler.take_due(now_ms);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].outlet_id, id);
        due.into_iter().next().expect("due probe")
    }

    #[test]
    fn startup_is_immediate_for_every_ready_outlet() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile(
            [
                ("active".into(), ProbeReadiness::Ready),
                ("backup".into(), ProbeReadiness::Ready),
            ],
            42_000,
        );
        let due = scheduler.take_due(42_000);
        assert_eq!(
            due.iter()
                .map(|item| item.outlet_id.as_str())
                .collect::<Vec<_>>(),
            ["active", "backup"]
        );
    }

    #[test]
    fn healthy_cadence_is_active_15_and_standby_60_with_bounded_jitter() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile([("active".into(), ProbeReadiness::Ready)], 0);
        let active = due_one(&mut scheduler, 0, "active");
        assert!(scheduler.complete(&active, ProbeCompletion::Healthy, true, 0));
        assert!((13_500..=16_500).contains(&scheduler.next_due_ms().expect("active due")));

        scheduler.trigger_all(ImmediateProbeReason::Manual, 20_000);
        let standby = due_one(&mut scheduler, 20_000, "active");
        assert!(scheduler.complete(&standby, ProbeCompletion::Healthy, false, 20_000));
        let delay = scheduler.next_due_ms().expect("standby due") - 20_000;
        assert!((54_000..=66_000).contains(&delay));
    }

    #[test]
    fn only_failed_outlet_enters_bounded_backoff_and_recovery_resets_it() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile(
            [
                ("bad".into(), ProbeReadiness::Ready),
                ("good".into(), ProbeReadiness::Ready),
            ],
            0,
        );
        let due = scheduler.take_due(0);
        let bad = due
            .iter()
            .find(|item| item.outlet_id == "bad")
            .expect("bad")
            .clone();
        let good = due
            .iter()
            .find(|item| item.outlet_id == "good")
            .expect("good")
            .clone();
        scheduler.complete(&bad, ProbeCompletion::RecoverableFailure, false, 0);
        scheduler.complete(&good, ProbeCompletion::Healthy, false, 0);
        assert!(scheduler.next_due_ms().expect("failed due") < 3_400);
        let retry = scheduler.take_due(3_400);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].outlet_id, "bad");
        scheduler.complete(&retry[0], ProbeCompletion::RecoverableFailure, false, 3_400);

        scheduler.trigger_all(ImmediateProbeReason::Manual, 10_000);
        let due = scheduler.take_due(10_000);
        let bad = due
            .into_iter()
            .find(|item| item.outlet_id == "bad")
            .expect("bad");
        scheduler.complete(&bad, ProbeCompletion::Healthy, false, 10_000);
        assert!(scheduler.next_due_ms().expect("recovered due") >= 64_000);
    }

    #[test]
    fn recovery_pending_stays_in_three_second_window_until_store_confirms_recovery() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile([("outlet".into(), ProbeReadiness::Ready)], 0);
        let mut probe = due_one(&mut scheduler, 0, "outlet");
        let mut now_ms = 0;
        for completion in [
            ProbeCompletion::RecoverableFailure,
            ProbeCompletion::RecoverableFailure,
            ProbeCompletion::RecoveryPending,
            ProbeCompletion::RecoveryPending,
        ] {
            assert!(scheduler.complete(&probe, completion, false, now_ms));
            let due_ms = scheduler.next_due_ms().expect("rapid confirmation due");
            assert!((2_700..=3_300).contains(&(due_ms - now_ms)));
            now_ms = due_ms;
            probe = due_one(&mut scheduler, now_ms, "outlet");
        }
        assert!(scheduler.complete(&probe, ProbeCompletion::Healthy, false, now_ms));
        let healthy_delay = scheduler.next_due_ms().expect("healthy cadence") - now_ms;
        assert!((54_000..=66_000).contains(&healthy_delay));
    }

    #[test]
    fn backoff_bases_are_exact_and_capped_before_jitter() {
        for (index, seconds) in FAILURE_BACKOFF_SECONDS.into_iter().enumerate() {
            let delay = jitter_ms(seconds, "outlet", 1, index);
            let base = seconds * 1_000;
            assert!((base - base / 10..=base + base / 10).contains(&delay));
        }
    }

    #[test]
    fn scheduler_walks_the_complete_failure_sequence_then_caps_at_180() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile([("outlet".into(), ProbeReadiness::Ready)], 0);
        let mut probe = due_one(&mut scheduler, 0, "outlet");
        let mut now_ms = 0;
        for seconds in FAILURE_BACKOFF_SECONDS {
            scheduler.complete(&probe, ProbeCompletion::RecoverableFailure, false, now_ms);
            let due_ms = scheduler.next_due_ms().expect("retry due");
            let delay = due_ms - now_ms;
            let base = seconds * 1_000;
            assert!((base - base / 10..=base + base / 10).contains(&delay));
            now_ms = due_ms;
            probe = due_one(&mut scheduler, now_ms, "outlet");
        }
        scheduler.complete(&probe, ProbeCompletion::RecoverableFailure, false, now_ms);
        let capped_delay = scheduler.next_due_ms().expect("capped due") - now_ms;
        assert!((162_000..=198_000).contains(&capped_delay));
    }

    #[test]
    fn structural_states_do_not_busy_loop_and_events_wake_them() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile(
            [
                ("missing".into(), ProbeReadiness::NotConfigured),
                ("waiting".into(), ProbeReadiness::WaitingForRuntime),
                ("terminal".into(), ProbeReadiness::TerminalGate),
            ],
            0,
        );
        assert!(scheduler.take_due(3_000).is_empty());
        assert_eq!(scheduler.next_due_ms(), Some(60_000));
        scheduler.mark_ready("waiting", ImmediateProbeReason::RuntimeReady, 4_000);
        assert_eq!(
            due_one(&mut scheduler, 4_000, "waiting").outlet_id,
            "waiting"
        );
        scheduler.mark_ready("terminal", ImmediateProbeReason::TerminalRecovered, 5_000);
        assert_eq!(
            due_one(&mut scheduler, 5_000, "terminal").outlet_id,
            "terminal"
        );
    }

    #[test]
    fn no_overlap_and_stale_generation_cannot_commit() {
        let mut scheduler = ProbeScheduler::new();
        scheduler.reconcile([("outlet".into(), ProbeReadiness::Ready)], 0);
        let old = due_one(&mut scheduler, 0, "outlet");
        assert!(scheduler.take_due(u64::MAX).is_empty());
        scheduler.trigger_all(ImmediateProbeReason::ConfigurationChanged, 1);
        assert!(!scheduler.complete(&old, ProbeCompletion::Healthy, true, 1));
        let current = due_one(&mut scheduler, 1, "outlet");
        assert!(scheduler.complete(&current, ProbeCompletion::Healthy, true, 1));
    }
}
