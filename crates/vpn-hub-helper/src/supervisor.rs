use std::collections::VecDeque;

use sha2::{Digest, Sha256};

const MAX_RECOVERY_ATTEMPTS: u8 = 5;
const EVENT_MAILBOX_CAPACITY: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailClosedReason {
    CorruptConfig,
    CorruptDatabase,
    PortConflict,
    OwnershipLost,
    AuthorityLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisorState {
    Stopped,
    Running { pid: u32, creation_identity: u64 },
    Backoff { delay_ms: u64 },
    FailClosed(FailClosedReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverySignal {
    Resume,
    NetworkChanged([u8; 32]),
    ConfigGeneration(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisorEvent {
    StartSucceeded { pid: u32, creation_identity: u64 },
    OwnedChildExited,
    RestartTimer,
    StartFailed,
    StableRun,
    ExplicitStop,
    ExplicitReset,
    Recovery(RecoverySignal),
    InvalidState(FailClosedReason),
    AuthorityLost,
}

#[derive(Debug)]
pub struct SupervisorMachine {
    state: SupervisorState,
    circuit: CircuitState,
    attempts: u8,
    expected_generation: u64,
    last_network_fingerprint: Option<[u8; 32]>,
    mailbox: VecDeque<SupervisorEvent>,
}

impl SupervisorMachine {
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self {
            state: SupervisorState::Stopped,
            circuit: CircuitState::Closed,
            attempts: 0,
            expected_generation: generation,
            last_network_fingerprint: None,
            mailbox: VecDeque::with_capacity(EVENT_MAILBOX_CAPACITY),
        }
    }

    #[must_use]
    pub const fn state(&self) -> SupervisorState {
        self.state
    }

    #[must_use]
    pub const fn circuit(&self) -> CircuitState {
        self.circuit
    }

    #[must_use]
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Bounded, coalescing mailbox. Recovery signals of the same class replace
    /// older pending signals; control events are never silently expanded.
    pub fn enqueue(&mut self, event: SupervisorEvent) -> bool {
        if let SupervisorEvent::Recovery(signal) = event {
            let same_class = |queued: &SupervisorEvent| {
                matches!(
                    (queued, signal),
                    (
                        SupervisorEvent::Recovery(RecoverySignal::Resume),
                        RecoverySignal::Resume
                    ) | (
                        SupervisorEvent::Recovery(RecoverySignal::NetworkChanged(_)),
                        RecoverySignal::NetworkChanged(_)
                    ) | (
                        SupervisorEvent::Recovery(RecoverySignal::ConfigGeneration(_)),
                        RecoverySignal::ConfigGeneration(_)
                    )
                )
            };
            if let Some(position) = self.mailbox.iter().position(same_class) {
                self.mailbox[position] = event;
                return true;
            }
        }
        if self.mailbox.len() >= EVENT_MAILBOX_CAPACITY {
            return false;
        }
        self.mailbox.push_back(event);
        true
    }

    pub fn process_next(&mut self) -> Option<SupervisorState> {
        let event = self.mailbox.pop_front()?;
        self.apply(event);
        Some(self.state)
    }

    pub fn apply(&mut self, event: SupervisorEvent) {
        match event {
            SupervisorEvent::StartSucceeded {
                pid,
                creation_identity,
            } if self.circuit == CircuitState::Closed => {
                self.state = SupervisorState::Running {
                    pid,
                    creation_identity,
                };
            }
            SupervisorEvent::OwnedChildExited | SupervisorEvent::StartFailed => {
                self.schedule_backoff();
            }
            SupervisorEvent::StableRun => {
                if matches!(self.state, SupervisorState::Running { .. }) {
                    self.attempts = 0;
                }
            }
            SupervisorEvent::RestartTimer => {
                if matches!(self.state, SupervisorState::Backoff { .. })
                    && self.circuit == CircuitState::Closed
                {
                    self.state = SupervisorState::Stopped;
                }
            }
            SupervisorEvent::ExplicitStop => {
                self.state = SupervisorState::Stopped;
                self.attempts = 0;
            }
            SupervisorEvent::ExplicitReset => {
                self.state = SupervisorState::Stopped;
                self.circuit = CircuitState::Closed;
                self.attempts = 0;
            }
            SupervisorEvent::Recovery(signal) => self.apply_recovery(signal),
            SupervisorEvent::InvalidState(reason) => {
                self.state = SupervisorState::FailClosed(reason);
            }
            SupervisorEvent::AuthorityLost => {
                self.state = SupervisorState::FailClosed(FailClosedReason::AuthorityLost);
            }
            SupervisorEvent::StartSucceeded { .. } => {}
        }
    }

    fn schedule_backoff(&mut self) {
        if matches!(self.state, SupervisorState::FailClosed(_)) {
            return;
        }
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts >= MAX_RECOVERY_ATTEMPTS {
            self.circuit = CircuitState::Open;
            self.state = SupervisorState::FailClosed(FailClosedReason::OwnershipLost);
            return;
        }
        let delay_ms = 1_000_u64 << u32::from(self.attempts.saturating_sub(1).min(5));
        self.state = SupervisorState::Backoff { delay_ms };
    }

    fn apply_recovery(&mut self, signal: RecoverySignal) {
        match signal {
            RecoverySignal::ConfigGeneration(generation)
                if generation > self.expected_generation =>
            {
                self.expected_generation = generation;
                if !matches!(self.state, SupervisorState::FailClosed(_)) {
                    self.state = SupervisorState::Stopped;
                }
            }
            RecoverySignal::NetworkChanged(fingerprint) => {
                let changed = self
                    .last_network_fingerprint
                    .is_none_or(|previous| previous != fingerprint);
                self.last_network_fingerprint = Some(fingerprint);
                if changed && self.circuit == CircuitState::Closed {
                    self.attempts = 0;
                }
            }
            RecoverySignal::Resume => {
                if self.circuit == CircuitState::Closed {
                    self.attempts = 0;
                }
            }
            RecoverySignal::ConfigGeneration(_) => {}
        }
    }

    #[must_use]
    pub fn network_fingerprint(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_backoff_opens_circuit_and_only_explicit_reset_closes_it() {
        let mut supervisor = SupervisorMachine::new(1);
        supervisor.apply(SupervisorEvent::StartSucceeded {
            pid: 40_001,
            creation_identity: 99,
        });
        for expected_attempt in 1..MAX_RECOVERY_ATTEMPTS {
            supervisor.apply(SupervisorEvent::OwnedChildExited);
            assert_eq!(supervisor.attempts(), expected_attempt);
            assert_eq!(supervisor.circuit(), CircuitState::Closed);
            supervisor.apply(SupervisorEvent::RestartTimer);
        }
        supervisor.apply(SupervisorEvent::StartFailed);
        assert_eq!(supervisor.circuit(), CircuitState::Open);
        assert!(matches!(
            supervisor.state(),
            SupervisorState::FailClosed(FailClosedReason::OwnershipLost)
        ));
        supervisor.apply(SupervisorEvent::Recovery(RecoverySignal::Resume));
        assert_eq!(supervisor.circuit(), CircuitState::Open);
        supervisor.apply(SupervisorEvent::ExplicitReset);
        assert_eq!(supervisor.circuit(), CircuitState::Closed);
        assert_eq!(supervisor.state(), SupervisorState::Stopped);
    }

    #[test]
    fn repeated_short_lived_successes_do_not_reset_crash_streak() {
        let mut supervisor = SupervisorMachine::new(1);
        for attempt in 0..MAX_RECOVERY_ATTEMPTS {
            supervisor.apply(SupervisorEvent::StartSucceeded {
                pid: 40_000 + u32::from(attempt),
                creation_identity: u64::from(attempt),
            });
            supervisor.apply(SupervisorEvent::OwnedChildExited);
            if attempt + 1 < MAX_RECOVERY_ATTEMPTS {
                supervisor.apply(SupervisorEvent::RestartTimer);
            }
        }
        assert_eq!(supervisor.circuit(), CircuitState::Open);
        assert!(matches!(
            supervisor.state(),
            SupervisorState::FailClosed(FailClosedReason::OwnershipLost)
        ));
    }

    #[test]
    fn corrupt_inputs_and_port_conflict_are_fail_closed() {
        for reason in [
            FailClosedReason::CorruptConfig,
            FailClosedReason::CorruptDatabase,
            FailClosedReason::PortConflict,
        ] {
            let mut supervisor = SupervisorMachine::new(1);
            supervisor.apply(SupervisorEvent::InvalidState(reason));
            assert_eq!(supervisor.state(), SupervisorState::FailClosed(reason));
        }
    }

    #[test]
    fn mailbox_is_bounded_and_recovery_signals_coalesce() {
        let mut supervisor = SupervisorMachine::new(1);
        assert!(
            supervisor.enqueue(SupervisorEvent::Recovery(RecoverySignal::ConfigGeneration(
                2
            )))
        );
        assert!(
            supervisor.enqueue(SupervisorEvent::Recovery(RecoverySignal::ConfigGeneration(
                3
            )))
        );
        assert_eq!(supervisor.mailbox.len(), 1);
        for _ in 1..EVENT_MAILBOX_CAPACITY {
            assert!(supervisor.enqueue(SupervisorEvent::ExplicitStop));
        }
        assert!(!supervisor.enqueue(SupervisorEvent::StartFailed));
    }

    #[test]
    fn network_fingerprint_is_stable_without_exposing_inputs() {
        let first = SupervisorMachine::network_fingerprint(&[b"adapter-a", b"network-a"]);
        let same = SupervisorMachine::network_fingerprint(&[b"adapter-a", b"network-a"]);
        let changed = SupervisorMachine::network_fingerprint(&[b"adapter-a", b"network-b"]);
        assert_eq!(first, same);
        assert_ne!(first, changed);

        let mut supervisor = SupervisorMachine::new(1);
        supervisor.apply(SupervisorEvent::Recovery(RecoverySignal::NetworkChanged(
            first,
        )));
        assert_eq!(supervisor.last_network_fingerprint, Some(first));
    }

    #[test]
    fn generation_changes_request_controlled_restart_but_stale_generation_does_not() {
        let mut supervisor = SupervisorMachine::new(4);
        supervisor.apply(SupervisorEvent::StartSucceeded {
            pid: 40_001,
            creation_identity: 99,
        });
        supervisor.apply(SupervisorEvent::Recovery(RecoverySignal::ConfigGeneration(
            4,
        )));
        assert!(matches!(
            supervisor.state(),
            SupervisorState::Running { .. }
        ));
        supervisor.apply(SupervisorEvent::Recovery(RecoverySignal::ConfigGeneration(
            5,
        )));
        assert_eq!(supervisor.state(), SupervisorState::Stopped);
    }
}
