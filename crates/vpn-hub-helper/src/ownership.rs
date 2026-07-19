use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedProcessIdentity {
    pub pid: u32,
    pub creation_identity: u64,
    pub executable_sha256: String,
    pub fencing_token: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessObservation {
    pub pid: u32,
    pub creation_identity: u64,
    pub executable_sha256: String,
}

impl OwnedProcessIdentity {
    #[must_use]
    pub fn matches(&self, observation: &ProcessObservation, active_fencing_token: u64) -> bool {
        self.fencing_token == active_fencing_token
            && self.pid == observation.pid
            && self.creation_identity == observation.creation_identity
            && self.executable_sha256 == observation.executable_sha256
    }
}

pub trait ChildControl {
    fn identity(&self) -> ProcessObservation;
    fn terminate_owned_job(&mut self) -> Result<(), String>;
    fn wait(&mut self) -> Result<(), String>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnershipError {
    #[error("process identity does not match the owned child")]
    IdentityMismatch,
    #[error("owned job termination failed")]
    TerminationFailed,
    #[error("owned child wait failed")]
    WaitFailed,
}

/// Owns the exact child handle. On Windows the production adapter must place
/// that child in a private Job Object configured with kill-on-close. This guard
/// has no API for PID lookup, process-name lookup, port ownership, or adoption.
pub struct OwnedChildGuard<C: ChildControl> {
    expected: OwnedProcessIdentity,
    child: C,
}

impl<C: ChildControl> OwnedChildGuard<C> {
    pub fn new(
        expected: OwnedProcessIdentity,
        child: C,
        active_fencing_token: u64,
    ) -> Result<Self, OwnershipError> {
        if !expected.matches(&child.identity(), active_fencing_token) {
            return Err(OwnershipError::IdentityMismatch);
        }
        Ok(Self { expected, child })
    }

    #[must_use]
    pub const fn identity(&self) -> &OwnedProcessIdentity {
        &self.expected
    }

    pub fn stop(mut self, active_fencing_token: u64) -> Result<(), OwnershipError> {
        if !self
            .expected
            .matches(&self.child.identity(), active_fencing_token)
        {
            return Err(OwnershipError::IdentityMismatch);
        }
        self.child
            .terminate_owned_job()
            .map_err(|_| OwnershipError::TerminationFailed)?;
        self.child.wait().map_err(|_| OwnershipError::WaitFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct FakeChild {
        identity: ProcessObservation,
        terminated: Arc<AtomicBool>,
        waited: Arc<AtomicBool>,
    }

    impl ChildControl for FakeChild {
        fn identity(&self) -> ProcessObservation {
            self.identity.clone()
        }

        fn terminate_owned_job(&mut self) -> Result<(), String> {
            self.terminated.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn wait(&mut self) -> Result<(), String> {
            self.waited.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn identity(pid: u32, creation_identity: u64, fencing_token: u64) -> OwnedProcessIdentity {
        OwnedProcessIdentity {
            pid,
            creation_identity,
            executable_sha256: "a".repeat(64),
            fencing_token,
        }
    }

    #[test]
    fn exact_owned_child_is_killed_and_waited() {
        let terminated = Arc::new(AtomicBool::new(false));
        let waited = Arc::new(AtomicBool::new(false));
        let expected = identity(41_001, 77, 9);
        let child = FakeChild {
            identity: ProcessObservation {
                pid: 41_001,
                creation_identity: 77,
                executable_sha256: "a".repeat(64),
            },
            terminated: Arc::clone(&terminated),
            waited: Arc::clone(&waited),
        };
        OwnedChildGuard::new(expected, child, 9)
            .unwrap()
            .stop(9)
            .unwrap();
        assert!(terminated.load(Ordering::SeqCst));
        assert!(waited.load(Ordering::SeqCst));
    }

    #[test]
    fn unknown_pid_or_reused_pid_is_never_touched() {
        let terminated = Arc::new(AtomicBool::new(false));
        let expected = identity(41_001, 77, 9);
        let unknown = FakeChild {
            identity: ProcessObservation {
                pid: 41_001,
                creation_identity: 78,
                executable_sha256: "a".repeat(64),
            },
            terminated: Arc::clone(&terminated),
            waited: Arc::new(AtomicBool::new(false)),
        };
        assert!(matches!(
            OwnedChildGuard::new(expected, unknown, 9),
            Err(OwnershipError::IdentityMismatch)
        ));
        assert!(!terminated.load(Ordering::SeqCst));
    }
}
