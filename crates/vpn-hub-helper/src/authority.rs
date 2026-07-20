use thiserror::Error;

use std::{
    fs::{File, OpenOptions},
    io::{Seek, Write},
    path::Path,
};

use fs2::FileExt as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisorAuthority {
    Desktop,
    Helper,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityLease {
    pub install_id: String,
    pub authority: SupervisorAuthority,
    pub fencing_token: u64,
    pub generation: u64,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("supervisor authority is already held")]
    AlreadyHeld,
    #[error("supervisor lease is stale")]
    StaleLease,
    #[error("supervisor generation moved backwards")]
    StaleGeneration,
    #[error("supervisor lease is invalid")]
    InvalidLease,
    #[error("cross-process supervisor authority is already held or unavailable")]
    CrossProcessLease,
}

pub struct AuthorityFileGuard {
    file: File,
}

impl AuthorityFileGuard {
    pub fn acquire(
        path: &Path,
        authority: SupervisorAuthority,
        generation: u64,
    ) -> Result<Self, AuthorityError> {
        Self::acquire_inner(path, authority, generation, true)
    }

    pub fn acquire_existing(
        path: &Path,
        authority: SupervisorAuthority,
        generation: u64,
    ) -> Result<Self, AuthorityError> {
        Self::acquire_inner(path, authority, generation, false)
    }

    /// Opens the installer-provisioned entry-switch authority lease through a
    /// no-follow, containment- and ACL-validated handle, then locks and writes
    /// that same handle.
    ///
    /// # Errors
    /// Returns an authority error before mutation if any validation or lock fails.
    #[cfg(target_os = "windows")]
    pub fn acquire_protected_entry_switch(
        installation: &crate::InstallationReference,
        interactive_user_sid: &str,
        authority: SupervisorAuthority,
        generation: u64,
    ) -> Result<Self, AuthorityError> {
        let (file, _) = vpn_hub_windows_security::open_current_user_mutable_file(
            installation.program_data_root(),
            &installation.entry_switch_authority_path(),
            interactive_user_sid,
        )
        .map_err(|_| AuthorityError::CrossProcessLease)?;
        Self::acquire_file(file, authority, generation)
    }

    /// Acquires the shared desktop/LocalService authority from the exact
    /// validated `ProgramData` handle without reopening it by path.
    ///
    /// # Errors
    /// Returns an authority error before mutation if validation or locking fails.
    #[cfg(target_os = "windows")]
    pub fn acquire_protected_shared(
        installation: &crate::InstallationReference,
        interactive_user_sid: &str,
        authority: SupervisorAuthority,
        generation: u64,
    ) -> Result<Self, AuthorityError> {
        let (file, _) = vpn_hub_windows_security::open_shared_authority_file(
            installation.program_data_root(),
            &installation.authority_path(),
            interactive_user_sid,
        )
        .map_err(|_| AuthorityError::CrossProcessLease)?;
        Self::acquire_file(file, authority, generation)
    }

    /// Acquires a helper's shared authority when its validated root is already
    /// known from installer-owned startup metadata.
    ///
    /// # Errors
    /// Returns an authority error before mutation if validation or locking fails.
    #[cfg(target_os = "windows")]
    pub fn acquire_protected_shared_root(
        root: &Path,
        interactive_user_sid: &str,
        authority: SupervisorAuthority,
        generation: u64,
    ) -> Result<Self, AuthorityError> {
        let (file, _) = vpn_hub_windows_security::open_shared_authority_file(
            root,
            &root.join("authority.lease"),
            interactive_user_sid,
        )
        .map_err(|_| AuthorityError::CrossProcessLease)?;
        Self::acquire_file(file, authority, generation)
    }

    fn acquire_inner(
        path: &Path,
        authority: SupervisorAuthority,
        generation: u64,
        create: bool,
    ) -> Result<Self, AuthorityError> {
        let file = OpenOptions::new()
            .create(create)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| AuthorityError::CrossProcessLease)?;
        Self::acquire_file(file, authority, generation)
    }

    fn acquire_file(
        mut file: File,
        authority: SupervisorAuthority,
        generation: u64,
    ) -> Result<Self, AuthorityError> {
        file.try_lock_exclusive()
            .map_err(|_| AuthorityError::AlreadyHeld)?;
        file.set_len(0)
            .and_then(|()| file.rewind())
            .and_then(|()| {
                write!(
                    file,
                    "authority={}\ngeneration={}\n",
                    match authority {
                        SupervisorAuthority::Desktop => "desktop",
                        SupervisorAuthority::Helper => "helper",
                    },
                    generation
                )
            })
            .and_then(|()| file.sync_data())
            .map_err(|_| AuthorityError::CrossProcessLease)?;
        Ok(Self { file })
    }
}

impl Drop for AuthorityFileGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Default)]
pub struct AuthorityRegistry {
    active: Option<AuthorityLease>,
    next_fencing_token: u64,
}

impl AuthorityRegistry {
    pub fn acquire(
        &mut self,
        install_id: &str,
        authority: SupervisorAuthority,
        generation: u64,
        now_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<AuthorityLease, AuthorityError> {
        if install_id.is_empty() || generation == 0 || lease_duration_ms <= 0 {
            return Err(AuthorityError::InvalidLease);
        }
        if self
            .active
            .as_ref()
            .is_some_and(|lease| lease.expires_at_unix_ms >= now_ms)
        {
            return Err(AuthorityError::AlreadyHeld);
        }
        self.next_fencing_token = self.next_fencing_token.saturating_add(1).max(1);
        let lease = AuthorityLease {
            install_id: install_id.to_owned(),
            authority,
            fencing_token: self.next_fencing_token,
            generation,
            expires_at_unix_ms: now_ms.saturating_add(lease_duration_ms),
        };
        self.active = Some(lease.clone());
        Ok(lease)
    }

    pub fn renew(
        &mut self,
        lease: &AuthorityLease,
        generation: u64,
        now_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<AuthorityLease, AuthorityError> {
        self.validate(lease, now_ms)?;
        if generation < lease.generation {
            return Err(AuthorityError::StaleGeneration);
        }
        if lease_duration_ms <= 0 {
            return Err(AuthorityError::InvalidLease);
        }
        let renewed = AuthorityLease {
            generation,
            expires_at_unix_ms: now_ms.saturating_add(lease_duration_ms),
            ..lease.clone()
        };
        self.active = Some(renewed.clone());
        Ok(renewed)
    }

    pub fn release(&mut self, lease: &AuthorityLease, now_ms: i64) -> Result<(), AuthorityError> {
        self.validate(lease, now_ms)?;
        self.active = None;
        Ok(())
    }

    pub fn validate(&self, lease: &AuthorityLease, now_ms: i64) -> Result<(), AuthorityError> {
        let Some(active) = &self.active else {
            return Err(AuthorityError::StaleLease);
        };
        if active.install_id != lease.install_id
            || active.authority != lease.authority
            || active.fencing_token != lease.fencing_token
            || active.generation != lease.generation
            || active.expires_at_unix_ms != lease.expires_at_unix_ms
            || active.expires_at_unix_ms < now_ms
        {
            return Err(AuthorityError::StaleLease);
        }
        Ok(())
    }

    #[must_use]
    pub fn active(&self, now_ms: i64) -> Option<&AuthorityLease> {
        self.active
            .as_ref()
            .filter(|lease| lease.expires_at_unix_ms >= now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_and_helper_cannot_supervise_together() {
        let mut registry = AuthorityRegistry::default();
        let desktop = registry
            .acquire("install-a", SupervisorAuthority::Desktop, 1, 1_000, 500)
            .unwrap();
        assert_eq!(
            registry.acquire("install-a", SupervisorAuthority::Helper, 1, 1_100, 500),
            Err(AuthorityError::AlreadyHeld)
        );
        registry.release(&desktop, 1_200).unwrap();
        let helper = registry
            .acquire("install-a", SupervisorAuthority::Helper, 1, 1_200, 500)
            .unwrap();
        assert!(helper.fencing_token > desktop.fencing_token);
        assert_eq!(
            registry.validate(&desktop, 1_200),
            Err(AuthorityError::StaleLease)
        );
    }

    #[test]
    fn expired_and_old_generation_leases_are_fenced() {
        let mut registry = AuthorityRegistry::default();
        let lease = registry
            .acquire("install-a", SupervisorAuthority::Helper, 3, 1_000, 100)
            .unwrap();
        assert_eq!(
            registry.validate(&lease, 1_101),
            Err(AuthorityError::StaleLease)
        );

        let current = registry
            .acquire("install-a", SupervisorAuthority::Helper, 4, 1_101, 100)
            .unwrap();
        assert_eq!(
            registry.renew(&current, 3, 1_102, 100),
            Err(AuthorityError::StaleGeneration)
        );
    }

    #[test]
    fn cross_process_guard_prevents_dual_supervisor() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.lease");
        let helper = AuthorityFileGuard::acquire(&path, SupervisorAuthority::Helper, 1).unwrap();
        assert!(matches!(
            AuthorityFileGuard::acquire(&path, SupervisorAuthority::Desktop, 1),
            Err(AuthorityError::AlreadyHeld)
        ));
        drop(helper);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "authority=helper\ngeneration=1\n",
            "failed lock must not truncate or rewrite"
        );
        assert!(AuthorityFileGuard::acquire(&path, SupervisorAuthority::Desktop, 1).is_ok());
    }
}
