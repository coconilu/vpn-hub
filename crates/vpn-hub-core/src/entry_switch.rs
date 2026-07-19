//! Fail-closed domain model for switching the product entry.
//!
//! This module performs no socket, process, or Windows proxy I/O. Production
//! callers must provide explicit adapters; tests use deterministic fakes.

use std::{collections::BTreeSet, fmt, fs, path::PathBuf};

use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{EntryConfig, normalize_loopback_host};

const CONSENT_LIFETIME_MS: i64 = 120_000;
const SCHEMA_VERSION: u16 = 1;
const NO_PROXY_SNAPSHOT: &str = "proxy-not-requested";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProxyMode {
    Direct,
    Manual,
    AutoConfig,
    Combined,
}

/// Lossless typed state required to restore the `WinINet` per-connection proxy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemProxySnapshot {
    pub mode: WindowsProxyMode,
    pub direct: bool,
    pub manual_proxy: Option<String>,
    pub proxy_bypass: Option<String>,
    pub auto_config_url: Option<String>,
    pub auto_detect: bool,
    /// Must be `None` for the deliberately supported default LAN scope.
    pub connection_name: Option<String>,
}

impl fmt::Debug for SystemProxySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemProxySnapshot")
            .field("mode", &self.mode)
            .field("direct", &self.direct)
            .field("manual_proxy_configured", &self.manual_proxy.is_some())
            .field("proxy_bypass_configured", &self.proxy_bypass.is_some())
            .field("auto_configured", &self.auto_config_url.is_some())
            .field("auto_detect", &self.auto_detect)
            .field("connection_named", &self.connection_name.is_some())
            .finish()
    }
}

impl SystemProxySnapshot {
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(self)
    }

    fn validate(&self) -> Result<(), EntrySwitchError> {
        let mode_matches = match self.mode {
            WindowsProxyMode::Direct => {
                self.manual_proxy.is_none() && self.auto_config_url.is_none()
            }
            WindowsProxyMode::Manual => {
                self.manual_proxy.is_some() && self.auto_config_url.is_none()
            }
            WindowsProxyMode::AutoConfig => {
                self.manual_proxy.is_none() && self.auto_config_url.is_some()
            }
            WindowsProxyMode::Combined => {
                self.manual_proxy.is_some() && self.auto_config_url.is_some()
            }
        };
        if self.connection_name.is_some()
            || !mode_matches
            || self
                .manual_proxy
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 4_096)
            || self
                .proxy_bypass
                .as_ref()
                .is_some_and(|value| value.len() > 16_384)
            || self
                .auto_config_url
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 4_096)
        {
            return Err(EntrySwitchError::UnsupportedProxyScope);
        }
        Ok(())
    }

    fn for_entry(entry: &EntryConfig, original_bypass: Option<String>) -> Self {
        let host = normalize_loopback_host(&entry.host)
            .expect("validated entry")
            .to_string();
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Self {
            mode: WindowsProxyMode::Manual,
            direct: false,
            manual_proxy: Some(format!(
                "http={host}:{};https={host}:{}",
                entry.port, entry.port
            )),
            proxy_bypass: original_bypass,
            auto_config_url: None,
            auto_detect: false,
            connection_name: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyCapability {
    SupportedDefaultLanCurrentUser,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserProxyAuthority {
    /// Opaque, non-secret digest of the interactive user scope.
    pub user_scope_id: String,
    pub generation: u64,
    pub fencing_token: u64,
}

impl UserProxyAuthority {
    fn validate(&self, generation: u64) -> Result<(), EntrySwitchError> {
        let valid_scope = (16..=128).contains(&self.user_scope_id.len())
            && self.user_scope_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            });
        if !valid_scope || self.generation != generation || self.fencing_token == 0 {
            return Err(EntrySwitchError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PortOwnership {
    Free,
    OwnedByVpnHub(OwnedCoreIdentity),
    UnknownOccupied,
    ThirdPartyOccupied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedCoreIdentity {
    pub pid: u32,
    pub creation_identity: u64,
    pub fencing_epoch: u64,
    pub generation: u64,
}

impl OwnedCoreIdentity {
    fn is_valid_for(&self, generation: u64) -> bool {
        self.pid > 0
            && self.creation_identity > 0
            && self.fencing_epoch > 0
            && self.generation == generation
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySwitchRequest {
    pub expected_config_generation: u64,
    pub target: EntryConfig,
    pub apply_system_proxy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySwitchConsent {
    pub schema_version: u16,
    pub config_generation: u64,
    pub current: EntryConfig,
    pub target: EntryConfig,
    pub apply_system_proxy: bool,
    pub proxy_snapshot_fingerprint: String,
    pub plan_fingerprint: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySwitchPlan {
    pub schema_version: u16,
    pub config_generation: u64,
    pub current: EntryConfig,
    pub target: EntryConfig,
    pub apply_system_proxy: bool,
    pub original_proxy: Option<SystemProxySnapshot>,
    pub desired_proxy: Option<SystemProxySnapshot>,
    pub consent: EntrySwitchConsent,
}

impl EntrySwitchPlan {
    /// Verifies every consent-bound field without performing external I/O.
    ///
    /// # Errors
    /// Returns a sanitized validation error for stale, tampered, unsupported,
    /// or internally inconsistent plans.
    pub fn validate(&self, now_ms: i64) -> Result<(), EntrySwitchError> {
        validate_entry(&self.current)?;
        validate_entry(&self.target)?;
        if self.schema_version != SCHEMA_VERSION
            || self.current == self.target
            || self.config_generation == 0
            || self.consent.schema_version != SCHEMA_VERSION
            || self.consent.config_generation != self.config_generation
            || self.consent.current != self.current
            || self.consent.target != self.target
            || self.consent.apply_system_proxy != self.apply_system_proxy
            || self.consent.issued_at_unix_ms > now_ms
            || self.consent.expires_at_unix_ms < now_ms
            || self.consent.expires_at_unix_ms - self.consent.issued_at_unix_ms
                > CONSENT_LIFETIME_MS
            || self.consent.nonce.len() != 32
        {
            return Err(EntrySwitchError::InvalidConsent);
        }
        let proxy_fingerprint = self.original_proxy.as_ref().map_or_else(
            || NO_PROXY_SNAPSHOT.into(),
            SystemProxySnapshot::fingerprint,
        );
        if proxy_fingerprint != self.consent.proxy_snapshot_fingerprint
            || self.consent.plan_fingerprint != plan_fingerprint(self, &self.consent.nonce)
            || self.apply_system_proxy != self.original_proxy.is_some()
            || self.apply_system_proxy != self.desired_proxy.is_some()
        {
            return Err(EntrySwitchError::InvalidConsent);
        }
        if let Some(snapshot) = &self.original_proxy {
            snapshot.validate()?;
        }
        if let Some(snapshot) = &self.desired_proxy {
            snapshot.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySwitchPhase {
    Prepared,
    Staged,
    Verified,
    EntryCommitPending,
    EntryCommitted,
    ProxyApplyPending,
    ProxyApplied,
    RollbackRequired,
    Restored,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySwitchJournalRecord {
    pub schema_version: u16,
    pub phase: EntrySwitchPhase,
    pub plan: EntrySwitchPlan,
    pub staged_core: Option<OwnedCoreIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchVerification {
    pub controller_owned: bool,
    pub enabled_outlets_healthy: bool,
    pub fail_closed_selected: bool,
    pub generation: u64,
}

impl SwitchVerification {
    fn validates(&self, generation: u64) -> bool {
        self.controller_owned
            && self.enabled_outlets_healthy
            && self.fail_closed_selected
            && self.generation == generation
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EntrySwitchError {
    #[error("entry switch target is invalid")]
    InvalidEntry,
    #[error("entry switch consent is invalid, stale, or already consumed")]
    InvalidConsent,
    #[error("entry configuration generation changed")]
    StaleGeneration,
    #[error("target port is occupied and will not be taken over")]
    PortUnavailable,
    #[error("interactive user authority is unavailable")]
    Unauthorized,
    #[error("the Windows proxy scope is unsupported")]
    UnsupportedProxyScope,
    #[error("the Windows proxy changed concurrently")]
    ConcurrentProxyChange,
    #[error("the staged core did not pass fail-closed verification")]
    VerificationFailed,
    #[error("entry switch journal operation failed")]
    Journal,
    #[error("entry switch backend operation failed")]
    Backend,
    #[error("rollback remains pending and must be retried")]
    RecoveryPending,
}

#[allow(clippy::missing_errors_doc)]
pub trait EntryBackend {
    fn config_generation(&self) -> Result<u64, EntrySwitchError>;
    fn current_entry(&self) -> Result<EntryConfig, EntrySwitchError>;
    fn inspect_port(&mut self, target: &EntryConfig) -> Result<PortOwnership, EntrySwitchError>;
    fn stage(&mut self, plan: &EntrySwitchPlan) -> Result<OwnedCoreIdentity, EntrySwitchError>;
    fn verify(&mut self, core: &OwnedCoreIdentity) -> Result<SwitchVerification, EntrySwitchError>;
    fn commit_entry(&mut self, plan: &EntrySwitchPlan) -> Result<(), EntrySwitchError>;
    fn restore_entry(&mut self, entry: &EntryConfig) -> Result<(), EntrySwitchError>;
    fn stop_if_owned(&mut self, core: &OwnedCoreIdentity) -> Result<(), EntrySwitchError>;
}

#[allow(clippy::missing_errors_doc)]
pub trait ProxyBackend {
    fn capability(&self) -> ProxyCapability;
    fn snapshot(&mut self) -> Result<SystemProxySnapshot, EntrySwitchError>;
    /// Returns false rather than overwriting a concurrently changed snapshot.
    fn compare_and_set(
        &mut self,
        expected_fingerprint: &str,
        replacement: &SystemProxySnapshot,
    ) -> Result<bool, EntrySwitchError>;
    fn verify(&mut self, expected: &SystemProxySnapshot) -> Result<bool, EntrySwitchError>;
}

#[allow(clippy::missing_errors_doc)]
pub trait EntrySwitchJournal {
    fn load(&self) -> Result<Option<EntrySwitchJournalRecord>, EntrySwitchError>;
    fn save(&mut self, record: &EntrySwitchJournalRecord) -> Result<(), EntrySwitchError>;
    fn clear(&mut self) -> Result<(), EntrySwitchError>;
    /// Atomically records first use. Returns false for a replay.
    fn consume_consent(&mut self, plan_fingerprint: &str) -> Result<bool, EntrySwitchError>;
}

#[derive(Default)]
pub struct MemoryEntrySwitchJournal {
    record: Option<EntrySwitchJournalRecord>,
    consumed: BTreeSet<String>,
}

impl EntrySwitchJournal for MemoryEntrySwitchJournal {
    fn load(&self) -> Result<Option<EntrySwitchJournalRecord>, EntrySwitchError> {
        Ok(self.record.clone())
    }

    fn save(&mut self, record: &EntrySwitchJournalRecord) -> Result<(), EntrySwitchError> {
        self.record = Some(record.clone());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), EntrySwitchError> {
        self.record = None;
        Ok(())
    }

    fn consume_consent(&mut self, plan_fingerprint: &str) -> Result<bool, EntrySwitchError> {
        Ok(self.consumed.insert(plan_fingerprint.into()))
    }
}

/// Durable, bounded journal. Writes use the core's atomic-save + adjacent
/// last-known-good protocol; cleanup durably flushes the parent directory.
pub struct FileEntrySwitchJournal {
    path: PathBuf,
}

impl FileEntrySwitchJournal {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read_path(path: &std::path::Path) -> Result<EntrySwitchJournalRecord, EntrySwitchError> {
        let bytes = fs::read(path).map_err(|_| EntrySwitchError::Journal)?;
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(EntrySwitchError::Journal);
        }
        let record: EntrySwitchJournalRecord =
            serde_json::from_slice(&bytes).map_err(|_| EntrySwitchError::Journal)?;
        if record.schema_version != SCHEMA_VERSION || record.plan.schema_version != SCHEMA_VERSION {
            return Err(EntrySwitchError::Journal);
        }
        Ok(record)
    }

    fn consumed_path(&self) -> PathBuf {
        self.path.with_extension("consumed.json")
    }
}

impl EntrySwitchJournal for FileEntrySwitchJournal {
    fn load(&self) -> Result<Option<EntrySwitchJournalRecord>, EntrySwitchError> {
        if !self.path.exists() {
            return Ok(None);
        }
        match Self::read_path(&self.path) {
            Ok(record) => Ok(Some(record)),
            Err(_) => Self::read_path(&self.path.with_extension("json.bak")).map(Some),
        }
    }

    fn save(&mut self, record: &EntrySwitchJournalRecord) -> Result<(), EntrySwitchError> {
        let bytes = serde_json::to_vec(record).map_err(|_| EntrySwitchError::Journal)?;
        crate::durable_atomic_save_with_backup(&self.path, &bytes, &crate::SystemDurableFileOps)
            .map_err(|_| EntrySwitchError::Journal)
    }

    fn clear(&mut self) -> Result<(), EntrySwitchError> {
        crate::durable_remove_if_exists(&self.path, &crate::SystemDurableFileOps)
            .map_err(|_| EntrySwitchError::Journal)?;
        crate::durable_remove_if_exists(
            &self.path.with_extension("json.bak"),
            &crate::SystemDurableFileOps,
        )
        .map_err(|_| EntrySwitchError::Journal)
    }

    fn consume_consent(&mut self, plan_fingerprint: &str) -> Result<bool, EntrySwitchError> {
        if plan_fingerprint.len() != 64
            || !plan_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EntrySwitchError::InvalidConsent);
        }
        let path = self.consumed_path();
        let mut consumed: Vec<String> = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| EntrySwitchError::Journal)?;
            if bytes.is_empty() || bytes.len() > 64 * 1024 {
                return Err(EntrySwitchError::Journal);
            }
            serde_json::from_slice(&bytes).map_err(|_| EntrySwitchError::Journal)?
        } else {
            Vec::new()
        };
        if consumed.len() > 256
            || consumed.iter().any(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        {
            return Err(EntrySwitchError::Journal);
        }
        if consumed.iter().any(|value| value == plan_fingerprint) {
            return Ok(false);
        }
        consumed.push(plan_fingerprint.into());
        if consumed.len() > 256 {
            consumed.drain(..consumed.len() - 256);
        }
        let bytes = serde_json::to_vec(&consumed).map_err(|_| EntrySwitchError::Journal)?;
        crate::durable_atomic_save_with_backup(&path, &bytes, &crate::SystemDurableFileOps)
            .map_err(|_| EntrySwitchError::Journal)?;
        Ok(true)
    }
}

pub struct EntrySwitchPlanner;

impl EntrySwitchPlanner {
    /// Produces a short-lived, snapshot-bound switch plan.
    ///
    /// # Errors
    /// Returns a fail-closed error for an invalid entry, stale generation,
    /// occupied port, unsupported proxy scope, or backend failure.
    pub fn preview<E: EntryBackend, P: ProxyBackend>(
        entry: &mut E,
        proxy: &mut P,
        request: &EntrySwitchRequest,
        now_ms: i64,
    ) -> Result<EntrySwitchPlan, EntrySwitchError> {
        validate_entry(&request.target)?;
        let generation = entry.config_generation()?;
        if generation == 0 || generation != request.expected_config_generation {
            return Err(EntrySwitchError::StaleGeneration);
        }
        let current = entry.current_entry()?;
        validate_entry(&current)?;
        if current == request.target {
            return Err(EntrySwitchError::InvalidEntry);
        }
        match entry.inspect_port(&request.target)? {
            PortOwnership::Free => {}
            PortOwnership::OwnedByVpnHub(identity) if identity.is_valid_for(generation) => {}
            PortOwnership::OwnedByVpnHub(_)
            | PortOwnership::UnknownOccupied
            | PortOwnership::ThirdPartyOccupied => {
                return Err(EntrySwitchError::PortUnavailable);
            }
        }
        let original_proxy = if request.apply_system_proxy {
            if proxy.capability() != ProxyCapability::SupportedDefaultLanCurrentUser {
                return Err(EntrySwitchError::UnsupportedProxyScope);
            }
            let snapshot = proxy.snapshot()?;
            snapshot.validate()?;
            Some(snapshot)
        } else {
            None
        };
        let desired_proxy = original_proxy.as_ref().map(|snapshot| {
            SystemProxySnapshot::for_entry(&request.target, snapshot.proxy_bypass.clone())
        });
        let mut nonce_bytes = [0_u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex(&nonce_bytes);
        let mut plan = EntrySwitchPlan {
            schema_version: SCHEMA_VERSION,
            config_generation: generation,
            current: current.clone(),
            target: request.target.clone(),
            apply_system_proxy: request.apply_system_proxy,
            original_proxy,
            desired_proxy,
            consent: EntrySwitchConsent {
                schema_version: SCHEMA_VERSION,
                config_generation: generation,
                current,
                target: request.target.clone(),
                apply_system_proxy: request.apply_system_proxy,
                proxy_snapshot_fingerprint: String::new(),
                plan_fingerprint: String::new(),
                issued_at_unix_ms: now_ms,
                expires_at_unix_ms: now_ms.saturating_add(CONSENT_LIFETIME_MS),
                nonce: nonce.clone(),
            },
        };
        plan.consent.proxy_snapshot_fingerprint = plan.original_proxy.as_ref().map_or_else(
            || NO_PROXY_SNAPSHOT.into(),
            SystemProxySnapshot::fingerprint,
        );
        plan.consent.plan_fingerprint = plan_fingerprint(&plan, &nonce);
        plan.validate(now_ms)?;
        Ok(plan)
    }
}

pub struct EntrySwitchTransaction<'a, E, P, J> {
    entry: &'a mut E,
    proxy: &'a mut P,
    journal: &'a mut J,
    authority: UserProxyAuthority,
}

impl<'a, E, P, J> EntrySwitchTransaction<'a, E, P, J>
where
    E: EntryBackend,
    P: ProxyBackend,
    J: EntrySwitchJournal,
{
    pub fn new(
        entry: &'a mut E,
        proxy: &'a mut P,
        journal: &'a mut J,
        authority: UserProxyAuthority,
    ) -> Self {
        Self {
            entry,
            proxy,
            journal,
            authority,
        }
    }

    /// Applies a valid plan in journaled fail-closed order.
    ///
    /// # Errors
    /// Returns a sanitized validation, authority, concurrency, journal,
    /// verification, backend, or pending-recovery error.
    pub fn apply(&mut self, plan: EntrySwitchPlan, now_ms: i64) -> Result<(), EntrySwitchError> {
        plan.validate(now_ms)?;
        self.authority.validate(plan.config_generation)?;
        if self.journal.load()?.is_some() {
            return Err(EntrySwitchError::RecoveryPending);
        }
        if self.entry.config_generation()? != plan.config_generation
            || self.entry.current_entry()? != plan.current
        {
            return Err(EntrySwitchError::StaleGeneration);
        }
        if !self
            .journal
            .consume_consent(&plan.consent.plan_fingerprint)?
        {
            return Err(EntrySwitchError::InvalidConsent);
        }
        if plan.apply_system_proxy {
            let current = self.proxy.snapshot()?;
            if current.fingerprint() != plan.consent.proxy_snapshot_fingerprint {
                return Err(EntrySwitchError::ConcurrentProxyChange);
            }
        }
        let mut record = EntrySwitchJournalRecord {
            schema_version: SCHEMA_VERSION,
            phase: EntrySwitchPhase::Prepared,
            plan,
            staged_core: None,
        };
        self.journal.save(&record)?;
        let result = self.apply_inner(&mut record);
        if result.is_err() {
            record.phase = EntrySwitchPhase::RollbackRequired;
            let _ = self.journal.save(&record);
            if self.restore_record(&mut record).is_err() {
                return Err(EntrySwitchError::RecoveryPending);
            }
        }
        result
    }

    fn apply_inner(
        &mut self,
        record: &mut EntrySwitchJournalRecord,
    ) -> Result<(), EntrySwitchError> {
        let core = self.entry.stage(&record.plan)?;
        if !core.is_valid_for(record.plan.config_generation) {
            return Err(EntrySwitchError::Backend);
        }
        record.staged_core = Some(core.clone());
        record.phase = EntrySwitchPhase::Staged;
        if let Err(error) = self.journal.save(record) {
            let _ = self.entry.stop_if_owned(&core);
            return Err(error);
        }
        let verification = self.entry.verify(&core)?;
        if !verification.validates(record.plan.config_generation) {
            return Err(EntrySwitchError::VerificationFailed);
        }
        record.phase = EntrySwitchPhase::Verified;
        self.journal.save(record)?;
        record.phase = EntrySwitchPhase::EntryCommitPending;
        self.journal.save(record)?;
        self.entry.commit_entry(&record.plan)?;
        record.phase = EntrySwitchPhase::EntryCommitted;
        self.journal.save(record)?;
        if let (Some(original), Some(desired)) = (
            record.plan.original_proxy.as_ref(),
            record.plan.desired_proxy.as_ref(),
        ) {
            record.phase = EntrySwitchPhase::ProxyApplyPending;
            self.journal.save(record)?;
            if !self
                .proxy
                .compare_and_set(&original.fingerprint(), desired)?
            {
                return Err(EntrySwitchError::ConcurrentProxyChange);
            }
            record.phase = EntrySwitchPhase::ProxyApplied;
            self.journal.save(record)?;
            if !self.proxy.verify(desired)? {
                return Err(EntrySwitchError::VerificationFailed);
            }
        }
        self.journal.clear()?;
        Ok(())
    }

    /// Restores an outstanding transaction, if one exists.
    ///
    /// # Errors
    /// Returns a sanitized authority, concurrency, journal, backend, or
    /// pending-recovery error. The journal is retained on failure.
    pub fn recover(&mut self) -> Result<bool, EntrySwitchError> {
        let Some(mut record) = self.journal.load()? else {
            return Ok(false);
        };
        self.authority.validate(record.plan.config_generation)?;
        self.restore_record(&mut record)?;
        Ok(true)
    }

    fn restore_record(
        &mut self,
        record: &mut EntrySwitchJournalRecord,
    ) -> Result<(), EntrySwitchError> {
        if matches!(
            record.phase,
            EntrySwitchPhase::ProxyApplyPending
                | EntrySwitchPhase::ProxyApplied
                | EntrySwitchPhase::RollbackRequired
        ) && let (Some(original), Some(desired)) = (
            record.plan.original_proxy.as_ref(),
            record.plan.desired_proxy.as_ref(),
        ) {
            let current = self.proxy.snapshot()?;
            if current == *desired {
                if !self
                    .proxy
                    .compare_and_set(&desired.fingerprint(), original)?
                    || !self.proxy.verify(original)?
                {
                    return Err(EntrySwitchError::RecoveryPending);
                }
            } else if current != *original {
                return Err(EntrySwitchError::ConcurrentProxyChange);
            }
        }
        if matches!(
            record.phase,
            EntrySwitchPhase::EntryCommitPending
                | EntrySwitchPhase::EntryCommitted
                | EntrySwitchPhase::ProxyApplyPending
                | EntrySwitchPhase::ProxyApplied
                | EntrySwitchPhase::RollbackRequired
        ) {
            self.entry.restore_entry(&record.plan.current)?;
        }
        if let Some(core) = &record.staged_core {
            self.entry.stop_if_owned(core)?;
        }
        record.phase = EntrySwitchPhase::Restored;
        self.journal.save(record)?;
        self.journal.clear()?;
        Ok(())
    }
}

fn validate_entry(entry: &EntryConfig) -> Result<(), EntrySwitchError> {
    if entry.port == 0 || normalize_loopback_host(&entry.host).is_none() {
        return Err(EntrySwitchError::InvalidEntry);
    }
    Ok(())
}

fn plan_fingerprint(plan: &EntrySwitchPlan, nonce: &str) -> String {
    #[derive(Serialize)]
    struct Sealed<'a> {
        schema_version: u16,
        config_generation: u64,
        current: &'a EntryConfig,
        target: &'a EntryConfig,
        apply_system_proxy: bool,
        proxy_snapshot_fingerprint: &'a str,
        issued_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        nonce: &'a str,
    }
    fingerprint(&Sealed {
        schema_version: plan.schema_version,
        config_generation: plan.config_generation,
        current: &plan.current,
        target: &plan.target,
        apply_system_proxy: plan.apply_system_proxy,
        proxy_snapshot_fingerprint: &plan.consent.proxy_snapshot_fingerprint,
        issued_at_unix_ms: plan.consent.issued_at_unix_ms,
        expires_at_unix_ms: plan.consent.expires_at_unix_ms,
        nonce,
    })
}

fn fingerprint<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializable entry switch value");
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(char::from(DIGITS[usize::from(byte >> 4)]));
        rendered.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeEntry {
        generation: u64,
        current: EntryConfig,
        ownership: Option<PortOwnership>,
        verification: Option<SwitchVerification>,
        events: Vec<&'static str>,
    }

    impl FakeEntry {
        fn ready() -> Self {
            Self {
                generation: 7,
                current: EntryConfig {
                    host: "127.0.0.9".into(),
                    port: 41_001,
                },
                ownership: Some(PortOwnership::Free),
                verification: Some(SwitchVerification {
                    controller_owned: true,
                    enabled_outlets_healthy: true,
                    fail_closed_selected: true,
                    generation: 7,
                }),
                events: Vec::new(),
            }
        }
    }

    impl EntryBackend for FakeEntry {
        fn config_generation(&self) -> Result<u64, EntrySwitchError> {
            Ok(self.generation)
        }
        fn current_entry(&self) -> Result<EntryConfig, EntrySwitchError> {
            Ok(self.current.clone())
        }
        fn inspect_port(&mut self, _: &EntryConfig) -> Result<PortOwnership, EntrySwitchError> {
            self.events.push("inspect");
            Ok(self
                .ownership
                .clone()
                .unwrap_or(PortOwnership::UnknownOccupied))
        }
        fn stage(&mut self, _: &EntrySwitchPlan) -> Result<OwnedCoreIdentity, EntrySwitchError> {
            self.events.push("stage");
            Ok(OwnedCoreIdentity {
                pid: 42,
                creation_identity: 88,
                fencing_epoch: 3,
                generation: self.generation,
            })
        }
        fn verify(
            &mut self,
            _: &OwnedCoreIdentity,
        ) -> Result<SwitchVerification, EntrySwitchError> {
            self.events.push("verify");
            Ok(self.verification.clone().unwrap())
        }
        fn commit_entry(&mut self, plan: &EntrySwitchPlan) -> Result<(), EntrySwitchError> {
            self.events.push("commit_entry");
            self.current = plan.target.clone();
            Ok(())
        }
        fn restore_entry(&mut self, entry: &EntryConfig) -> Result<(), EntrySwitchError> {
            self.events.push("restore_entry");
            self.current = entry.clone();
            Ok(())
        }
        fn stop_if_owned(&mut self, _: &OwnedCoreIdentity) -> Result<(), EntrySwitchError> {
            self.events.push("stop_owned");
            Ok(())
        }
    }

    struct FakeProxy {
        capability: ProxyCapability,
        current: SystemProxySnapshot,
        calls: usize,
        events: Vec<&'static str>,
    }

    impl FakeProxy {
        fn ready() -> Self {
            Self {
                capability: ProxyCapability::SupportedDefaultLanCurrentUser,
                current: SystemProxySnapshot {
                    mode: WindowsProxyMode::Combined,
                    direct: true,
                    manual_proxy: Some("http=old.invalid:8080".into()),
                    proxy_bypass: Some("<local>;example.invalid".into()),
                    auto_config_url: Some("https://pac.invalid/proxy.pac".into()),
                    auto_detect: true,
                    connection_name: None,
                },
                calls: 0,
                events: Vec::new(),
            }
        }
    }

    impl ProxyBackend for FakeProxy {
        fn capability(&self) -> ProxyCapability {
            self.capability
        }
        fn snapshot(&mut self) -> Result<SystemProxySnapshot, EntrySwitchError> {
            self.calls += 1;
            self.events.push("snapshot");
            Ok(self.current.clone())
        }
        fn compare_and_set(
            &mut self,
            expected: &str,
            replacement: &SystemProxySnapshot,
        ) -> Result<bool, EntrySwitchError> {
            self.calls += 1;
            self.events.push("cas");
            if self.current.fingerprint() != expected {
                return Ok(false);
            }
            self.current = replacement.clone();
            Ok(true)
        }
        fn verify(&mut self, expected: &SystemProxySnapshot) -> Result<bool, EntrySwitchError> {
            self.calls += 1;
            self.events.push("verify_proxy");
            Ok(&self.current == expected)
        }
    }

    fn request(apply_system_proxy: bool) -> EntrySwitchRequest {
        EntrySwitchRequest {
            expected_config_generation: 7,
            target: EntryConfig {
                host: "127.0.0.8".into(),
                port: 41_002,
            },
            apply_system_proxy,
        }
    }

    fn authority() -> UserProxyAuthority {
        UserProxyAuthority {
            user_scope_id: "0123456789abcdef".into(),
            generation: 7,
            fencing_token: 9,
        }
    }

    #[test]
    fn opt_out_never_calls_proxy_backend() {
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(false), 1_000).unwrap();
        assert_eq!(proxy.calls, 0);
        let mut journal = MemoryEntrySwitchJournal::default();
        EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
            .apply(plan, 1_001)
            .unwrap();
        assert_eq!(proxy.calls, 0);
        assert_eq!(entry.events, ["inspect", "stage", "verify", "commit_entry"]);
    }

    #[test]
    fn proxy_apply_occurs_only_after_fail_closed_verification_and_entry_commit() {
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 1_000).unwrap();
        let original = plan.original_proxy.clone().unwrap();
        let mut journal = MemoryEntrySwitchJournal::default();
        EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
            .apply(plan, 1_001)
            .unwrap();
        assert_eq!(entry.current.port, 41_002);
        assert_ne!(proxy.current, original);
        assert_eq!(entry.events, ["inspect", "stage", "verify", "commit_entry"]);
        assert_eq!(
            proxy.events,
            ["snapshot", "snapshot", "cas", "verify_proxy"]
        );
    }

    #[test]
    fn unknown_and_third_party_occupants_fail_closed_without_staging_or_stop() {
        for ownership in [
            PortOwnership::UnknownOccupied,
            PortOwnership::ThirdPartyOccupied,
        ] {
            let mut entry = FakeEntry::ready();
            entry.ownership = Some(ownership);
            let mut proxy = FakeProxy::ready();
            assert_eq!(
                EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(false), 1_000),
                Err(EntrySwitchError::PortUnavailable)
            );
            assert_eq!(entry.events, ["inspect"]);
        }
    }

    #[test]
    fn consent_seals_generation_snapshot_expiry_and_is_one_shot() {
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 1_000).unwrap();
        let mut expired = plan.clone();
        assert_eq!(
            expired.validate(121_001),
            Err(EntrySwitchError::InvalidConsent)
        );
        expired = plan.clone();
        expired.target.port += 1;
        assert_eq!(
            expired.validate(1_001),
            Err(EntrySwitchError::InvalidConsent)
        );

        let mut journal = MemoryEntrySwitchJournal::default();
        EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
            .apply(plan.clone(), 1_001)
            .unwrap();
        assert_eq!(
            EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                .apply(plan, 1_002),
            Err(EntrySwitchError::StaleGeneration)
        );
    }

    #[test]
    fn failed_verification_restores_entry_and_never_applies_proxy() {
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 1_000).unwrap();
        entry.verification.as_mut().unwrap().fail_closed_selected = false;
        let original_entry = entry.current.clone();
        let original_proxy = proxy.current.clone();
        let mut journal = MemoryEntrySwitchJournal::default();
        assert_eq!(
            EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                .apply(plan.clone(), 1_001),
            Err(EntrySwitchError::VerificationFailed)
        );
        assert_eq!(entry.current, original_entry);
        assert_eq!(proxy.current, original_proxy);
        assert!(entry.events.ends_with(&["stop_owned"]));
        assert_eq!(
            EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                .apply(plan, 1_002),
            Err(EntrySwitchError::InvalidConsent),
            "a failed attempt still consumes its consent"
        );
    }

    #[test]
    fn recovery_uses_proxy_cas_and_never_overwrites_manual_user_change() {
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 1_000).unwrap();
        let desired = plan.desired_proxy.clone().unwrap();
        let core = OwnedCoreIdentity {
            pid: 42,
            creation_identity: 88,
            fencing_epoch: 3,
            generation: 7,
        };
        entry.current = plan.target.clone();
        proxy.current = desired;
        let mut journal = MemoryEntrySwitchJournal {
            record: Some(EntrySwitchJournalRecord {
                schema_version: SCHEMA_VERSION,
                phase: EntrySwitchPhase::ProxyApplied,
                plan: plan.clone(),
                staged_core: Some(core),
            }),
            ..MemoryEntrySwitchJournal::default()
        };
        EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
            .recover()
            .unwrap();
        assert_eq!(entry.current, plan.current);
        assert_eq!(proxy.current, plan.original_proxy.unwrap());

        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 2_000).unwrap();
        proxy.current = SystemProxySnapshot {
            manual_proxy: Some("user-change.invalid:9000".into()),
            ..proxy.current.clone()
        };
        let mut journal = MemoryEntrySwitchJournal {
            record: Some(EntrySwitchJournalRecord {
                schema_version: SCHEMA_VERSION,
                phase: EntrySwitchPhase::ProxyApplied,
                plan,
                staged_core: None,
            }),
            ..MemoryEntrySwitchJournal::default()
        };
        assert_eq!(
            EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                .recover(),
            Err(EntrySwitchError::ConcurrentProxyChange)
        );
        assert!(journal.load().unwrap().is_some());
    }

    #[test]
    fn pending_intents_recover_whether_or_not_each_effect_happened() {
        for entry_effect_happened in [false, true] {
            let mut entry = FakeEntry::ready();
            let mut proxy = FakeProxy::ready();
            let plan = EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(false), 3_000)
                .unwrap();
            if entry_effect_happened {
                entry.current = plan.target.clone();
            }
            let core = OwnedCoreIdentity {
                pid: 42,
                creation_identity: 88,
                fencing_epoch: 3,
                generation: 7,
            };
            let mut journal = MemoryEntrySwitchJournal {
                record: Some(EntrySwitchJournalRecord {
                    schema_version: SCHEMA_VERSION,
                    phase: EntrySwitchPhase::EntryCommitPending,
                    plan: plan.clone(),
                    staged_core: Some(core),
                }),
                ..MemoryEntrySwitchJournal::default()
            };
            EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                .recover()
                .unwrap();
            assert_eq!(entry.current, plan.current);
            assert!(journal.load().unwrap().is_none());
        }

        for proxy_effect_happened in [false, true] {
            let mut entry = FakeEntry::ready();
            let mut proxy = FakeProxy::ready();
            let plan =
                EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 4_000).unwrap();
            entry.current = plan.target.clone();
            if proxy_effect_happened {
                proxy.current = plan.desired_proxy.clone().unwrap();
            }
            let mut journal = MemoryEntrySwitchJournal {
                record: Some(EntrySwitchJournalRecord {
                    schema_version: SCHEMA_VERSION,
                    phase: EntrySwitchPhase::ProxyApplyPending,
                    plan: plan.clone(),
                    staged_core: None,
                }),
                ..MemoryEntrySwitchJournal::default()
            };
            EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                .recover()
                .unwrap();
            assert_eq!(entry.current, plan.current);
            assert_eq!(proxy.current, plan.original_proxy.unwrap());
            assert!(journal.load().unwrap().is_none());
        }
    }

    struct PhaseFailJournal {
        inner: MemoryEntrySwitchJournal,
        fail_once_at: EntrySwitchPhase,
        failed: bool,
    }

    impl EntrySwitchJournal for PhaseFailJournal {
        fn load(&self) -> Result<Option<EntrySwitchJournalRecord>, EntrySwitchError> {
            self.inner.load()
        }
        fn save(&mut self, record: &EntrySwitchJournalRecord) -> Result<(), EntrySwitchError> {
            if !self.failed && record.phase == self.fail_once_at {
                self.failed = true;
                return Err(EntrySwitchError::Journal);
            }
            self.inner.save(record)
        }
        fn clear(&mut self) -> Result<(), EntrySwitchError> {
            self.inner.clear()
        }
        fn consume_consent(&mut self, plan_fingerprint: &str) -> Result<bool, EntrySwitchError> {
            self.inner.consume_consent(plan_fingerprint)
        }
    }

    #[test]
    fn effect_followed_by_journal_failure_is_observed_and_rolled_back() {
        for failed_phase in [
            EntrySwitchPhase::EntryCommitted,
            EntrySwitchPhase::ProxyApplied,
        ] {
            let mut entry = FakeEntry::ready();
            let original_entry = entry.current.clone();
            let mut proxy = FakeProxy::ready();
            let original_proxy = proxy.current.clone();
            let plan =
                EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 5_000).unwrap();
            let mut journal = PhaseFailJournal {
                inner: MemoryEntrySwitchJournal::default(),
                fail_once_at: failed_phase,
                failed: false,
            };
            assert_eq!(
                EntrySwitchTransaction::new(&mut entry, &mut proxy, &mut journal, authority())
                    .apply(plan, 5_001),
                Err(EntrySwitchError::Journal)
            );
            assert_eq!(entry.current, original_entry);
            assert_eq!(proxy.current, original_proxy);
            assert!(journal.load().unwrap().is_none());
        }
    }

    #[test]
    fn serialized_contract_has_no_process_arguments_or_business_targets() {
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(true), 1_000).unwrap();
        let fields = serde_json::to_value(plan).unwrap();
        let keys = collect_keys(&fields);
        for forbidden in ["command_line", "arguments", "probe_target", "secret", "url"] {
            assert!(!keys.contains(forbidden), "forbidden field: {forbidden}");
        }
    }

    #[test]
    fn file_journal_is_durable_bounded_and_recovers_from_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("entry-switch.json");
        let mut entry = FakeEntry::ready();
        let mut proxy = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut entry, &mut proxy, &request(false), 1_000).unwrap();
        let first = EntrySwitchJournalRecord {
            schema_version: SCHEMA_VERSION,
            phase: EntrySwitchPhase::Prepared,
            plan: plan.clone(),
            staged_core: None,
        };
        let second = EntrySwitchJournalRecord {
            phase: EntrySwitchPhase::Verified,
            ..first.clone()
        };
        let mut journal = FileEntrySwitchJournal::new(path.clone());
        journal.save(&first).unwrap();
        journal.save(&second).unwrap();
        assert_eq!(journal.load().unwrap(), Some(second.clone()));
        fs::write(&path, b"corrupt").unwrap();
        assert_eq!(journal.load().unwrap(), Some(second));
        let fingerprint = first.plan.consent.plan_fingerprint.as_str();
        assert!(journal.consume_consent(fingerprint).unwrap());
        assert!(!journal.consume_consent(fingerprint).unwrap());
        journal.clear().unwrap();
        assert_eq!(journal.load().unwrap(), None);
        assert!(!journal.consume_consent(fingerprint).unwrap());
    }

    fn collect_keys(value: &serde_json::Value) -> BTreeSet<&str> {
        fn visit<'a>(value: &'a serde_json::Value, keys: &mut BTreeSet<&'a str>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        keys.insert(key);
                        visit(value, keys);
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        visit(value, keys);
                    }
                }
                _ => {}
            }
        }
        let mut keys = BTreeSet::new();
        visit(value, &mut keys);
        keys
    }
}
