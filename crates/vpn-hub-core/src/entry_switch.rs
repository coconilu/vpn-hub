//! Fail-closed domain model for switching the product entry.
//!
//! This module performs no socket, process, filesystem, clock, or Windows
//! proxy I/O. Production callers must supply guarded adapters. The public
//! audit DTO deliberately excludes confidential proxy recovery material.

use std::{
    collections::BTreeMap,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{EntryConfig, normalize_loopback_host};

type HmacSha256 = Hmac<Sha256>;
const CONSENT_LIFETIME_MS: i64 = 120_000;
const SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowsProxyMode {
    Direct,
    Manual,
    AutoConfig,
    Combined,
}

/// Confidential, lossless state needed to restore `WinINet`. It intentionally
/// does not implement `Serialize`; only an authenticated confidential journal
/// adapter may encode it through explicit field access.
#[derive(Clone, PartialEq, Eq)]
pub struct SystemProxySnapshot {
    pub mode: WindowsProxyMode,
    pub direct: bool,
    pub manual_proxy: Option<String>,
    pub proxy_bypass: Option<String>,
    pub auto_config_url: Option<String>,
    pub auto_detect: bool,
    pub connection_name: Option<String>,
}

impl fmt::Debug for SystemProxySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemProxySnapshot")
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
        hex(&Sha256::digest(proxy_bytes(self)))
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
                .is_some_and(|v| v.is_empty() || v.len() > 4_096)
            || self.proxy_bypass.as_ref().is_some_and(|v| v.len() > 16_384)
            || self
                .auto_config_url
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 4_096)
        {
            return Err(EntrySwitchError::UnsupportedProxyScope);
        }
        Ok(())
    }

    fn for_entry(entry: &EntryConfig, bypass: Option<String>) -> Self {
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
            proxy_bypass: bypass,
            auto_config_url: None,
            auto_detect: false,
            connection_name: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyCapability {
    SupportedDefaultLanCurrentUser,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySwitchContext {
    pub install_id: String,
    pub user_scope_id: String,
}

impl EntrySwitchContext {
    fn validate(&self) -> Result<(), EntrySwitchError> {
        fn valid(value: &str) -> bool {
            (16..=128).contains(&value.len())
                && value.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')
                })
        }
        if !valid(&self.install_id) || !valid(&self.user_scope_id) {
            return Err(EntrySwitchError::Unauthorized);
        }
        Ok(())
    }
}

/// HMAC key loaded from the current-user protected store. No Debug, Clone, or
/// serialization implementation exists, and its bytes are zeroized on drop.
pub struct ConsentKey(Zeroizing<[u8; 32]>);

impl ConsentKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }
    /// Constructs a key only after a platform adapter has unprotected it.
    #[must_use]
    pub fn from_protected_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

pub trait TrustedClock {
    /// # Errors
    /// Returns an error when a trustworthy bounded Unix timestamp is unavailable.
    fn now_unix_ms(&self) -> Result<i64, EntrySwitchError>;
}
pub struct SystemTrustedClock;
impl TrustedClock for SystemTrustedClock {
    fn now_unix_ms(&self) -> Result<i64, EntrySwitchError> {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EntrySwitchError::InvalidConsent)?
            .as_millis();
        i64::try_from(value).map_err(|_| EntrySwitchError::InvalidConsent)
    }
}

/// Must represent an OS lock held continuously for the transaction lifetime.
pub trait EntrySwitchAuthorityGuard {
    fn context(&self) -> &EntrySwitchContext;
    fn generation(&self) -> u64;
    /// # Errors
    /// Returns `Unauthorized` if the OS-backed exclusive guard is no longer held.
    fn ensure_held(&self) -> Result<(), EntrySwitchError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortOwnership {
    Free,
    OwnedByVpnHub(OwnedCoreIdentity),
    UnknownOccupied,
    ThirdPartyOccupied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageDeclaration {
    pub transaction_id: String,
    pub ownership_token: String,
    pub generation: u64,
}

impl StageDeclaration {
    fn valid(&self, generation: u64) -> bool {
        self.generation == generation
            && valid_hex(&self.transaction_id, 32)
            && valid_hex(&self.ownership_token, 64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedCoreIdentity {
    pub pid: u32,
    pub creation_identity: u64,
    pub generation: u64,
    pub transaction_id: String,
    pub ownership_token: String,
}

impl OwnedCoreIdentity {
    fn matches(&self, declaration: &StageDeclaration) -> bool {
        self.pid > 0
            && self.creation_identity > 0
            && self.generation == declaration.generation
            && self.transaction_id == declaration.transaction_id
            && self.ownership_token == declaration.ownership_token
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySwitchRequest {
    pub expected_config_generation: u64,
    pub target: EntryConfig,
    pub apply_system_proxy: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EntrySwitchConsent {
    token: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl fmt::Debug for EntrySwitchConsent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySwitchConsent")
            .field("token_id", &self.token_id())
            .field("issued_at_unix_ms", &self.issued_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}

impl EntrySwitchConsent {
    fn token_id(&self) -> Option<&str> {
        self.token.split_once('.').map(|v| v.0)
    }
    #[cfg(test)]
    fn replace_token(&mut self, value: String) {
        self.token = value;
    }
}

/// Confidential plan; it deliberately has no generic serialization support.
#[derive(Clone, PartialEq, Eq)]
pub struct EntrySwitchPlan {
    pub schema_version: u16,
    pub context: EntrySwitchContext,
    pub config_generation: u64,
    pub current: EntryConfig,
    pub target: EntryConfig,
    pub apply_system_proxy: bool,
    pub original_proxy: Option<SystemProxySnapshot>,
    pub desired_proxy: Option<SystemProxySnapshot>,
    pub consent: EntrySwitchConsent,
}

impl fmt::Debug for EntrySwitchPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySwitchPlan")
            .field("schema_version", &self.schema_version)
            .field("context", &self.context)
            .field("config_generation", &self.config_generation)
            .field("current", &self.current)
            .field("target", &self.target)
            .field("apply_system_proxy", &self.apply_system_proxy)
            .field("consent", &self.consent)
            .finish_non_exhaustive()
    }
}

impl EntrySwitchPlan {
    /// Validates the keyed consent and trusted-clock freshness.
    ///
    /// # Errors
    /// Returns a fail-closed validation error for any stale or altered field.
    pub fn validate(
        &self,
        key: &ConsentKey,
        clock: &impl TrustedClock,
    ) -> Result<(), EntrySwitchError> {
        self.validate_integrity(key)?;
        let now = clock.now_unix_ms()?;
        if now < self.consent.issued_at_unix_ms || now > self.consent.expires_at_unix_ms {
            return Err(EntrySwitchError::InvalidConsent);
        }
        Ok(())
    }

    fn validate_integrity(&self, key: &ConsentKey) -> Result<(), EntrySwitchError> {
        validate_entry(&self.current)?;
        validate_entry(&self.target)?;
        self.context.validate()?;
        let lifetime = self
            .consent
            .expires_at_unix_ms
            .checked_sub(self.consent.issued_at_unix_ms)
            .ok_or(EntrySwitchError::InvalidConsent)?;
        if self.schema_version != SCHEMA_VERSION
            || self.current == self.target
            || self.config_generation == 0
            || self.consent.issued_at_unix_ms < 0
            || lifetime != CONSENT_LIFETIME_MS
            || self.apply_system_proxy != self.original_proxy.is_some()
            || self.apply_system_proxy != self.desired_proxy.is_some()
        {
            return Err(EntrySwitchError::InvalidConsent);
        }
        if let Some(v) = &self.original_proxy {
            v.validate()?;
        }
        if let Some(v) = &self.desired_proxy {
            v.validate()?;
        }
        let (id, signature) = self
            .consent
            .token
            .split_once('.')
            .ok_or(EntrySwitchError::InvalidConsent)?;
        if !valid_hex(id, 32) || !valid_hex(signature, 64) {
            return Err(EntrySwitchError::InvalidConsent);
        }
        let signature = decode_hex_32(signature).ok_or(EntrySwitchError::InvalidConsent)?;
        let mut mac =
            HmacSha256::new_from_slice(&key.0[..]).map_err(|_| EntrySwitchError::InvalidConsent)?;
        mac.update(&canonical_plan(self, id));
        mac.verify_slice(&signature)
            .map_err(|_| EntrySwitchError::InvalidConsent)
    }

    #[must_use]
    pub fn audit(&self) -> EntrySwitchAudit {
        EntrySwitchAudit {
            schema_version: self.schema_version,
            install_id: self.context.install_id.clone(),
            user_scope_id: self.context.user_scope_id.clone(),
            config_generation: self.config_generation,
            current: self.current.clone(),
            target: self.target.clone(),
            apply_system_proxy: self.apply_system_proxy,
            original_proxy_fingerprint: self
                .original_proxy
                .as_ref()
                .map(SystemProxySnapshot::fingerprint),
            desired_proxy_fingerprint: self
                .desired_proxy
                .as_ref()
                .map(SystemProxySnapshot::fingerprint),
            consent_id: self.consent.token_id().unwrap_or("invalid").into(),
            expires_at_unix_ms: self.consent.expires_at_unix_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySwitchAudit {
    pub schema_version: u16,
    pub install_id: String,
    pub user_scope_id: String,
    pub config_generation: u64,
    pub current: EntryConfig,
    pub target: EntryConfig,
    pub apply_system_proxy: bool,
    pub original_proxy_fingerprint: Option<String>,
    pub desired_proxy_fingerprint: Option<String>,
    pub consent_id: String,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntrySwitchPhase {
    Prepared,
    StagePending,
    Staged,
    Verified,
    EntryCommitPending,
    EntryCommitted,
    ProxyApplyPending,
    ProxyApplied,
    RollbackRequired,
    Restored,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrySwitchJournalRecord {
    pub schema_version: u16,
    pub phase: EntrySwitchPhase,
    pub plan: EntrySwitchPlan,
    pub stage_declaration: Option<StageDeclaration>,
    pub staged_core: Option<OwnedCoreIdentity>,
}

impl EntrySwitchJournalRecord {
    /// Validates authenticated recovery invariants against the held authority.
    ///
    /// # Errors
    /// Returns a journal or authority error for an impossible or foreign record.
    pub fn validate_recovery(
        &self,
        key: &ConsentKey,
        authority: &impl EntrySwitchAuthorityGuard,
    ) -> Result<(), EntrySwitchError> {
        self.plan.validate_integrity(key)?;
        if self.schema_version != SCHEMA_VERSION
            || authority.context() != &self.plan.context
            || authority.generation() != self.plan.config_generation
        {
            return Err(EntrySwitchError::Unauthorized);
        }
        let shape = match self.phase {
            EntrySwitchPhase::Prepared => {
                self.stage_declaration.is_none() && self.staged_core.is_none()
            }
            EntrySwitchPhase::StagePending => {
                self.stage_declaration
                    .as_ref()
                    .is_some_and(|d| d.valid(self.plan.config_generation))
                    && self.staged_core.is_none()
            }
            EntrySwitchPhase::RollbackRequired | EntrySwitchPhase::Restored => {
                recovery_identity_shape(self)
            }
            _ => {
                self.stage_declaration
                    .as_ref()
                    .is_some_and(|d| d.valid(self.plan.config_generation))
                    && self
                        .staged_core
                        .as_ref()
                        .zip(self.stage_declaration.as_ref())
                        .is_some_and(|(core, declaration)| core.matches(declaration))
            }
        };
        if !shape {
            return Err(EntrySwitchError::Journal);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), EntrySwitchError> {
        let shape = match self.phase {
            EntrySwitchPhase::Prepared => {
                self.stage_declaration.is_none() && self.staged_core.is_none()
            }
            EntrySwitchPhase::StagePending => {
                self.stage_declaration
                    .as_ref()
                    .is_some_and(|d| d.valid(self.plan.config_generation))
                    && self.staged_core.is_none()
            }
            EntrySwitchPhase::RollbackRequired | EntrySwitchPhase::Restored => {
                recovery_identity_shape(self)
            }
            _ => {
                self.stage_declaration
                    .as_ref()
                    .is_some_and(|d| d.valid(self.plan.config_generation))
                    && self
                        .staged_core
                        .as_ref()
                        .zip(self.stage_declaration.as_ref())
                        .is_some_and(|(core, declaration)| core.matches(declaration))
            }
        };
        if shape {
            Ok(())
        } else {
            Err(EntrySwitchError::Journal)
        }
    }
}

fn recovery_identity_shape(record: &EntrySwitchJournalRecord) -> bool {
    match (&record.stage_declaration, &record.staged_core) {
        (None, None) => true,
        (Some(declaration), None) => declaration.valid(record.plan.config_generation),
        (Some(declaration), Some(core)) => {
            declaration.valid(record.plan.config_generation) && core.matches(declaration)
        }
        (None, Some(_)) => false,
    }
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
    fn declare_stage(
        &mut self,
        plan: &EntrySwitchPlan,
    ) -> Result<StageDeclaration, EntrySwitchError>;
    fn stage(
        &mut self,
        plan: &EntrySwitchPlan,
        declaration: &StageDeclaration,
    ) -> Result<OwnedCoreIdentity, EntrySwitchError>;
    fn verify(&mut self, core: &OwnedCoreIdentity) -> Result<SwitchVerification, EntrySwitchError>;
    fn commit_entry(&mut self, plan: &EntrySwitchPlan) -> Result<(), EntrySwitchError>;
    fn restore_entry(&mut self, entry: &EntryConfig) -> Result<(), EntrySwitchError>;
    fn stop_declared_if_owned(
        &mut self,
        declaration: &StageDeclaration,
    ) -> Result<(), EntrySwitchError>;
    fn stop_if_owned(&mut self, core: &OwnedCoreIdentity) -> Result<(), EntrySwitchError>;
}

#[allow(clippy::missing_errors_doc)]
pub trait ProxyBackend {
    fn capability(&self) -> ProxyCapability;
    fn snapshot(&mut self) -> Result<SystemProxySnapshot, EntrySwitchError>;
    /// Query followed by apply; this is not atomic and production remains blocked.
    fn compare_then_apply(
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
    /// Must atomically prune only expired IDs and record this unexpired ID.
    fn consume_consent(
        &mut self,
        token_id: &str,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, EntrySwitchError>;
}

#[derive(Default)]
pub struct MemoryEntrySwitchJournal {
    record: Option<EntrySwitchJournalRecord>,
    consumed: BTreeMap<String, i64>,
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
    fn consume_consent(
        &mut self,
        id: &str,
        expires: i64,
        now: i64,
    ) -> Result<bool, EntrySwitchError> {
        self.consumed.retain(|_, expiry| *expiry >= now);
        if self.consumed.contains_key(id) {
            return Ok(false);
        }
        self.consumed.insert(id.into(), expires);
        Ok(true)
    }
}

/// Current-user confidentiality boundary used by the protected journal codec.
pub trait ConfidentialProtector {
    /// # Errors
    /// Returns an error when current-user protection cannot be applied.
    fn seal(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, EntrySwitchError>;
    /// # Errors
    /// Returns an error when current-user protection cannot be removed.
    fn open(&self, ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, EntrySwitchError>;
}

/// In-memory journal state. It has no serialization implementation; encoding
/// is possible only through `ProtectedJournalCodec`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtectedJournalState {
    pub record: Option<EntrySwitchJournalRecord>,
    pub consumed: BTreeMap<String, i64>,
}

pub struct ProtectedJournalCodec<'a, P> {
    context: EntrySwitchContext,
    key: &'a ConsentKey,
    protector: &'a P,
}

impl<'a, P: ConfidentialProtector> ProtectedJournalCodec<'a, P> {
    #[must_use]
    pub fn new(context: EntrySwitchContext, key: &'a ConsentKey, protector: &'a P) -> Self {
        Self {
            context,
            key,
            protector,
        }
    }

    /// Authenticates and encrypts a complete journal state.
    ///
    /// # Errors
    /// Returns a journal error for invalid state or protection failure.
    pub fn seal(&self, state: &ProtectedJournalState) -> Result<Vec<u8>, EntrySwitchError> {
        self.context.validate()?;
        if state.consumed.len() > 4096
            || state
                .consumed
                .iter()
                .any(|(id, expiry)| !valid_hex(id, 32) || *expiry < 0)
        {
            return Err(EntrySwitchError::Journal);
        }
        if let Some(record) = &state.record {
            record.plan.validate_integrity(self.key)?;
            record.validate_shape()?;
            if record.plan.context != self.context {
                return Err(EntrySwitchError::Journal);
            }
        }
        let payload = JournalPayloadWire {
            schema_version: SCHEMA_VERSION,
            context: self.context.clone(),
            record: state.record.as_ref().map(RecordWire::from),
            consumed: state.consumed.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(|_| EntrySwitchError::Journal)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key.0[..]).map_err(|_| EntrySwitchError::Journal)?;
        mac.update(&payload_bytes);
        let envelope = JournalEnvelopeWire {
            payload,
            mac: hex(&mac.finalize().into_bytes()),
        };
        let plaintext = serde_json::to_vec(&envelope).map_err(|_| EntrySwitchError::Journal)?;
        self.protector
            .seal(&plaintext, &journal_entropy(&self.context))
    }

    /// Decrypts and authenticates a complete journal state.
    ///
    /// # Errors
    /// Returns a journal error for altered, foreign, or malformed ciphertext.
    pub fn open(&self, ciphertext: &[u8]) -> Result<ProtectedJournalState, EntrySwitchError> {
        if ciphertext.is_empty() || ciphertext.len() > 1024 * 1024 {
            return Err(EntrySwitchError::Journal);
        }
        let plaintext = self
            .protector
            .open(ciphertext, &journal_entropy(&self.context))?;
        let envelope: JournalEnvelopeWire =
            serde_json::from_slice(&plaintext).map_err(|_| EntrySwitchError::Journal)?;
        if envelope.payload.schema_version != SCHEMA_VERSION
            || envelope.payload.context != self.context
            || !valid_hex(&envelope.mac, 64)
        {
            return Err(EntrySwitchError::Journal);
        }
        let payload_bytes =
            serde_json::to_vec(&envelope.payload).map_err(|_| EntrySwitchError::Journal)?;
        let signature = decode_hex_32(&envelope.mac).ok_or(EntrySwitchError::Journal)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key.0[..]).map_err(|_| EntrySwitchError::Journal)?;
        mac.update(&payload_bytes);
        mac.verify_slice(&signature)
            .map_err(|_| EntrySwitchError::Journal)?;
        if envelope.payload.consumed.len() > 4096
            || envelope
                .payload
                .consumed
                .iter()
                .any(|(id, expiry)| !valid_hex(id, 32) || *expiry < 0)
        {
            return Err(EntrySwitchError::Journal);
        }
        let record = envelope
            .payload
            .record
            .map(EntrySwitchJournalRecord::try_from)
            .transpose()?;
        if let Some(record) = &record {
            record.plan.validate_integrity(self.key)?;
            record.validate_shape()?;
        }
        Ok(ProtectedJournalState {
            record,
            consumed: envelope.payload.consumed,
        })
    }
}

fn journal_entropy(context: &EntrySwitchContext) -> Vec<u8> {
    let mut bytes = b"vpn-hub/entry-switch/v2".to_vec();
    put_str(&mut bytes, &context.install_id);
    put_str(&mut bytes, &context.user_scope_id);
    bytes
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelopeWire {
    payload: JournalPayloadWire,
    mac: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalPayloadWire {
    schema_version: u16,
    context: EntrySwitchContext,
    record: Option<RecordWire>,
    consumed: BTreeMap<String, i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    schema_version: u16,
    phase: u8,
    plan: PlanWire,
    stage_declaration: Option<StageWire>,
    staged_core: Option<CoreWire>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanWire {
    schema_version: u16,
    context: EntrySwitchContext,
    config_generation: u64,
    current: EntryConfig,
    target: EntryConfig,
    apply_system_proxy: bool,
    original_proxy: Option<ProxyWire>,
    desired_proxy: Option<ProxyWire>,
    token: String,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyWire {
    mode: u8,
    direct: bool,
    manual_proxy: Option<String>,
    proxy_bypass: Option<String>,
    auto_config_url: Option<String>,
    auto_detect: bool,
    connection_name: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageWire {
    transaction_id: String,
    ownership_token: String,
    generation: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreWire {
    pid: u32,
    creation_identity: u64,
    generation: u64,
    transaction_id: String,
    ownership_token: String,
}

impl From<&EntrySwitchJournalRecord> for RecordWire {
    fn from(v: &EntrySwitchJournalRecord) -> Self {
        Self {
            schema_version: v.schema_version,
            phase: phase_to_u8(v.phase),
            plan: PlanWire::from(&v.plan),
            stage_declaration: v.stage_declaration.as_ref().map(StageWire::from),
            staged_core: v.staged_core.as_ref().map(CoreWire::from),
        }
    }
}
impl TryFrom<RecordWire> for EntrySwitchJournalRecord {
    type Error = EntrySwitchError;
    fn try_from(v: RecordWire) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: v.schema_version,
            phase: u8_to_phase(v.phase)?,
            plan: v.plan.try_into()?,
            stage_declaration: v.stage_declaration.map(Into::into),
            staged_core: v.staged_core.map(Into::into),
        })
    }
}
impl From<&EntrySwitchPlan> for PlanWire {
    fn from(v: &EntrySwitchPlan) -> Self {
        Self {
            schema_version: v.schema_version,
            context: v.context.clone(),
            config_generation: v.config_generation,
            current: v.current.clone(),
            target: v.target.clone(),
            apply_system_proxy: v.apply_system_proxy,
            original_proxy: v.original_proxy.as_ref().map(ProxyWire::from),
            desired_proxy: v.desired_proxy.as_ref().map(ProxyWire::from),
            token: v.consent.token.clone(),
            issued_at_unix_ms: v.consent.issued_at_unix_ms,
            expires_at_unix_ms: v.consent.expires_at_unix_ms,
        }
    }
}
impl TryFrom<PlanWire> for EntrySwitchPlan {
    type Error = EntrySwitchError;
    fn try_from(v: PlanWire) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: v.schema_version,
            context: v.context,
            config_generation: v.config_generation,
            current: v.current,
            target: v.target,
            apply_system_proxy: v.apply_system_proxy,
            original_proxy: v
                .original_proxy
                .map(SystemProxySnapshot::try_from)
                .transpose()?,
            desired_proxy: v
                .desired_proxy
                .map(SystemProxySnapshot::try_from)
                .transpose()?,
            consent: EntrySwitchConsent {
                token: v.token,
                issued_at_unix_ms: v.issued_at_unix_ms,
                expires_at_unix_ms: v.expires_at_unix_ms,
            },
        })
    }
}
impl From<&SystemProxySnapshot> for ProxyWire {
    fn from(v: &SystemProxySnapshot) -> Self {
        Self {
            mode: match v.mode {
                WindowsProxyMode::Direct => 0,
                WindowsProxyMode::Manual => 1,
                WindowsProxyMode::AutoConfig => 2,
                WindowsProxyMode::Combined => 3,
            },
            direct: v.direct,
            manual_proxy: v.manual_proxy.clone(),
            proxy_bypass: v.proxy_bypass.clone(),
            auto_config_url: v.auto_config_url.clone(),
            auto_detect: v.auto_detect,
            connection_name: v.connection_name.clone(),
        }
    }
}
impl TryFrom<ProxyWire> for SystemProxySnapshot {
    type Error = EntrySwitchError;
    fn try_from(v: ProxyWire) -> Result<Self, Self::Error> {
        let value = Self {
            mode: match v.mode {
                0 => WindowsProxyMode::Direct,
                1 => WindowsProxyMode::Manual,
                2 => WindowsProxyMode::AutoConfig,
                3 => WindowsProxyMode::Combined,
                _ => return Err(EntrySwitchError::Journal),
            },
            direct: v.direct,
            manual_proxy: v.manual_proxy,
            proxy_bypass: v.proxy_bypass,
            auto_config_url: v.auto_config_url,
            auto_detect: v.auto_detect,
            connection_name: v.connection_name,
        };
        value.validate()?;
        Ok(value)
    }
}
impl From<&StageDeclaration> for StageWire {
    fn from(v: &StageDeclaration) -> Self {
        Self {
            transaction_id: v.transaction_id.clone(),
            ownership_token: v.ownership_token.clone(),
            generation: v.generation,
        }
    }
}
impl From<StageWire> for StageDeclaration {
    fn from(v: StageWire) -> Self {
        Self {
            transaction_id: v.transaction_id,
            ownership_token: v.ownership_token,
            generation: v.generation,
        }
    }
}
impl From<&OwnedCoreIdentity> for CoreWire {
    fn from(v: &OwnedCoreIdentity) -> Self {
        Self {
            pid: v.pid,
            creation_identity: v.creation_identity,
            generation: v.generation,
            transaction_id: v.transaction_id.clone(),
            ownership_token: v.ownership_token.clone(),
        }
    }
}
impl From<CoreWire> for OwnedCoreIdentity {
    fn from(v: CoreWire) -> Self {
        Self {
            pid: v.pid,
            creation_identity: v.creation_identity,
            generation: v.generation,
            transaction_id: v.transaction_id,
            ownership_token: v.ownership_token,
        }
    }
}
fn phase_to_u8(v: EntrySwitchPhase) -> u8 {
    match v {
        EntrySwitchPhase::Prepared => 0,
        EntrySwitchPhase::StagePending => 1,
        EntrySwitchPhase::Staged => 2,
        EntrySwitchPhase::Verified => 3,
        EntrySwitchPhase::EntryCommitPending => 4,
        EntrySwitchPhase::EntryCommitted => 5,
        EntrySwitchPhase::ProxyApplyPending => 6,
        EntrySwitchPhase::ProxyApplied => 7,
        EntrySwitchPhase::RollbackRequired => 8,
        EntrySwitchPhase::Restored => 9,
    }
}
fn u8_to_phase(v: u8) -> Result<EntrySwitchPhase, EntrySwitchError> {
    match v {
        0 => Ok(EntrySwitchPhase::Prepared),
        1 => Ok(EntrySwitchPhase::StagePending),
        2 => Ok(EntrySwitchPhase::Staged),
        3 => Ok(EntrySwitchPhase::Verified),
        4 => Ok(EntrySwitchPhase::EntryCommitPending),
        5 => Ok(EntrySwitchPhase::EntryCommitted),
        6 => Ok(EntrySwitchPhase::ProxyApplyPending),
        7 => Ok(EntrySwitchPhase::ProxyApplied),
        8 => Ok(EntrySwitchPhase::RollbackRequired),
        9 => Ok(EntrySwitchPhase::Restored),
        _ => Err(EntrySwitchError::Journal),
    }
}

pub struct EntrySwitchPlanner;
impl EntrySwitchPlanner {
    /// Builds a keyed, short-lived plan without mutating entry or proxy state.
    ///
    /// # Errors
    /// Returns a fail-closed error for invalid scope, occupancy, time, or state.
    pub fn preview<E: EntryBackend, P: ProxyBackend>(
        entry: &mut E,
        proxy: &mut P,
        request: &EntrySwitchRequest,
        context: EntrySwitchContext,
        key: &ConsentKey,
        clock: &impl TrustedClock,
    ) -> Result<EntrySwitchPlan, EntrySwitchError> {
        validate_entry(&request.target)?;
        context.validate()?;
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
            PortOwnership::OwnedByVpnHub(identity) if identity.generation == generation => {}
            _ => return Err(EntrySwitchError::PortUnavailable),
        }
        let original_proxy = if request.apply_system_proxy {
            if proxy.capability() != ProxyCapability::SupportedDefaultLanCurrentUser {
                return Err(EntrySwitchError::UnsupportedProxyScope);
            }
            let value = proxy.snapshot()?;
            value.validate()?;
            Some(value)
        } else {
            None
        };
        let desired_proxy = original_proxy
            .as_ref()
            .map(|v| SystemProxySnapshot::for_entry(&request.target, v.proxy_bypass.clone()));
        let issued = clock.now_unix_ms()?;
        if issued < 0 {
            return Err(EntrySwitchError::InvalidConsent);
        }
        let expires = issued
            .checked_add(CONSENT_LIFETIME_MS)
            .ok_or(EntrySwitchError::InvalidConsent)?;
        let mut id_bytes = [0; 16];
        rand::rng().fill_bytes(&mut id_bytes);
        let id = hex(&id_bytes);
        let mut plan = EntrySwitchPlan {
            schema_version: SCHEMA_VERSION,
            context,
            config_generation: generation,
            current,
            target: request.target.clone(),
            apply_system_proxy: request.apply_system_proxy,
            original_proxy,
            desired_proxy,
            consent: EntrySwitchConsent {
                token: String::new(),
                issued_at_unix_ms: issued,
                expires_at_unix_ms: expires,
            },
        };
        let mut mac =
            HmacSha256::new_from_slice(&key.0[..]).map_err(|_| EntrySwitchError::InvalidConsent)?;
        mac.update(&canonical_plan(&plan, &id));
        plan.consent.token = format!("{id}.{}", hex(&mac.finalize().into_bytes()));
        plan.validate(key, clock)?;
        Ok(plan)
    }
}

pub struct EntrySwitchTransaction<'a, E, P, J, A, C> {
    entry: &'a mut E,
    proxy: &'a mut P,
    journal: &'a mut J,
    authority: &'a mut A,
    key: &'a ConsentKey,
    clock: &'a C,
}
impl<'a, E, P, J, A, C> EntrySwitchTransaction<'a, E, P, J, A, C>
where
    E: EntryBackend,
    P: ProxyBackend,
    J: EntrySwitchJournal,
    A: EntrySwitchAuthorityGuard,
    C: TrustedClock,
{
    pub fn new(
        entry: &'a mut E,
        proxy: &'a mut P,
        journal: &'a mut J,
        authority: &'a mut A,
        key: &'a ConsentKey,
        clock: &'a C,
    ) -> Self {
        Self {
            entry,
            proxy,
            journal,
            authority,
            key,
            clock,
        }
    }

    /// Applies a journaled switch while continuously holding OS authority.
    ///
    /// # Errors
    /// Returns a fail-closed error and attempts exact-owned rollback.
    pub fn apply(&mut self, plan: EntrySwitchPlan) -> Result<(), EntrySwitchError> {
        self.authority.ensure_held()?;
        plan.validate(self.key, self.clock)?;
        self.validate_authority(&plan)?;
        if self.journal.load()?.is_some() {
            return Err(EntrySwitchError::RecoveryPending);
        }
        if self.entry.config_generation()? != plan.config_generation
            || self.entry.current_entry()? != plan.current
        {
            return Err(EntrySwitchError::StaleGeneration);
        }
        let now = self.clock.now_unix_ms()?;
        let id = plan
            .consent
            .token_id()
            .ok_or(EntrySwitchError::InvalidConsent)?;
        if !self
            .journal
            .consume_consent(id, plan.consent.expires_at_unix_ms, now)?
        {
            return Err(EntrySwitchError::InvalidConsent);
        }
        self.authority.ensure_held()?;
        if plan.apply_system_proxy {
            let original = plan
                .original_proxy
                .as_ref()
                .ok_or(EntrySwitchError::InvalidConsent)?;
            if self.proxy.snapshot()?.fingerprint() != original.fingerprint() {
                return Err(EntrySwitchError::ConcurrentProxyChange);
            }
        }
        let mut record = EntrySwitchJournalRecord {
            schema_version: SCHEMA_VERSION,
            phase: EntrySwitchPhase::Prepared,
            plan,
            stage_declaration: None,
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
        let declaration = self.entry.declare_stage(&record.plan)?;
        if !declaration.valid(record.plan.config_generation) {
            return Err(EntrySwitchError::Backend);
        }
        record.stage_declaration = Some(declaration.clone());
        record.phase = EntrySwitchPhase::StagePending;
        self.journal.save(record)?;
        let core = self.entry.stage(&record.plan, &declaration)?;
        if !core.matches(&declaration) {
            return Err(EntrySwitchError::Backend);
        }
        record.staged_core = Some(core.clone());
        record.phase = EntrySwitchPhase::Staged;
        self.journal.save(record)?;
        if !self
            .entry
            .verify(&core)?
            .validates(record.plan.config_generation)
        {
            return Err(EntrySwitchError::VerificationFailed);
        }
        record.phase = EntrySwitchPhase::Verified;
        self.journal.save(record)?;
        record.phase = EntrySwitchPhase::EntryCommitPending;
        self.journal.save(record)?;
        self.entry.commit_entry(&record.plan)?;
        record.phase = EntrySwitchPhase::EntryCommitted;
        self.journal.save(record)?;
        if let (Some(original), Some(desired)) =
            (&record.plan.original_proxy, &record.plan.desired_proxy)
        {
            record.phase = EntrySwitchPhase::ProxyApplyPending;
            self.journal.save(record)?;
            if !self
                .proxy
                .compare_then_apply(&original.fingerprint(), desired)?
            {
                return Err(EntrySwitchError::ConcurrentProxyChange);
            }
            record.phase = EntrySwitchPhase::ProxyApplied;
            self.journal.save(record)?;
            if !self.proxy.verify(desired)? {
                return Err(EntrySwitchError::VerificationFailed);
            }
        }
        self.authority.ensure_held()?;
        self.journal.clear()
    }

    /// Recovers an authenticated outstanding transaction under the same guard.
    ///
    /// # Errors
    /// Returns a fail-closed error and retains the journal when recovery is unsafe.
    pub fn recover(&mut self) -> Result<bool, EntrySwitchError> {
        self.authority.ensure_held()?;
        let Some(mut record) = self.journal.load()? else {
            return Ok(false);
        };
        record.validate_recovery(self.key, self.authority)?;
        self.restore_record(&mut record)?;
        Ok(true)
    }

    fn restore_record(
        &mut self,
        record: &mut EntrySwitchJournalRecord,
    ) -> Result<(), EntrySwitchError> {
        self.authority.ensure_held()?;
        if matches!(
            record.phase,
            EntrySwitchPhase::ProxyApplyPending
                | EntrySwitchPhase::ProxyApplied
                | EntrySwitchPhase::RollbackRequired
        ) && let (Some(original), Some(desired)) =
            (&record.plan.original_proxy, &record.plan.desired_proxy)
        {
            let current = self.proxy.snapshot()?;
            if current == *desired {
                if !self
                    .proxy
                    .compare_then_apply(&desired.fingerprint(), original)?
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
        } else if let Some(declaration) = &record.stage_declaration {
            self.entry.stop_declared_if_owned(declaration)?;
        }
        record.phase = EntrySwitchPhase::Restored;
        self.journal.save(record)?;
        self.authority.ensure_held()?;
        self.journal.clear()
    }

    fn validate_authority(&self, plan: &EntrySwitchPlan) -> Result<(), EntrySwitchError> {
        if self.authority.context() != &plan.context
            || self.authority.generation() != plan.config_generation
        {
            return Err(EntrySwitchError::Unauthorized);
        }
        Ok(())
    }
}

fn validate_entry(entry: &EntryConfig) -> Result<(), EntrySwitchError> {
    if entry.port == 0 || normalize_loopback_host(&entry.host).is_none() {
        Err(EntrySwitchError::InvalidEntry)
    } else {
        Ok(())
    }
}
fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if !valid_hex(value, 64) {
        return None;
    }
    let mut out = [0; 32];
    for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Some(out)
}
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
fn put(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}
fn put_str(bytes: &mut Vec<u8>, value: &str) {
    put(bytes, value.as_bytes());
}
fn put_opt(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            bytes.push(1);
            put_str(bytes, v);
        }
        None => bytes.push(0),
    }
}
fn proxy_bytes(v: &SystemProxySnapshot) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(match v.mode {
        WindowsProxyMode::Direct => 0,
        WindowsProxyMode::Manual => 1,
        WindowsProxyMode::AutoConfig => 2,
        WindowsProxyMode::Combined => 3,
    });
    b.push(u8::from(v.direct));
    put_opt(&mut b, v.manual_proxy.as_deref());
    put_opt(&mut b, v.proxy_bypass.as_deref());
    put_opt(&mut b, v.auto_config_url.as_deref());
    b.push(u8::from(v.auto_detect));
    put_opt(&mut b, v.connection_name.as_deref());
    b
}
fn canonical_plan(plan: &EntrySwitchPlan, id: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&plan.schema_version.to_be_bytes());
    put_str(&mut b, &plan.context.install_id);
    put_str(&mut b, &plan.context.user_scope_id);
    b.extend_from_slice(&plan.config_generation.to_be_bytes());
    put_str(&mut b, &plan.current.host);
    b.extend_from_slice(&plan.current.port.to_be_bytes());
    put_str(&mut b, &plan.target.host);
    b.extend_from_slice(&plan.target.port.to_be_bytes());
    b.push(u8::from(plan.apply_system_proxy));
    for p in [&plan.original_proxy, &plan.desired_proxy] {
        match p {
            Some(v) => {
                b.push(1);
                put(&mut b, &proxy_bytes(v));
            }
            None => b.push(0),
        }
    }
    b.extend_from_slice(&plan.consent.issued_at_unix_ms.to_be_bytes());
    b.extend_from_slice(&plan.consent.expires_at_unix_ms.to_be_bytes());
    put_str(&mut b, id);
    b
}
fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push(char::from(D[usize::from(byte >> 4)]));
        s.push(char::from(D[usize::from(byte & 15)]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Clock(i64);
    impl TrustedClock for Clock {
        fn now_unix_ms(&self) -> Result<i64, EntrySwitchError> {
            Ok(self.0)
        }
    }
    struct FakeProtector(u8);
    impl ConfidentialProtector for FakeProtector {
        fn seal(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, EntrySwitchError> {
            let salt = entropy.iter().fold(self.0, |a, b| a ^ b);
            Ok(plaintext.iter().map(|b| b ^ salt).collect())
        }
        fn open(&self, ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, EntrySwitchError> {
            self.seal(ciphertext, entropy)
        }
    }
    struct Guard {
        context: EntrySwitchContext,
        generation: u64,
        held: bool,
    }
    impl EntrySwitchAuthorityGuard for Guard {
        fn context(&self) -> &EntrySwitchContext {
            &self.context
        }
        fn generation(&self) -> u64 {
            self.generation
        }
        fn ensure_held(&self) -> Result<(), EntrySwitchError> {
            if self.held {
                Ok(())
            } else {
                Err(EntrySwitchError::Unauthorized)
            }
        }
    }
    struct FakeEntry {
        generation: u64,
        current: EntryConfig,
        ownership: PortOwnership,
        verification: SwitchVerification,
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
                ownership: PortOwnership::Free,
                verification: SwitchVerification {
                    controller_owned: true,
                    enabled_outlets_healthy: true,
                    fail_closed_selected: true,
                    generation: 7,
                },
                events: vec![],
            }
        }
    }
    fn declaration() -> StageDeclaration {
        StageDeclaration {
            transaction_id: "11".repeat(16),
            ownership_token: "22".repeat(32),
            generation: 7,
        }
    }
    fn identity() -> OwnedCoreIdentity {
        let d = declaration();
        OwnedCoreIdentity {
            pid: 42,
            creation_identity: 88,
            generation: 7,
            transaction_id: d.transaction_id,
            ownership_token: d.ownership_token,
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
            Ok(self.ownership.clone())
        }
        fn declare_stage(
            &mut self,
            _: &EntrySwitchPlan,
        ) -> Result<StageDeclaration, EntrySwitchError> {
            self.events.push("declare");
            Ok(declaration())
        }
        fn stage(
            &mut self,
            _: &EntrySwitchPlan,
            _: &StageDeclaration,
        ) -> Result<OwnedCoreIdentity, EntrySwitchError> {
            self.events.push("stage");
            Ok(identity())
        }
        fn verify(
            &mut self,
            _: &OwnedCoreIdentity,
        ) -> Result<SwitchVerification, EntrySwitchError> {
            self.events.push("verify");
            Ok(self.verification.clone())
        }
        fn commit_entry(&mut self, p: &EntrySwitchPlan) -> Result<(), EntrySwitchError> {
            self.events.push("commit");
            self.current = p.target.clone();
            Ok(())
        }
        fn restore_entry(&mut self, e: &EntryConfig) -> Result<(), EntrySwitchError> {
            self.events.push("restore");
            self.current = e.clone();
            Ok(())
        }
        fn stop_declared_if_owned(&mut self, _: &StageDeclaration) -> Result<(), EntrySwitchError> {
            self.events.push("stop_declared");
            Ok(())
        }
        fn stop_if_owned(&mut self, _: &OwnedCoreIdentity) -> Result<(), EntrySwitchError> {
            self.events.push("stop_owned");
            Ok(())
        }
    }
    struct FakeProxy {
        current: SystemProxySnapshot,
        calls: usize,
        events: Vec<&'static str>,
    }
    impl FakeProxy {
        fn ready() -> Self {
            Self {
                current: SystemProxySnapshot {
                    mode: WindowsProxyMode::Combined,
                    direct: true,
                    manual_proxy: Some("http=secret.invalid:8080".into()),
                    proxy_bypass: Some("<local>;secret.invalid".into()),
                    auto_config_url: Some("https://secret.invalid/proxy.pac".into()),
                    auto_detect: true,
                    connection_name: None,
                },
                calls: 0,
                events: vec![],
            }
        }
    }
    impl ProxyBackend for FakeProxy {
        fn capability(&self) -> ProxyCapability {
            ProxyCapability::SupportedDefaultLanCurrentUser
        }
        fn snapshot(&mut self) -> Result<SystemProxySnapshot, EntrySwitchError> {
            self.calls += 1;
            self.events.push("snapshot");
            Ok(self.current.clone())
        }
        fn compare_then_apply(
            &mut self,
            e: &str,
            r: &SystemProxySnapshot,
        ) -> Result<bool, EntrySwitchError> {
            self.calls += 1;
            self.events.push("compare_then_apply");
            if self.current.fingerprint() != e {
                return Ok(false);
            }
            self.current = r.clone();
            Ok(true)
        }
        fn verify(&mut self, e: &SystemProxySnapshot) -> Result<bool, EntrySwitchError> {
            self.calls += 1;
            self.events.push("verify_proxy");
            Ok(self.current == *e)
        }
    }
    fn context() -> EntrySwitchContext {
        EntrySwitchContext {
            install_id: "install_0123456789".into(),
            user_scope_id: "user_01234567890".into(),
        }
    }
    fn guard() -> Guard {
        Guard {
            context: context(),
            generation: 7,
            held: true,
        }
    }
    fn request(proxy: bool) -> EntrySwitchRequest {
        EntrySwitchRequest {
            expected_config_generation: 7,
            target: EntryConfig {
                host: "127.0.0.8".into(),
                port: 41_002,
            },
            apply_system_proxy: proxy,
        }
    }
    fn plan(
        proxy: bool,
        key: &ConsentKey,
        clock: &Clock,
    ) -> (FakeEntry, FakeProxy, EntrySwitchPlan) {
        let mut e = FakeEntry::ready();
        let mut p = FakeProxy::ready();
        let plan =
            EntrySwitchPlanner::preview(&mut e, &mut p, &request(proxy), context(), key, clock)
                .unwrap();
        (e, p, plan)
    }

    #[test]
    fn opt_out_never_calls_proxy() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let clock = Clock(1_000);
        let (mut e, mut p, plan) = plan(false, &key, &clock);
        let mut j = MemoryEntrySwitchJournal::default();
        let mut a = guard();
        EntrySwitchTransaction::new(&mut e, &mut p, &mut j, &mut a, &key, &clock)
            .apply(plan)
            .unwrap();
        assert_eq!(p.calls, 0);
    }
    #[test]
    fn proxy_is_after_verified_entry_commit() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let clock = Clock(1_000);
        let (mut e, mut p, plan) = plan(true, &key, &clock);
        let mut j = MemoryEntrySwitchJournal::default();
        let mut a = guard();
        EntrySwitchTransaction::new(&mut e, &mut p, &mut j, &mut a, &key, &clock)
            .apply(plan)
            .unwrap();
        assert_eq!(
            e.events,
            ["inspect", "declare", "stage", "verify", "commit"]
        );
        assert_eq!(
            p.events,
            ["snapshot", "snapshot", "compare_then_apply", "verify_proxy"]
        );
    }
    #[test]
    fn keyed_consent_binds_every_sensitive_field_and_time() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let other = ConsentKey::from_protected_bytes([8; 32]);
        let clock = Clock(1_000);
        let (_, _, plan) = plan(true, &key, &clock);
        assert_eq!(
            plan.validate(&other, &clock),
            Err(EntrySwitchError::InvalidConsent)
        );
        let mut cases = vec![];
        let mut v = plan.clone();
        v.context.install_id.push('x');
        cases.push(v);
        let mut v = plan.clone();
        v.context.user_scope_id.push('x');
        cases.push(v);
        let mut v = plan.clone();
        v.current.port += 1;
        cases.push(v);
        let mut v = plan.clone();
        v.target.port += 1;
        cases.push(v);
        let mut v = plan.clone();
        v.original_proxy.as_mut().unwrap().manual_proxy = Some("attacker".into());
        cases.push(v);
        let mut v = plan.clone();
        v.desired_proxy.as_mut().unwrap().proxy_bypass = Some("attacker".into());
        cases.push(v);
        let mut v = plan.clone();
        v.config_generation += 1;
        cases.push(v);
        for v in cases {
            assert_eq!(
                v.validate(&key, &clock),
                Err(EntrySwitchError::InvalidConsent)
            );
        }
        assert_eq!(
            plan.validate(&key, &Clock(121_001)),
            Err(EntrySwitchError::InvalidConsent)
        );
        assert_eq!(
            plan.validate(&key, &Clock(999)),
            Err(EntrySwitchError::InvalidConsent)
        );
        let mut fake = plan.clone();
        let digest = hex(&Sha256::digest(canonical_plan(
            &fake,
            "00".repeat(16).as_str(),
        )));
        fake.consent
            .replace_token(format!("{}.{}", "00".repeat(16), digest));
        assert_eq!(
            fake.validate(&key, &clock),
            Err(EntrySwitchError::InvalidConsent)
        );
    }
    #[test]
    fn clock_overflow_and_extremes_fail_closed() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let mut e = FakeEntry::ready();
        let mut p = FakeProxy::ready();
        assert_eq!(
            EntrySwitchPlanner::preview(
                &mut e,
                &mut p,
                &request(false),
                context(),
                &key,
                &Clock(i64::MAX)
            ),
            Err(EntrySwitchError::InvalidConsent)
        );
        assert_eq!(
            EntrySwitchPlanner::preview(
                &mut e,
                &mut p,
                &request(false),
                context(),
                &key,
                &Clock(-1)
            ),
            Err(EntrySwitchError::InvalidConsent)
        );
    }
    #[test]
    fn stage_pending_recovery_stops_declared_effect() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let clock = Clock(1_000);
        let (mut e, mut p, plan) = plan(false, &key, &clock);
        let mut j = MemoryEntrySwitchJournal {
            record: Some(EntrySwitchJournalRecord {
                schema_version: SCHEMA_VERSION,
                phase: EntrySwitchPhase::StagePending,
                plan,
                stage_declaration: Some(declaration()),
                staged_core: None,
            }),
            ..Default::default()
        };
        let mut a = guard();
        EntrySwitchTransaction::new(&mut e, &mut p, &mut j, &mut a, &key, &clock)
            .recover()
            .unwrap();
        assert!(e.events.ends_with(&["stop_declared"]));
        assert!(j.load().unwrap().is_none());
    }
    #[test]
    fn invalid_phase_shape_and_authority_fail_closed() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let clock = Clock(1_000);
        let (_, _, plan) = plan(false, &key, &clock);
        let record = EntrySwitchJournalRecord {
            schema_version: SCHEMA_VERSION,
            phase: EntrySwitchPhase::Staged,
            plan,
            stage_declaration: Some(declaration()),
            staged_core: None,
        };
        assert_eq!(
            record.validate_recovery(&key, &guard()),
            Err(EntrySwitchError::Journal)
        );
        let mut bad = guard();
        bad.context.user_scope_id = "other_01234567890".into();
        let mut valid = record.clone();
        valid.staged_core = Some(identity());
        assert_eq!(
            valid.validate_recovery(&key, &bad),
            Err(EntrySwitchError::Unauthorized)
        );
    }
    #[test]
    fn failed_verification_rolls_back_and_consumes_once() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let clock = Clock(1_000);
        let (mut e, mut p, plan) = plan(true, &key, &clock);
        e.verification.fail_closed_selected = false;
        let mut j = MemoryEntrySwitchJournal::default();
        let mut a = guard();
        assert_eq!(
            EntrySwitchTransaction::new(&mut e, &mut p, &mut j, &mut a, &key, &clock)
                .apply(plan.clone()),
            Err(EntrySwitchError::VerificationFailed)
        );
        assert_eq!(
            EntrySwitchTransaction::new(&mut e, &mut p, &mut j, &mut a, &key, &clock).apply(plan),
            Err(EntrySwitchError::InvalidConsent)
        );
    }
    #[test]
    fn consumed_ids_prune_only_after_expiry() {
        let mut j = MemoryEntrySwitchJournal::default();
        assert!(j.consume_consent("a", 200, 100).unwrap());
        assert!(!j.consume_consent("a", 200, 150).unwrap());
        assert!(j.consume_consent("b", 300, 201).unwrap());
        assert!(j.consume_consent("a", 400, 201).unwrap());
    }
    #[test]
    fn audit_serialization_does_not_leak_proxy_recovery_values() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let clock = Clock(1_000);
        let (_, _, plan) = plan(true, &key, &clock);
        let json = serde_json::to_string(&plan.audit()).unwrap();
        for secret in ["secret.invalid:8080", "<local>;secret.invalid", "proxy.pac"] {
            assert!(!json.contains(secret));
        }
        assert!(json.contains("original_proxy_fingerprint"));
    }
    #[test]
    fn protected_journal_is_confidential_authenticated_and_context_bound() {
        let key = ConsentKey::from_protected_bytes([7; 32]);
        let wrong = ConsentKey::from_protected_bytes([8; 32]);
        let clock = Clock(1_000);
        let (_, _, plan) = plan(true, &key, &clock);
        let state = ProtectedJournalState {
            record: Some(EntrySwitchJournalRecord {
                schema_version: SCHEMA_VERSION,
                phase: EntrySwitchPhase::StagePending,
                plan,
                stage_declaration: Some(declaration()),
                staged_core: None,
            }),
            consumed: BTreeMap::from([("aa".repeat(16), 121_000)]),
        };
        let protector = FakeProtector(0x5a);
        let codec = ProtectedJournalCodec::new(context(), &key, &protector);
        let bytes = codec.seal(&state).unwrap();
        let rendered = String::from_utf8_lossy(&bytes);
        for secret in ["secret.invalid:8080", "<local>;secret.invalid", "proxy.pac"] {
            assert!(!rendered.contains(secret));
        }
        assert_eq!(codec.open(&bytes).unwrap(), state);
        assert!(
            ProtectedJournalCodec::new(context(), &wrong, &protector)
                .open(&bytes)
                .is_err()
        );
        let mut other = context();
        other.install_id = "other_install_0123".into();
        assert!(
            ProtectedJournalCodec::new(other, &key, &protector)
                .open(&bytes)
                .is_err()
        );
        let mut tampered = bytes;
        let midpoint = tampered.len() / 2;
        tampered[midpoint] ^= 1;
        assert!(codec.open(&tampered).is_err());
    }
}
