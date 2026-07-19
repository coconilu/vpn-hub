//! Fail-closed TUN planning and transactional recovery boundary.
//!
//! This module deliberately contains no Windows route, DNS, adapter, WFP or
//! TUN mutation API. The production adapter validates a typed plan and reports
//! unsupported until a separately reviewed Windows backend can prove exact
//! application-identity exclusion. Tests use the fake backend below the trait.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use vpn_hub_core::{
    OutletConfig, OutletKind, UdpCapabilityEvidence, UdpCapabilityStatus, current_udp_status,
};

use crate::{AuthorityFileGuard, InstallationReference, SupervisorAuthority};

const JOURNAL_SCHEMA_VERSION: u16 = 2;
const PLAN_SCHEMA_VERSION: u16 = 2;
const CONSENT_VERSION: u16 = 1;
const MAX_OUTLETS: usize = 128;
const MAX_IDENTITIES: usize = 131;
const MAX_JOURNAL_BYTES: usize = 512 * 1024;
const MAX_PLAN_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessExclusionCapability {
    /// A reviewed packet-routing executor can combine normalized application
    /// identity enforcement with TUN/route bypass and deny semantics.
    /// Ordinary WFP permit/block filters alone do not satisfy this capability.
    VerifiedApplicationIdentity,
    /// A name, PID or port based approximation is not sufficient.
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlatformCapability {
    pub process_exclusion: ProcessExclusionCapability,
    pub ipv4: bool,
    pub ipv6: bool,
    pub tcp: bool,
    pub udp: bool,
    pub dns_tcp: bool,
    pub dns_udp: bool,
    pub durable_snapshot_restore: bool,
}

impl PlatformCapability {
    #[must_use]
    pub const fn plan_only_windows() -> Self {
        Self {
            process_exclusion: ProcessExclusionCapability::Unsupported,
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: true,
            dns_tcp: true,
            dns_udp: true,
            durable_snapshot_restore: false,
        }
    }

    #[cfg(test)]
    const fn fake_verified() -> Self {
        Self {
            process_exclusion: ProcessExclusionCapability::VerifiedApplicationIdentity,
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: true,
            dns_tcp: true,
            dns_udp: true,
            durable_snapshot_restore: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableRole {
    Gui,
    Core,
    Helper,
    LocalOutlet,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub role: ExecutableRole,
    /// Installer/user supplied absolute local path; never discovered by scanning.
    pub canonical_path: String,
    /// Lowercase SHA-256 pinned at registration time.
    pub sha256: String,
    /// Present only for a user-registered local outlet.
    pub outlet_id: Option<String>,
}

impl ExecutableIdentity {
    fn validate(&self) -> Result<(), TunError> {
        if !valid_sha256(&self.sha256) || !valid_local_windows_executable(&self.canonical_path) {
            return Err(TunError::InvalidExecutableIdentity);
        }
        match self.role {
            ExecutableRole::LocalOutlet => {
                let id = self.outlet_id.as_deref().ok_or(TunError::InvalidOutlet)?;
                validate_id(id)?;
            }
            ExecutableRole::Gui | ExecutableRole::Core | ExecutableRole::Helper => {
                if self.outlet_id.is_some() {
                    return Err(TunError::InvalidExecutableIdentity);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutletTransport {
    Subscription,
    LocalProxy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredOutlet {
    /// Current private routing declaration. It is input-only: subscription
    /// secret references are never copied into `TunPlan` or its journal.
    pub config: OutletConfig,
    pub healthy: bool,
    /// Versioned Issue #11 evidence. Missing, stale, unknown and TCP-only
    /// evidence are all excluded from the UDP eligible set.
    pub udp_evidence: Option<UdpCapabilityEvidence>,
    /// Required only for local proxies, and must carry the same stable outlet ID.
    pub executable: Option<ExecutableIdentity>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutletDeclaration {
    pub outlet_id: String,
    pub transport: OutletTransport,
    /// Present only for local proxies; subscriptions remain credential-free.
    pub loopback_endpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct TunConsent {
    pub accepted: bool,
    pub risk_version: u16,
}

impl Default for TunConsent {
    fn default() -> Self {
        Self {
            accepted: false,
            risk_version: CONSENT_VERSION,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunPlanAction {
    Enable,
    Disable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClass {
    Application,
    Dns,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedDisposition {
    Tunneled,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeakCheck {
    pub family: AddressFamily,
    pub transport: TransportProtocol,
    pub traffic: TrafficClass,
    pub expected: ExpectedDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProcessNetworkPolicy {
    /// GUI and Helper control-plane processes receive no generic network escape.
    ControlPlaneDenyEgress,
    /// The exact VPN Hub-owned core may create only planned upstream flows.
    OwnedCoreUpstreamOnly,
    /// Explicitly registered local-client infrastructure bypass.
    RegisteredOutletInfrastructureBypass,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProcessRule {
    pub identity: ExecutableIdentity,
    pub policy: ProcessNetworkPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalOutlet {
    transport: OutletTransport,
    loopback_endpoint: Option<String>,
    executable: Option<ExecutableIdentity>,
}

/// Opaque, validated TUN transaction input. Only `TunPlanBuilder` can create a
/// plan outside this module; untrusted serialized data cannot deserialize into
/// this type and its raw policy fields cannot be mutated by callers.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TunPlan {
    schema_version: u16,
    install_id: String,
    authority_id: String,
    generation: u64,
    action: TunPlanAction,
    consent_version: Option<u16>,
    all_down: bool,
    strict_route: bool,
    dns_hijack_tcp: bool,
    dns_hijack_udp: bool,
    process_rules: Vec<ProcessRule>,
    outlet_registry: Vec<OutletDeclaration>,
    local_endpoints: BTreeMap<String, String>,
    tcp_eligible_outlets: Vec<String>,
    udp_eligible_outlets: Vec<String>,
    leak_checks: Vec<LeakCheck>,
    /// Full, non-secret builder provenance used to reject a post-build policy
    /// injection even when all public policy vectors are changed consistently.
    #[serde(skip)]
    canonical_outlets: BTreeMap<String, CanonicalOutlet>,
}

impl TunPlan {
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(bytes))
    }

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), TunError> {
        validate_id(&self.install_id)?;
        validate_id(&self.authority_id)?;
        if self.schema_version != PLAN_SCHEMA_VERSION || self.generation == 0 {
            return Err(TunError::InvalidPlan);
        }
        match self.action {
            TunPlanAction::Enable
                if self.consent_version != Some(CONSENT_VERSION)
                    || !self.strict_route
                    || !self.dns_hijack_tcp
                    || !self.dns_hijack_udp =>
            {
                return Err(TunError::InvalidPlan);
            }
            TunPlanAction::Disable
                if self.consent_version.is_some()
                    || !self.process_rules.is_empty()
                    || !self.outlet_registry.is_empty()
                    || !self.local_endpoints.is_empty()
                    || !self.tcp_eligible_outlets.is_empty()
                    || !self.udp_eligible_outlets.is_empty() =>
            {
                return Err(TunError::InvalidPlan);
            }
            TunPlanAction::Enable | TunPlanAction::Disable => {}
        }
        if self.process_rules.len() > MAX_IDENTITIES {
            return Err(TunError::InvalidPlan);
        }
        let mut unique_rules = BTreeSet::new();
        let mut application_roles = BTreeSet::new();
        let mut local_rule_ids = BTreeSet::new();
        for rule in &self.process_rules {
            rule.identity.validate()?;
            if !unique_rules.insert(rule.clone()) {
                return Err(TunError::InvalidProcessPolicy);
            }
            match (rule.identity.role, rule.policy) {
                (
                    ExecutableRole::Gui | ExecutableRole::Helper,
                    ProcessNetworkPolicy::ControlPlaneDenyEgress,
                )
                | (ExecutableRole::Core, ProcessNetworkPolicy::OwnedCoreUpstreamOnly) => {
                    if !application_roles.insert(rule.identity.role) {
                        return Err(TunError::InvalidProcessPolicy);
                    }
                }
                (
                    ExecutableRole::LocalOutlet,
                    ProcessNetworkPolicy::RegisteredOutletInfrastructureBypass,
                ) => {
                    if !local_rule_ids.insert(
                        rule.identity
                            .outlet_id
                            .as_deref()
                            .ok_or(TunError::InvalidProcessPolicy)?,
                    ) {
                        return Err(TunError::InvalidProcessPolicy);
                    }
                }
                _ => return Err(TunError::InvalidProcessPolicy),
            }
        }
        if self.action == TunPlanAction::Enable
            && application_roles
                != BTreeSet::from([
                    ExecutableRole::Gui,
                    ExecutableRole::Core,
                    ExecutableRole::Helper,
                ])
        {
            return Err(TunError::ApplicationIdentityMissing);
        }
        let mut declared_ids = BTreeSet::new();
        let mut declared_local_ids = BTreeSet::new();
        for declaration in &self.outlet_registry {
            validate_id(&declaration.outlet_id)?;
            if !declared_ids.insert(declaration.outlet_id.as_str()) {
                return Err(TunError::DuplicateOutlet);
            }
            match declaration.transport {
                OutletTransport::Subscription if declaration.loopback_endpoint.is_none() => {}
                OutletTransport::LocalProxy => {
                    let endpoint = declaration
                        .loopback_endpoint
                        .as_deref()
                        .ok_or(TunError::LoopbackEndpointRequired)?;
                    validate_loopback_endpoint(endpoint)?;
                    declared_local_ids.insert(declaration.outlet_id.as_str());
                    if self
                        .local_endpoints
                        .get(&declaration.outlet_id)
                        .map(String::as_str)
                        != Some(endpoint)
                    {
                        return Err(TunError::InvalidOutlet);
                    }
                }
                OutletTransport::Subscription => return Err(TunError::InvalidOutlet),
            }
        }
        if local_rule_ids != declared_local_ids
            || declared_local_ids
                != self
                    .local_endpoints
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
        {
            return Err(TunError::LocalProcessIdentityRequired);
        }
        let observed_outlets = self
            .outlet_registry
            .iter()
            .map(|declaration| {
                let executable = self
                    .process_rules
                    .iter()
                    .find(|rule| {
                        rule.identity.role == ExecutableRole::LocalOutlet
                            && rule.identity.outlet_id.as_deref()
                                == Some(declaration.outlet_id.as_str())
                    })
                    .map(|rule| rule.identity.clone());
                (
                    declaration.outlet_id.clone(),
                    CanonicalOutlet {
                        transport: declaration.transport,
                        loopback_endpoint: declaration.loopback_endpoint.clone(),
                        executable,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if observed_outlets != self.canonical_outlets {
            return Err(TunError::CanonicalOutletMismatch);
        }
        let tcp = validate_unique_ids(&self.tcp_eligible_outlets)?;
        let udp = validate_unique_ids(&self.udp_eligible_outlets)?;
        let expected_all_down = self.action == TunPlanAction::Enable && tcp.is_empty();
        if !tcp.is_subset(&declared_ids)
            || !udp.is_subset(&declared_ids)
            || !udp.is_subset(&tcp)
            || self.all_down != expected_all_down
            || self.leak_checks != leak_matrix(!tcp.is_empty(), !udp.is_empty())
        {
            return Err(TunError::LeakPolicyInvalid);
        }
        let json = serde_json::to_vec(self).map_err(|_| TunError::InvalidPlan)?;
        if json.len() > MAX_PLAN_BYTES {
            return Err(TunError::InvalidPlan);
        }
        Ok(())
    }
}

pub struct TunPlanBuilder<'a> {
    pub install_id: &'a str,
    pub authority_id: &'a str,
    pub generation: u64,
    pub requested_enabled: bool,
    pub consent: TunConsent,
    pub capabilities: &'a PlatformCapability,
    pub application_identities: &'a [ExecutableIdentity],
    pub outlets: &'a [RegisteredOutlet],
}

impl TunPlanBuilder<'_> {
    /// Builds a complete, auditable plan without touching the operating system.
    #[allow(clippy::too_many_lines)]
    pub fn build(&self) -> Result<TunPlan, TunError> {
        validate_id(self.install_id)?;
        validate_id(self.authority_id)?;
        if self.generation == 0 || self.outlets.len() > MAX_OUTLETS {
            return Err(TunError::InvalidPlan);
        }
        if !self.requested_enabled {
            let plan = TunPlan {
                schema_version: PLAN_SCHEMA_VERSION,
                install_id: self.install_id.into(),
                authority_id: self.authority_id.into(),
                generation: self.generation,
                action: TunPlanAction::Disable,
                consent_version: None,
                all_down: false,
                strict_route: true,
                dns_hijack_tcp: true,
                dns_hijack_udp: true,
                process_rules: Vec::new(),
                outlet_registry: Vec::new(),
                local_endpoints: BTreeMap::new(),
                tcp_eligible_outlets: Vec::new(),
                udp_eligible_outlets: Vec::new(),
                leak_checks: leak_matrix(false, false),
                canonical_outlets: BTreeMap::new(),
            };
            plan.validate()?;
            return Ok(plan);
        }
        if !self.consent.accepted || self.consent.risk_version != CONSENT_VERSION {
            return Err(TunError::ConsentRequired);
        }
        require_platform_capabilities(self.capabilities)?;
        let mut process_rules = Vec::new();
        let mut roles = BTreeSet::new();
        for identity in self.application_identities {
            identity.validate()?;
            if identity.role == ExecutableRole::LocalOutlet || !roles.insert(identity.role) {
                return Err(TunError::InvalidExecutableIdentity);
            }
            let policy = match identity.role {
                ExecutableRole::Gui | ExecutableRole::Helper => {
                    ProcessNetworkPolicy::ControlPlaneDenyEgress
                }
                ExecutableRole::Core => ProcessNetworkPolicy::OwnedCoreUpstreamOnly,
                ExecutableRole::LocalOutlet => return Err(TunError::InvalidExecutableIdentity),
            };
            process_rules.push(ProcessRule {
                identity: identity.clone(),
                policy,
            });
        }
        if roles
            != BTreeSet::from([
                ExecutableRole::Gui,
                ExecutableRole::Core,
                ExecutableRole::Helper,
            ])
        {
            return Err(TunError::ApplicationIdentityMissing);
        }

        let mut outlet_ids = BTreeSet::new();
        let mut outlet_registry = Vec::new();
        let mut canonical_outlets = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        let mut tcp_eligible_outlets = Vec::new();
        let mut udp_eligible_outlets = Vec::new();
        for outlet in self.outlets.iter().filter(|outlet| outlet.config.enabled) {
            let outlet_id = outlet.config.id.as_str();
            validate_id(outlet_id)?;
            if !outlet_ids.insert(outlet_id) {
                return Err(TunError::DuplicateOutlet);
            }
            if outlet.healthy {
                tcp_eligible_outlets.push(outlet_id.to_owned());
                if current_udp_status(&outlet.config, outlet.udp_evidence.as_ref())
                    == UdpCapabilityStatus::Supported
                {
                    udp_eligible_outlets.push(outlet_id.to_owned());
                }
            }
            match &outlet.config.kind {
                OutletKind::Subscription { .. } => {
                    if outlet.executable.is_some() {
                        return Err(TunError::InvalidOutlet);
                    }
                    outlet_registry.push(OutletDeclaration {
                        outlet_id: outlet_id.to_owned(),
                        transport: OutletTransport::Subscription,
                        loopback_endpoint: None,
                    });
                    canonical_outlets.insert(
                        outlet_id.to_owned(),
                        CanonicalOutlet {
                            transport: OutletTransport::Subscription,
                            loopback_endpoint: None,
                            executable: None,
                        },
                    );
                }
                OutletKind::LocalProxy { endpoint } => {
                    validate_loopback_endpoint(endpoint)?;
                    let executable = outlet
                        .executable
                        .as_ref()
                        .ok_or(TunError::LocalProcessIdentityRequired)?;
                    executable.validate()?;
                    if executable.role != ExecutableRole::LocalOutlet
                        || executable.outlet_id.as_deref() != Some(outlet_id)
                    {
                        return Err(TunError::LocalProcessIdentityRequired);
                    }
                    endpoints.insert(outlet_id.to_owned(), endpoint.clone());
                    outlet_registry.push(OutletDeclaration {
                        outlet_id: outlet_id.to_owned(),
                        transport: OutletTransport::LocalProxy,
                        loopback_endpoint: Some(endpoint.clone()),
                    });
                    process_rules.push(ProcessRule {
                        identity: executable.clone(),
                        policy: ProcessNetworkPolicy::RegisteredOutletInfrastructureBypass,
                    });
                    canonical_outlets.insert(
                        outlet_id.to_owned(),
                        CanonicalOutlet {
                            transport: OutletTransport::LocalProxy,
                            loopback_endpoint: Some(endpoint.clone()),
                            executable: Some(executable.clone()),
                        },
                    );
                }
            }
        }
        let all_down = tcp_eligible_outlets.is_empty();
        let has_udp = !udp_eligible_outlets.is_empty();
        let plan = TunPlan {
            schema_version: PLAN_SCHEMA_VERSION,
            install_id: self.install_id.into(),
            authority_id: self.authority_id.into(),
            generation: self.generation,
            action: TunPlanAction::Enable,
            consent_version: Some(CONSENT_VERSION),
            all_down,
            strict_route: true,
            dns_hijack_tcp: true,
            dns_hijack_udp: true,
            process_rules,
            outlet_registry,
            local_endpoints: endpoints,
            tcp_eligible_outlets,
            udp_eligible_outlets,
            leak_checks: leak_matrix(!all_down, has_udp),
            canonical_outlets,
        };
        plan.validate()?;
        Ok(plan)
    }
}

fn require_platform_capabilities(capabilities: &PlatformCapability) -> Result<(), TunError> {
    if capabilities.process_exclusion != ProcessExclusionCapability::VerifiedApplicationIdentity {
        return Err(TunError::ProcessExclusionUnsupported);
    }
    if !capabilities.ipv4
        || !capabilities.ipv6
        || !capabilities.tcp
        || !capabilities.udp
        || !capabilities.dns_tcp
        || !capabilities.dns_udp
        || !capabilities.durable_snapshot_restore
    {
        return Err(TunError::PlatformCapabilityUnsupported);
    }
    Ok(())
}

fn leak_matrix(has_tcp: bool, has_udp: bool) -> Vec<LeakCheck> {
    [AddressFamily::Ipv4, AddressFamily::Ipv6]
        .into_iter()
        .flat_map(|family| {
            [TrafficClass::Application, TrafficClass::Dns]
                .into_iter()
                .flat_map(move |traffic| {
                    [TransportProtocol::Tcp, TransportProtocol::Udp]
                        .into_iter()
                        .map(move |transport| LeakCheck {
                            family,
                            transport,
                            traffic,
                            expected: if match transport {
                                TransportProtocol::Tcp => has_tcp,
                                TransportProtocol::Udp => has_udp,
                            } {
                                ExpectedDisposition::Tunneled
                            } else {
                                ExpectedDisposition::Rejected
                            },
                        })
                })
        })
        .collect()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSnapshot {
    /// Opaque, backend-created records. They intentionally contain no command text.
    pub route_records: Vec<String>,
    pub dns_records: Vec<String>,
    pub adapter_records: Vec<String>,
    pub tun_records: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunJournalPhase {
    Snapshotted,
    Staged,
    Applied,
    Verified,
    Committed,
    RolledBack,
    Restored,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunJournal {
    pub schema_version: u16,
    pub install_id: String,
    pub authority_id: String,
    pub generation: u64,
    pub action: TunPlanAction,
    pub plan_fingerprint: String,
    pub phase: TunJournalPhase,
    pub snapshot: NetworkSnapshot,
}

pub trait TunJournalStore {
    fn load(&self) -> Result<Option<TunJournal>, TunError>;
    fn save(&mut self, journal: &TunJournal) -> Result<(), TunError>;
    fn clear(&mut self) -> Result<(), TunError>;
}

#[derive(Clone, Debug)]
pub struct FileTunJournalStore {
    path: PathBuf,
}

impl FileTunJournalStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl TunJournalStore for FileTunJournalStore {
    fn load(&self) -> Result<Option<TunJournal>, TunError> {
        let mut found = false;
        for path in [&self.path, &journal_backup_path(&self.path)] {
            let bytes = match fs::read(path) {
                Ok(bytes) => {
                    found = true;
                    bytes
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(TunError::JournalRead),
            };
            if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
                continue;
            }
            let Ok(journal) = serde_json::from_slice::<TunJournal>(&bytes) else {
                continue;
            };
            if validate_journal(&journal).is_ok() {
                return Ok(Some(journal));
            }
        }
        if found {
            Err(TunError::JournalCorrupt)
        } else {
            Ok(None)
        }
    }

    fn save(&mut self, journal: &TunJournal) -> Result<(), TunError> {
        validate_journal(journal)?;
        let bytes = serde_json::to_vec(journal).map_err(|_| TunError::JournalWrite)?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(TunError::JournalCorrupt);
        }
        vpn_hub_core::durable_atomic_save_with_backup(
            &self.path,
            &bytes,
            &vpn_hub_core::SystemDurableFileOps,
        )
        .map_err(|_| TunError::JournalWrite)
    }

    fn clear(&mut self) -> Result<(), TunError> {
        vpn_hub_core::durable_remove_if_exists(&self.path, &vpn_hub_core::SystemDurableFileOps)
            .and_then(|()| {
                vpn_hub_core::durable_remove_if_exists(
                    &journal_backup_path(&self.path),
                    &vpn_hub_core::SystemDurableFileOps,
                )
            })
            .map_err(|_| TunError::JournalWrite)
    }
}

fn journal_backup_path(path: &Path) -> PathBuf {
    let mut extension = path
        .extension()
        .map_or_else(String::new, |value| value.to_string_lossy().into_owned());
    if !extension.is_empty() {
        extension.push('.');
    }
    extension.push_str("bak");
    path.with_extension(extension)
}

pub trait TunBackend {
    fn capabilities(&self) -> PlatformCapability;
    fn snapshot(&mut self) -> Result<NetworkSnapshot, TunError>;
    fn stage(&mut self, plan: &TunPlan) -> Result<(), TunError>;
    fn apply(&mut self, plan: &TunPlan) -> Result<(), TunError>;
    fn verify(&mut self, plan: &TunPlan) -> Result<(), TunError>;
    fn commit(&mut self, plan: &TunPlan) -> Result<(), TunError>;
    fn restore(&mut self, snapshot: &NetworkSnapshot) -> Result<(), TunError>;
    fn verify_restored(&mut self, snapshot: &NetworkSnapshot) -> Result<(), TunError>;
}

/// OS-backed cross-process authority held for the complete TUN transaction.
/// The signed installer must pre-provision the dedicated lease file with the
/// reviewed `ProgramData` ACL; this API never creates it.
pub struct TunAuthorityGuard {
    _file_guard: AuthorityFileGuard,
    install_id: String,
    authority_id: String,
    generation: u64,
}

impl TunAuthorityGuard {
    pub fn acquire_existing(
        installation: &InstallationReference,
        authority_id: &str,
        generation: u64,
    ) -> Result<Self, TunError> {
        if !installation.helper_enabled {
            return Err(TunError::AuthorityConflict);
        }
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .ok_or(TunError::AuthorityConflict)?;
        installation
            .validate(&program_data)
            .map_err(|_| TunError::AuthorityConflict)?;
        Self::acquire_at(
            &installation.tun_authority_path(),
            &installation.install_id,
            authority_id,
            generation,
        )
    }

    fn acquire_at(
        path: &Path,
        install_id: &str,
        authority_id: &str,
        generation: u64,
    ) -> Result<Self, TunError> {
        validate_id(install_id)?;
        validate_id(authority_id)?;
        if generation == 0 {
            return Err(TunError::StaleGeneration);
        }
        let file_guard =
            AuthorityFileGuard::acquire_existing(path, SupervisorAuthority::Helper, generation)
                .map_err(|_| TunError::AuthorityConflict)?;
        Ok(Self {
            _file_guard: file_guard,
            install_id: install_id.into(),
            authority_id: authority_id.into(),
            generation,
        })
    }

    fn validates(&self, plan: &TunPlan) -> bool {
        self.install_id == plan.install_id
            && self.authority_id == plan.authority_id
            && self.generation == plan.generation
    }
}

pub struct TunTransaction<B, J> {
    backend: B,
    journal: J,
    authority: TunAuthorityGuard,
}

impl<B: TunBackend, J: TunJournalStore> TunTransaction<B, J> {
    #[must_use]
    pub const fn new(backend: B, journal: J, authority: TunAuthorityGuard) -> Self {
        Self {
            backend,
            journal,
            authority,
        }
    }

    pub fn apply(&mut self, plan: &TunPlan) -> Result<TunJournal, TunError> {
        plan.validate()?;
        if plan.action != TunPlanAction::Enable {
            return Err(TunError::DisableRequiresCommittedSnapshot);
        }
        if !self.authority.validates(plan) {
            return Err(TunError::AuthorityConflict);
        }
        require_platform_capabilities(&self.backend.capabilities())?;
        self.fence(plan)?;
        let snapshot = self.backend.snapshot()?;
        let mut state = TunJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id: plan.install_id.clone(),
            authority_id: plan.authority_id.clone(),
            generation: plan.generation,
            action: TunPlanAction::Enable,
            plan_fingerprint: plan.fingerprint(),
            phase: TunJournalPhase::Snapshotted,
            snapshot,
        };
        if let Err(error) = self.journal.save(&state) {
            return self.rollback_after_failure(&mut state, error, false);
        }
        self.step(&mut state, TunJournalPhase::Staged, |backend| {
            backend.stage(plan)
        })?;
        self.step(&mut state, TunJournalPhase::Applied, |backend| {
            backend.apply(plan)
        })?;
        self.step(&mut state, TunJournalPhase::Verified, |backend| {
            backend.verify(plan)
        })?;
        self.step(&mut state, TunJournalPhase::Committed, |backend| {
            backend.commit(plan)
        })?;
        Ok(state)
    }

    /// Disables only by restoring the outstanding pre-enable snapshot. It
    /// never snapshots the currently enabled TUN state as a recovery target.
    pub fn disable(&mut self, plan: &TunPlan) -> Result<bool, TunError> {
        plan.validate()?;
        if plan.action != TunPlanAction::Disable {
            return Err(TunError::DisableRequiresCommittedSnapshot);
        }
        if !self.authority.validates(plan) {
            return Err(TunError::AuthorityConflict);
        }
        let Some(state) = self.journal.load()? else {
            return Ok(false);
        };
        if state.install_id != plan.install_id || state.authority_id != plan.authority_id {
            return Err(TunError::AuthorityConflict);
        }
        if plan.generation < state.generation {
            return Err(TunError::StaleGeneration);
        }
        self.restore_outstanding(state, Some(plan.generation))
    }

    /// Restores any recorded pre-TUN snapshot. Used for cancellation, crash,
    /// forced restart, normal stop and uninstall. Repetition is safe.
    pub fn recover(&mut self, install_id: &str, authority_id: &str) -> Result<bool, TunError> {
        if self.authority.install_id != install_id || self.authority.authority_id != authority_id {
            return Err(TunError::AuthorityConflict);
        }
        let Some(state) = self.journal.load()? else {
            return Ok(false);
        };
        if state.install_id != install_id || state.authority_id != authority_id {
            return Err(TunError::AuthorityConflict);
        }
        if self.authority.generation < state.generation {
            return Err(TunError::StaleGeneration);
        }
        self.restore_outstanding(state, None)
    }

    fn restore_outstanding(
        &mut self,
        mut state: TunJournal,
        completed_generation: Option<u64>,
    ) -> Result<bool, TunError> {
        if state.action != TunPlanAction::Enable {
            return Err(TunError::JournalCorrupt);
        }
        if state.phase == TunJournalPhase::Restored {
            self.backend.verify_restored(&state.snapshot)?;
        } else {
            self.backend.restore(&state.snapshot)?;
            self.backend.verify_restored(&state.snapshot)?;
            state.phase = TunJournalPhase::Restored;
            if let Some(generation) = completed_generation {
                state.generation = generation;
            }
            self.journal.save(&state)?;
        }
        self.journal.clear()?;
        Ok(true)
    }

    fn fence(&self, plan: &TunPlan) -> Result<(), TunError> {
        let Some(existing) = self.journal.load()? else {
            return Ok(());
        };
        if existing.install_id != plan.install_id || existing.authority_id != plan.authority_id {
            return Err(TunError::AuthorityConflict);
        }
        if plan.generation <= existing.generation {
            return Err(TunError::StaleGeneration);
        }
        Err(TunError::RecoveryRequired)
    }

    fn step<F>(
        &mut self,
        state: &mut TunJournal,
        next: TunJournalPhase,
        operation: F,
    ) -> Result<(), TunError>
    where
        F: FnOnce(&mut B) -> Result<(), TunError>,
    {
        if let Err(error) = operation(&mut self.backend) {
            return self.rollback_after_failure(state, error, true);
        }
        state.phase = next;
        if let Err(error) = self.journal.save(state) {
            return self.rollback_after_failure(state, error, true);
        }
        Ok(())
    }

    fn rollback_after_failure<T>(
        &mut self,
        state: &mut TunJournal,
        cause: TunError,
        journal_persisted: bool,
    ) -> Result<T, TunError> {
        if self.backend.restore(&state.snapshot).is_err()
            || self.backend.verify_restored(&state.snapshot).is_err()
        {
            if !journal_persisted {
                let _ = self.journal.save(state);
            }
            return Err(TunError::RollbackFailed);
        }
        state.phase = TunJournalPhase::RolledBack;
        self.journal
            .save(state)
            .map_err(|_| TunError::RollbackJournalFailed)?;
        Err(cause)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPlanOnlyTunBackend;

impl WindowsPlanOnlyTunBackend {
    /// Validates the smallest safe plan but never translates it into shell or OS calls.
    pub fn validate_plan(plan: &TunPlan) -> Result<(), TunError> {
        plan.validate()?;
        Err(TunError::ProcessExclusionUnsupported)
    }
}

impl TunBackend for WindowsPlanOnlyTunBackend {
    fn capabilities(&self) -> PlatformCapability {
        PlatformCapability::plan_only_windows()
    }

    fn snapshot(&mut self) -> Result<NetworkSnapshot, TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }

    fn stage(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }

    fn apply(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }

    fn verify(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }

    fn commit(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }

    fn restore(&mut self, _snapshot: &NetworkSnapshot) -> Result<(), TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }

    fn verify_restored(&mut self, _snapshot: &NetworkSnapshot) -> Result<(), TunError> {
        Err(TunError::PlatformCapabilityUnsupported)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TunError {
    #[error("TUN risk consent is required")]
    ConsentRequired,
    #[error("verified application identity exclusion is unsupported")]
    ProcessExclusionUnsupported,
    #[error("required platform capability is unsupported")]
    PlatformCapabilityUnsupported,
    #[error("an application executable identity is missing")]
    ApplicationIdentityMissing,
    #[error("local proxy process identity is required")]
    LocalProcessIdentityRequired,
    #[error("a loopback endpoint is required")]
    LoopbackEndpointRequired,
    #[error("an executable identity is invalid")]
    InvalidExecutableIdentity,
    #[error("a process network policy is invalid")]
    InvalidProcessPolicy,
    #[error("an outlet is invalid")]
    InvalidOutlet,
    #[error("duplicate outlet identifier")]
    DuplicateOutlet,
    #[error("TUN plan is invalid")]
    InvalidPlan,
    #[error("TUN leak policy is invalid")]
    LeakPolicyInvalid,
    #[error("TUN outlet policy does not match its validated builder provenance")]
    CanonicalOutletMismatch,
    #[error("TUN state serialization is unsafe")]
    UnsafeSerializedState,
    #[error("another authority owns the TUN transaction")]
    AuthorityConflict,
    #[error("TUN generation is stale")]
    StaleGeneration,
    #[error("an interrupted TUN transaction must be recovered first")]
    RecoveryRequired,
    #[error("TUN disable requires an outstanding committed enable snapshot")]
    DisableRequiresCommittedSnapshot,
    #[error("TUN journal could not be read")]
    JournalRead,
    #[error("TUN journal could not be written")]
    JournalWrite,
    #[error("TUN journal is corrupt")]
    JournalCorrupt,
    #[error("TUN backend stage failed")]
    BackendStage,
    #[error("TUN backend apply failed")]
    BackendApply,
    #[error("TUN verification failed")]
    BackendVerify,
    #[error("TUN backend commit failed")]
    BackendCommit,
    #[error("TUN rollback failed")]
    RollbackFailed,
    #[error("TUN rollback journal failed")]
    RollbackJournalFailed,
}

fn validate_journal(journal: &TunJournal) -> Result<(), TunError> {
    validate_id(&journal.install_id)?;
    validate_id(&journal.authority_id)?;
    if journal.schema_version != JOURNAL_SCHEMA_VERSION
        || journal.generation == 0
        || journal.action != TunPlanAction::Enable
        || !valid_sha256(&journal.plan_fingerprint)
        || journal.snapshot.route_records.len() > 4096
        || journal.snapshot.dns_records.len() > 4096
        || journal.snapshot.adapter_records.len() > 4096
        || journal.snapshot.tun_records.len() > 4096
    {
        return Err(TunError::JournalCorrupt);
    }
    let records = journal
        .snapshot
        .route_records
        .iter()
        .chain(&journal.snapshot.dns_records)
        .chain(&journal.snapshot.adapter_records)
        .chain(&journal.snapshot.tun_records);
    for record in records {
        let lower = record.to_ascii_lowercase();
        if record.is_empty()
            || record.len() > 1024
            || [
                "secret",
                "token",
                "password",
                "credential",
                "subscription",
                "controller",
                "https://",
                "http://",
            ]
            .iter()
            .any(|term| lower.contains(term))
        {
            return Err(TunError::UnsafeSerializedState);
        }
    }
    let encoded = serde_json::to_string(journal).map_err(|_| TunError::JournalCorrupt)?;
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(TunError::JournalCorrupt);
    }
    if encoded.contains("DIRECT")
        || encoded.contains("subscription_url")
        || encoded.contains("token")
    {
        return Err(TunError::UnsafeSerializedState);
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), TunError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(TunError::InvalidOutlet);
    }
    Ok(())
}

fn validate_unique_ids(values: &[String]) -> Result<BTreeSet<&str>, TunError> {
    let mut ids = BTreeSet::new();
    for value in values {
        validate_id(value)?;
        if !ids.insert(value.as_str()) {
            return Err(TunError::InvalidOutlet);
        }
    }
    Ok(ids)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_local_windows_executable(value: &str) -> bool {
    if value.len() < 7 || value.len() > 1024 || value.starts_with("\\\\") {
        return false;
    }
    let bytes = value.as_bytes();
    bytes.get(1) == Some(&b':')
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .get(2)
            .is_some_and(|byte| matches!(byte, b'\\' | b'/'))
        && value.to_ascii_lowercase().ends_with(".exe")
        && !Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

fn validate_loopback_endpoint(value: &str) -> Result<(), TunError> {
    let lower = value.to_ascii_lowercase();
    let authority = ["socks5://", "socks5h://", "http://"]
        .into_iter()
        .find_map(|prefix| lower.strip_prefix(prefix))
        .ok_or(TunError::LoopbackEndpointRequired)?;
    let valid = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']')
            .is_some_and(|(host, suffix)| host == "::1" && valid_port_suffix(suffix))
    } else {
        authority.rsplit_once(':').is_some_and(|(host, port)| {
            matches!(host, "127.0.0.1" | "localhost") && valid_port(port)
        })
    };
    valid
        .then_some(())
        .ok_or(TunError::LoopbackEndpointRequired)
}

fn valid_port_suffix(value: &str) -> bool {
    value
        .strip_prefix(':')
        .is_some_and(|port| valid_port(port) && !port.contains('/'))
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn identity(role: ExecutableRole, outlet_id: Option<&str>, marker: char) -> ExecutableIdentity {
        ExecutableIdentity {
            role,
            canonical_path: format!(r"C:\Program Files\VPN Hub\{marker}.exe"),
            sha256: marker.to_string().repeat(64),
            outlet_id: outlet_id.map(str::to_owned),
        }
    }

    fn apps() -> Vec<ExecutableIdentity> {
        vec![
            identity(ExecutableRole::Gui, None, 'a'),
            identity(ExecutableRole::Core, None, 'b'),
            identity(ExecutableRole::Helper, None, 'c'),
        ]
    }

    fn subscription_config(id: &str) -> OutletConfig {
        OutletConfig {
            id: id.into(),
            label: format!("Subscription {id}"),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: format!("private.{id}"),
                provider_update_seconds: 180,
            },
        }
    }

    fn local_config(id: &str, endpoint: &str) -> OutletConfig {
        OutletConfig {
            id: id.into(),
            label: format!("Local {id}"),
            enabled: true,
            kind: OutletKind::LocalProxy {
                endpoint: endpoint.into(),
            },
        }
    }

    fn supported_evidence(config: &OutletConfig) -> UdpCapabilityEvidence {
        let mut evidence = vpn_hub_core::unknown_udp_evidence(config, "test_fixture");
        evidence.status = UdpCapabilityStatus::Supported;
        evidence
    }

    fn outlets() -> Vec<RegisteredOutlet> {
        let sub_a = subscription_config("sub-a");
        let sub_b = subscription_config("sub-b");
        let local_a = local_config("local-a", "socks5h://127.0.0.1:42661");
        let local_b = local_config("local-b", "http://[::1]:42662");
        vec![
            RegisteredOutlet {
                udp_evidence: Some(supported_evidence(&sub_a)),
                config: sub_a,
                healthy: true,
                executable: None,
            },
            RegisteredOutlet {
                config: sub_b,
                healthy: false,
                udp_evidence: None,
                executable: None,
            },
            RegisteredOutlet {
                udp_evidence: Some(supported_evidence(&local_a)),
                config: local_a,
                healthy: true,
                executable: Some(identity(ExecutableRole::LocalOutlet, Some("local-a"), 'd')),
            },
            RegisteredOutlet {
                config: local_b,
                healthy: false,
                udp_evidence: None,
                executable: Some(identity(ExecutableRole::LocalOutlet, Some("local-b"), 'e')),
            },
        ]
    }

    fn plan_with(outlets: &[RegisteredOutlet]) -> Result<TunPlan, TunError> {
        TunPlanBuilder {
            install_id: "install-a",
            authority_id: "helper-a",
            generation: 7,
            requested_enabled: true,
            consent: TunConsent {
                accepted: true,
                risk_version: CONSENT_VERSION,
            },
            capabilities: &PlatformCapability::fake_verified(),
            application_identities: &apps(),
            outlets,
        }
        .build()
    }

    fn disable_plan(generation: u64) -> TunPlan {
        TunPlanBuilder {
            install_id: "install-a",
            authority_id: "helper-a",
            generation,
            requested_enabled: false,
            consent: TunConsent::default(),
            capabilities: &PlatformCapability::plan_only_windows(),
            application_identities: &[],
            outlets: &[],
        }
        .build()
        .unwrap()
    }

    fn test_authority(generation: u64) -> (tempfile::TempDir, TunAuthorityGuard) {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("tun-authority.lease");
        fs::write(&path, b"preprovisioned-by-installer").unwrap();
        let authority =
            TunAuthorityGuard::acquire_at(&path, "install-a", "helper-a", generation).unwrap();
        (temporary, authority)
    }

    fn committed_state(plan: &TunPlan) -> TunJournal {
        TunJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id: plan.install_id.clone(),
            authority_id: plan.authority_id.clone(),
            generation: plan.generation,
            action: TunPlanAction::Enable,
            plan_fingerprint: plan.fingerprint(),
            phase: TunJournalPhase::Committed,
            snapshot: NetworkSnapshot {
                route_records: vec!["route-snapshot-a".into()],
                dns_records: vec!["dns-snapshot-a".into()],
                adapter_records: vec!["adapter-snapshot-a".into()],
                tun_records: vec!["tun-snapshot-a".into()],
            },
        }
    }

    #[test]
    fn default_is_off_and_first_enable_requires_current_consent() {
        assert!(!TunConsent::default().accepted);
        let plan = TunPlanBuilder {
            install_id: "install-a",
            authority_id: "helper-a",
            generation: 1,
            requested_enabled: false,
            consent: TunConsent::default(),
            capabilities: &PlatformCapability::plan_only_windows(),
            application_identities: &[],
            outlets: &[],
        }
        .build()
        .unwrap();
        assert_eq!(plan.action, TunPlanAction::Disable);
        assert!(matches!(
            TunPlanBuilder {
                requested_enabled: true,
                ..TunPlanBuilder {
                    install_id: "install-a",
                    authority_id: "helper-a",
                    generation: 1,
                    requested_enabled: false,
                    consent: TunConsent::default(),
                    capabilities: &PlatformCapability::fake_verified(),
                    application_identities: &apps(),
                    outlets: &outlets(),
                }
            }
            .build(),
            Err(TunError::ConsentRequired)
        ));
    }

    #[test]
    fn dynamic_subscriptions_and_local_proxies_keep_stable_exact_exclusions() {
        let current = outlets();
        let first = plan_with(&current).unwrap();
        assert_eq!(first.local_endpoints.len(), 2);
        assert_eq!(first.process_rules.len(), 5);
        let mut changed = current.clone();
        changed.remove(2);
        let local_c = local_config("local-c", "socks5://localhost:42663");
        changed.push(RegisteredOutlet {
            udp_evidence: Some(supported_evidence(&local_c)),
            config: local_c,
            healthy: true,
            executable: Some(identity(ExecutableRole::LocalOutlet, Some("local-c"), 'f')),
        });
        let second = plan_with(&changed).unwrap();
        assert!(!second.local_endpoints.contains_key("local-a"));
        assert!(second.local_endpoints.contains_key("local-c"));
        assert!(second.process_rules.iter().all(|item| {
            item.identity.outlet_id.as_deref() != Some("local-a")
                && item.identity.canonical_path != r"C:\Unknown\mystery.exe"
        }));
    }

    #[test]
    fn local_proxy_requires_loopback_and_exact_executable_identity() {
        let mut current = outlets();
        current[2].config.kind = OutletKind::LocalProxy {
            endpoint: "socks5://192.0.2.10:42".into(),
        };
        assert_eq!(plan_with(&current), Err(TunError::LoopbackEndpointRequired));
        current[2].config.kind = OutletKind::LocalProxy {
            endpoint: "socks5://127.0.0.1:42".into(),
        };
        current[2].executable = None;
        assert_eq!(
            plan_with(&current),
            Err(TunError::LocalProcessIdentityRequired)
        );
        current[2].executable = Some(identity(
            ExecutableRole::LocalOutlet,
            Some("other-outlet"),
            'd',
        ));
        assert_eq!(
            plan_with(&current),
            Err(TunError::LocalProcessIdentityRequired)
        );
    }

    #[test]
    fn production_windows_adapter_fails_closed_without_verified_process_exclusion() {
        let current = outlets();
        let result = TunPlanBuilder {
            install_id: "install-a",
            authority_id: "helper-a",
            generation: 1,
            requested_enabled: true,
            consent: TunConsent {
                accepted: true,
                risk_version: CONSENT_VERSION,
            },
            capabilities: &PlatformCapability::plan_only_windows(),
            application_identities: &apps(),
            outlets: &current,
        }
        .build();
        assert_eq!(result, Err(TunError::ProcessExclusionUnsupported));
    }

    #[test]
    fn all_down_matrix_rejects_ipv4_ipv6_tcp_udp_and_dns_without_direct() {
        let mut current = outlets();
        for outlet in &mut current {
            outlet.healthy = false;
        }
        let plan = plan_with(&current).unwrap();
        assert!(plan.all_down);
        assert_eq!(plan.leak_checks.len(), 8);
        assert!(
            plan.leak_checks
                .iter()
                .all(|check| check.expected == ExpectedDisposition::Rejected)
        );
        let encoded = serde_json::to_string(&plan).unwrap();
        assert!(!encoded.contains("DIRECT"));
    }

    #[test]
    fn tcp_only_outlets_reject_udp_vectors_but_keep_tcp_tunneled() {
        let mut current = outlets();
        for outlet in &mut current {
            let mut evidence = vpn_hub_core::unknown_udp_evidence(&outlet.config, "tcp_only");
            evidence.status = UdpCapabilityStatus::TcpOnly;
            outlet.udp_evidence = Some(evidence);
        }
        let plan = plan_with(&current).unwrap();
        assert!(!plan.all_down);
        assert!(plan.udp_eligible_outlets.is_empty());
        assert!(plan.leak_checks.iter().all(|check| match check.transport {
            TransportProtocol::Tcp => check.expected == ExpectedDisposition::Tunneled,
            TransportProtocol::Udp => check.expected == ExpectedDisposition::Rejected,
        }));
    }

    #[test]
    fn control_plane_processes_never_receive_infrastructure_bypass() {
        let plan = plan_with(&outlets()).unwrap();
        assert!(
            plan.process_rules
                .iter()
                .all(|rule| match rule.identity.role {
                    ExecutableRole::Gui | ExecutableRole::Helper => {
                        rule.policy == ProcessNetworkPolicy::ControlPlaneDenyEgress
                    }
                    ExecutableRole::Core =>
                        rule.policy == ProcessNetworkPolicy::OwnedCoreUpstreamOnly,
                    ExecutableRole::LocalOutlet => {
                        rule.policy == ProcessNetworkPolicy::RegisteredOutletInfrastructureBypass
                    }
                })
        );
    }

    #[test]
    fn tampered_plan_cannot_expand_process_or_leak_policy() {
        let original = plan_with(&outlets()).unwrap();
        let mut wrong_process_policy = original.clone();
        wrong_process_policy.process_rules[0].policy =
            ProcessNetworkPolicy::RegisteredOutletInfrastructureBypass;
        assert_eq!(
            wrong_process_policy.validate(),
            Err(TunError::InvalidProcessPolicy)
        );

        let mut orphan_endpoint = original.clone();
        orphan_endpoint
            .process_rules
            .retain(|rule| rule.identity.outlet_id.as_deref() != Some("local-a"));
        assert_eq!(
            orphan_endpoint.validate(),
            Err(TunError::LocalProcessIdentityRequired)
        );

        let mut udp_escape = original.clone();
        udp_escape.udp_eligible_outlets.push("unknown-udp".into());
        assert_eq!(udp_escape.validate(), Err(TunError::LeakPolicyInvalid));

        let mut tcp_escape = original.clone();
        tcp_escape.tcp_eligible_outlets.push("unknown-tcp".into());
        assert_eq!(tcp_escape.validate(), Err(TunError::LeakPolicyInvalid));

        let mut missing_declaration = original.clone();
        missing_declaration
            .outlet_registry
            .retain(|item| item.outlet_id != "sub-a");
        assert_eq!(
            missing_declaration.validate(),
            Err(TunError::CanonicalOutletMismatch)
        );

        let mut orphan_local_declaration = original.clone();
        orphan_local_declaration
            .outlet_registry
            .push(OutletDeclaration {
                outlet_id: "local-orphan".into(),
                transport: OutletTransport::LocalProxy,
                loopback_endpoint: Some("socks5://127.0.0.1:42663".into()),
            });
        assert_eq!(
            orphan_local_declaration.validate(),
            Err(TunError::InvalidOutlet)
        );

        let mut self_consistent_subscription_injection = original.clone();
        self_consistent_subscription_injection
            .outlet_registry
            .push(OutletDeclaration {
                outlet_id: "injected-sub".into(),
                transport: OutletTransport::Subscription,
                loopback_endpoint: None,
            });
        self_consistent_subscription_injection
            .tcp_eligible_outlets
            .push("injected-sub".into());
        assert_eq!(
            self_consistent_subscription_injection.validate(),
            Err(TunError::CanonicalOutletMismatch)
        );

        let mut self_consistent_local_injection = original.clone();
        self_consistent_local_injection
            .outlet_registry
            .push(OutletDeclaration {
                outlet_id: "injected-local".into(),
                transport: OutletTransport::LocalProxy,
                loopback_endpoint: Some("socks5://127.0.0.1:42664".into()),
            });
        self_consistent_local_injection
            .local_endpoints
            .insert("injected-local".into(), "socks5://127.0.0.1:42664".into());
        self_consistent_local_injection
            .process_rules
            .push(ProcessRule {
                identity: identity(ExecutableRole::LocalOutlet, Some("injected-local"), 'f'),
                policy: ProcessNetworkPolicy::RegisteredOutletInfrastructureBypass,
            });
        self_consistent_local_injection
            .tcp_eligible_outlets
            .push("injected-local".into());
        assert_eq!(
            self_consistent_local_injection.validate(),
            Err(TunError::CanonicalOutletMismatch)
        );

        let mut duplicate_vector = original;
        duplicate_vector.leak_checks[0] = duplicate_vector.leak_checks[1].clone();
        assert_eq!(
            duplicate_vector.validate(),
            Err(TunError::LeakPolicyInvalid)
        );
    }

    #[test]
    fn plan_registry_is_sanitized_and_contains_no_subscription_secrets() {
        let plan = plan_with(&outlets()).unwrap();
        assert_eq!(plan.outlet_registry.len(), 4);
        let encoded = serde_json::to_string(&plan).unwrap();
        assert!(!encoded.contains("private.sub-a"));
        assert!(!encoded.contains("secret_ref"));
        assert!(!encoded.contains("subscription_url"));
        assert!(!encoded.contains("controller"));
    }

    #[test]
    fn every_malformed_stale_or_non_supported_udp_evidence_field_is_rejected_by_core() {
        let mutations: [fn(&mut UdpCapabilityEvidence); 9] = [
            |item| item.outlet_id = "other-outlet".into(),
            |item| item.status = UdpCapabilityStatus::Unknown,
            |item| item.observed_at.clear(),
            |item| item.evidence_version += 1,
            |item| item.probe_version.push_str("-stale"),
            |item| item.model_version += 1,
            |item| item.configuration_fingerprint.push('0'),
            |item| item.configuration_generation = item.configuration_generation.saturating_add(1),
            |item| item.reason_code.clear(),
        ];
        for mutate in mutations {
            let mut current = outlets();
            mutate(current[0].udp_evidence.as_mut().unwrap());
            let plan = plan_with(&current).unwrap();
            assert!(!plan.udp_eligible_outlets.iter().any(|id| id == "sub-a"));
        }

        let mut changed_configuration = outlets();
        changed_configuration[0].config.label.push_str(" changed");
        let plan = plan_with(&changed_configuration).unwrap();
        assert!(!plan.udp_eligible_outlets.iter().any(|id| id == "sub-a"));
    }

    #[test]
    fn authority_file_must_exist_and_is_exclusive_across_handles() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join("missing-tun-authority.lease");
        assert!(matches!(
            TunAuthorityGuard::acquire_at(&missing, "install-a", "helper-a", 7),
            Err(TunError::AuthorityConflict)
        ));
        assert!(!missing.exists());

        let path = temporary.path().join("tun-authority.lease");
        fs::write(&path, b"preprovisioned-by-installer").unwrap();
        let first = TunAuthorityGuard::acquire_at(&path, "install-a", "helper-a", 7).unwrap();
        assert!(matches!(
            TunAuthorityGuard::acquire_at(&path, "install-a", "helper-a", 8),
            Err(TunError::AuthorityConflict)
        ));
        drop(first);
        assert!(TunAuthorityGuard::acquire_at(&path, "install-a", "helper-a", 8).is_ok());
    }

    #[test]
    fn authority_identity_and_generation_are_checked_before_snapshot() {
        let plan = plan_with(&outlets()).unwrap();
        let (_authority_directory, wrong_generation) = test_authority(plan.generation + 1);
        let mut transaction = TunTransaction::new(
            FakeBackend::default(),
            MemoryJournal::default(),
            wrong_generation,
        );
        assert_eq!(transaction.apply(&plan), Err(TunError::AuthorityConflict));
        assert!(transaction.backend.events.is_empty());
        assert_eq!(transaction.journal.save_count, 0);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FailurePoint {
        Snapshot,
        Stage,
        Apply,
        Verify,
        Commit,
        Restore,
        VerifyRestored,
    }

    #[derive(Default)]
    struct FakeBackend {
        failures: VecDeque<FailurePoint>,
        events: Vec<&'static str>,
        process_rules: Vec<ProcessRule>,
    }

    impl FakeBackend {
        fn fail(point: FailurePoint) -> Self {
            Self {
                failures: VecDeque::from([point]),
                ..Self::default()
            }
        }

        fn fail_in_order(points: impl IntoIterator<Item = FailurePoint>) -> Self {
            Self {
                failures: points.into_iter().collect(),
                ..Self::default()
            }
        }

        fn boundary(&mut self, point: FailurePoint, event: &'static str) -> Result<(), TunError> {
            self.events.push(event);
            if self.failures.front() == Some(&point) {
                self.failures.pop_front();
                return Err(match point {
                    FailurePoint::Stage => TunError::BackendStage,
                    FailurePoint::Apply => TunError::BackendApply,
                    FailurePoint::Verify | FailurePoint::VerifyRestored => TunError::BackendVerify,
                    FailurePoint::Commit => TunError::BackendCommit,
                    FailurePoint::Snapshot | FailurePoint::Restore => TunError::RollbackFailed,
                });
            }
            Ok(())
        }
    }

    impl TunBackend for FakeBackend {
        fn capabilities(&self) -> PlatformCapability {
            PlatformCapability::fake_verified()
        }

        fn snapshot(&mut self) -> Result<NetworkSnapshot, TunError> {
            self.boundary(FailurePoint::Snapshot, "snapshot")?;
            Ok(NetworkSnapshot {
                route_records: vec!["route-snapshot-a".into()],
                dns_records: vec!["dns-snapshot-a".into()],
                adapter_records: vec!["adapter-snapshot-a".into()],
                tun_records: vec!["tun-snapshot-a".into()],
            })
        }

        fn stage(&mut self, plan: &TunPlan) -> Result<(), TunError> {
            self.process_rules.clone_from(&plan.process_rules);
            self.boundary(FailurePoint::Stage, "stage")
        }

        fn apply(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
            self.boundary(FailurePoint::Apply, "apply")
        }

        fn verify(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
            self.boundary(FailurePoint::Verify, "verify")
        }

        fn commit(&mut self, _plan: &TunPlan) -> Result<(), TunError> {
            self.boundary(FailurePoint::Commit, "commit")
        }

        fn restore(&mut self, _snapshot: &NetworkSnapshot) -> Result<(), TunError> {
            self.boundary(FailurePoint::Restore, "restore")
        }

        fn verify_restored(&mut self, _snapshot: &NetworkSnapshot) -> Result<(), TunError> {
            self.boundary(FailurePoint::VerifyRestored, "verify-restored")
        }
    }

    #[derive(Default)]
    struct MemoryJournal {
        state: Option<TunJournal>,
        fail_on_save: Option<usize>,
        save_count: usize,
        fail_clear_once: bool,
        clear_count: usize,
    }

    impl TunJournalStore for MemoryJournal {
        fn load(&self) -> Result<Option<TunJournal>, TunError> {
            Ok(self.state.clone())
        }

        fn save(&mut self, journal: &TunJournal) -> Result<(), TunError> {
            self.save_count += 1;
            if self.fail_on_save == Some(self.save_count) {
                return Err(TunError::JournalWrite);
            }
            self.state = Some(journal.clone());
            Ok(())
        }

        fn clear(&mut self) -> Result<(), TunError> {
            self.clear_count += 1;
            if self.fail_clear_once {
                self.fail_clear_once = false;
                return Err(TunError::JournalWrite);
            }
            self.state = None;
            Ok(())
        }
    }

    #[test]
    fn transaction_persists_every_boundary_and_commits() {
        let plan = plan_with(&outlets()).unwrap();
        let (_authority_directory, authority) = test_authority(plan.generation);
        let mut transaction =
            TunTransaction::new(FakeBackend::default(), MemoryJournal::default(), authority);
        let state = transaction.apply(&plan).unwrap();
        assert_eq!(state.phase, TunJournalPhase::Committed);
        assert_eq!(transaction.journal.save_count, 5);
        assert_eq!(
            transaction.backend.events,
            ["snapshot", "stage", "apply", "verify", "commit"]
        );
        assert!(
            transaction
                .backend
                .process_rules
                .iter()
                .all(|item| item.identity.canonical_path != r"C:\Unknown\mystery.exe")
        );
    }

    #[test]
    fn every_os_mutation_failure_rolls_back_to_snapshot() {
        let plan = plan_with(&outlets()).unwrap();
        for point in [
            FailurePoint::Stage,
            FailurePoint::Apply,
            FailurePoint::Verify,
            FailurePoint::Commit,
        ] {
            let (_authority_directory, authority) = test_authority(plan.generation);
            let mut transaction = TunTransaction::new(
                FakeBackend::fail(point),
                MemoryJournal::default(),
                authority,
            );
            assert!(transaction.apply(&plan).is_err());
            assert_eq!(transaction.backend.events.last(), Some(&"verify-restored"));
            assert_eq!(
                transaction.journal.state.as_ref().map(|state| state.phase),
                Some(TunJournalPhase::RolledBack)
            );
        }
    }

    #[test]
    fn every_journal_boundary_failure_rolls_back() {
        let plan = plan_with(&outlets()).unwrap();
        for save in 1..=5 {
            let journal = MemoryJournal {
                fail_on_save: Some(save),
                ..MemoryJournal::default()
            };
            let (_authority_directory, authority) = test_authority(plan.generation);
            let mut transaction = TunTransaction::new(FakeBackend::default(), journal, authority);
            assert!(transaction.apply(&plan).is_err());
            assert_eq!(transaction.backend.events.last(), Some(&"verify-restored"));
        }
    }

    #[test]
    fn rollback_verification_failure_keeps_every_backend_boundary_recoverable() {
        let plan = plan_with(&outlets()).unwrap();
        for point in [
            FailurePoint::Stage,
            FailurePoint::Apply,
            FailurePoint::Verify,
            FailurePoint::Commit,
        ] {
            let (_authority_directory, authority) = test_authority(plan.generation);
            let mut transaction = TunTransaction::new(
                FakeBackend::fail_in_order([point, FailurePoint::VerifyRestored]),
                MemoryJournal::default(),
                authority,
            );
            assert_eq!(transaction.apply(&plan), Err(TunError::RollbackFailed));
            assert_ne!(
                transaction.journal.state.as_ref().map(|state| state.phase),
                Some(TunJournalPhase::RolledBack)
            );
            assert!(transaction.recover("install-a", "helper-a").unwrap());
            assert!(transaction.journal.state.is_none());
        }
    }

    #[test]
    fn rollback_verification_failure_keeps_every_journal_boundary_recoverable() {
        let plan = plan_with(&outlets()).unwrap();
        for save in 1..=5 {
            let journal = MemoryJournal {
                fail_on_save: Some(save),
                ..MemoryJournal::default()
            };
            let (_authority_directory, authority) = test_authority(plan.generation);
            let mut transaction = TunTransaction::new(
                FakeBackend::fail(FailurePoint::VerifyRestored),
                journal,
                authority,
            );
            assert_eq!(transaction.apply(&plan), Err(TunError::RollbackFailed));
            assert!(transaction.journal.state.is_some());
            assert_ne!(
                transaction.journal.state.as_ref().map(|state| state.phase),
                Some(TunJournalPhase::RolledBack)
            );
            assert!(transaction.recover("install-a", "helper-a").unwrap());
            assert!(transaction.journal.state.is_none());
        }
    }

    #[test]
    fn first_journal_save_and_rollback_verify_failure_survive_transaction_restart() {
        let plan = plan_with(&outlets()).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let authority_path = temporary.path().join("tun-authority.lease");
        fs::write(&authority_path, b"preprovisioned-by-installer").unwrap();
        let authority = TunAuthorityGuard::acquire_at(
            &authority_path,
            &plan.install_id,
            &plan.authority_id,
            plan.generation,
        )
        .unwrap();
        let mut transaction = TunTransaction::new(
            FakeBackend::fail(FailurePoint::VerifyRestored),
            MemoryJournal {
                fail_on_save: Some(1),
                ..MemoryJournal::default()
            },
            authority,
        );
        assert_eq!(transaction.apply(&plan), Err(TunError::RollbackFailed));
        assert_eq!(
            transaction.journal.state.as_ref().map(|state| state.phase),
            Some(TunJournalPhase::Snapshotted)
        );

        let TunTransaction {
            journal, authority, ..
        } = transaction;
        drop(authority);
        let restarted_authority = TunAuthorityGuard::acquire_at(
            &authority_path,
            &plan.install_id,
            &plan.authority_id,
            plan.generation,
        )
        .unwrap();
        let mut restarted =
            TunTransaction::new(FakeBackend::default(), journal, restarted_authority);
        assert!(restarted.recover("install-a", "helper-a").unwrap());
        assert!(restarted.journal.state.is_none());
        assert_eq!(restarted.backend.events, ["restore", "verify-restored"]);
    }

    #[test]
    fn first_journal_failure_reports_failed_restore_instead_of_hiding_it() {
        let plan = plan_with(&outlets()).unwrap();
        let journal = MemoryJournal {
            fail_on_save: Some(1),
            ..MemoryJournal::default()
        };
        let (_authority_directory, authority) = test_authority(plan.generation);
        let mut transaction =
            TunTransaction::new(FakeBackend::fail(FailurePoint::Restore), journal, authority);
        assert_eq!(transaction.apply(&plan), Err(TunError::RollbackFailed));
    }

    #[test]
    fn crash_cancel_restart_and_uninstall_recovery_are_idempotent() {
        let plan = plan_with(&outlets()).unwrap();
        let (_authority_directory, authority) = test_authority(plan.generation);
        let mut transaction =
            TunTransaction::new(FakeBackend::default(), MemoryJournal::default(), authority);
        transaction.apply(&plan).unwrap();
        assert!(transaction.recover("install-a", "helper-a").unwrap());
        assert!(!transaction.recover("install-a", "helper-a").unwrap());
        assert_eq!(
            transaction.backend.events,
            [
                "snapshot",
                "stage",
                "apply",
                "verify",
                "commit",
                "restore",
                "verify-restored"
            ]
        );
    }

    #[test]
    fn disable_restores_committed_enable_snapshot_without_taking_a_new_snapshot() {
        let enable = plan_with(&outlets()).unwrap();
        let disable = disable_plan(enable.generation + 1);
        let (_authority_directory, authority) = test_authority(disable.generation);
        let mut transaction = TunTransaction::new(
            FakeBackend::default(),
            MemoryJournal {
                state: Some(committed_state(&enable)),
                ..MemoryJournal::default()
            },
            authority,
        );

        assert!(transaction.disable(&disable).unwrap());
        assert_eq!(transaction.backend.events, ["restore", "verify-restored"]);
        assert!(transaction.journal.state.is_none());
        assert_eq!(transaction.journal.clear_count, 1);
        assert!(!transaction.disable(&disable).unwrap());
    }

    #[test]
    fn apply_rejects_disable_before_snapshot_or_mutation() {
        let disable = disable_plan(8);
        let (_authority_directory, authority) = test_authority(disable.generation);
        let mut transaction =
            TunTransaction::new(FakeBackend::default(), MemoryJournal::default(), authority);
        assert_eq!(
            transaction.apply(&disable),
            Err(TunError::DisableRequiresCommittedSnapshot)
        );
        assert!(transaction.backend.events.is_empty());
        assert_eq!(transaction.journal.save_count, 0);
    }

    #[test]
    fn disable_retries_restore_when_restored_phase_save_fails() {
        let enable = plan_with(&outlets()).unwrap();
        let disable = disable_plan(enable.generation + 1);
        let (_authority_directory, authority) = test_authority(disable.generation);
        let mut transaction = TunTransaction::new(
            FakeBackend::default(),
            MemoryJournal {
                state: Some(committed_state(&enable)),
                fail_on_save: Some(1),
                ..MemoryJournal::default()
            },
            authority,
        );

        assert_eq!(transaction.disable(&disable), Err(TunError::JournalWrite));
        assert_eq!(
            transaction.journal.state.as_ref().map(|state| state.phase),
            Some(TunJournalPhase::Committed)
        );
        assert!(transaction.disable(&disable).unwrap());
        assert_eq!(
            transaction.backend.events,
            ["restore", "verify-restored", "restore", "verify-restored"]
        );
        assert!(transaction.journal.state.is_none());
    }

    #[test]
    fn disable_retries_only_verification_when_journal_clear_fails() {
        let enable = plan_with(&outlets()).unwrap();
        let disable = disable_plan(enable.generation + 1);
        let (_authority_directory, authority) = test_authority(disable.generation);
        let mut transaction = TunTransaction::new(
            FakeBackend::default(),
            MemoryJournal {
                state: Some(committed_state(&enable)),
                fail_clear_once: true,
                ..MemoryJournal::default()
            },
            authority,
        );

        assert_eq!(transaction.disable(&disable), Err(TunError::JournalWrite));
        assert_eq!(
            transaction.journal.state.as_ref().map(|state| state.phase),
            Some(TunJournalPhase::Restored)
        );
        assert!(transaction.disable(&disable).unwrap());
        assert_eq!(
            transaction.backend.events,
            ["restore", "verify-restored", "verify-restored"]
        );
        assert_eq!(transaction.journal.clear_count, 2);
        assert!(transaction.journal.state.is_none());
    }

    #[test]
    fn stale_generation_and_second_authority_are_rejected() {
        let plan = plan_with(&outlets()).unwrap();
        let existing = TunJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id: plan.install_id.clone(),
            authority_id: plan.authority_id.clone(),
            generation: plan.generation,
            action: TunPlanAction::Enable,
            plan_fingerprint: plan.fingerprint(),
            phase: TunJournalPhase::Applied,
            snapshot: NetworkSnapshot::default(),
        };
        let (_authority_directory, authority) = test_authority(plan.generation);
        let mut transaction = TunTransaction::new(
            FakeBackend::default(),
            MemoryJournal {
                state: Some(existing.clone()),
                ..MemoryJournal::default()
            },
            authority,
        );
        assert_eq!(transaction.apply(&plan), Err(TunError::StaleGeneration));
        let mut other = plan.clone();
        other.authority_id = "desktop-b".into();
        assert_eq!(transaction.apply(&other), Err(TunError::AuthorityConflict));
    }

    #[test]
    fn journal_is_durable_sanitized_and_recoverable() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("tun-transaction.json");
        let plan = plan_with(&outlets()).unwrap();
        let (_authority_directory, authority) = test_authority(plan.generation);
        let mut transaction = TunTransaction::new(
            FakeBackend::default(),
            FileTunJournalStore::new(path.clone()),
            authority,
        );
        transaction.apply(&plan).unwrap();
        let bytes = fs::read(&path).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("DIRECT"));
        assert!(!text.contains("subscription_url"));
        assert!(!text.contains("controller"));
        assert!(transaction.recover("install-a", "helper-a").unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn file_journal_loads_backup_after_primary_corruption() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("tun-transaction.json");
        let plan = plan_with(&outlets()).unwrap();
        let mut store = FileTunJournalStore::new(path.clone());
        let state = TunJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id: plan.install_id.clone(),
            authority_id: plan.authority_id.clone(),
            generation: plan.generation,
            action: TunPlanAction::Enable,
            plan_fingerprint: plan.fingerprint(),
            phase: TunJournalPhase::Snapshotted,
            snapshot: NetworkSnapshot::default(),
        };
        store.save(&state).unwrap();
        let mut next = state.clone();
        next.phase = TunJournalPhase::Staged;
        store.save(&next).unwrap();
        fs::write(&path, b"corrupt-primary").unwrap();
        assert_eq!(store.load().unwrap(), Some(next));
    }

    #[test]
    fn journal_rejects_oversized_and_secret_shaped_opaque_records() {
        let plan = plan_with(&outlets()).unwrap();
        let mut state = TunJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id: plan.install_id.clone(),
            authority_id: plan.authority_id.clone(),
            generation: plan.generation,
            action: TunPlanAction::Enable,
            plan_fingerprint: plan.fingerprint(),
            phase: TunJournalPhase::Snapshotted,
            snapshot: NetworkSnapshot::default(),
        };
        state.snapshot.route_records.push("x".repeat(1025));
        assert_eq!(
            validate_journal(&state),
            Err(TunError::UnsafeSerializedState)
        );
        state.snapshot.route_records = vec!["controller-token=value".into()];
        assert_eq!(
            validate_journal(&state),
            Err(TunError::UnsafeSerializedState)
        );
    }
}
