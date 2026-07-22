//! VPN Hub Guardian core.
//!
//! This crate deliberately has no API for changing the Windows system proxy or
//! binding the product entry port. It only probes explicitly configured local
//! proxy outlets and records sanitized health data.

mod config;
mod controller;
mod durable;
mod entry_switch;
mod guardian_cycle;
mod history;
mod mihomo;
mod model;
mod probe;
mod routing;
mod secret_store;
mod settings;
mod store;
mod udp_capability;

pub use config::{ConfigError, GuardianConfig, MonitorConfig, ProbeOutletConfig};
pub use controller::{ControllerClient, ControllerError, SelectorNodeSnapshot, SubscriptionNode};
pub use durable::{
    DurableFileOps, SystemDurableFileOps, durable_atomic_save_with_backup,
    durable_remove_if_exists, durable_replace, durable_write_new,
};
pub use entry_switch::{
    ConfidentialProtector, ConsentKey, EntryBackend, EntrySwitchAudit, EntrySwitchAuthorityGuard,
    EntrySwitchConsent, EntrySwitchContext, EntrySwitchError, EntrySwitchJournal,
    EntrySwitchJournalRecord, EntrySwitchPhase, EntrySwitchPlan, EntrySwitchPlanner,
    EntrySwitchRequest, EntrySwitchTransaction, MemoryEntrySwitchJournal, OwnedCoreIdentity,
    PortOwnership, ProtectedJournalCodec, ProtectedJournalState, ProxyBackend, ProxyCapability,
    StageDeclaration, SwitchVerification, SystemProxySnapshot, SystemTrustedClock, TrustedClock,
    WindowsProxyMode,
};
pub use guardian_cycle::{
    DEFAULT_GUARDIAN_CONCURRENCY, DEFAULT_GUARDIAN_CYCLE_BUDGET, GuardianCycleError,
    GuardianCycleOutcome, RoutingSession, RoutingStateError, run_controller_guardian_cycle,
    run_controller_guardian_cycle_controlled,
};
pub use history::{
    HistoryEventType, HistoryExport, HistoryFilter, HistoryMetric, HistoryOutletKind,
    HistoryOutletOption, HistoryOutletSnapshot, HistoryRecord, HistoryResponse, HistoryWindow,
};
pub use mihomo::{
    CURRENT_CONFIG_VERSION, EntryConfig, FAIL_CLOSED_PROXY, MASTER_SELECTOR, OutletConfig,
    OutletConfigSummary, OutletKind, PrivateConfigError, PrivateConfigSummary,
    PrivateRoutingConfig, ResolvedSubscriptionUrls, RuntimeConfigSummary, UDP_SELECTOR,
    UdpCapabilityMap, generate_controller_secret, generate_mihomo_config,
    generate_mihomo_config_with_udp_capabilities, generate_mihomo_startup_config,
    normalize_loopback_host, outlet_proxy_name, provider_name, validate_subscription_url,
};
pub use model::{
    HealthStatus, LatencySample, OutletSummary, ProbeResult, RouteSwitchEvent, StateEvent,
    UdpCapabilityEvidence, UdpCapabilityStatus,
};
pub use probe::probe_outlet;
pub use routing::{
    FAIL_CLOSED_OUTLET, OutletHealth, RouteDecision, RouteMode, RoutingEngine, RoutingPolicy,
};
pub use secret_store::{
    CredentialState, LegacyMigrationOutcome, SecretStore, SecretStoreError,
    SubscriptionCredentialStatus, SubscriptionSecrets, SystemSecretStore,
    migrate_legacy_subscription,
};
pub use settings::{
    LocalProxyProtocol, SafeSettingsView, SafeSubscriptionStatus, SettingsChange, SettingsDiff,
    SettingsDraft, SettingsImpact, SettingsOutletDraft, ValidationIssue,
};
pub use store::{GuardianStore, StoreError};
pub use udp_capability::{
    UDP_EVIDENCE_VERSION, UDP_MODEL_VERSION, UDP_PROBE_VERSION, UdpProbeError, UdpProbeTarget,
    classify_subscription_udp, current_udp_status, is_current_udp_evidence,
    outlet_udp_configuration, probe_authorized_socks5_udp, probe_local_proxy_udp,
    unknown_udp_evidence,
};
