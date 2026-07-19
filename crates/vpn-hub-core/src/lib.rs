//! VPN Hub Guardian core.
//!
//! This crate deliberately has no API for changing the Windows system proxy or
//! binding the product entry port. It only probes explicitly configured local
//! proxy outlets and records sanitized health data.

mod config;
mod controller;
mod guardian_cycle;
mod mihomo;
mod model;
mod probe;
mod routing;
mod secret_store;
mod store;
mod udp_capability;

pub use config::{ConfigError, GuardianConfig, MonitorConfig, ProbeOutletConfig};
pub use controller::{ControllerClient, ControllerError};
pub use guardian_cycle::{
    GuardianCycleError, GuardianCycleOutcome, RoutingSession, RoutingStateError,
    run_controller_guardian_cycle,
};
pub use mihomo::{
    CURRENT_CONFIG_VERSION, EntryConfig, FAIL_CLOSED_PROXY, MASTER_SELECTOR, OutletConfig,
    OutletConfigSummary, OutletKind, PrivateConfigError, PrivateConfigSummary,
    PrivateRoutingConfig, ResolvedSubscriptionUrls, RuntimeConfigSummary, UDP_SELECTOR,
    UdpCapabilityMap, generate_controller_secret, generate_mihomo_config,
    generate_mihomo_config_with_udp_capabilities, outlet_proxy_name,
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
pub use store::{GuardianStore, StoreError};
pub use udp_capability::{
    UDP_EVIDENCE_VERSION, UDP_MODEL_VERSION, UDP_PROBE_VERSION, UdpProbeTarget,
    classify_subscription_udp, probe_local_proxy_udp, unknown_udp_evidence,
};
