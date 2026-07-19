//! VPN Hub Guardian core.
//!
//! This crate deliberately has no API for changing the Windows system proxy or
//! binding the product entry port. It only probes explicitly configured local
//! proxy outlets and records sanitized health data.

mod config;
mod controller;
mod mihomo;
mod model;
mod probe;
mod routing;
mod store;

pub use config::{ConfigError, GuardianConfig, MonitorConfig, OutletConfig};
pub use controller::{ControllerClient, ControllerError};
pub use mihomo::{
    FAIL_CLOSED_PROXY, LOCAL_PROXY, MASTER_SELECTOR, PrivateConfigError, PrivateConfigSummary,
    PrivateRoutingConfig, RuntimeConfigSummary, SUBSCRIPTION_PROXY, generate_controller_secret,
    generate_mihomo_config, outlet_proxy_name,
};
pub use model::{
    HealthStatus, LatencySample, OutletSummary, ProbeResult, RouteSwitchEvent, StateEvent,
};
pub use probe::probe_outlet;
pub use routing::{
    FAIL_CLOSED_OUTLET, LOCAL_OUTLET, OutletHealth, RouteDecision, RouteMode, RoutingEngine,
    RoutingPolicy, SUBSCRIPTION_OUTLET,
};
pub use store::{GuardianStore, StoreError};
