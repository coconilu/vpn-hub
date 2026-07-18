//! VPN Hub Guardian core.
//!
//! This crate deliberately has no API for changing the Windows system proxy or
//! binding the product entry port. It only probes explicitly configured local
//! proxy outlets and records sanitized health data.

mod config;
mod model;
mod probe;
mod store;

pub use config::{ConfigError, GuardianConfig, MonitorConfig, OutletConfig};
pub use model::{HealthStatus, LatencySample, OutletSummary, ProbeResult, StateEvent};
pub use probe::probe_outlet;
pub use store::{GuardianStore, StoreError};
