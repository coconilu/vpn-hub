use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Unknown,
    Healthy,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpCapabilityStatus {
    Supported,
    TcpOnly,
    Unknown,
}

impl UdpCapabilityStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::TcpOnly => "tcp_only",
            Self::Unknown => "unknown",
        }
    }
}

impl TryFrom<&str> for UdpCapabilityStatus {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "supported" => Ok(Self::Supported),
            "tcp_only" => Ok(Self::TcpOnly),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown UDP capability status: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpCapabilityEvidence {
    pub outlet_id: String,
    pub status: UdpCapabilityStatus,
    pub observed_at: String,
    pub evidence_version: u32,
    pub probe_version: String,
    pub model_version: u32,
    pub configuration_fingerprint: String,
    pub configuration_generation: u64,
    pub reason_code: String,
}

impl HealthStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
        }
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for HealthStatus {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "down" => Ok(Self::Down),
            other => Err(format!("unknown health status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub outlet_id: String,
    pub label: String,
    pub observed_at: String,
    pub port_reachable: bool,
    pub status: HealthStatus,
    pub http_status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub error_code: Option<String>,
    #[serde(default)]
    pub successful_targets: u32,
    #[serde(default = "default_target_count")]
    pub total_targets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    pub outlet_id: String,
    pub occurred_at: String,
    pub from_status: HealthStatus,
    pub to_status: HealthStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletSummary {
    pub outlet_id: String,
    pub label: String,
    pub samples: u64,
    pub successful_samples: u64,
    pub failed_samples: u64,
    pub availability_percent: f64,
    pub average_latency_ms: Option<f64>,
    pub last_status: HealthStatus,
    pub last_observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySample {
    pub outlet_id: String,
    pub observed_at: String,
    pub port_reachable: bool,
    pub status: HealthStatus,
    pub latency_ms: Option<u64>,
    pub error_code: Option<String>,
    pub successful_targets: u32,
    pub total_targets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSwitchEvent {
    pub occurred_at: String,
    pub from_outlet: Option<String>,
    pub to_outlet: String,
    pub mode: String,
    pub reason: String,
    pub duration_ms: u64,
}

const fn default_target_count() -> u32 {
    1
}
