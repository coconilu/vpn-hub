use std::{collections::HashSet, fs, net::IpAddr, path::Path};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    pub database_path: std::path::PathBuf,
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub outlets: Vec<ProbeOutletConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_recovery_threshold")]
    pub recovery_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOutletConfig {
    pub id: String,
    pub label: String,
    pub proxy_url: String,
    pub probe_url: String,
    #[serde(default = "default_degraded_latency_ms")]
    pub degraded_latency_ms: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl GuardianConfig {
    /// Loads a TOML configuration and resolves the database path relative to
    /// the configuration file, not the caller's working directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&content)?;
        config.validate()?;
        if config.database_path.is_relative() {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            config.database_path = parent.join(&config.database_path);
        }
        Ok(config)
    }

    /// Validates safety and state-machine constraints.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate outlet IDs, remote proxy hosts, invalid
    /// URLs, zero thresholds, or an empty enabled outlet set.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.monitor.interval_seconds == 0 {
            return Err(ConfigError::Invalid(
                "monitor.interval_seconds must be greater than zero".into(),
            ));
        }
        if self.monitor.failure_threshold == 0 || self.monitor.recovery_threshold == 0 {
            return Err(ConfigError::Invalid(
                "failure and recovery thresholds must be greater than zero".into(),
            ));
        }

        let mut ids = HashSet::new();
        for outlet in &self.outlets {
            if outlet.id.trim().is_empty() || outlet.label.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "outlet id and label must not be empty".into(),
                ));
            }
            if !ids.insert(outlet.id.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate outlet id: {}",
                    outlet.id
                )));
            }
            validate_proxy_url(outlet)?;
            validate_probe_url(outlet)?;
        }
        if !self.outlets.iter().any(|outlet| outlet.enabled) {
            return Err(ConfigError::Invalid(
                "at least one outlet must be enabled".into(),
            ));
        }
        Ok(())
    }
}

impl ProbeOutletConfig {
    /// Returns the local socket address encoded in the proxy URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL has no port or does not target loopback.
    pub fn socket_addr(&self) -> Result<std::net::SocketAddr, ConfigError> {
        let url = Url::parse(&self.proxy_url)
            .map_err(|_| ConfigError::Invalid(format!("invalid proxy URL for {}", self.id)))?;
        let host = url
            .host_str()
            .ok_or_else(|| ConfigError::Invalid(format!("missing proxy host for {}", self.id)))?;
        let ip: IpAddr = if host.eq_ignore_ascii_case("localhost") {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            host.parse().map_err(|_| {
                ConfigError::Invalid(format!("proxy host for {} must be local", self.id))
            })?
        };
        if !ip.is_loopback() {
            return Err(ConfigError::Invalid(format!(
                "proxy host for {} must be a loopback address",
                self.id
            )));
        }
        let port = url
            .port()
            .ok_or_else(|| ConfigError::Invalid(format!("missing proxy port for {}", self.id)))?;
        Ok(std::net::SocketAddr::new(ip, port))
    }
}

fn validate_proxy_url(outlet: &ProbeOutletConfig) -> Result<(), ConfigError> {
    let url = Url::parse(&outlet.proxy_url)
        .map_err(|_| ConfigError::Invalid(format!("invalid proxy URL for {}", outlet.id)))?;
    if !matches!(url.scheme(), "http" | "socks5" | "socks5h") {
        return Err(ConfigError::Invalid(format!(
            "unsupported proxy scheme for {}",
            outlet.id
        )));
    }
    outlet.socket_addr().map(|_| ())
}

fn validate_probe_url(outlet: &ProbeOutletConfig) -> Result<(), ConfigError> {
    let url = Url::parse(&outlet.probe_url)
        .map_err(|_| ConfigError::Invalid(format!("invalid probe URL for {}", outlet.id)))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConfigError::Invalid(format!(
            "probe URL for {} must be HTTP or HTTPS",
            outlet.id
        )));
    }
    Ok(())
}

fn default_interval_seconds() -> u64 {
    15
}
fn default_connect_timeout_ms() -> u64 {
    1_500
}
fn default_request_timeout_ms() -> u64 {
    8_000
}
fn default_failure_threshold() -> u32 {
    2
}
fn default_recovery_threshold() -> u32 {
    3
}
fn default_degraded_latency_ms() -> u64 {
    2_500
}
const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> GuardianConfig {
        GuardianConfig {
            database_path: "guardian.db".into(),
            monitor: MonitorConfig {
                interval_seconds: 15,
                connect_timeout_ms: 1_500,
                request_timeout_ms: 8_000,
                failure_threshold: 2,
                recovery_threshold: 3,
            },
            outlets: vec![ProbeOutletConfig {
                id: "local-a".into(),
                label: "Local A".into(),
                proxy_url: "socks5h://127.0.0.1:16666".into(),
                probe_url: "https://example.com".into(),
                degraded_latency_ms: 2_500,
                enabled: true,
            }],
        }
    }

    #[test]
    fn accepts_loopback_proxy() {
        assert!(base_config().validate().is_ok());
    }

    #[test]
    fn rejects_remote_proxy() {
        let mut config = base_config();
        config.outlets[0].proxy_url = "socks5h://192.0.2.1:1080".into();
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let mut config = base_config();
        config.outlets.push(config.outlets[0].clone());
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }
}
