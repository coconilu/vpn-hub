use std::fmt::Write as _;
use std::{collections::BTreeMap, fs, path::Path};

use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{LOCAL_OUTLET, RouteMode, SUBSCRIPTION_OUTLET};

pub const MASTER_SELECTOR: &str = "VPN-HUB-MASTER";
pub const SUBSCRIPTION_PROXY: &str = "VPN-HUB-SUBSCRIPTION-A";
pub const LOCAL_PROXY: &str = "VPN-HUB-CHAOSHIHUI";
pub const FAIL_CLOSED_PROXY: &str = "REJECT";

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivateRoutingConfig {
    subscription_url: String,
    pub provider_update_seconds: u64,
    pub controller_port: u16,
    pub route_mode: RouteMode,
    pub manual_outlet: Option<String>,
    pub priority: Vec<String>,
    pub cooldown_seconds: u64,
    pub minimum_improvement_ms: u64,
    pub probe_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateConfigSummary {
    pub subscription_configured: bool,
    pub provider_update_seconds: u64,
    pub route_mode: RouteMode,
    pub manual_outlet: Option<String>,
    pub cooldown_seconds: u64,
    pub probe_target_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeConfigSummary {
    pub entry_port: u16,
    pub controller_port: u16,
    pub subscription_enabled: bool,
    pub provider_update_seconds: u64,
    pub has_direct_fallback: bool,
}

#[derive(Debug, Error)]
pub enum PrivateConfigError {
    #[error("failed to read private routing configuration")]
    Read,
    #[error("private routing configuration is invalid")]
    Parse,
    #[error("private routing configuration failed validation: {0}")]
    Invalid(String),
    #[error("failed to write private routing configuration")]
    Write,
    #[error("failed to generate Mihomo runtime configuration")]
    Generate,
}

impl Default for PrivateRoutingConfig {
    fn default() -> Self {
        Self {
            subscription_url: String::new(),
            provider_update_seconds: 180,
            controller_port: 39_090,
            route_mode: RouteMode::Priority,
            manual_outlet: None,
            priority: vec![SUBSCRIPTION_OUTLET.into(), LOCAL_OUTLET.into()],
            cooldown_seconds: 60,
            minimum_improvement_ms: 150,
            probe_targets: vec![
                "https://www.gstatic.com/generate_204".into(),
                "https://www.baidu.com/".into(),
                "https://github.com/".into(),
            ],
        }
    }
}

impl PrivateRoutingConfig {
    /// Loads a local-only TOML file without including its content in errors.
    ///
    /// # Errors
    ///
    /// Returns sanitized read, parse, or validation failures.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PrivateConfigError> {
        let content = fs::read_to_string(path).map_err(|_| PrivateConfigError::Read)?;
        let config = toml::from_str::<Self>(&content).map_err(|_| PrivateConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Creates the default private config if absent.
    ///
    /// # Errors
    ///
    /// Returns a sanitized write failure.
    pub fn create_default(path: impl AsRef<Path>) -> Result<(), PrivateConfigError> {
        let path = path.as_ref();
        if path.exists() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| PrivateConfigError::Write)?;
        }
        Self::default().save(path)
    }

    /// Saves the private config. Callers must apply OS-level ACL hardening.
    ///
    /// # Errors
    ///
    /// Returns a sanitized serialization or write failure.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), PrivateConfigError> {
        self.validate()?;
        let content = toml::to_string_pretty(self).map_err(|_| PrivateConfigError::Write)?;
        fs::write(path, content).map_err(|_| PrivateConfigError::Write)
    }

    /// Replaces only the subscription URL after validating HTTPS.
    ///
    /// # Errors
    ///
    /// Returns a validation error without echoing the URL.
    pub fn set_subscription_url(&mut self, value: &str) -> Result<(), PrivateConfigError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            self.subscription_url.clear();
            return Ok(());
        }
        validate_subscription_url(trimmed)?;
        trimmed.clone_into(&mut self.subscription_url);
        Ok(())
    }

    #[must_use]
    pub fn subscription_configured(&self) -> bool {
        !self.subscription_url.is_empty()
    }

    #[must_use]
    pub fn summary(&self) -> PrivateConfigSummary {
        PrivateConfigSummary {
            subscription_configured: self.subscription_configured(),
            provider_update_seconds: self.provider_update_seconds,
            route_mode: self.route_mode,
            manual_outlet: self.manual_outlet.clone(),
            cooldown_seconds: self.cooldown_seconds,
            probe_target_count: self.probe_targets.len(),
        }
    }

    fn validate(&self) -> Result<(), PrivateConfigError> {
        if self.subscription_configured() {
            validate_subscription_url(&self.subscription_url)?;
        }
        if self.provider_update_seconds < 60 {
            return Err(PrivateConfigError::Invalid(
                "provider_update_seconds must be at least 60".into(),
            ));
        }
        if matches!(self.controller_port, 6_666 | 16_666 | 36_666) {
            return Err(PrivateConfigError::Invalid(
                "controller_port conflicts with a protected routing port".into(),
            ));
        }
        if self.priority.is_empty()
            || self
                .priority
                .iter()
                .any(|id| !matches!(id.as_str(), SUBSCRIPTION_OUTLET | LOCAL_OUTLET))
        {
            return Err(PrivateConfigError::Invalid(
                "priority contains an unknown outlet".into(),
            ));
        }
        if self
            .manual_outlet
            .as_deref()
            .is_some_and(|id| !matches!(id, SUBSCRIPTION_OUTLET | LOCAL_OUTLET))
        {
            return Err(PrivateConfigError::Invalid(
                "manual_outlet is unknown".into(),
            ));
        }
        if self.cooldown_seconds == 0 {
            return Err(PrivateConfigError::Invalid(
                "cooldown_seconds must be greater than zero".into(),
            ));
        }
        if self.probe_targets.len() < 2 {
            return Err(PrivateConfigError::Invalid(
                "at least two probe_targets are required".into(),
            ));
        }
        for target in &self.probe_targets {
            let url = Url::parse(target)
                .map_err(|_| PrivateConfigError::Invalid("probe target URL is invalid".into()))?;
            if url.scheme() != "https" {
                return Err(PrivateConfigError::Invalid(
                    "probe targets must use HTTPS".into(),
                ));
            }
        }
        Ok(())
    }
}

#[must_use]
pub fn generate_controller_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut value, byte| {
            let _ = write!(value, "{byte:02x}");
            value
        })
}

/// Generates a dual-outlet Mihomo config in memory.
///
/// # Errors
///
/// Returns a sanitized generation failure.
pub fn generate_mihomo_config(
    config: &PrivateRoutingConfig,
    controller_secret: &str,
) -> Result<(String, RuntimeConfigSummary), PrivateConfigError> {
    config.validate()?;
    let subscription_enabled = config.subscription_configured();
    let mut providers = BTreeMap::new();
    if subscription_enabled {
        providers.insert(
            "subscription-a".to_owned(),
            ProviderConfig {
                provider_type: "http",
                url: &config.subscription_url,
                path: "./providers/subscription-a.yaml",
                interval: config.provider_update_seconds,
                health_check: ProviderHealthCheck {
                    enable: true,
                    url: &config.probe_targets[0],
                    interval: config.provider_update_seconds,
                    lazy: false,
                },
            },
        );
    }

    let mut groups = Vec::new();
    if subscription_enabled {
        groups.push(ProxyGroup {
            name: SUBSCRIPTION_PROXY,
            group_type: "url-test",
            proxies: Vec::new(),
            use_providers: vec!["subscription-a"],
            url: Some(&config.probe_targets[0]),
            interval: Some(config.provider_update_seconds),
            tolerance: Some(100),
            lazy: Some(false),
        });
    }
    let mut master_proxies = vec![FAIL_CLOSED_PROXY];
    if subscription_enabled {
        master_proxies.push(SUBSCRIPTION_PROXY);
    }
    master_proxies.push(LOCAL_PROXY);
    groups.push(ProxyGroup {
        name: MASTER_SELECTOR,
        group_type: "select",
        proxies: master_proxies,
        use_providers: Vec::new(),
        url: None,
        interval: None,
        tolerance: None,
        lazy: None,
    });

    let document = MihomoConfig {
        mixed_port: 36_666,
        bind_address: "127.0.0.1",
        allow_lan: false,
        mode: "rule",
        log_level: "warning",
        ipv6: false,
        find_process_mode: "off",
        unified_delay: true,
        tcp_concurrent: true,
        external_controller: format!("127.0.0.1:{}", config.controller_port),
        secret: controller_secret,
        profile: ProfileConfig {
            store_selected: false,
            store_fake_ip: false,
        },
        proxies: vec![LocalProxyConfig {
            name: LOCAL_PROXY,
            proxy_type: "socks5",
            server: "127.0.0.1",
            port: 16_666,
            udp: false,
        }],
        proxy_providers: providers,
        proxy_groups: groups,
        rules: vec![format!("MATCH,{MASTER_SELECTOR}")],
    };
    let yaml = serde_yaml::to_string(&document).map_err(|_| PrivateConfigError::Generate)?;
    Ok((
        yaml,
        RuntimeConfigSummary {
            entry_port: 36_666,
            controller_port: config.controller_port,
            subscription_enabled,
            provider_update_seconds: config.provider_update_seconds,
            has_direct_fallback: false,
        },
    ))
}

#[must_use]
pub fn outlet_proxy_name(outlet_id: &str) -> Option<&'static str> {
    match outlet_id {
        SUBSCRIPTION_OUTLET => Some(SUBSCRIPTION_PROXY),
        LOCAL_OUTLET => Some(LOCAL_PROXY),
        "fail-closed" => Some(FAIL_CLOSED_PROXY),
        _ => None,
    }
}

fn validate_subscription_url(value: &str) -> Result<(), PrivateConfigError> {
    let url = Url::parse(value)
        .map_err(|_| PrivateConfigError::Invalid("subscription URL is invalid".into()))?;
    if url.scheme() != "https" || url.host_str().is_none() || url.username() != "" {
        return Err(PrivateConfigError::Invalid(
            "subscription URL must be an HTTPS URL without userinfo".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::struct_excessive_bools)]
struct MihomoConfig<'a> {
    mixed_port: u16,
    bind_address: &'a str,
    allow_lan: bool,
    mode: &'a str,
    log_level: &'a str,
    ipv6: bool,
    find_process_mode: &'a str,
    unified_delay: bool,
    tcp_concurrent: bool,
    external_controller: String,
    secret: &'a str,
    profile: ProfileConfig,
    proxies: Vec<LocalProxyConfig<'a>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    proxy_providers: BTreeMap<String, ProviderConfig<'a>>,
    proxy_groups: Vec<ProxyGroup<'a>>,
    rules: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ProfileConfig {
    store_selected: bool,
    store_fake_ip: bool,
}

#[derive(Serialize)]
struct LocalProxyConfig<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    proxy_type: &'a str,
    server: &'a str,
    port: u16,
    udp: bool,
}

#[derive(Serialize)]
struct ProviderConfig<'a> {
    #[serde(rename = "type")]
    provider_type: &'a str,
    url: &'a str,
    path: &'a str,
    interval: u64,
    #[serde(rename = "health-check")]
    health_check: ProviderHealthCheck<'a>,
}

#[derive(Serialize)]
struct ProviderHealthCheck<'a> {
    enable: bool,
    url: &'a str,
    interval: u64,
    lazy: bool,
}

#[derive(Serialize)]
struct ProxyGroup<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    group_type: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    proxies: Vec<&'a str>,
    #[serde(rename = "use", skip_serializing_if = "Vec::is_empty")]
    use_providers: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tolerance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lazy: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_dual_config_is_loopback_and_has_no_direct() {
        let mut config = PrivateRoutingConfig::default();
        config
            .set_subscription_url("https://example.invalid/provider")
            .expect("URL");
        let (yaml, summary) = generate_mihomo_config(&config, "test-secret").expect("config");
        assert!(yaml.contains("mixed-port: 36666"));
        assert!(yaml.contains("external-controller: 127.0.0.1:39090"));
        assert!(yaml.contains("VPN-HUB-SUBSCRIPTION-A"));
        assert!(yaml.contains("VPN-HUB-CHAOSHIHUI"));
        assert!(yaml.contains("REJECT"));
        assert!(!yaml.contains("DIRECT"));
        let document = serde_yaml::from_str::<serde_yaml::Value>(&yaml).expect("yaml");
        let groups = document["proxy-groups"].as_sequence().expect("groups");
        let master = groups
            .iter()
            .find(|group| group["name"] == MASTER_SELECTOR)
            .expect("master");
        assert_eq!(master["proxies"][0], FAIL_CLOSED_PROXY);
        assert!(!summary.has_direct_fallback);
    }

    #[test]
    fn local_only_config_still_fails_closed() {
        let (yaml, summary) =
            generate_mihomo_config(&PrivateRoutingConfig::default(), "test-secret")
                .expect("config");
        assert!(!summary.subscription_enabled);
        assert!(yaml.contains("REJECT"));
        assert!(!yaml.contains("DIRECT"));
    }

    #[test]
    fn invalid_private_config_error_does_not_echo_secret() {
        let mut config = PrivateRoutingConfig::default();
        let secret_value = "not-a-url-sensitive-value";
        let error = config
            .set_subscription_url(secret_value)
            .expect_err("invalid");
        assert!(!error.to_string().contains(secret_value));
    }
}
