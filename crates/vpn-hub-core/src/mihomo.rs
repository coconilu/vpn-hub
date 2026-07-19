use std::fmt::Write as _;
use std::{collections::BTreeMap, fs, net::IpAddr, path::Path};

use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{RouteMode, UdpCapabilityStatus};

pub const CURRENT_CONFIG_VERSION: u32 = 1;
pub const MASTER_SELECTOR: &str = "VPN-HUB-MASTER";
pub const UDP_SELECTOR: &str = "VPN-HUB-UDP";
pub const FAIL_CLOSED_PROXY: &str = "REJECT";
const DEFAULT_ENTRY_PORT: u16 = 3_666;
const LEGACY_SUBSCRIPTION_ID: &str = "subscription-a";
const LEGACY_LOCAL_ID: &str = "chaoshihui";
const LEGACY_SECRET_REF: &str = "legacy.subscription-a";
const RESERVED_OUTLET_IDS: [&str; 1] = ["fail-closed"];

pub type ResolvedSubscriptionUrls = BTreeMap<String, String>;
pub type UdpCapabilityMap = BTreeMap<String, UdpCapabilityStatus>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EntryConfig {
    pub host: String,
    pub port: u16,
}

impl Default for EntryConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: DEFAULT_ENTRY_PORT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletConfig {
    pub id: String,
    pub label: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(flatten)]
    pub kind: OutletKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutletKind {
    Subscription {
        secret_ref: String,
        #[serde(default = "default_provider_update_seconds")]
        provider_update_seconds: u64,
    },
    LocalProxy {
        endpoint: String,
    },
}

impl OutletConfig {
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            OutletKind::Subscription { .. } => "subscription",
            OutletKind::LocalProxy { .. } => "local_proxy",
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> Option<&str> {
        match &self.kind {
            OutletKind::Subscription { .. } => None,
            OutletKind::LocalProxy { endpoint } => Some(endpoint),
        }
    }

    #[must_use]
    pub fn secret_ref(&self) -> Option<&str> {
        match &self.kind {
            OutletKind::Subscription { secret_ref, .. } => Some(secret_ref),
            OutletKind::LocalProxy { .. } => None,
        }
    }

    #[must_use]
    pub fn provider_update_seconds(&self) -> Option<u64> {
        match self.kind {
            OutletKind::Subscription {
                provider_update_seconds,
                ..
            } => Some(provider_update_seconds),
            OutletKind::LocalProxy { .. } => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivateRoutingConfig {
    pub version: u32,
    pub entry: EntryConfig,
    pub controller_port: u16,
    pub route_mode: RouteMode,
    pub manual_outlet: Option<String>,
    pub cooldown_seconds: u64,
    pub minimum_improvement_ms: u64,
    pub probe_targets: Vec<String>,
    pub outlets: Vec<OutletConfig>,
    #[serde(skip)]
    legacy_subscription_urls: ResolvedSubscriptionUrls,
    #[serde(skip)]
    source_format: SourceFormat,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum SourceFormat {
    #[default]
    Versioned,
    Legacy,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateConfigSummary {
    pub version: u32,
    pub entry: EntryConfig,
    pub route_mode: RouteMode,
    pub manual_outlet: Option<String>,
    pub cooldown_seconds: u64,
    pub probe_target_count: usize,
    pub outlets: Vec<OutletConfigSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutletConfigSummary {
    pub outlet_id: String,
    pub label: String,
    pub kind: String,
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeConfigSummary {
    pub entry: EntryConfig,
    pub controller_port: u16,
    pub enabled_outlet_count: usize,
    pub configured_subscription_count: usize,
    pub udp_supported_outlet_count: usize,
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
            version: CURRENT_CONFIG_VERSION,
            entry: EntryConfig::default(),
            controller_port: 39_090,
            route_mode: RouteMode::Priority,
            manual_outlet: None,
            cooldown_seconds: 60,
            minimum_improvement_ms: 150,
            probe_targets: vec![
                "https://www.gstatic.com/generate_204".into(),
                "https://www.baidu.com/".into(),
                "https://github.com/".into(),
            ],
            outlets: Vec::new(),
            legacy_subscription_urls: BTreeMap::new(),
            source_format: SourceFormat::Versioned,
        }
    }
}

impl PrivateRoutingConfig {
    /// Loads either the current versioned format or the legacy fixed dual-outlet format.
    /// A damaged primary file falls back to the last atomically saved backup.
    ///
    /// # Errors
    ///
    /// Returns sanitized read, parse, or validation failures.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PrivateConfigError> {
        let path = path.as_ref();
        match Self::load_exact(path) {
            Ok(config) => Ok(config),
            Err(primary_error) => {
                let backup = backup_path(path);
                Self::load_exact(&backup).map_err(|_| primary_error)
            }
        }
    }

    fn load_exact(path: &Path) -> Result<Self, PrivateConfigError> {
        let content = fs::read_to_string(path).map_err(|_| PrivateConfigError::Read)?;
        let document =
            toml::from_str::<toml::Value>(&content).map_err(|_| PrivateConfigError::Parse)?;
        let config = if document.get("version").is_some() {
            let mut config =
                toml::from_str::<Self>(&content).map_err(|_| PrivateConfigError::Parse)?;
            config.source_format = SourceFormat::Versioned;
            config
        } else {
            let legacy = toml::from_str::<LegacyPrivateRoutingConfig>(&content)
                .map_err(|_| PrivateConfigError::Parse)?;
            Self::from_legacy(legacy)?
        };
        config.validate()?;
        Ok(config)
    }

    /// Creates the default versioned config if absent.
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

    /// Saves an already validated config through a temporary file and retains
    /// the previous valid document as a rollback candidate.
    ///
    /// # Errors
    ///
    /// Returns a sanitized validation, serialization, or write failure.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), PrivateConfigError> {
        self.validate()?;
        let content = if self.source_format == SourceFormat::Legacy {
            toml::to_string_pretty(&self.as_legacy()).map_err(|_| PrivateConfigError::Write)?
        } else {
            toml::to_string_pretty(self).map_err(|_| PrivateConfigError::Write)?
        };
        atomic_save(path.as_ref(), content.as_bytes())
    }

    #[must_use]
    pub fn priority(&self) -> Vec<String> {
        self.outlets
            .iter()
            .filter(|outlet| outlet.enabled)
            .map(|outlet| outlet.id.clone())
            .collect()
    }

    pub fn enabled_outlets(&self) -> impl Iterator<Item = &OutletConfig> {
        self.outlets.iter().filter(|outlet| outlet.enabled)
    }

    #[must_use]
    pub fn resolved_subscription_urls(&self) -> ResolvedSubscriptionUrls {
        self.legacy_subscription_urls.clone()
    }

    pub(crate) fn is_legacy_format(&self) -> bool {
        self.source_format == SourceFormat::Legacy
    }

    pub(crate) fn legacy_subscription_credential(&self) -> Option<(&str, &str, &str)> {
        self.legacy_subscription_urls
            .get(LEGACY_SECRET_REF)
            .map(|url| (LEGACY_SUBSCRIPTION_ID, LEGACY_SECRET_REF, url.as_str()))
    }

    pub(crate) fn promote_legacy_format(&mut self) {
        self.source_format = SourceFormat::Versioned;
        self.legacy_subscription_urls.clear();
    }

    #[must_use]
    pub fn summary(&self, resolved: &ResolvedSubscriptionUrls) -> PrivateConfigSummary {
        PrivateConfigSummary {
            version: self.version,
            entry: self.entry.clone(),
            route_mode: self.route_mode,
            manual_outlet: self.manual_outlet.clone(),
            cooldown_seconds: self.cooldown_seconds,
            probe_target_count: self.probe_targets.len(),
            outlets: self
                .outlets
                .iter()
                .map(|outlet| OutletConfigSummary {
                    outlet_id: outlet.id.clone(),
                    label: outlet.label.clone(),
                    kind: outlet.kind_name().into(),
                    enabled: outlet.enabled,
                    endpoint: outlet.endpoint().map(str::to_owned),
                    configured: match &outlet.kind {
                        OutletKind::Subscription { secret_ref, .. } => {
                            resolved.contains_key(secret_ref)
                        }
                        OutletKind::LocalProxy { .. } => true,
                    },
                })
                .collect(),
        }
    }

    /// Validates version, loopback boundaries, stable IDs and route references.
    ///
    /// # Errors
    ///
    /// Returns a sanitized validation error before any runtime config is applied.
    pub fn validate(&self) -> Result<(), PrivateConfigError> {
        if self.version != CURRENT_CONFIG_VERSION {
            return Err(PrivateConfigError::Invalid(format!(
                "unsupported config version: {}",
                self.version
            )));
        }
        let entry_ip = parse_loopback(&self.entry.host, "entry.host")?;
        if self.entry.port == 0 {
            return Err(PrivateConfigError::Invalid(
                "entry.port must be a valid port".into(),
            ));
        }
        if self.entry.port == self.controller_port {
            return Err(PrivateConfigError::Invalid(
                "entry.port conflicts with controller_port".into(),
            ));
        }
        if self.controller_port == 0 {
            return Err(PrivateConfigError::Invalid(
                "controller_port must be a valid port".into(),
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

        let ids = validate_outlets(self, entry_ip)?;
        if let Some(manual) = self.manual_outlet.as_deref()
            && !ids.contains(manual)
        {
            return Err(PrivateConfigError::Invalid(
                "manual_outlet is unknown".into(),
            ));
        }
        Ok(())
    }

    fn from_legacy(legacy: LegacyPrivateRoutingConfig) -> Result<Self, PrivateConfigError> {
        legacy.validate()?;
        let mut outlets = Vec::new();
        let mut legacy_subscription_urls = BTreeMap::new();
        outlets.push(OutletConfig {
            id: LEGACY_SUBSCRIPTION_ID.into(),
            label: "Subscription A".into(),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: LEGACY_SECRET_REF.into(),
                provider_update_seconds: legacy.provider_update_seconds,
            },
        });
        if !legacy.subscription_url.is_empty() {
            legacy_subscription_urls
                .insert(LEGACY_SECRET_REF.into(), legacy.subscription_url.clone());
        }
        outlets.push(OutletConfig {
            id: LEGACY_LOCAL_ID.into(),
            label: "Local client A".into(),
            enabled: true,
            kind: OutletKind::LocalProxy {
                endpoint: "socks5h://127.0.0.1:16666".into(),
            },
        });
        let order = legacy
            .priority
            .iter()
            .filter_map(|id| outlets.iter().find(|outlet| outlet.id == *id).cloned())
            .chain(
                outlets
                    .iter()
                    .filter(|outlet| !legacy.priority.contains(&outlet.id))
                    .cloned(),
            )
            .collect();
        Ok(Self {
            version: CURRENT_CONFIG_VERSION,
            entry: EntryConfig {
                host: "127.0.0.1".into(),
                port: 36_666,
            },
            controller_port: legacy.controller_port,
            route_mode: legacy.route_mode,
            manual_outlet: legacy.manual_outlet,
            cooldown_seconds: legacy.cooldown_seconds,
            minimum_improvement_ms: legacy.minimum_improvement_ms,
            probe_targets: legacy.probe_targets,
            outlets: order,
            legacy_subscription_urls,
            source_format: SourceFormat::Legacy,
        })
    }

    fn as_legacy(&self) -> LegacyPrivateRoutingConfig {
        let subscription_url = self
            .legacy_subscription_urls
            .get(LEGACY_SECRET_REF)
            .cloned()
            .unwrap_or_default();
        let provider_update_seconds = self
            .outlets
            .iter()
            .find(|outlet| outlet.id == LEGACY_SUBSCRIPTION_ID)
            .and_then(OutletConfig::provider_update_seconds)
            .unwrap_or_else(default_provider_update_seconds);
        LegacyPrivateRoutingConfig {
            subscription_url,
            provider_update_seconds,
            controller_port: self.controller_port,
            route_mode: self.route_mode,
            manual_outlet: self.manual_outlet.clone(),
            priority: self.priority(),
            cooldown_seconds: self.cooldown_seconds,
            minimum_improvement_ms: self.minimum_improvement_ms,
            probe_targets: self.probe_targets.clone(),
        }
    }
}

fn validate_outlets(
    config: &PrivateRoutingConfig,
    entry_ip: IpAddr,
) -> Result<std::collections::HashSet<&str>, PrivateConfigError> {
    let mut ids = std::collections::HashSet::new();
    let mut secret_refs = std::collections::HashSet::new();
    let mut local_endpoints = std::collections::HashSet::new();
    for outlet in &config.outlets {
        validate_outlet_id(&outlet.id)?;
        if outlet.label.trim().is_empty() {
            return Err(PrivateConfigError::Invalid(
                "outlet label must not be empty".into(),
            ));
        }
        if !ids.insert(outlet.id.as_str()) {
            return Err(PrivateConfigError::Invalid(format!(
                "duplicate outlet id: {}",
                outlet.id
            )));
        }
        match &outlet.kind {
            OutletKind::Subscription {
                secret_ref,
                provider_update_seconds,
            } => {
                validate_subscription_outlet(outlet, secret_ref, *provider_update_seconds)?;
                if !secret_refs.insert(secret_ref.as_str()) {
                    return Err(PrivateConfigError::Invalid(
                        "duplicate subscription secret_ref".into(),
                    ));
                }
            }
            OutletKind::LocalProxy { endpoint } => {
                let endpoint = parse_local_proxy_endpoint(endpoint, &outlet.id)?;
                if endpoint.ip() == entry_ip && endpoint.port() == config.entry.port {
                    return Err(PrivateConfigError::Invalid(format!(
                        "local proxy {} conflicts with the entry listener",
                        outlet.id
                    )));
                }
                if endpoint.port() == config.controller_port {
                    return Err(PrivateConfigError::Invalid(format!(
                        "local proxy {} conflicts with the controller listener",
                        outlet.id
                    )));
                }
                if !local_endpoints.insert(endpoint) {
                    return Err(PrivateConfigError::Invalid(format!(
                        "duplicate local proxy endpoint for {}",
                        outlet.id
                    )));
                }
            }
        }
    }
    Ok(ids)
}

fn validate_subscription_outlet(
    outlet: &OutletConfig,
    secret_ref: &str,
    provider_update_seconds: u64,
) -> Result<(), PrivateConfigError> {
    validate_secret_ref(secret_ref)?;
    if provider_update_seconds < 60 {
        return Err(PrivateConfigError::Invalid(format!(
            "provider_update_seconds for {} must be at least 60",
            outlet.id
        )));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct LegacyPrivateRoutingConfig {
    subscription_url: String,
    provider_update_seconds: u64,
    controller_port: u16,
    route_mode: RouteMode,
    manual_outlet: Option<String>,
    priority: Vec<String>,
    cooldown_seconds: u64,
    minimum_improvement_ms: u64,
    probe_targets: Vec<String>,
}

impl Default for LegacyPrivateRoutingConfig {
    fn default() -> Self {
        Self {
            subscription_url: String::new(),
            provider_update_seconds: default_provider_update_seconds(),
            controller_port: 39_090,
            route_mode: RouteMode::Priority,
            manual_outlet: None,
            priority: vec![LEGACY_SUBSCRIPTION_ID.into(), LEGACY_LOCAL_ID.into()],
            cooldown_seconds: 60,
            minimum_improvement_ms: 150,
            probe_targets: PrivateRoutingConfig::default().probe_targets,
        }
    }
}

impl LegacyPrivateRoutingConfig {
    fn validate(&self) -> Result<(), PrivateConfigError> {
        if !self.subscription_url.is_empty() {
            validate_subscription_url(&self.subscription_url)?;
        }
        if self.provider_update_seconds < 60 || self.cooldown_seconds == 0 {
            return Err(PrivateConfigError::Invalid(
                "legacy routing thresholds are invalid".into(),
            ));
        }
        if self
            .priority
            .iter()
            .any(|id| !matches!(id.as_str(), LEGACY_SUBSCRIPTION_ID | LEGACY_LOCAL_ID))
        {
            return Err(PrivateConfigError::Invalid(
                "legacy priority contains an unknown outlet".into(),
            ));
        }
        if self
            .manual_outlet
            .as_deref()
            .is_some_and(|id| !matches!(id, LEGACY_SUBSCRIPTION_ID | LEGACY_LOCAL_ID))
        {
            return Err(PrivateConfigError::Invalid(
                "legacy manual_outlet is unknown".into(),
            ));
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

/// Generates a dynamic, loopback-only and fail-closed Mihomo config in memory.
///
/// # Errors
///
/// Returns a sanitized validation or generation failure.
#[allow(clippy::too_many_lines)]
pub fn generate_mihomo_config(
    config: &PrivateRoutingConfig,
    resolved_subscriptions: &ResolvedSubscriptionUrls,
    controller_secret: &str,
) -> Result<(String, RuntimeConfigSummary), PrivateConfigError> {
    generate_mihomo_config_with_udp_capabilities(
        config,
        resolved_subscriptions,
        controller_secret,
        &UdpCapabilityMap::new(),
    )
}

/// Generates a dynamic fail-closed Mihomo config with an independently
/// constrained UDP selector. Unknown and TCP-only outlets are never UDP
/// candidates.
///
/// # Errors
///
/// Returns a sanitized validation or generation failure.
#[allow(clippy::too_many_lines)]
pub fn generate_mihomo_config_with_udp_capabilities(
    config: &PrivateRoutingConfig,
    resolved_subscriptions: &ResolvedSubscriptionUrls,
    controller_secret: &str,
    udp_capabilities: &UdpCapabilityMap,
) -> Result<(String, RuntimeConfigSummary), PrivateConfigError> {
    config.validate()?;
    let mut providers = BTreeMap::new();
    let mut proxies = Vec::new();
    let mut groups = Vec::new();
    let mut master_proxies = vec![FAIL_CLOSED_PROXY.to_owned()];
    let mut udp_proxies = vec![FAIL_CLOSED_PROXY.to_owned()];
    let mut configured_subscription_count = 0;

    for outlet in config.enabled_outlets() {
        let proxy_name = outlet_proxy_name(&outlet.id);
        match &outlet.kind {
            OutletKind::Subscription {
                secret_ref,
                provider_update_seconds,
            } => {
                let Some(url) = resolved_subscriptions.get(secret_ref) else {
                    continue;
                };
                validate_subscription_url(url)?;
                let provider_name = provider_name(&outlet.id);
                providers.insert(
                    provider_name.clone(),
                    ProviderConfig {
                        provider_type: "http".into(),
                        url: url.clone(),
                        path: format!("./providers/{}.yaml", outlet.id),
                        interval: *provider_update_seconds,
                        health_check: ProviderHealthCheck {
                            enable: true,
                            url: config.probe_targets[0].clone(),
                            interval: *provider_update_seconds,
                            lazy: false,
                        },
                    },
                );
                groups.push(ProxyGroup {
                    name: proxy_name.clone(),
                    group_type: "url-test".into(),
                    proxies: vec![FAIL_CLOSED_PROXY.into()],
                    use_providers: vec![provider_name],
                    url: Some(config.probe_targets[0].clone()),
                    interval: Some(*provider_update_seconds),
                    tolerance: Some(100),
                    lazy: Some(false),
                });
                configured_subscription_count += 1;
            }
            OutletKind::LocalProxy { endpoint } => {
                let parsed = Url::parse(endpoint).map_err(|_| PrivateConfigError::Generate)?;
                let address = parse_local_proxy_endpoint(endpoint, &outlet.id)?;
                proxies.push(LocalProxyConfig {
                    name: proxy_name.clone(),
                    proxy_type: if parsed.scheme() == "http" {
                        "http".into()
                    } else {
                        "socks5".into()
                    },
                    server: address.ip().to_string(),
                    port: address.port(),
                    udp: udp_capabilities.get(&outlet.id) == Some(&UdpCapabilityStatus::Supported),
                });
            }
        }
        if udp_capabilities.get(&outlet.id) == Some(&UdpCapabilityStatus::Supported) {
            udp_proxies.push(proxy_name.clone());
        }
        master_proxies.push(proxy_name);
    }
    groups.push(ProxyGroup {
        name: MASTER_SELECTOR.into(),
        group_type: "select".into(),
        proxies: master_proxies,
        use_providers: Vec::new(),
        url: None,
        interval: None,
        tolerance: None,
        lazy: None,
    });
    groups.push(ProxyGroup {
        name: UDP_SELECTOR.into(),
        group_type: "select".into(),
        proxies: udp_proxies.clone(),
        use_providers: Vec::new(),
        url: None,
        interval: None,
        tolerance: None,
        lazy: None,
    });

    let document = MihomoConfig {
        mixed_port: config.entry.port,
        bind_address: parse_loopback(&config.entry.host, "entry.host")?.to_string(),
        allow_lan: false,
        mode: "rule".into(),
        log_level: "warning".into(),
        ipv6: false,
        find_process_mode: "off".into(),
        unified_delay: true,
        tcp_concurrent: true,
        external_controller: format!("127.0.0.1:{}", config.controller_port),
        secret: controller_secret.into(),
        profile: ProfileConfig {
            store_selected: false,
            store_fake_ip: false,
        },
        proxies,
        proxy_providers: providers,
        proxy_groups: groups,
        rules: vec![
            format!("NETWORK,UDP,{UDP_SELECTOR}"),
            format!("MATCH,{MASTER_SELECTOR}"),
        ],
    };
    let yaml = serde_yaml::to_string(&document).map_err(|_| PrivateConfigError::Generate)?;
    Ok((
        yaml,
        RuntimeConfigSummary {
            entry: config.entry.clone(),
            controller_port: config.controller_port,
            enabled_outlet_count: config.enabled_outlets().count(),
            configured_subscription_count,
            udp_supported_outlet_count: udp_proxies.len().saturating_sub(1),
            has_direct_fallback: false,
        },
    ))
}

#[must_use]
pub fn outlet_proxy_name(outlet_id: &str) -> String {
    if outlet_id == "fail-closed" {
        FAIL_CLOSED_PROXY.into()
    } else {
        format!("VPN-HUB-OUTLET-{outlet_id}")
    }
}

fn provider_name(outlet_id: &str) -> String {
    format!("vpn-hub-provider-{outlet_id}")
}

pub(crate) fn validate_subscription_url(value: &str) -> Result<(), PrivateConfigError> {
    let url = Url::parse(value)
        .map_err(|_| PrivateConfigError::Invalid("subscription URL is invalid".into()))?;
    if url.scheme() != "https" || url.host_str().is_none() || url.username() != "" {
        return Err(PrivateConfigError::Invalid(
            "subscription URL must be an HTTPS URL without userinfo".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_secret_ref(value: &str) -> Result<(), PrivateConfigError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_')
        });
    if !valid {
        return Err(PrivateConfigError::Invalid(
            "secret_ref must be 1-128 lowercase ASCII letters, digits, '.', '-' or '_'".into(),
        ));
    }
    Ok(())
}

fn validate_outlet_id(id: &str) -> Result<(), PrivateConfigError> {
    if RESERVED_OUTLET_IDS.contains(&id) {
        return Err(PrivateConfigError::Invalid(format!(
            "outlet id is reserved by the routing engine: {id}"
        )));
    }
    let mut chars = id.chars();
    let valid_first = chars
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit());
    let valid_rest = chars.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_')
    });
    if !valid_first || !valid_rest || id.len() > 64 {
        return Err(PrivateConfigError::Invalid(
            "outlet id must be 1-64 lowercase ASCII letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(())
}

fn parse_loopback(value: &str, field: &str) -> Result<IpAddr, PrivateConfigError> {
    let ip = if value.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        value
            .parse::<IpAddr>()
            .map_err(|_| PrivateConfigError::Invalid(format!("{field} must be loopback")))?
    };
    if !ip.is_loopback() {
        return Err(PrivateConfigError::Invalid(format!(
            "{field} must be loopback"
        )));
    }
    Ok(ip)
}

fn parse_local_proxy_endpoint(
    value: &str,
    outlet_id: &str,
) -> Result<std::net::SocketAddr, PrivateConfigError> {
    let url = Url::parse(value).map_err(|_| {
        PrivateConfigError::Invalid(format!("invalid local proxy endpoint for {outlet_id}"))
    })?;
    if !matches!(url.scheme(), "http" | "socks5" | "socks5h") {
        return Err(PrivateConfigError::Invalid(format!(
            "unsupported local proxy protocol for {outlet_id}"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(PrivateConfigError::Invalid(format!(
            "local proxy endpoint for {outlet_id} must not contain credentials, path or query"
        )));
    }
    let host = url.host_str().ok_or_else(|| {
        PrivateConfigError::Invalid(format!("missing local proxy host for {outlet_id}"))
    })?;
    let ip = parse_loopback(host, &format!("local proxy host for {outlet_id}"))?;
    let port = url.port().ok_or_else(|| {
        PrivateConfigError::Invalid(format!("missing local proxy port for {outlet_id}"))
    })?;
    if port == 0 {
        return Err(PrivateConfigError::Invalid(format!(
            "local proxy port for {outlet_id} must be valid"
        )));
    }
    Ok(std::net::SocketAddr::new(ip, port))
}

fn atomic_save(path: &Path, content: &[u8]) -> Result<(), PrivateConfigError> {
    let temporary = path.with_extension("toml.tmp");
    let backup = backup_path(path);
    fs::write(&temporary, content).map_err(|_| PrivateConfigError::Write)?;
    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup).map_err(|_| PrivateConfigError::Write)?;
        }
        fs::rename(path, &backup).map_err(|_| PrivateConfigError::Write)?;
    }
    if fs::rename(&temporary, path).is_err() {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        let _ = fs::remove_file(&temporary);
        return Err(PrivateConfigError::Write);
    }
    fs::copy(path, &backup).map_err(|_| PrivateConfigError::Write)?;
    Ok(())
}

fn backup_path(path: &Path) -> std::path::PathBuf {
    path.with_extension("toml.bak")
}

const fn default_true() -> bool {
    true
}

const fn default_provider_update_seconds() -> u64 {
    180
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::struct_excessive_bools)]
struct MihomoConfig {
    mixed_port: u16,
    bind_address: String,
    allow_lan: bool,
    mode: String,
    log_level: String,
    ipv6: bool,
    find_process_mode: String,
    unified_delay: bool,
    tcp_concurrent: bool,
    external_controller: String,
    secret: String,
    profile: ProfileConfig,
    proxies: Vec<LocalProxyConfig>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    proxy_providers: BTreeMap<String, ProviderConfig>,
    proxy_groups: Vec<ProxyGroup>,
    rules: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ProfileConfig {
    store_selected: bool,
    store_fake_ip: bool,
}

#[derive(Serialize)]
struct LocalProxyConfig {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    server: String,
    port: u16,
    udp: bool,
}

#[derive(Serialize)]
struct ProviderConfig {
    #[serde(rename = "type")]
    provider_type: String,
    url: String,
    path: String,
    interval: u64,
    #[serde(rename = "health-check")]
    health_check: ProviderHealthCheck,
}

#[derive(Serialize)]
struct ProviderHealthCheck {
    enable: bool,
    url: String,
    interval: u64,
    lazy: bool,
}

#[derive(Serialize)]
struct ProxyGroup {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    proxies: Vec<String>,
    #[serde(rename = "use", skip_serializing_if = "Vec::is_empty")]
    use_providers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
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

    fn subscription(id: &str, secret_ref: &str) -> OutletConfig {
        OutletConfig {
            id: id.into(),
            label: id.into(),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: secret_ref.into(),
                provider_update_seconds: 180,
            },
        }
    }

    fn local(id: &str, endpoint: &str, enabled: bool) -> OutletConfig {
        OutletConfig {
            id: id.into(),
            label: id.into(),
            enabled,
            kind: OutletKind::LocalProxy {
                endpoint: endpoint.into(),
            },
        }
    }

    #[test]
    fn versioned_config_persists_three_subscriptions_and_two_local_outlets() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("routing.toml");
        let mut config = PrivateRoutingConfig::default();
        config.entry.port = 4_321;
        config.outlets = vec![
            subscription("sub-a", "secret.a"),
            subscription("sub-b", "secret.b"),
            subscription("sub-c", "secret.c"),
            local("local-a", "http://127.0.0.1:2666", true),
            local("local-b", "socks5h://127.0.0.1:4666", false),
        ];
        config.save(&path).expect("save");
        let mut loaded = PrivateRoutingConfig::load(&path).expect("load");
        assert_eq!(loaded.entry.port, 4_321);
        assert_eq!(loaded.outlets, config.outlets);
        assert_eq!(loaded.priority(), ["sub-a", "sub-b", "sub-c", "local-a"]);
        loaded.outlets.remove(1);
        loaded.outlets.swap(0, 2);
        loaded.save(&path).expect("save reordered config");
        let reordered = PrivateRoutingConfig::load(&path).expect("reload reordered config");
        assert_eq!(
            reordered
                .outlets
                .iter()
                .map(|outlet| outlet.id.as_str())
                .collect::<Vec<_>>(),
            ["local-a", "sub-c", "sub-a", "local-b"]
        );
        assert!(!reordered.outlets[3].enabled);
        let serialized = fs::read_to_string(path).expect("document");
        assert!(!serialized.contains("https://provider"));
        assert!(serialized.contains("secret_ref"));
    }

    #[test]
    fn repository_example_is_a_valid_five_outlet_config() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/private-routing.example.toml");
        let config = PrivateRoutingConfig::load(path).expect("repository example");
        assert_eq!(config.entry, EntryConfig::default());
        assert_eq!(config.outlets.len(), 5);
        assert_eq!(config.enabled_outlets().count(), 4);
    }

    #[test]
    fn rejects_remote_duplicate_and_recursive_local_endpoints() {
        let mut config = PrivateRoutingConfig {
            outlets: vec![local("local-a", "socks5://192.0.2.1:2666", true)],
            ..PrivateRoutingConfig::default()
        };
        assert!(config.validate().is_err());

        config.outlets = vec![
            local("local-a", "http://127.0.0.1:2666", true),
            local("local-b", "socks5h://127.0.0.1:2666", true),
        ];
        assert!(config.validate().is_err());

        config.outlets = vec![local("local-a", "http://127.0.0.1:3666", true)];
        assert!(config.validate().is_err());
    }

    #[test]
    fn reserved_fail_closed_id_is_rejected_before_generation() {
        let config = PrivateRoutingConfig {
            outlets: vec![local("fail-closed", "socks5h://127.0.0.1:2666", true)],
            ..PrivateRoutingConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(PrivateConfigError::Invalid(message)) if message.contains("reserved")
        ));
        assert!(generate_mihomo_config(&config, &BTreeMap::new(), "test-secret").is_err());
    }

    #[test]
    fn duplicate_subscription_secret_refs_are_rejected() {
        let mut config = PrivateRoutingConfig {
            outlets: vec![
                subscription("subscription-a", "subscription.shared"),
                subscription("subscription-b", "subscription.shared"),
            ],
            ..PrivateRoutingConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(PrivateConfigError::Invalid(message))
                if message == "duplicate subscription secret_ref"
        ));

        config.outlets[1] = subscription("subscription-b", "subscription.b");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn migrates_legacy_dual_outlet_without_exposing_url_in_summary() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("routing.toml");
        let legacy = r#"
subscription_url = "https://example.invalid/provider/credential-token"
provider_update_seconds = 180
controller_port = 39090
route_mode = "priority"
priority = ["subscription-a", "chaoshihui"]
cooldown_seconds = 60
minimum_improvement_ms = 150
probe_targets = ["https://a.invalid/", "https://b.invalid/"]
"#;
        fs::write(&path, legacy).expect("legacy file");
        let config = PrivateRoutingConfig::load(&path).expect("migrate");
        assert_eq!(config.entry.port, 36_666);
        assert_eq!(config.outlets.len(), 2);
        assert_eq!(config.priority(), ["subscription-a", "chaoshihui"]);
        let summary = serde_json::to_string(&config.summary(&config.resolved_subscription_urls()))
            .expect("summary");
        assert!(!summary.contains("credential-token"));
        assert!(!summary.contains("example.invalid"));
    }

    #[test]
    fn migrates_empty_legacy_subscription_slot_and_manual_reference() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("routing.toml");
        let legacy = r#"
subscription_url = ""
provider_update_seconds = 180
controller_port = 39090
route_mode = "manual"
manual_outlet = "subscription-a"
priority = ["chaoshihui", "subscription-a"]
cooldown_seconds = 60
minimum_improvement_ms = 150
probe_targets = ["https://a.invalid/", "https://b.invalid/"]
"#;
        fs::write(&path, legacy).expect("legacy file");
        let config = PrivateRoutingConfig::load(&path).expect("migrate");
        assert_eq!(config.manual_outlet.as_deref(), Some("subscription-a"));
        assert_eq!(config.priority(), ["chaoshihui", "subscription-a"]);
        assert_eq!(config.outlets.len(), 2);
        assert!(config.resolved_subscription_urls().is_empty());
        assert!(matches!(
            config.outlets[1].kind,
            OutletKind::Subscription { .. }
        ));
    }

    #[test]
    fn invalid_primary_rolls_back_to_last_valid_config() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("routing.toml");
        let mut config = PrivateRoutingConfig::default();
        config.entry.port = 4_001;
        config.save(&path).expect("first save");
        config.entry.port = 4_002;
        config.save(&path).expect("second save");
        fs::write(&path, "version = 999").expect("damage primary");
        let recovered = PrivateRoutingConfig::load(&path).expect("backup");
        assert_eq!(recovered.entry.port, 4_002);
    }

    #[test]
    fn generated_dynamic_config_uses_resolved_subscriptions_and_fails_closed() {
        let config = PrivateRoutingConfig {
            outlets: vec![
                subscription("sub-a", "secret.a"),
                subscription("sub-b", "secret.b"),
                subscription("sub-c", "secret.c"),
                local("local-a", "http://127.0.0.1:2666", true),
                local("local-b", "socks5h://127.0.0.1:4666", true),
            ],
            ..PrivateRoutingConfig::default()
        };
        let resolved = [
            ("secret.a".into(), "https://a.invalid/provider".into()),
            ("secret.b".into(), "https://b.invalid/provider".into()),
            ("secret.c".into(), "https://c.invalid/provider".into()),
        ]
        .into_iter()
        .collect();
        let (yaml, summary) =
            generate_mihomo_config(&config, &resolved, "test-secret").expect("config");
        assert!(yaml.contains("mixed-port: 3666"));
        for id in ["sub-a", "sub-b", "sub-c", "local-a", "local-b"] {
            assert!(yaml.contains(&outlet_proxy_name(id)));
        }
        let document = serde_yaml::from_str::<serde_yaml::Value>(&yaml).expect("runtime yaml");
        let groups = document
            .get("proxy-groups")
            .and_then(serde_yaml::Value::as_sequence)
            .expect("proxy groups");
        for id in ["sub-a", "sub-b", "sub-c"] {
            let group = groups
                .iter()
                .find(|group| {
                    group.get("name").and_then(serde_yaml::Value::as_str)
                        == Some(outlet_proxy_name(id).as_str())
                })
                .expect("subscription group");
            assert!(
                group
                    .get("proxies")
                    .and_then(serde_yaml::Value::as_sequence)
                    .is_some_and(|proxies| proxies
                        .iter()
                        .any(|proxy| { proxy.as_str() == Some(FAIL_CLOSED_PROXY) })),
                "subscription group must have an explicit REJECT fallback"
            );
        }
        assert!(yaml.contains("REJECT"));
        assert!(!yaml.contains("DIRECT"));
        assert_eq!(summary.enabled_outlet_count, 5);
        assert_eq!(summary.configured_subscription_count, 3);
    }

    #[test]
    fn missing_subscription_secret_is_not_added_to_master_selector() {
        let config = PrivateRoutingConfig {
            outlets: vec![subscription("sub-a", "secret.a")],
            ..PrivateRoutingConfig::default()
        };
        let (yaml, summary) =
            generate_mihomo_config(&config, &BTreeMap::new(), "test-secret").expect("config");
        assert!(!yaml.contains("VPN-HUB-OUTLET-sub-a"));
        assert!(yaml.contains("REJECT"));
        assert_eq!(summary.configured_subscription_count, 0);
    }

    #[test]
    fn udp_selector_contains_only_evidence_backed_supported_outlets() {
        let config = PrivateRoutingConfig {
            outlets: vec![
                subscription("sub-supported", "secret.supported"),
                subscription("sub-unknown", "secret.unknown"),
                local("local-tcp-only", "socks5://127.0.0.1:2666", true),
                local("local-supported", "socks5://127.0.0.1:4666", true),
            ],
            ..PrivateRoutingConfig::default()
        };
        let resolved = [
            (
                "secret.supported".into(),
                "https://supported.invalid/provider".into(),
            ),
            (
                "secret.unknown".into(),
                "https://unknown.invalid/provider".into(),
            ),
        ]
        .into_iter()
        .collect();
        let capabilities = [
            ("sub-supported".into(), UdpCapabilityStatus::Supported),
            ("sub-unknown".into(), UdpCapabilityStatus::Unknown),
            ("local-tcp-only".into(), UdpCapabilityStatus::TcpOnly),
            ("local-supported".into(), UdpCapabilityStatus::Supported),
        ]
        .into_iter()
        .collect();
        let (yaml, summary) = generate_mihomo_config_with_udp_capabilities(
            &config,
            &resolved,
            "test-secret",
            &capabilities,
        )
        .expect("config");
        let document = serde_yaml::from_str::<serde_yaml::Value>(&yaml).expect("runtime yaml");
        let groups = document
            .get("proxy-groups")
            .and_then(serde_yaml::Value::as_sequence)
            .expect("groups");
        let udp_group = groups
            .iter()
            .find(|group| {
                group.get("name").and_then(serde_yaml::Value::as_str) == Some(UDP_SELECTOR)
            })
            .expect("UDP group");
        let udp_candidates = udp_group
            .get("proxies")
            .and_then(serde_yaml::Value::as_sequence)
            .expect("UDP candidates")
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            udp_candidates,
            [
                FAIL_CLOSED_PROXY,
                "VPN-HUB-OUTLET-sub-supported",
                "VPN-HUB-OUTLET-local-supported"
            ]
        );
        assert_eq!(
            document
                .get("rules")
                .and_then(serde_yaml::Value::as_sequence)
                .and_then(|rules| rules.first())
                .and_then(serde_yaml::Value::as_str),
            Some("NETWORK,UDP,VPN-HUB-UDP")
        );
        assert!(!yaml.contains("DIRECT"));
        assert_eq!(summary.udp_supported_outlet_count, 2);
        let proxies = document
            .get("proxies")
            .and_then(serde_yaml::Value::as_sequence)
            .expect("local proxies");
        assert_eq!(
            proxies
                .iter()
                .find(|proxy| {
                    proxy.get("name").and_then(serde_yaml::Value::as_str)
                        == Some("VPN-HUB-OUTLET-local-tcp-only")
                })
                .and_then(|proxy| proxy.get("udp"))
                .and_then(serde_yaml::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            proxies
                .iter()
                .find(|proxy| {
                    proxy.get("name").and_then(serde_yaml::Value::as_str)
                        == Some("VPN-HUB-OUTLET-local-supported")
                })
                .and_then(|proxy| proxy.get("udp"))
                .and_then(serde_yaml::Value::as_bool),
            Some(true)
        );
    }
}
