use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    CredentialState, EntryConfig, GuardianConfig, MonitorConfig, OutletConfig, OutletKind,
    PrivateRoutingConfig, RouteMode, SubscriptionCredentialStatus, normalize_loopback_host,
};

const MIN_REFRESH_SECONDS: u64 = 5;
const MAX_REFRESH_SECONDS: u64 = 86_400;
const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_THRESHOLD: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalProxyProtocol {
    Http,
    Socks5,
    Socks5h,
}

impl LocalProxyProtocol {
    const fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
        }
    }

    fn from_scheme(value: &str) -> Option<Self> {
        match value {
            "http" => Some(Self::Http),
            "socks5" => Some(Self::Socks5),
            "socks5h" => Some(Self::Socks5h),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SettingsOutletDraft {
    Subscription {
        outlet_id: String,
        label: String,
        enabled: bool,
        provider_update_seconds: u64,
    },
    LocalProxy {
        outlet_id: String,
        label: String,
        enabled: bool,
        protocol: LocalProxyProtocol,
        host: String,
        port: u16,
    },
}

impl SettingsOutletDraft {
    #[must_use]
    pub fn outlet_id(&self) -> &str {
        match self {
            Self::Subscription { outlet_id, .. } | Self::LocalProxy { outlet_id, .. } => outlet_id,
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        match self {
            Self::Subscription { enabled, .. } | Self::LocalProxy { enabled, .. } => *enabled,
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Subscription { label, .. } | Self::LocalProxy { label, .. } => label,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsDraft {
    pub entry: EntryConfig,
    pub route_mode: RouteMode,
    pub manual_outlet: Option<String>,
    pub cooldown_seconds: u64,
    pub minimum_improvement_ms: u64,
    pub probe_targets: Vec<String>,
    pub refresh_interval_seconds: u64,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub retention_days: u32,
    pub outlets: Vec<SettingsOutletDraft>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafeSubscriptionStatus {
    pub subscription_id: String,
    pub state: CredentialState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafeSettingsView {
    pub draft: SettingsDraft,
    pub credentials: Vec<SafeSubscriptionStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationIssue {
    pub field: String,
    pub code: String,
    pub message: String,
}

impl ValidationIssue {
    #[must_use]
    pub fn new(
        field: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsChange {
    pub code: String,
    pub summary: String,
    pub impact: SettingsImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsImpact {
    LiveApply,
    ManagedCoreReload,
    DedicatedTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsDiff {
    pub changes: Vec<SettingsChange>,
}

impl SettingsDiff {
    #[must_use]
    pub fn has_impact(&self, impact: SettingsImpact) -> bool {
        self.changes.iter().any(|change| change.impact == impact)
    }

    #[must_use]
    pub fn requires_managed_core_reload(&self) -> bool {
        self.has_impact(SettingsImpact::ManagedCoreReload)
    }

    #[must_use]
    pub fn affects_private_routing(&self) -> bool {
        self.changes.iter().any(|change| {
            matches!(
                change.code.as_str(),
                "entry_changed"
                    | "route_policy_changed"
                    | "routing_thresholds_changed"
                    | "probe_targets_changed"
                    | "outlets_changed"
            )
        })
    }

    #[must_use]
    pub fn requires_authenticated_controller_apply(&self) -> bool {
        self.changes.iter().any(|change| {
            matches!(
                change.code.as_str(),
                "route_policy_changed" | "routing_thresholds_changed"
            )
        })
    }

    pub fn add_change(
        &mut self,
        code: impl Into<String>,
        summary: impl Into<String>,
        impact: SettingsImpact,
    ) {
        self.changes.push(SettingsChange {
            code: code.into(),
            summary: summary.into(),
            impact,
        });
    }
}

impl SettingsDraft {
    #[must_use]
    pub fn from_configs(
        private: &PrivateRoutingConfig,
        guardian: &GuardianConfig,
        retention_days: u32,
    ) -> Self {
        let outlets = private
            .outlets
            .iter()
            .filter_map(|outlet| match &outlet.kind {
                OutletKind::Subscription {
                    provider_update_seconds,
                    ..
                } => Some(SettingsOutletDraft::Subscription {
                    outlet_id: outlet.id.clone(),
                    label: outlet.label.clone(),
                    enabled: outlet.enabled,
                    provider_update_seconds: *provider_update_seconds,
                }),
                OutletKind::LocalProxy { endpoint } => {
                    let url = reqwest::Url::parse(endpoint).ok()?;
                    let protocol = LocalProxyProtocol::from_scheme(url.scheme())?;
                    Some(SettingsOutletDraft::LocalProxy {
                        outlet_id: outlet.id.clone(),
                        label: outlet.label.clone(),
                        enabled: outlet.enabled,
                        protocol,
                        host: url.host_str()?.to_owned(),
                        port: url.port()?,
                    })
                }
            })
            .collect();
        Self {
            entry: private.entry.clone(),
            route_mode: private.route_mode,
            manual_outlet: private.manual_outlet.clone(),
            cooldown_seconds: private.cooldown_seconds,
            minimum_improvement_ms: private.minimum_improvement_ms,
            probe_targets: private.probe_targets.clone(),
            refresh_interval_seconds: guardian.monitor.interval_seconds,
            connect_timeout_ms: guardian.monitor.connect_timeout_ms,
            request_timeout_ms: guardian.monitor.request_timeout_ms,
            failure_threshold: guardian.monitor.failure_threshold,
            recovery_threshold: guardian.monitor.recovery_threshold,
            retention_days,
            outlets,
        }
    }

    /// Builds the private routing candidate while preserving stable secret
    /// references for existing subscription IDs. Kind changes for an existing
    /// ID are rejected to keep historical and credential identity stable.
    ///
    /// # Errors
    ///
    /// Returns field-scoped, non-sensitive validation issues when the draft
    /// cannot form a safe private routing configuration.
    #[allow(clippy::too_many_lines)]
    pub fn private_candidate(
        &self,
        current: &PrivateRoutingConfig,
    ) -> Result<PrivateRoutingConfig, Vec<ValidationIssue>> {
        let mut issues = self.basic_validation_issues();
        let current_by_id = current
            .outlets
            .iter()
            .map(|outlet| (outlet.id.as_str(), outlet))
            .collect::<HashMap<_, _>>();
        let mut outlets = Vec::with_capacity(self.outlets.len());
        for draft in &self.outlets {
            let id = draft.outlet_id();
            let old = current_by_id.get(id).copied();
            let outlet = match draft {
                SettingsOutletDraft::Subscription {
                    outlet_id,
                    label,
                    enabled,
                    provider_update_seconds,
                } => {
                    let secret_ref = match old.map(|outlet| &outlet.kind) {
                        Some(OutletKind::Subscription { secret_ref, .. }) => secret_ref.clone(),
                        Some(OutletKind::LocalProxy { .. }) => {
                            issues.push(ValidationIssue::new(
                                format!("outlets.{outlet_id}.kind"),
                                "stable_id_kind_change",
                                "已有出口不能在保留 ID 的同时改变类型",
                            ));
                            continue;
                        }
                        None => format!("settings.{outlet_id}"),
                    };
                    OutletConfig {
                        id: outlet_id.clone(),
                        label: label.clone(),
                        enabled: *enabled,
                        kind: OutletKind::Subscription {
                            secret_ref,
                            provider_update_seconds: *provider_update_seconds,
                        },
                    }
                }
                SettingsOutletDraft::LocalProxy {
                    outlet_id,
                    label,
                    enabled,
                    protocol,
                    host,
                    port,
                } => {
                    if matches!(
                        old.map(|outlet| &outlet.kind),
                        Some(OutletKind::Subscription { .. })
                    ) {
                        issues.push(ValidationIssue::new(
                            format!("outlets.{outlet_id}.kind"),
                            "stable_id_kind_change",
                            "已有出口不能在保留 ID 的同时改变类型",
                        ));
                        continue;
                    }
                    let formatted_host = if host.contains(':') {
                        format!("[{host}]")
                    } else {
                        host.clone()
                    };
                    OutletConfig {
                        id: outlet_id.clone(),
                        label: label.clone(),
                        enabled: *enabled,
                        kind: OutletKind::LocalProxy {
                            endpoint: format!("{}://{formatted_host}:{port}", protocol.scheme()),
                        },
                    }
                }
            };
            outlets.push(outlet);
        }
        let mut candidate = current.clone();
        candidate.entry = self.entry.clone();
        candidate.route_mode = self.route_mode;
        candidate.manual_outlet.clone_from(&self.manual_outlet);
        candidate.cooldown_seconds = self.cooldown_seconds;
        candidate.minimum_improvement_ms = self.minimum_improvement_ms;
        candidate.probe_targets.clone_from(&self.probe_targets);
        candidate.outlets = outlets;
        if let Err(error) = candidate.validate() {
            let message = error.to_string();
            let field = if message.contains("entry.") {
                "entry"
            } else if message.contains("probe target") || message.contains("probe_targets") {
                "probe_targets"
            } else if message.contains("manual_outlet") {
                "manual_outlet"
            } else {
                "outlets"
            };
            if !issues.iter().any(|issue| issue.field == field) {
                issues.push(ValidationIssue::new(
                    field,
                    "invalid_routing_config",
                    message,
                ));
            }
        }
        if let Some(manual) = candidate.manual_outlet.as_deref()
            && !candidate
                .enabled_outlets()
                .any(|outlet| outlet.id == manual)
        {
            issues.push(ValidationIssue::new(
                "manual_outlet",
                "manual_outlet_disabled",
                "手动出口必须存在且已启用",
            ));
        }
        if issues.is_empty() {
            Ok(candidate)
        } else {
            Err(issues)
        }
    }

    #[must_use]
    pub fn guardian_candidate(&self, current: &GuardianConfig) -> GuardianConfig {
        let mut candidate = current.clone();
        candidate.monitor = MonitorConfig {
            interval_seconds: self.refresh_interval_seconds,
            connect_timeout_ms: self.connect_timeout_ms,
            request_timeout_ms: self.request_timeout_ms,
            failure_threshold: self.failure_threshold,
            recovery_threshold: self.recovery_threshold,
        };
        candidate
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn basic_validation_issues(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        if self.outlets.is_empty() || !self.outlets.iter().any(SettingsOutletDraft::enabled) {
            issues.push(ValidationIssue::new(
                "outlets",
                "enabled_outlet_required",
                "正式路由配置至少需要一个启用出口；仅 Guardian monitor-only 配置可以为空",
            ));
        }
        if self.outlets.len() > 64 {
            issues.push(ValidationIssue::new(
                "outlets",
                "too_many_outlets",
                "出口数量不能超过 64",
            ));
        }
        let mut ids = HashSet::new();
        for outlet in &self.outlets {
            if !ids.insert(outlet.outlet_id()) {
                issues.push(ValidationIssue::new(
                    "outlets",
                    "duplicate_outlet_id",
                    "出口 ID 不能重复",
                ));
            }
            let label = outlet.label();
            let lower = label.to_ascii_lowercase();
            if label.trim().is_empty()
                || label.len() > 80
                || label.chars().any(char::is_control)
                || label.contains("://")
                || ["token", "secret", "password", "controller"]
                    .iter()
                    .any(|marker| lower.contains(marker))
            {
                issues.push(ValidationIssue::new(
                    format!("outlets.{}.label", outlet.outlet_id()),
                    "unsafe_outlet_label",
                    "出口名称不能包含 URL、凭据形态或控制字符",
                ));
            }
            match outlet {
                SettingsOutletDraft::Subscription {
                    outlet_id,
                    provider_update_seconds,
                    ..
                } if *provider_update_seconds < 60 => issues.push(ValidationIssue::new(
                    format!("outlets.{outlet_id}.provider_update_seconds"),
                    "provider_update_too_short",
                    "订阅 provider 更新周期不能小于 60 秒",
                )),
                SettingsOutletDraft::LocalProxy {
                    outlet_id,
                    host,
                    port,
                    ..
                } => {
                    if normalize_loopback_host(host).is_none() {
                        issues.push(ValidationIssue::new(
                            format!("outlets.{outlet_id}.host"),
                            "local_proxy_host_not_loopback",
                            "本地出口地址必须是 loopback IP 或 localhost",
                        ));
                    }
                    if *port == 0 {
                        issues.push(ValidationIssue::new(
                            format!("outlets.{outlet_id}.port"),
                            "local_proxy_port_invalid",
                            "本地出口端口必须在 1 到 65535 之间",
                        ));
                    }
                }
                SettingsOutletDraft::Subscription { .. } => {}
            }
        }
        if self.route_mode == RouteMode::Manual && self.manual_outlet.is_none() {
            issues.push(ValidationIssue::new(
                "manual_outlet",
                "manual_outlet_required",
                "手动模式必须选择一个已启用出口",
            ));
        }
        if self.probe_targets.len() < 2
            || self.probe_targets.iter().any(|target| {
                reqwest::Url::parse(target).map_or(true, |url| url.scheme() != "https")
            })
        {
            issues.push(ValidationIssue::new(
                "probe_targets",
                "invalid_probe_targets",
                "探测目标至少需要两个有效 HTTPS URL",
            ));
        }
        if !(MIN_REFRESH_SECONDS..=MAX_REFRESH_SECONDS).contains(&self.refresh_interval_seconds) {
            issues.push(ValidationIssue::new(
                "refresh_interval_seconds",
                "refresh_interval_out_of_range",
                "刷新周期必须在 5 秒到 24 小时之间",
            ));
        }
        if self.connect_timeout_ms == 0 || self.connect_timeout_ms > MAX_TIMEOUT_MS {
            issues.push(ValidationIssue::new(
                "connect_timeout_ms",
                "connect_timeout_out_of_range",
                "连接超时必须在 1 毫秒到 120 秒之间",
            ));
        }
        if self.request_timeout_ms == 0 || self.request_timeout_ms > MAX_TIMEOUT_MS {
            issues.push(ValidationIssue::new(
                "request_timeout_ms",
                "request_timeout_out_of_range",
                "请求超时必须在 1 毫秒到 120 秒之间",
            ));
        }
        if (1..=MAX_TIMEOUT_MS).contains(&self.connect_timeout_ms)
            && (1..=MAX_TIMEOUT_MS).contains(&self.request_timeout_ms)
            && self.request_timeout_ms < self.connect_timeout_ms
        {
            issues.push(ValidationIssue::new(
                "request_timeout_ms",
                "request_timeout_before_connect_timeout",
                "请求超时不能小于连接超时",
            ));
        }
        if !(1..=MAX_THRESHOLD).contains(&self.failure_threshold) {
            issues.push(ValidationIssue::new(
                "failure_threshold",
                "failure_threshold_out_of_range",
                "失败阈值必须在 1 到 100 之间",
            ));
        }
        if !(1..=MAX_THRESHOLD).contains(&self.recovery_threshold) {
            issues.push(ValidationIssue::new(
                "recovery_threshold",
                "recovery_threshold_out_of_range",
                "恢复阈值必须在 1 到 100 之间",
            ));
        }
        if !(1..=3650).contains(&self.retention_days) {
            issues.push(ValidationIssue::new(
                "retention_days",
                "retention_out_of_range",
                "历史保留期必须在 1 到 3650 天之间",
            ));
        }
        if self.cooldown_seconds == 0 || self.cooldown_seconds > 86_400 {
            issues.push(ValidationIssue::new(
                "cooldown_seconds",
                "cooldown_out_of_range",
                "冷却时间必须在 1 秒到 24 小时之间",
            ));
        }
        if self.minimum_improvement_ms > 60_000 {
            issues.push(ValidationIssue::new(
                "minimum_improvement_ms",
                "improvement_out_of_range",
                "切换改善阈值不能超过 60 秒",
            ));
        }
        issues
    }

    #[must_use]
    pub fn diff(&self, current: &Self) -> SettingsDiff {
        let mut diff = SettingsDiff {
            changes: Vec::new(),
        };
        let mut add = |code: &str, summary: &str, impact: SettingsImpact| {
            diff.add_change(code, summary, impact);
        };
        if self.entry != current.entry {
            add(
                "entry_changed",
                "统一入口只能通过专用安全事务更新",
                SettingsImpact::DedicatedTransaction,
            );
        }
        if self.route_mode != current.route_mode || self.manual_outlet != current.manual_outlet {
            add(
                "route_policy_changed",
                "默认路由模式或手动出口将通过 Controller 在线更新",
                SettingsImpact::LiveApply,
            );
        }
        if self.cooldown_seconds != current.cooldown_seconds
            || self.minimum_improvement_ms != current.minimum_improvement_ms
        {
            add(
                "routing_thresholds_changed",
                "切换阈值将在线更新",
                SettingsImpact::LiveApply,
            );
        }
        if self.probe_targets != current.probe_targets {
            add(
                "probe_targets_changed",
                "探测目标影响 Mihomo provider 健康检查，将受控重载核心",
                SettingsImpact::ManagedCoreReload,
            );
        }
        if self.outlets != current.outlets {
            add(
                "outlets_changed",
                "出口定义、provider、启用状态或顺序将受控重载核心",
                SettingsImpact::ManagedCoreReload,
            );
        }
        if self.refresh_interval_seconds != current.refresh_interval_seconds
            || self.connect_timeout_ms != current.connect_timeout_ms
            || self.request_timeout_ms != current.request_timeout_ms
            || self.failure_threshold != current.failure_threshold
            || self.recovery_threshold != current.recovery_threshold
        {
            add(
                "monitor_changed",
                "Guardian 探测周期与阈值将在线更新",
                SettingsImpact::LiveApply,
            );
        }
        if self.retention_days != current.retention_days {
            add(
                "retention_changed",
                "历史保留期将在线更新并清理过期数据",
                SettingsImpact::LiveApply,
            );
        }
        diff
    }
}

impl SafeSettingsView {
    #[must_use]
    pub fn new(draft: SettingsDraft, statuses: &[SubscriptionCredentialStatus]) -> Self {
        Self {
            draft,
            credentials: statuses
                .iter()
                .map(|status| SafeSubscriptionStatus {
                    subscription_id: status.subscription_id.clone(),
                    state: status.state,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialState, ProbeOutletConfig};

    fn guardian() -> GuardianConfig {
        GuardianConfig {
            database_path: "guardian.db".into(),
            monitor: MonitorConfig {
                interval_seconds: 15,
                connect_timeout_ms: 1_500,
                request_timeout_ms: 8_000,
                failure_threshold: 2,
                recovery_threshold: 3,
            },
            outlets: Vec::<ProbeOutletConfig>::new(),
        }
    }

    fn five_outlet_draft() -> SettingsDraft {
        let private = PrivateRoutingConfig::default();
        let mut draft = SettingsDraft::from_configs(&private, &guardian(), 30);
        draft.entry.port = 45_001;
        draft.outlets = vec![
            SettingsOutletDraft::Subscription {
                outlet_id: "sub-a".into(),
                label: "订阅 A".into(),
                enabled: true,
                provider_update_seconds: 180,
            },
            SettingsOutletDraft::Subscription {
                outlet_id: "sub-b".into(),
                label: "订阅 B".into(),
                enabled: true,
                provider_update_seconds: 180,
            },
            SettingsOutletDraft::Subscription {
                outlet_id: "sub-c".into(),
                label: "订阅 C".into(),
                enabled: false,
                provider_update_seconds: 180,
            },
            SettingsOutletDraft::LocalProxy {
                outlet_id: "local-a".into(),
                label: "本地 A".into(),
                enabled: true,
                protocol: LocalProxyProtocol::Socks5h,
                host: "127.0.0.1".into(),
                port: 45_002,
            },
            SettingsOutletDraft::LocalProxy {
                outlet_id: "local-b".into(),
                label: "本地 B".into(),
                enabled: true,
                protocol: LocalProxyProtocol::Http,
                host: "127.0.0.2".into(),
                port: 45_003,
            },
        ];
        draft
    }

    #[test]
    fn builds_three_subscriptions_and_two_local_outlets_with_stable_ids() {
        let current = PrivateRoutingConfig::default();
        let draft = five_outlet_draft();
        let first = draft.private_candidate(&current).expect("candidate");
        let mut renamed = draft.clone();
        renamed.outlets.swap(0, 3);
        if let SettingsOutletDraft::Subscription { label, .. } = &mut renamed.outlets[1] {
            *label = "重命名订阅".into();
        }
        let second = renamed.private_candidate(&first).expect("reordered");
        assert_eq!(first.outlets.len(), 5);
        assert_eq!(second.outlets[0].id, "local-a");
        let refs = first
            .outlets
            .iter()
            .filter_map(|outlet| outlet.secret_ref().map(str::to_owned))
            .collect::<HashSet<_>>();
        let renamed_refs = second
            .outlets
            .iter()
            .filter_map(|outlet| outlet.secret_ref().map(str::to_owned))
            .collect::<HashSet<_>>();
        assert_eq!(refs, renamed_refs);
    }

    #[test]
    fn rejects_empty_duplicate_remote_and_unreasonable_drafts() {
        let current = PrivateRoutingConfig::default();
        let mut draft = five_outlet_draft();
        draft.outlets.clear();
        draft.failure_threshold = 0;
        draft.retention_days = 0;
        let Err(issues) = draft.private_candidate(&current) else {
            panic!("invalid draft was accepted");
        };
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "enabled_outlet_required")
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "failure_threshold_out_of_range")
        );

        let mut draft = five_outlet_draft();
        if let SettingsOutletDraft::LocalProxy { host, .. } = &mut draft.outlets[3] {
            *host = "192.0.2.1".into();
        }
        let duplicate = draft.outlets[0].clone();
        draft.outlets.push(duplicate);
        let Err(issues) = draft.private_candidate(&current) else {
            panic!("invalid draft was accepted");
        };
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "duplicate_outlet_id")
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "local_proxy_host_not_loopback"
                    && issue.field == "outlets.local-a.host")
        );
    }

    #[test]
    fn safe_view_never_contains_secret_reference_or_value() {
        let draft = five_outlet_draft();
        let view = SafeSettingsView::new(
            draft,
            &[SubscriptionCredentialStatus {
                subscription_id: "sub-a".into(),
                secret_ref: "settings.sub-a".into(),
                state: CredentialState::Configured,
            }],
        );
        let json = serde_json::to_string(&view).expect("safe JSON");
        assert!(!json.contains("settings.sub-a"));
        assert!(!json.contains("secret_ref"));
        assert!(json.contains("configured"));
    }

    #[test]
    fn classifies_every_settings_field_by_operational_impact() {
        fn assert_only_impact(
            current: &SettingsDraft,
            mutate: impl FnOnce(&mut SettingsDraft),
            expected: SettingsImpact,
        ) {
            let mut candidate = current.clone();
            mutate(&mut candidate);
            let diff = candidate.diff(current);
            assert_eq!(diff.changes.len(), 1, "unexpected changes: {diff:?}");
            assert_eq!(diff.changes[0].impact, expected);
        }

        let current = five_outlet_draft();
        assert_only_impact(
            &current,
            |draft| draft.entry.port += 1,
            SettingsImpact::DedicatedTransaction,
        );
        assert_only_impact(
            &current,
            |draft| draft.route_mode = RouteMode::Fastest,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.manual_outlet = Some("local-a".into()),
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.cooldown_seconds += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.minimum_improvement_ms += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| {
                draft
                    .probe_targets
                    .push("https://probe.invalid/health".into());
            },
            SettingsImpact::ManagedCoreReload,
        );
        assert_only_impact(
            &current,
            |draft| draft.refresh_interval_seconds += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.connect_timeout_ms += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.request_timeout_ms += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.failure_threshold += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.recovery_threshold += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| draft.retention_days += 1,
            SettingsImpact::LiveApply,
        );
        assert_only_impact(
            &current,
            |draft| {
                let SettingsOutletDraft::Subscription {
                    provider_update_seconds,
                    ..
                } = &mut draft.outlets[0]
                else {
                    panic!("expected subscription outlet");
                };
                *provider_update_seconds += 60;
            },
            SettingsImpact::ManagedCoreReload,
        );
    }

    #[test]
    fn ordinary_settings_draft_rejects_dedicated_capability_fields() {
        for field in ["system_proxy", "tun", "service"] {
            let mut value = serde_json::to_value(five_outlet_draft()).expect("serialize draft");
            let object = value.as_object_mut().expect("draft object");
            object.insert(field.into(), serde_json::json!(true));
            assert!(
                serde_json::from_value::<SettingsDraft>(value).is_err(),
                "ordinary settings accepted dedicated field {field}"
            );
        }
    }

    #[test]
    fn validation_issues_identify_the_exact_editable_field() {
        let current = PrivateRoutingConfig::default();

        let mut connect = five_outlet_draft();
        connect.connect_timeout_ms = 0;
        let issues = connect.basic_validation_issues();
        assert!(
            issues
                .iter()
                .any(|issue| issue.field == "connect_timeout_ms")
        );
        assert!(!issues.iter().any(|issue| {
            issue.code == "connect_timeout_out_of_range" && issue.field == "request_timeout_ms"
        }));

        let mut recovery = five_outlet_draft();
        recovery.recovery_threshold = 0;
        let issues = recovery.basic_validation_issues();
        assert!(
            issues
                .iter()
                .any(|issue| issue.field == "recovery_threshold")
        );
        assert!(!issues.iter().any(|issue| {
            issue.code == "recovery_threshold_out_of_range" && issue.field == "failure_threshold"
        }));

        let mut manual = five_outlet_draft();
        manual.route_mode = RouteMode::Manual;
        manual.manual_outlet = None;
        let issues = manual.basic_validation_issues();
        assert!(issues.iter().any(|issue| issue.field == "manual_outlet"));

        let mut probes = five_outlet_draft();
        probes.probe_targets.truncate(1);
        let issues = probes.basic_validation_issues();
        assert!(issues.iter().any(|issue| issue.field == "probe_targets"));

        let mut outlet = five_outlet_draft();
        let SettingsOutletDraft::LocalProxy { host, .. } = &mut outlet.outlets[3] else {
            panic!("expected local outlet");
        };
        *host = "192.0.2.1".into();
        let Err(issues) = outlet.private_candidate(&current) else {
            panic!("remote outlet must fail");
        };
        assert!(
            issues
                .iter()
                .any(|issue| issue.field == "outlets.local-a.host")
        );
        assert!(!issues.iter().any(|issue| issue.field == "route_mode"));
    }
}
