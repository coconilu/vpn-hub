use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    CredentialState, EntryConfig, GuardianConfig, MonitorConfig, OutletConfig, OutletKind,
    PrivateRoutingConfig, RouteMode, SubscriptionCredentialStatus,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsDiff {
    pub changes: Vec<SettingsChange>,
    pub runtime_changed: bool,
    pub monitor_changed: bool,
    pub retention_changed: bool,
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
            issues.push(ValidationIssue::new(
                "routing",
                "invalid_routing_config",
                error.to_string(),
            ));
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
            if label.len() > 80
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
        }
        if !(MIN_REFRESH_SECONDS..=MAX_REFRESH_SECONDS).contains(&self.refresh_interval_seconds) {
            issues.push(ValidationIssue::new(
                "refresh_interval_seconds",
                "refresh_interval_out_of_range",
                "刷新周期必须在 5 秒到 24 小时之间",
            ));
        }
        if self.connect_timeout_ms == 0
            || self.connect_timeout_ms > MAX_TIMEOUT_MS
            || self.request_timeout_ms < self.connect_timeout_ms
            || self.request_timeout_ms > MAX_TIMEOUT_MS
        {
            issues.push(ValidationIssue::new(
                "request_timeout_ms",
                "timeout_out_of_range",
                "请求超时必须不小于连接超时，且不超过 120 秒",
            ));
        }
        if !(1..=MAX_THRESHOLD).contains(&self.failure_threshold)
            || !(1..=MAX_THRESHOLD).contains(&self.recovery_threshold)
        {
            issues.push(ValidationIssue::new(
                "failure_threshold",
                "threshold_out_of_range",
                "失败与恢复阈值必须在 1 到 100 之间",
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
        let mut changes = Vec::new();
        let mut runtime_changed = false;
        let mut monitor_changed = false;
        let mut add = |code: &str, summary: &str| {
            changes.push(SettingsChange {
                code: code.into(),
                summary: summary.into(),
            });
        };
        if self.entry != current.entry {
            runtime_changed = true;
            add("entry_changed", "统一入口将更新");
        }
        if self.route_mode != current.route_mode || self.manual_outlet != current.manual_outlet {
            runtime_changed = true;
            add("route_policy_changed", "默认路由模式或手动出口将更新");
        }
        if self.cooldown_seconds != current.cooldown_seconds
            || self.minimum_improvement_ms != current.minimum_improvement_ms
        {
            runtime_changed = true;
            add("routing_thresholds_changed", "切换阈值将更新");
        }
        if self.probe_targets != current.probe_targets {
            runtime_changed = true;
            add("probe_targets_changed", "探测目标将更新");
        }
        if self.outlets != current.outlets {
            runtime_changed = true;
            add("outlets_changed", "出口定义、启用状态或顺序将更新");
        }
        if self.refresh_interval_seconds != current.refresh_interval_seconds
            || self.connect_timeout_ms != current.connect_timeout_ms
            || self.request_timeout_ms != current.request_timeout_ms
            || self.failure_threshold != current.failure_threshold
            || self.recovery_threshold != current.recovery_threshold
        {
            monitor_changed = true;
            add("monitor_changed", "Guardian 探测周期与阈值将更新");
        }
        let retention_changed = self.retention_days != current.retention_days;
        if retention_changed {
            add("retention_changed", "历史保留期将更新并清理过期数据");
        }
        SettingsDiff {
            changes,
            runtime_changed,
            monitor_changed,
            retention_changed,
        }
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
                .any(|issue| issue.code == "threshold_out_of_range")
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
                .any(|issue| issue.code == "invalid_routing_config")
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
}
