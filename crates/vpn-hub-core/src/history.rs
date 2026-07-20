use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::HealthStatus;

/// Supported, bounded history windows. The wire values are stable API values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryWindow {
    #[serde(rename = "1h")]
    OneHour,
    #[serde(rename = "24h")]
    #[default]
    TwentyFourHours,
    #[serde(rename = "7d")]
    SevenDays,
    #[serde(rename = "30d")]
    ThirtyDays,
}

impl HistoryWindow {
    #[must_use]
    pub const fn seconds(self) -> i64 {
        match self {
            Self::OneHour => 60 * 60,
            Self::TwentyFourHours => 24 * 60 * 60,
            Self::SevenDays => 7 * 24 * 60 * 60,
            Self::ThirtyDays => 30 * 24 * 60 * 60,
        }
    }

    pub(crate) fn start(self, now: DateTime<Utc>) -> DateTime<Utc> {
        now - Duration::seconds(self.seconds())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryOutletKind {
    Subscription,
    LocalProxy,
    Unknown,
}

impl HistoryOutletKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::LocalProxy => "local_proxy",
            Self::Unknown => "unknown",
        }
    }
}

impl TryFrom<&str> for HistoryOutletKind {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "subscription" => Ok(Self::Subscription),
            "local_proxy" => Ok(Self::LocalProxy),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown history outlet kind: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryEventType {
    Probe,
    State,
    RouteSwitch,
}

impl HistoryEventType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::State => "state",
            Self::RouteSwitch => "route_switch",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFilter {
    #[serde(default)]
    pub window: HistoryWindow,
    #[serde(default)]
    pub outlet_id: Option<String>,
    #[serde(default)]
    pub kind: Option<HistoryOutletKind>,
    #[serde(default)]
    pub status: Option<HealthStatus>,
    #[serde(default)]
    pub event_type: Option<HistoryEventType>,
    #[serde(default)]
    pub page: u32,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

impl Default for HistoryFilter {
    fn default() -> Self {
        Self {
            window: HistoryWindow::default(),
            outlet_id: None,
            kind: None,
            status: None,
            event_type: None,
            page: 0,
            page_size: default_page_size(),
        }
    }
}

impl HistoryFilter {
    pub(crate) fn bounded_page_size(&self) -> u32 {
        self.page_size.clamp(1, 500)
    }
}

const fn default_page_size() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryOutletSnapshot {
    pub outlet_id: String,
    pub label: String,
    pub kind: HistoryOutletKind,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryMetric {
    pub outlet_id: String,
    pub label: String,
    pub kind: HistoryOutletKind,
    pub deleted: bool,
    pub sample_count: u64,
    pub online_samples: u64,
    pub availability_percent: f64,
    pub p50_latency_ms: Option<u64>,
    pub p95_latency_ms: Option<u64>,
    pub failure_count: u64,
    pub failure_duration_seconds: u64,
    pub ongoing_failure: bool,
    pub confirmed_route_switches: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryOutletOption {
    pub outlet_id: String,
    pub label: String,
    pub kind: HistoryOutletKind,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub event_type: HistoryEventType,
    pub occurred_at: String,
    pub outlet_id: String,
    pub outlet_label: String,
    pub outlet_kind: HistoryOutletKind,
    pub deleted: bool,
    pub status: Option<HealthStatus>,
    pub from_status: Option<HealthStatus>,
    pub to_status: Option<HealthStatus>,
    pub latency_ms: Option<u64>,
    pub from_outlet_id: Option<String>,
    pub to_outlet_id: Option<String>,
    pub mode: Option<String>,
    pub reason: Option<String>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryResponse {
    pub window_start: String,
    pub window_end: String,
    pub metrics: Vec<HistoryMetric>,
    pub outlets: Vec<HistoryOutletOption>,
    pub records: Vec<HistoryRecord>,
    pub total_count: u64,
    pub page: u32,
    pub total_pages: u32,
    pub next_page: Option<u32>,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryExport {
    pub path: String,
    pub rows: u64,
}

pub(crate) fn sanitized_code(value: &str) -> String {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if valid {
        value.to_owned()
    } else {
        "redacted_reason".into()
    }
}

pub(crate) fn sanitized_label(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let looks_sensitive = value.is_empty()
        || value.len() > 80
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.matches('.').count() >= 3
        || ["token", "secret", "password", "controller", "节点"]
            .iter()
            .any(|marker| lower.contains(marker));
    if looks_sensitive {
        "已脱敏出口".into()
    } else {
        value.to_owned()
    }
}

/// Escapes one already-sanitized value for RFC 4180 CSV and neutralizes
/// spreadsheet formula prefixes (including whitespace-prefixed formulas).
pub(crate) fn csv_cell(value: &str) -> String {
    let formula = value
        .trim_start_matches(|character: char| {
            character.is_ascii_control() || character.is_whitespace()
        })
        .starts_with(['=', '+', '-', '@']);
    let guarded = if formula {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_formula_prefixes_are_neutralized() {
        for value in [
            "=cmd()",
            "+1",
            "-2",
            "@sum",
            "  =hidden",
            "\t+hidden",
            "\n=hidden",
            "\r\n@hidden",
        ] {
            let cell = csv_cell(value);
            assert!(cell.starts_with("\"'"), "{value:?}: {cell}");
        }
        assert_eq!(csv_cell("safe, value"), "\"safe, value\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("第一行\n第二行"), "\"第一行\n第二行\"");
        assert_eq!(csv_cell("出口甲"), "\"出口甲\"");
    }

    #[test]
    fn unsafe_reason_is_replaced_instead_of_partially_leaked() {
        assert_eq!(sanitized_code("timeout"), "timeout");
        assert_eq!(
            sanitized_code("https://secret.invalid/token"),
            "redacted_reason"
        );
        assert_eq!(sanitized_code("@formula"), "redacted_reason");
    }

    #[test]
    fn display_labels_reject_secret_shaped_values() {
        assert_eq!(sanitized_label("本地出口 A"), "本地出口 A");
        for value in [
            "https://example.invalid/private",
            "controller-secret-value",
            "192.0.2.1",
            "订阅节点甲",
        ] {
            assert_eq!(sanitized_label(value), "已脱敏出口");
        }
    }
}
