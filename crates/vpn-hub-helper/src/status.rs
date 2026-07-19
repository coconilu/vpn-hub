use serde::{Deserialize, Serialize};

use crate::{CircuitState, EntrySummary, OutletSummary, SupervisorAuthority};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityStatus {
    Disabled,
    Desktop,
    Helper,
}

impl From<Option<SupervisorAuthority>> for AuthorityStatus {
    fn from(value: Option<SupervisorAuthority>) -> Self {
        match value {
            None => Self::Disabled,
            Some(SupervisorAuthority::Desktop) => Self::Desktop,
            Some(SupervisorAuthority::Helper) => Self::Helper,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnedProcessStatus {
    pub pid: u32,
    /// A one-way digest of PID creation identity, never a handle or executable path.
    pub creation_identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HelperStatus {
    pub protocol_version: u16,
    pub install_id: String,
    pub authority: AuthorityStatus,
    pub generation: u64,
    pub entry: EntrySummary,
    pub outlets: Vec<OutletSummary>,
    pub circuit_open: bool,
    pub owned_process: Option<OwnedProcessStatus>,
    pub fail_closed_reason: Option<String>,
}

impl HelperStatus {
    #[must_use]
    pub fn circuit_open(circuit: CircuitState) -> bool {
        circuit == CircuitState::Open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OutletHealthSummary, OutletKindSummary, PROTOCOL_VERSION};

    #[test]
    fn status_is_dynamic_and_sanitized() {
        let status = HelperStatus {
            protocol_version: PROTOCOL_VERSION,
            install_id: "install-a".into(),
            authority: AuthorityStatus::Helper,
            generation: 8,
            entry: EntrySummary {
                host: "127.0.0.1".into(),
                port: 49_151,
            },
            outlets: vec![OutletSummary {
                outlet_id: "subscription-work".into(),
                kind: OutletKindSummary::Subscription,
                health: OutletHealthSummary::Healthy,
            }],
            circuit_open: false,
            owned_process: Some(OwnedProcessStatus {
                pid: 42_001,
                creation_identity_sha256: "b".repeat(64),
            }),
            fail_closed_reason: None,
        };
        let rendered = serde_json::to_string(&status).unwrap();
        assert!(rendered.contains("49151"));
        for forbidden in [
            "subscription_url",
            "token",
            "password",
            "target",
            "node_name",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
