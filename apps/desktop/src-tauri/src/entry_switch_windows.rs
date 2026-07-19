//! Interactive-desktop `WinINet` adapter.
//!
//! The adapter is intentionally not wired to an IPC command until isolated
//! Windows acceptance proves the scope classifier. It cannot be constructed
//! for a service, RAS/VPN, named connection, or multi-connection context.
#![allow(dead_code)] // Compiled now; wiring stays disabled until isolated acceptance.

use vpn_hub_core::{
    EntrySwitchError, ProxyBackend, ProxyCapability, SystemProxySnapshot, UserProxyAuthority,
    WindowsProxyMode,
};
use vpn_hub_helper::{AuthorityFileGuard, InstallationReference, SupervisorAuthority};
use vpn_hub_windows_security::{
    WinInetLanProxySnapshot, query_current_user_default_lan_proxy,
    set_current_user_default_lan_proxy,
};

const PROXY_TYPE_DIRECT: u32 = 1;
const PROXY_TYPE_PROXY: u32 = 2;
const PROXY_TYPE_AUTO_PROXY_URL: u32 = 4;
const PROXY_TYPE_AUTO_DETECT: u32 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InteractiveUserLanScopeEvidence {
    pub interactive_user_scope_id: String,
    pub interactive_session: bool,
    pub active_connection_count: u8,
    pub has_ras_or_vpn: bool,
    pub connection_name: Option<String>,
}

pub(crate) struct WinInetUserProxyAdapter {
    scope_id: String,
}

pub(crate) struct EntrySwitchDesktopAuthorityGuard {
    _file_guard: AuthorityFileGuard,
    authority: UserProxyAuthority,
}

impl EntrySwitchDesktopAuthorityGuard {
    /// `installation` must originate from `InstallationReference::load`, which
    /// validates the fixed `ProgramData` installation root before this method
    /// opens the installer-preprovisioned lease without creating it.
    pub(crate) fn acquire(
        installation: &InstallationReference,
        user_scope_id: String,
        generation: u64,
        fencing_token: u64,
    ) -> Result<Self, EntrySwitchError> {
        let file_guard = AuthorityFileGuard::acquire_existing(
            &installation.entry_switch_authority_path(),
            SupervisorAuthority::Desktop,
            generation,
        )
        .map_err(|_| EntrySwitchError::Unauthorized)?;
        let authority = UserProxyAuthority {
            user_scope_id,
            generation,
            fencing_token,
        };
        Ok(Self {
            _file_guard: file_guard,
            authority,
        })
    }

    pub(crate) fn authority(&self) -> UserProxyAuthority {
        self.authority.clone()
    }
}

impl WinInetUserProxyAdapter {
    pub(crate) fn from_scope(
        evidence: InteractiveUserLanScopeEvidence,
    ) -> Result<Self, EntrySwitchError> {
        let valid_id = (16..=128).contains(&evidence.interactive_user_scope_id.len())
            && evidence.interactive_user_scope_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            });
        if !valid_id
            || !evidence.interactive_session
            || evidence.active_connection_count != 1
            || evidence.has_ras_or_vpn
            || evidence.connection_name.is_some()
        {
            return Err(EntrySwitchError::UnsupportedProxyScope);
        }
        Ok(Self {
            scope_id: evidence.interactive_user_scope_id,
        })
    }

    fn query(&self) -> Result<SystemProxySnapshot, EntrySwitchError> {
        debug_assert!(!self.scope_id.is_empty());
        let raw = query_current_user_default_lan_proxy()
            .map_err(|_| EntrySwitchError::UnsupportedProxyScope)?;
        Ok(from_raw(raw))
    }
}

impl ProxyBackend for WinInetUserProxyAdapter {
    fn capability(&self) -> ProxyCapability {
        ProxyCapability::SupportedDefaultLanCurrentUser
    }

    fn snapshot(&mut self) -> Result<SystemProxySnapshot, EntrySwitchError> {
        self.query()
    }

    fn compare_and_set(
        &mut self,
        expected_fingerprint: &str,
        replacement: &SystemProxySnapshot,
    ) -> Result<bool, EntrySwitchError> {
        let observed = self.query()?;
        if observed.fingerprint() != expected_fingerprint {
            return Ok(false);
        }
        let raw = to_raw(replacement)?;
        set_current_user_default_lan_proxy(&raw).map_err(|_| EntrySwitchError::Backend)?;
        Ok(true)
    }

    fn verify(&mut self, expected: &SystemProxySnapshot) -> Result<bool, EntrySwitchError> {
        self.query().map(|observed| observed == *expected)
    }
}

fn from_raw(raw: WinInetLanProxySnapshot) -> SystemProxySnapshot {
    let manual = raw.flags & PROXY_TYPE_PROXY != 0;
    let auto_config = raw.flags & PROXY_TYPE_AUTO_PROXY_URL != 0;
    let mode = match (manual, auto_config) {
        (false, false) => WindowsProxyMode::Direct,
        (true, false) => WindowsProxyMode::Manual,
        (false, true) => WindowsProxyMode::AutoConfig,
        (true, true) => WindowsProxyMode::Combined,
    };
    SystemProxySnapshot {
        mode,
        direct: raw.flags & PROXY_TYPE_DIRECT != 0,
        manual_proxy: raw.proxy_server,
        proxy_bypass: raw.proxy_bypass,
        auto_config_url: raw.auto_config_url,
        auto_detect: raw.flags & PROXY_TYPE_AUTO_DETECT != 0,
        connection_name: None,
    }
}

fn to_raw(snapshot: &SystemProxySnapshot) -> Result<WinInetLanProxySnapshot, EntrySwitchError> {
    if snapshot.connection_name.is_some() {
        return Err(EntrySwitchError::UnsupportedProxyScope);
    }
    let mut flags = 0;
    if snapshot.direct {
        flags |= PROXY_TYPE_DIRECT;
    }
    if snapshot.manual_proxy.is_some() {
        flags |= PROXY_TYPE_PROXY;
    }
    if snapshot.auto_config_url.is_some() {
        flags |= PROXY_TYPE_AUTO_PROXY_URL;
    }
    if snapshot.auto_detect {
        flags |= PROXY_TYPE_AUTO_DETECT;
    }
    if flags == 0 {
        flags = PROXY_TYPE_DIRECT;
    }
    let raw = WinInetLanProxySnapshot {
        flags,
        proxy_server: snapshot.manual_proxy.clone(),
        proxy_bypass: snapshot.proxy_bypass.clone(),
        auto_config_url: snapshot.auto_config_url.clone(),
    };
    raw.validate()
        .map_err(|_| EntrySwitchError::UnsupportedProxyScope)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_classifier_rejects_service_ras_vpn_named_and_multi_connection_contexts() {
        let valid = InteractiveUserLanScopeEvidence {
            interactive_user_scope_id: "0123456789abcdef".into(),
            interactive_session: true,
            active_connection_count: 1,
            has_ras_or_vpn: false,
            connection_name: None,
        };
        assert!(WinInetUserProxyAdapter::from_scope(valid.clone()).is_ok());
        for invalid in [
            InteractiveUserLanScopeEvidence {
                interactive_session: false,
                ..valid.clone()
            },
            InteractiveUserLanScopeEvidence {
                active_connection_count: 2,
                ..valid.clone()
            },
            InteractiveUserLanScopeEvidence {
                has_ras_or_vpn: true,
                ..valid.clone()
            },
            InteractiveUserLanScopeEvidence {
                connection_name: Some("named".into()),
                ..valid.clone()
            },
        ] {
            assert!(matches!(
                WinInetUserProxyAdapter::from_scope(invalid),
                Err(EntrySwitchError::UnsupportedProxyScope)
            ));
        }
    }

    #[test]
    fn raw_conversion_preserves_empty_bypass_and_combined_flags() {
        let raw = WinInetLanProxySnapshot {
            flags: PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT,
            proxy_server: Some("http=127.0.0.8:41002".into()),
            proxy_bypass: Some(String::new()),
            auto_config_url: Some("https://pac.invalid/proxy.pac".into()),
        };
        let typed = from_raw(raw.clone());
        assert_eq!(typed.mode, WindowsProxyMode::Combined);
        assert_eq!(typed.proxy_bypass.as_deref(), Some(""));
        assert_eq!(to_raw(&typed).unwrap(), raw);
    }

    #[test]
    #[ignore = "requires an isolated disposable Windows user and explicit live-network acceptance; mutates that user's WinINet default LAN proxy"]
    fn isolated_live_round_trip_scaffold() {
        panic!("run only from the dedicated acceptance harness with snapshot/CAS/restore guards")
    }
}
