//! Interactive-desktop `WinINet` adapter.
//!
//! The adapter is intentionally not wired to an IPC command until isolated
//! Windows acceptance proves the scope classifier. It cannot be constructed
//! for a service, RAS/VPN, named connection, or multi-connection context.
#![allow(dead_code)] // Compiled now; wiring stays disabled until isolated acceptance.

use std::{
    io::{Read as _, Seek as _},
    path::PathBuf,
};

use vpn_hub_core::{
    ConfidentialProtector, ConsentKey, EntrySwitchAuthorityGuard, EntrySwitchContext,
    EntrySwitchError, EntrySwitchJournal, EntrySwitchJournalRecord, ProtectedJournalCodec,
    ProtectedJournalState, ProxyBackend, ProxyCapability, SystemDurableFileOps,
    SystemProxySnapshot, WindowsProxyMode, durable_atomic_save_with_backup,
};
use vpn_hub_helper::{AuthorityFileGuard, InstallationReference, SupervisorAuthority};
use vpn_hub_windows_security::{
    ProtectedPathPolicy, WinInetLanProxySnapshot, open_current_user_mutable_directory,
    open_current_user_mutable_file, protect_current_user_data,
    query_current_user_default_lan_proxy, set_current_user_default_lan_proxy,
    unprotect_current_user_data, validate_protected_installation,
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
    context: EntrySwitchContext,
    generation: u64,
}

impl EntrySwitchDesktopAuthorityGuard {
    /// `installation` must originate from `InstallationReference::load`, which
    /// validates the fixed `ProgramData` installation root before this method
    /// opens the installer-preprovisioned lease without creating it.
    pub(crate) fn acquire(
        installation: &InstallationReference,
        interactive_user_sid: &str,
        user_scope_id: String,
        generation: u64,
        _fencing_token: u64,
    ) -> Result<Self, EntrySwitchError> {
        let file_guard = AuthorityFileGuard::acquire_protected_entry_switch(
            installation,
            interactive_user_sid,
            SupervisorAuthority::Desktop,
            generation,
        )
        .map_err(|_| EntrySwitchError::Unauthorized)?;
        let context = EntrySwitchContext {
            install_id: installation.install_id().to_owned(),
            user_scope_id,
        };
        Ok(Self {
            _file_guard: file_guard,
            context,
            generation,
        })
    }
}

impl EntrySwitchAuthorityGuard for EntrySwitchDesktopAuthorityGuard {
    fn context(&self) -> &EntrySwitchContext {
        &self.context
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn ensure_held(&self) -> Result<(), EntrySwitchError> {
        Ok(())
    }
}

struct CurrentUserDpapi;

impl ConfidentialProtector for CurrentUserDpapi {
    fn seal(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, EntrySwitchError> {
        protect_current_user_data(plaintext, entropy).map_err(|_| EntrySwitchError::Journal)
    }

    fn open(&self, ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, EntrySwitchError> {
        unprotect_current_user_data(ciphertext, entropy).map_err(|_| EntrySwitchError::Journal)
    }
}

/// Fixed-path journal. Construction revalidates the installation root, exact
/// mutable state file and authority lease against the interactive-user DACL.
/// It is private and cannot accept a caller-controlled path.
struct ProtectedFileEntrySwitchJournal<'a> {
    installation: InstallationReference,
    interactive_user_sid: String,
    context: EntrySwitchContext,
    key: &'a ConsentKey,
    protector: CurrentUserDpapi,
}

impl<'a> ProtectedFileEntrySwitchJournal<'a> {
    fn open(
        installation: &InstallationReference,
        interactive_user_sid: String,
        user_scope_id: String,
        key: &'a ConsentKey,
    ) -> Result<Self, EntrySwitchError> {
        let journal = Self {
            installation: installation.clone(),
            interactive_user_sid,
            context: EntrySwitchContext {
                install_id: installation.install_id().to_owned(),
                user_scope_id,
            },
            key,
            protector: CurrentUserDpapi,
        };
        journal.validate_fixed_storage()?;
        Ok(journal)
    }

    fn path(&self) -> PathBuf {
        self.installation.entry_switch_journal_path()
    }

    fn validate_fixed_storage(&self) -> Result<(), EntrySwitchError> {
        let mut paths = vec![
            (
                self.installation.program_data_root().join("entry-switch"),
                ProtectedPathPolicy::CurrentUserMutableDirectory,
            ),
            (
                self.installation.entry_switch_authority_path(),
                ProtectedPathPolicy::CurrentUserMutableFile,
            ),
            (self.path(), ProtectedPathPolicy::CurrentUserMutableFile),
        ];
        let backup = self.path().with_extension("json.bak");
        if backup.exists() {
            paths.push((backup, ProtectedPathPolicy::CurrentUserMutableFile));
        }
        validate_protected_installation(
            self.installation.program_data_root(),
            &paths,
            &self.interactive_user_sid,
        )
        .map_err(|_| EntrySwitchError::Unauthorized)
    }

    fn read_exact_file(&self, path: &std::path::Path) -> Result<Option<Vec<u8>>, EntrySwitchError> {
        let primary = self.path();
        if path != primary && path != primary.with_extension("json.bak") {
            return Err(EntrySwitchError::Journal);
        }
        if !path.exists() {
            return Ok(None);
        }
        self.validate_fixed_storage()?;
        let (mut file, _) = open_current_user_mutable_file(
            self.installation.program_data_root(),
            path,
            &self.interactive_user_sid,
        )
        .map_err(|_| EntrySwitchError::Journal)?;
        file.rewind().map_err(|_| EntrySwitchError::Journal)?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| EntrySwitchError::Journal)?;
        if bytes.len() > 1024 * 1024 {
            return Err(EntrySwitchError::Journal);
        }
        Ok(Some(bytes))
    }

    fn load_state(&self) -> Result<ProtectedJournalState, EntrySwitchError> {
        let codec = ProtectedJournalCodec::new(self.context.clone(), self.key, &self.protector);
        let Some(bytes) = self.read_exact_file(&self.path())? else {
            return Err(EntrySwitchError::Journal);
        };
        if bytes.is_empty() {
            return Ok(ProtectedJournalState::default());
        }
        codec.open(&bytes).or_else(|_| {
            let backup = self.path().with_extension("json.bak");
            self.read_exact_file(&backup)?
                .ok_or(EntrySwitchError::Journal)
                .and_then(|value| codec.open(&value))
        })
    }

    fn save_state(&self, state: &ProtectedJournalState) -> Result<(), EntrySwitchError> {
        self.validate_fixed_storage()?;
        let _directory_guard = open_current_user_mutable_directory(
            self.installation.program_data_root(),
            &self.installation.program_data_root().join("entry-switch"),
            &self.interactive_user_sid,
        )
        .map_err(|_| EntrySwitchError::Journal)?;
        let codec = ProtectedJournalCodec::new(self.context.clone(), self.key, &self.protector);
        let bytes = codec.seal(state)?;
        durable_atomic_save_with_backup(&self.path(), &bytes, &SystemDurableFileOps)
            .map_err(|_| EntrySwitchError::Journal)?;
        self.validate_fixed_storage()?;
        let _ = open_current_user_mutable_file(
            self.installation.program_data_root(),
            &self.path(),
            &self.interactive_user_sid,
        )
        .map_err(|_| EntrySwitchError::Journal)?;
        Ok(())
    }
}

impl EntrySwitchJournal for ProtectedFileEntrySwitchJournal<'_> {
    fn load(&self) -> Result<Option<EntrySwitchJournalRecord>, EntrySwitchError> {
        Ok(self.load_state()?.record)
    }
    fn save(&mut self, record: &EntrySwitchJournalRecord) -> Result<(), EntrySwitchError> {
        let mut state = self.load_state()?;
        state.record = Some(record.clone());
        self.save_state(&state)
    }
    fn clear(&mut self) -> Result<(), EntrySwitchError> {
        let mut state = self.load_state()?;
        state.record = None;
        self.save_state(&state)
    }
    fn consume_consent(
        &mut self,
        token_id: &str,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, EntrySwitchError> {
        let mut state = self.load_state()?;
        state.consumed.retain(|_, expiry| *expiry >= now_ms);
        if state.consumed.contains_key(token_id) {
            return Ok(false);
        }
        state.consumed.insert(token_id.to_owned(), expires_at_ms);
        self.save_state(&state)?;
        Ok(true)
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

    fn compare_then_apply(
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
        panic!(
            "run only from the dedicated acceptance harness with snapshot/compare-then-apply/restore guards"
        )
    }
}
