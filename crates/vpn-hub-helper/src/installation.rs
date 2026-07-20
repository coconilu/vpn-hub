use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_REFERENCE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InstallationReferenceDocument {
    schema_version: u16,
    install_id: String,
    helper_enabled: bool,
    program_data_root: PathBuf,
    client_secret_ref: String,
}

/// A structurally validated installation reference. Its fields are private so
/// callers cannot forge a value that bypasses `ProgramData` containment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationReference {
    document: InstallationReferenceDocument,
}

#[derive(Debug, Error)]
pub enum InstallationReferenceError {
    #[error("helper installation reference is unavailable")]
    Unavailable,
    #[error("helper installation reference is malformed")]
    Malformed,
    #[error("helper installation reference is outside the allowed ProgramData root")]
    UnsafeRoot,
}

impl InstallationReference {
    /// Loads and validates a non-secret client installation reference.
    ///
    /// # Errors
    /// Returns a sanitized error for missing, malformed, or unsafe references.
    pub fn load(path: &Path, program_data: &Path) -> Result<Self, InstallationReferenceError> {
        let bytes = fs::read(path).map_err(|_| InstallationReferenceError::Unavailable)?;
        if bytes.is_empty() || bytes.len() > MAX_REFERENCE_BYTES {
            return Err(InstallationReferenceError::Malformed);
        }
        let document: InstallationReferenceDocument =
            serde_json::from_slice(&bytes).map_err(|_| InstallationReferenceError::Malformed)?;
        Self::build_after_validation(document, program_data)
    }

    fn build_after_validation(
        document: InstallationReferenceDocument,
        program_data: &Path,
    ) -> Result<Self, InstallationReferenceError> {
        if document.schema_version != 1
            || !valid_id(&document.install_id)
            || !valid_secret_ref(&document.client_secret_ref)
        {
            return Err(InstallationReferenceError::Malformed);
        }
        let expected_parent = program_data.join("VPN Hub");
        if !document.program_data_root.is_absolute()
            || document
                .program_data_root
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
            || !path_eq_case_insensitive(
                document.program_data_root.parent().unwrap_or(Path::new("")),
                &expected_parent,
            )
            || document
                .program_data_root
                .file_name()
                .and_then(|name| name.to_str())
                != Some(document.install_id.as_str())
        {
            return Err(InstallationReferenceError::UnsafeRoot);
        }
        Ok(Self { document })
    }

    #[must_use]
    pub fn install_id(&self) -> &str {
        &self.document.install_id
    }

    #[must_use]
    pub fn helper_enabled(&self) -> bool {
        self.document.helper_enabled
    }

    #[must_use]
    pub fn program_data_root(&self) -> &Path {
        &self.document.program_data_root
    }

    #[must_use]
    pub fn client_secret_ref(&self) -> &str {
        &self.document.client_secret_ref
    }

    #[must_use]
    pub fn authority_path(&self) -> PathBuf {
        self.document.program_data_root.join("authority.lease")
    }

    #[must_use]
    pub fn entry_switch_authority_path(&self) -> PathBuf {
        self.document
            .program_data_root
            .join("entry-switch/authority.lease")
    }

    #[must_use]
    pub fn entry_switch_journal_path(&self) -> PathBuf {
        self.document
            .program_data_root
            .join("entry-switch/entry-switch.json")
    }
}

/// Validates installer-owned root metadata without constructing the
/// capability-bearing reference. Only `InstallationReference::load` can
/// produce that newtype outside this module.
///
/// # Errors
/// Returns a sanitized error for invalid identity or `ProgramData` containment.
pub fn validate_installation_location(
    install_id: &str,
    program_data_root: &Path,
    program_data: &Path,
) -> Result<(), InstallationReferenceError> {
    InstallationReference::build_after_validation(
        InstallationReferenceDocument {
            schema_version: 1,
            install_id: install_id.into(),
            helper_enabled: false,
            program_data_root: program_data_root.into(),
            client_secret_ref: "validation-only".into(),
        },
        program_data,
    )
    .map(drop)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_secret_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn path_eq_case_insensitive(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_executable_locations_resolve_one_shared_authority_path() {
        let program_data = PathBuf::from(r"C:\ProgramData");
        let reference = InstallationReference::build_after_validation(
            InstallationReferenceDocument {
                schema_version: 1,
                install_id: "install-a".into(),
                helper_enabled: true,
                program_data_root: program_data.join("VPN Hub/install-a"),
                client_secret_ref: "helper.install-a.protocol".into(),
            },
            &program_data,
        )
        .unwrap();
        let desktop_exe = Path::new(r"C:\Program Files\VPN Hub\vpn-hub.exe");
        let helper_exe = Path::new(r"C:\ProgramData\VPN Hub\install-a\bin\vpn-hub-helper.exe");
        assert_ne!(desktop_exe.parent(), helper_exe.parent());
        assert_eq!(
            reference.authority_path(),
            program_data.join("VPN Hub/install-a/authority.lease")
        );
        assert_eq!(
            reference.entry_switch_authority_path(),
            program_data.join("VPN Hub/install-a/entry-switch/authority.lease")
        );
        assert_eq!(
            reference.entry_switch_journal_path(),
            program_data.join("VPN Hub/install-a/entry-switch/entry-switch.json")
        );
    }

    #[test]
    fn traversal_or_sibling_installation_is_rejected() {
        let program_data = PathBuf::from(r"C:\ProgramData");
        assert!(
            validate_installation_location(
                "install-a",
                &program_data.join("VPN Hub/../install-a"),
                &program_data,
            )
            .is_err()
        );
        assert!(
            validate_installation_location(
                "install-a",
                &program_data.join("Other/install-a"),
                &program_data,
            )
            .is_err()
        );
    }
}
