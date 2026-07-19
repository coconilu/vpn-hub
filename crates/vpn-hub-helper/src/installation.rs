use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_REFERENCE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationReference {
    pub schema_version: u16,
    pub install_id: String,
    pub helper_enabled: bool,
    pub program_data_root: PathBuf,
    pub client_secret_ref: String,
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
        let reference: Self =
            serde_json::from_slice(&bytes).map_err(|_| InstallationReferenceError::Malformed)?;
        reference.validate(program_data)?;
        Ok(reference)
    }

    /// Validates schema, identifiers, secret reference and `ProgramData` containment.
    ///
    /// # Errors
    /// Returns a sanitized error for any invalid field or unsafe root.
    pub fn validate(&self, program_data: &Path) -> Result<(), InstallationReferenceError> {
        if self.schema_version != 1
            || !valid_id(&self.install_id)
            || !valid_secret_ref(&self.client_secret_ref)
        {
            return Err(InstallationReferenceError::Malformed);
        }
        let expected_parent = program_data.join("VPN Hub");
        if !self.program_data_root.is_absolute()
            || self
                .program_data_root
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
            || !path_eq_case_insensitive(
                self.program_data_root.parent().unwrap_or(Path::new("")),
                &expected_parent,
            )
            || self
                .program_data_root
                .file_name()
                .and_then(|name| name.to_str())
                != Some(self.install_id.as_str())
        {
            return Err(InstallationReferenceError::UnsafeRoot);
        }
        Ok(())
    }

    #[must_use]
    pub fn authority_path(&self) -> PathBuf {
        self.program_data_root.join("authority.lease")
    }
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
        let reference = InstallationReference {
            schema_version: 1,
            install_id: "install-a".into(),
            helper_enabled: true,
            program_data_root: program_data.join("VPN Hub/install-a"),
            client_secret_ref: "helper.install-a.protocol".into(),
        };
        reference.validate(&program_data).unwrap();
        let desktop_exe = Path::new(r"C:\Program Files\VPN Hub\vpn-hub.exe");
        let helper_exe = Path::new(r"C:\ProgramData\VPN Hub\install-a\bin\vpn-hub-helper.exe");
        assert_ne!(desktop_exe.parent(), helper_exe.parent());
        assert_eq!(
            reference.authority_path(),
            program_data.join("VPN Hub/install-a/authority.lease")
        );
    }

    #[test]
    fn traversal_or_sibling_installation_is_rejected() {
        let program_data = PathBuf::from(r"C:\ProgramData");
        let mut reference = InstallationReference {
            schema_version: 1,
            install_id: "install-a".into(),
            helper_enabled: true,
            program_data_root: program_data.join("VPN Hub/../install-a"),
            client_secret_ref: "helper.install-a.protocol".into(),
        };
        assert!(reference.validate(&program_data).is_err());
        reference.program_data_root = program_data.join("Other/install-a");
        assert!(reference.validate(&program_data).is_err());
    }
}
