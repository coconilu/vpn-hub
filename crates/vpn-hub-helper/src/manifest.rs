use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_OUTLETS: usize = 128;
const FIXED_CORE_PATH: &str = "bin/mihomo.exe";
const FIXED_RUNTIME_CONFIG_PATH: &str = "runtime/mihomo.yaml";
const FIXED_DATABASE_PATH: &str = "data/guardian.db";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupervisionManifest {
    pub schema_version: u16,
    pub install_id: String,
    pub generation: u64,
    pub core: CoreArtifact,
    pub runtime_config_relative_path: String,
    pub guardian_database_relative_path: String,
    pub entry: EntrySummary,
    pub outlets: Vec<OutletSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreArtifact {
    pub relative_path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntrySummary {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OutletKindSummary {
    Subscription,
    LocalProxy,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OutletHealthSummary {
    Unknown,
    Healthy,
    Degraded,
    Down,
    Recovering,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutletSummary {
    pub outlet_id: String,
    pub kind: OutletKindSummary,
    pub health: OutletHealthSummary,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("supervision manifest is unavailable")]
    Unavailable(#[source] std::io::Error),
    #[error("supervision manifest is malformed")]
    Malformed,
    #[error("supervision manifest uses an unsupported schema")]
    UnsupportedSchema,
    #[error("supervision manifest contains an unsafe path")]
    UnsafePath,
    #[error("supervision manifest does not match the installation")]
    WrongInstallation,
    #[error("supervision manifest violates the sanitized schema")]
    UnsafeContent,
}

pub fn load_manifest(
    program_data_root: &Path,
    manifest_path: &Path,
    expected_install_id: &str,
) -> Result<SupervisionManifest, ManifestError> {
    let relative = manifest_path
        .strip_prefix(program_data_root)
        .map_err(|_| ManifestError::UnsafePath)?;
    validate_relative_path(relative)?;
    let bytes = fs::read(manifest_path).map_err(ManifestError::Unavailable)?;
    parse_manifest(&bytes, expected_install_id)
}

pub fn parse_manifest(
    bytes: &[u8],
    expected_install_id: &str,
) -> Result<SupervisionManifest, ManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::Malformed);
    }
    reject_secret_vocabulary(bytes)?;
    let manifest: SupervisionManifest =
        serde_json::from_slice(bytes).map_err(|_| ManifestError::Malformed)?;
    manifest.validate(expected_install_id)?;
    Ok(manifest)
}

impl SupervisionManifest {
    pub fn validate(&self, expected_install_id: &str) -> Result<(), ManifestError> {
        if self.schema_version != 1 {
            return Err(ManifestError::UnsupportedSchema);
        }
        validate_identifier(&self.install_id)?;
        if self.install_id != expected_install_id {
            return Err(ManifestError::WrongInstallation);
        }
        if self.generation == 0
            || self.entry.port == 0
            || !matches!(self.entry.host.as_str(), "127.0.0.1" | "localhost" | "::1")
            || self.outlets.len() > MAX_OUTLETS
        {
            return Err(ManifestError::UnsafeContent);
        }
        validate_fixed_path(&self.core.relative_path, FIXED_CORE_PATH)?;
        validate_fixed_path(
            &self.runtime_config_relative_path,
            FIXED_RUNTIME_CONFIG_PATH,
        )?;
        validate_fixed_path(&self.guardian_database_relative_path, FIXED_DATABASE_PATH)?;
        validate_sha256(&self.core.sha256)?;
        for outlet in &self.outlets {
            validate_identifier(&outlet.outlet_id)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn core_path(&self, program_data_root: &Path) -> PathBuf {
        program_data_root.join(&self.core.relative_path)
    }

    #[must_use]
    pub fn runtime_config_path(&self, program_data_root: &Path) -> PathBuf {
        program_data_root.join(&self.runtime_config_relative_path)
    }

    #[must_use]
    pub fn guardian_database_path(&self, program_data_root: &Path) -> PathBuf {
        program_data_root.join(&self.guardian_database_relative_path)
    }
}

fn reject_secret_vocabulary(bytes: &[u8]) -> Result<(), ManifestError> {
    const FORBIDDEN: [&str; 9] = [
        "subscription_url",
        "subscription-url",
        "token",
        "password",
        "credential",
        "secret",
        "proxy_provider",
        "target_url",
        "controller_secret",
    ];
    let text = std::str::from_utf8(bytes).map_err(|_| ManifestError::Malformed)?;
    let lower = text.to_ascii_lowercase();
    if FORBIDDEN.iter().any(|term| lower.contains(term)) {
        return Err(ManifestError::UnsafeContent);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ManifestError::UnsafeContent);
    }
    Ok(())
}

fn validate_fixed_path(value: &str, expected: &str) -> Result<(), ManifestError> {
    let path = Path::new(value);
    validate_relative_path(path)?;
    if value.replace('\\', "/") != expected {
        return Err(ManifestError::UnsafePath);
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), ManifestError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ManifestError::UnsafePath);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ManifestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ManifestError::UnsafeContent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SupervisionManifest {
        SupervisionManifest {
            schema_version: 1,
            install_id: "install-a".into(),
            generation: 7,
            core: CoreArtifact {
                relative_path: FIXED_CORE_PATH.into(),
                sha256: "a".repeat(64),
            },
            runtime_config_relative_path: FIXED_RUNTIME_CONFIG_PATH.into(),
            guardian_database_relative_path: FIXED_DATABASE_PATH.into(),
            entry: EntrySummary {
                host: "127.0.0.1".into(),
                port: 42_391,
            },
            outlets: vec![
                OutletSummary {
                    outlet_id: "subscription-work".into(),
                    kind: OutletKindSummary::Subscription,
                    health: OutletHealthSummary::Healthy,
                },
                OutletSummary {
                    outlet_id: "local-backup".into(),
                    kind: OutletKindSummary::LocalProxy,
                    health: OutletHealthSummary::Unknown,
                },
            ],
        }
    }

    #[test]
    fn dynamic_sanitized_manifest_accepts_non_default_entry() {
        let value = manifest();
        assert!(value.validate("install-a").is_ok());
        assert_eq!(value.entry.port, 42_391);
        assert_eq!(value.outlets.len(), 2);
    }

    #[test]
    fn paths_hash_schema_and_installation_are_strict() {
        let mut value = manifest();
        value.core.relative_path = "../mihomo.exe".into();
        assert!(matches!(
            value.validate("install-a"),
            Err(ManifestError::UnsafePath)
        ));

        let mut value = manifest();
        value.core.sha256 = "not-a-hash".into();
        assert!(matches!(
            value.validate("install-a"),
            Err(ManifestError::UnsafeContent)
        ));

        let value = manifest();
        assert!(matches!(
            value.validate("other-install"),
            Err(ManifestError::WrongInstallation)
        ));
    }

    #[test]
    fn secret_shaped_and_unknown_fields_are_rejected_before_use() {
        let mut encoded = serde_json::to_value(manifest()).unwrap();
        encoded["subscription_url"] = "https://example.invalid/private".into();
        assert!(matches!(
            parse_manifest(&serde_json::to_vec(&encoded).unwrap(), "install-a"),
            Err(ManifestError::UnsafeContent)
        ));

        let mut encoded = serde_json::to_value(manifest()).unwrap();
        encoded["arbitrary_args"] = serde_json::json!(["--listen", "0.0.0.0"]);
        assert!(matches!(
            parse_manifest(&serde_json::to_vec(&encoded).unwrap(), "install-a"),
            Err(ManifestError::Malformed)
        ));
    }

    #[test]
    fn manifest_must_stay_inside_program_data_root() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("../outside.json");
        assert!(matches!(
            load_manifest(temp.path(), &outside, "install-a"),
            Err(ManifestError::UnsafePath)
        ));
    }
}
