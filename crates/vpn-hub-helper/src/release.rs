//! Fail-closed release, updater, and migration contracts.
//!
//! This module deliberately contains no downloader, signer, installer, SCM,
//! registry, system-proxy, or network mutation. Production update verification
//! remains disabled until a release embeds an explicitly reviewed trust root.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{InstallAction, InstallPlan, InstallPlanError, PlanOperation};

const RELEASE_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseChannel {
    Dev,
    Stable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    NsisExe,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub file_name: String,
    pub kind: ArtifactKind,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseToolchain {
    pub rust: String,
    pub cargo: String,
    pub node: String,
    pub npm: String,
    pub tauri_cli: String,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u16,
    pub product: String,
    pub version: String,
    pub commit: String,
    pub channel: ReleaseChannel,
    pub source_url: String,
    pub signing_key_id: String,
    pub artifact: ReleaseArtifact,
    pub rust_sbom_sha256: String,
    pub frontend_sbom_sha256: String,
    pub licenses_sha256: String,
    pub reproducibility_sha256: String,
    pub toolchain: ReleaseToolchain,
    pub system_proxy_included: bool,
    pub tun_executor_supported: bool,
}

impl ReleaseManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        serde_json::to_vec(self).map_err(|_| ReleaseError::MalformedManifest)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseManifest {
    pub manifest: ReleaseManifest,
    pub signature_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub version: Version,
    pub source: Url,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Default)]
pub struct ReleasePolicy {
    trusted_keys: BTreeMap<String, [u8; 32]>,
    allowed_hosts: BTreeSet<String>,
}

impl ReleasePolicy {
    /// Production default: updates are disabled instead of trusting a
    /// placeholder key or an arbitrary source.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn from_trust_roots(
        trusted_keys: BTreeMap<String, [u8; 32]>,
        allowed_hosts: BTreeSet<String>,
    ) -> Result<Self, ReleaseError> {
        if trusted_keys.is_empty() || allowed_hosts.is_empty() {
            return Err(ReleaseError::UpdatesDisabled);
        }
        if trusted_keys.keys().any(|id| !valid_identifier(id))
            || allowed_hosts.iter().any(|host| !valid_host(host))
        {
            return Err(ReleaseError::InvalidTrustPolicy);
        }
        Ok(Self {
            trusted_keys,
            allowed_hosts,
        })
    }

    pub fn verify(
        &self,
        signed: &SignedReleaseManifest,
        current_version: &Version,
        artifact_bytes: &[u8],
    ) -> Result<VerifiedRelease, ReleaseError> {
        if self.trusted_keys.is_empty() || self.allowed_hosts.is_empty() {
            return Err(ReleaseError::UpdatesDisabled);
        }
        validate_manifest(&signed.manifest)?;
        if signed.manifest.channel != ReleaseChannel::Stable {
            return Err(ReleaseError::DevelopmentArtifact);
        }
        let candidate =
            Version::parse(&signed.manifest.version).map_err(|_| ReleaseError::InvalidVersion)?;
        if !candidate.pre.is_empty() || !candidate.build.is_empty() {
            return Err(ReleaseError::InvalidVersion);
        }
        if candidate <= *current_version {
            return Err(ReleaseError::RollbackRejected);
        }

        let source = validate_source(
            &signed.manifest.source_url,
            &signed.manifest.artifact.file_name,
            &self.allowed_hosts,
        )?;
        let key_bytes = self
            .trusted_keys
            .get(&signed.manifest.signing_key_id)
            .ok_or(ReleaseError::UnknownKey)?;
        let key = VerifyingKey::from_bytes(key_bytes).map_err(|_| ReleaseError::InvalidKey)?;
        let signature_bytes = STANDARD
            .decode(&signed.signature_base64)
            .map_err(|_| ReleaseError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ReleaseError::InvalidSignature)?;
        key.verify_strict(&signed.manifest.canonical_bytes()?, &signature)
            .map_err(|_| ReleaseError::InvalidSignature)?;

        let actual_hash = format!("{:x}", Sha256::digest(artifact_bytes));
        if actual_hash != signed.manifest.artifact.sha256
            || usize::try_from(signed.manifest.artifact.size).ok() != Some(artifact_bytes.len())
        {
            return Err(ReleaseError::ArtifactMismatch);
        }

        Ok(VerifiedRelease {
            version: candidate,
            source,
            artifact_sha256: actual_hash,
        })
    }
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    if manifest.schema_version != RELEASE_SCHEMA_VERSION
        || manifest.product != "VPN Hub"
        || !valid_commit(&manifest.commit)
        || !valid_identifier(&manifest.signing_key_id)
        || manifest.artifact.kind != ArtifactKind::NsisExe
        || manifest.artifact.size == 0
        || !valid_file_name(&manifest.artifact.file_name)
        || !valid_hash(&manifest.artifact.sha256)
        || !valid_hash(&manifest.rust_sbom_sha256)
        || !valid_hash(&manifest.frontend_sbom_sha256)
        || !valid_hash(&manifest.licenses_sha256)
        || !valid_hash(&manifest.reproducibility_sha256)
        || manifest.system_proxy_included
        || manifest.tun_executor_supported
    {
        return Err(ReleaseError::MalformedManifest);
    }
    Ok(())
}

fn validate_source(
    source: &str,
    artifact_name: &str,
    allowed_hosts: &BTreeSet<String>,
) -> Result<Url, ReleaseError> {
    let url = Url::parse(source).map_err(|_| ReleaseError::UntrustedSource)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url
            .host_str()
            .is_none_or(|host| !allowed_hosts.contains(host))
        || url
            .path_segments()
            .and_then(Iterator::last)
            .is_none_or(|name| name != artifact_name)
    {
        return Err(ReleaseError::UntrustedSource);
    }
    Ok(url)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_host(value: &str) -> bool {
    value == value.to_ascii_lowercase()
        && !value.is_empty()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 180
        && value.ends_with("-setup.exe")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.contains("..")
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseLifecycleAction {
    FreshInstall,
    Upgrade,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DataDisposition {
    Preserve,
    Delete,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationComponent {
    EntryConfig,
    OutletConfig,
    SecretStore,
    Sqlite,
    Helper,
    TunJournal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum ReleaseOperation {
    HelperOperation { helper_step: PlanOperation },
    SnapshotOwnedData,
    Migrate { component: MigrationComponent },
    Preserve { component: MigrationComponent },
    DeleteOwned { component: MigrationComponent },
    VerifySchemas,
    VerifyNoOrphans,
    AssertTunExecutorDisabled,
    AssertSystemProxyExcluded,
}

impl ReleaseOperation {
    fn mutates_owned_state(&self) -> bool {
        matches!(self, Self::Migrate { .. } | Self::DeleteOwned { .. })
            || matches!(
                self,
                Self::HelperOperation {
                    helper_step: PlanOperation::ApplyProgramDataAcl { .. }
                        | PlanOperation::ProvisionAuthorityLeaseFile
                        | PlanOperation::ProvisionTunAuthorityLeaseFile
                        | PlanOperation::RegisterService { .. }
                        | PlanOperation::ConfigureNamedPipeAcl { .. }
                        | PlanOperation::WriteProtectedReference { .. }
                        | PlanOperation::RemoveServiceRegistration
                        | PlanOperation::RemoveProtectedReference { .. }
                        | PlanOperation::RemoveProgramDataTree
                }
            )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseMigrationPlan {
    pub schema_version: u16,
    pub action: ReleaseLifecycleAction,
    pub disposition: DataDisposition,
    pub dry_run: bool,
    pub system_proxy_included: bool,
    pub tun_executor_supported: bool,
    pub operations: Vec<ReleaseOperation>,
}

impl ReleaseMigrationPlan {
    pub fn build(
        action: ReleaseLifecycleAction,
        disposition: DataDisposition,
        install_id: &str,
        helper_sha256: &str,
    ) -> Result<Self, ReleaseError> {
        let install_action = match action {
            ReleaseLifecycleAction::FreshInstall => InstallAction::Install,
            ReleaseLifecycleAction::Upgrade => InstallAction::Upgrade,
            ReleaseLifecycleAction::Uninstall => InstallAction::Uninstall,
        };
        let helper = InstallPlan::build(install_action, install_id, helper_sha256)?;
        verify_helper_recovery_prefix(action, &helper.operations)?;

        let helper_operations = helper.operations;
        let mut operations = Vec::new();

        match action {
            ReleaseLifecycleAction::FreshInstall => {
                operations.extend(
                    helper_operations
                        .into_iter()
                        .map(|helper_step| ReleaseOperation::HelperOperation { helper_step }),
                );
                operations.push(ReleaseOperation::AssertSystemProxyExcluded);
                operations.push(ReleaseOperation::AssertTunExecutorDisabled);
                operations.push(ReleaseOperation::SnapshotOwnedData);
                operations.extend(
                    migration_components()
                        .into_iter()
                        .map(|component| ReleaseOperation::Migrate { component }),
                );
                operations.push(ReleaseOperation::VerifySchemas);
                operations.push(ReleaseOperation::VerifyNoOrphans);
            }
            ReleaseLifecycleAction::Upgrade => {
                let (safety_prefix, remaining) = helper_operations.split_at(3);
                operations.extend(
                    safety_prefix
                        .iter()
                        .cloned()
                        .map(|helper_step| ReleaseOperation::HelperOperation { helper_step }),
                );
                operations.push(ReleaseOperation::AssertSystemProxyExcluded);
                operations.push(ReleaseOperation::AssertTunExecutorDisabled);
                operations.push(ReleaseOperation::SnapshotOwnedData);
                operations.extend(
                    remaining
                        .iter()
                        .cloned()
                        .map(|helper_step| ReleaseOperation::HelperOperation { helper_step }),
                );
                operations.extend(
                    migration_components()
                        .into_iter()
                        .map(|component| ReleaseOperation::Migrate { component }),
                );
                operations.push(ReleaseOperation::VerifySchemas);
                operations.push(ReleaseOperation::VerifyNoOrphans);
            }
            ReleaseLifecycleAction::Uninstall => {
                let (safety_prefix, remaining) = helper_operations.split_at(3);
                operations.extend(
                    safety_prefix
                        .iter()
                        .cloned()
                        .map(|helper_step| ReleaseOperation::HelperOperation { helper_step }),
                );
                operations.push(ReleaseOperation::AssertSystemProxyExcluded);
                operations.push(ReleaseOperation::AssertTunExecutorDisabled);
                operations.push(ReleaseOperation::SnapshotOwnedData);
                operations.extend(data_components().into_iter().map(
                    |component| match disposition {
                        DataDisposition::Preserve => ReleaseOperation::Preserve { component },
                        DataDisposition::Delete => ReleaseOperation::DeleteOwned { component },
                    },
                ));
                for helper_step in remaining.iter().cloned() {
                    if helper_step == PlanOperation::RemoveProgramDataTree {
                        operations.push(ReleaseOperation::DeleteOwned {
                            component: MigrationComponent::Helper,
                        });
                        operations.push(ReleaseOperation::DeleteOwned {
                            component: MigrationComponent::TunJournal,
                        });
                    }
                    operations.push(ReleaseOperation::HelperOperation { helper_step });
                }
                operations.push(ReleaseOperation::VerifyNoOrphans);
            }
        }

        Ok(Self {
            schema_version: RELEASE_SCHEMA_VERSION,
            action,
            disposition,
            dry_run: true,
            system_proxy_included: false,
            tun_executor_supported: false,
            operations,
        })
    }
}

fn verify_helper_recovery_prefix(
    action: ReleaseLifecycleAction,
    operations: &[PlanOperation],
) -> Result<(), ReleaseError> {
    if matches!(
        action,
        ReleaseLifecycleAction::Upgrade | ReleaseLifecycleAction::Uninstall
    ) && !matches!(
        operations,
        [
            PlanOperation::EnterFailClosed,
            PlanOperation::StopOwnedJob,
            PlanOperation::RestoreTunSnapshot,
            ..
        ]
    ) {
        return Err(ReleaseError::UnsafeMigrationPlan);
    }
    Ok(())
}

fn migration_components() -> [MigrationComponent; 6] {
    [
        MigrationComponent::EntryConfig,
        MigrationComponent::OutletConfig,
        MigrationComponent::SecretStore,
        MigrationComponent::Sqlite,
        MigrationComponent::Helper,
        MigrationComponent::TunJournal,
    ]
}

fn data_components() -> [MigrationComponent; 4] {
    [
        MigrationComponent::EntryConfig,
        MigrationComponent::OutletConfig,
        MigrationComponent::SecretStore,
        MigrationComponent::Sqlite,
    ]
}

pub trait ReleaseMigrationBackend {
    type Error;

    fn execute(&mut self, operation: &ReleaseOperation) -> Result<(), Self::Error>;
    fn rollback_owned(&mut self, completed: &[ReleaseOperation]) -> Result<(), Self::Error>;
}

pub fn execute_release_migration<B: ReleaseMigrationBackend>(
    plan: &ReleaseMigrationPlan,
    backend: &mut B,
) -> Result<(), MigrationExecutionError<B::Error>> {
    let mut completed = Vec::new();
    for operation in &plan.operations {
        if let Err(error) = backend.execute(operation) {
            let rollback_scope = completed
                .iter()
                .filter(|item: &&ReleaseOperation| item.mutates_owned_state())
                .cloned()
                .collect::<Vec<_>>();
            backend
                .rollback_owned(&rollback_scope)
                .map_err(MigrationExecutionError::Rollback)?;
            return Err(MigrationExecutionError::Operation(error));
        }
        completed.push(operation.clone());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceStatus {
    Missing,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PromotionEvidence {
    pub manifest_channel: ReleaseChannel,
    pub authenticode_chain: EvidenceStatus,
    pub authenticode_timestamp: EvidenceStatus,
    pub update_signature: EvidenceStatus,
    pub trusted_https_source: EvidenceStatus,
    pub artifact_hash: EvidenceStatus,
    pub rust_sbom: EvidenceStatus,
    pub frontend_sbom: EvidenceStatus,
    pub licenses: EvidenceStatus,
    pub reproducible_materials: EvidenceStatus,
    pub clean_windows_vm_acceptance: EvidenceStatus,
    pub system_proxy_included: bool,
    pub tun_executor_supported: bool,
}

impl PromotionEvidence {
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.manifest_channel != ReleaseChannel::Stable
            || self.authenticode_chain != EvidenceStatus::Verified
            || self.authenticode_timestamp != EvidenceStatus::Verified
            || self.update_signature != EvidenceStatus::Verified
            || self.trusted_https_source != EvidenceStatus::Verified
            || self.artifact_hash != EvidenceStatus::Verified
            || self.rust_sbom != EvidenceStatus::Verified
            || self.frontend_sbom != EvidenceStatus::Verified
            || self.licenses != EvidenceStatus::Verified
            || self.reproducible_materials != EvidenceStatus::Verified
            || self.clean_windows_vm_acceptance != EvidenceStatus::Verified
            || self.system_proxy_included
            || self.tun_executor_supported
        {
            return Err(ReleaseError::PromotionBlocked);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MigrationExecutionError<E> {
    Operation(E),
    Rollback(E),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("updates are disabled because no production trust root is configured")]
    UpdatesDisabled,
    #[error("release trust policy is invalid")]
    InvalidTrustPolicy,
    #[error("release manifest is malformed or enables unsupported features")]
    MalformedManifest,
    #[error("release version is invalid")]
    InvalidVersion,
    #[error("development artifacts cannot enter the update channel")]
    DevelopmentArtifact,
    #[error("release source is not an allowed HTTPS origin")]
    UntrustedSource,
    #[error("release signing key is unknown")]
    UnknownKey,
    #[error("release public key is invalid")]
    InvalidKey,
    #[error("release manifest signature is invalid")]
    InvalidSignature,
    #[error("release downgrade or same-version update was rejected")]
    RollbackRejected,
    #[error("release artifact hash or size does not match the manifest")]
    ArtifactMismatch,
    #[error("helper install contract has an unsafe migration order")]
    UnsafeMigrationPlan,
    #[error("release promotion evidence is incomplete")]
    PromotionBlocked,
    #[error("helper install plan is invalid")]
    InstallPlan,
}

impl From<InstallPlanError> for ReleaseError {
    fn from(_: InstallPlanError) -> Self {
        Self::InstallPlan
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    const ARTIFACT: &[u8] = b"unsigned-development-installer-fixture";

    fn fixture_manifest() -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            product: "VPN Hub".into(),
            version: "0.3.0".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            channel: ReleaseChannel::Stable,
            source_url: "https://updates.example.test/vpn-hub-0.3.0-setup.exe".into(),
            signing_key_id: "fixture-2026".into(),
            artifact: ReleaseArtifact {
                file_name: "vpn-hub-0.3.0-setup.exe".into(),
                kind: ArtifactKind::NsisExe,
                sha256: format!("{:x}", Sha256::digest(ARTIFACT)),
                size: ARTIFACT.len() as u64,
            },
            rust_sbom_sha256: "1".repeat(64),
            frontend_sbom_sha256: "2".repeat(64),
            licenses_sha256: "3".repeat(64),
            reproducibility_sha256: "4".repeat(64),
            toolchain: ReleaseToolchain {
                rust: "1.97.0".into(),
                cargo: "1.97.0".into(),
                node: "24.15.0".into(),
                npm: "11.12.1".into(),
                tauri_cli: "2.11.4".into(),
                target: "x86_64-pc-windows-msvc".into(),
            },
            system_proxy_included: false,
            tun_executor_supported: false,
        }
    }

    fn signed_fixture() -> (ReleasePolicy, SignedReleaseManifest) {
        // Deterministic test-only key material; never compiled into non-test builds.
        let signing = SigningKey::from_bytes(&[0x15; 32]);
        let manifest = fixture_manifest();
        let signature = signing.sign(&manifest.canonical_bytes().unwrap());
        let policy = ReleasePolicy::from_trust_roots(
            BTreeMap::from([("fixture-2026".into(), signing.verifying_key().to_bytes())]),
            BTreeSet::from(["updates.example.test".into()]),
        )
        .unwrap();
        (
            policy,
            SignedReleaseManifest {
                manifest,
                signature_base64: STANDARD.encode(signature.to_bytes()),
            },
        )
    }

    #[test]
    fn production_without_trust_roots_is_disabled() {
        let (_, signed) = signed_fixture();
        assert_eq!(
            ReleasePolicy::disabled().verify(&signed, &Version::parse("0.2.0").unwrap(), ARTIFACT),
            Err(ReleaseError::UpdatesDisabled)
        );
    }

    #[test]
    fn verifies_signature_source_version_and_artifact() {
        let (policy, signed) = signed_fixture();
        let verified = policy
            .verify(&signed, &Version::parse("0.2.0").unwrap(), ARTIFACT)
            .unwrap();
        assert_eq!(verified.version, Version::parse("0.3.0").unwrap());
        assert_eq!(verified.source.scheme(), "https");
    }

    #[test]
    fn rejects_unknown_key_tamper_and_hash_mismatch() {
        let (policy, signed) = signed_fixture();
        let mut unknown = signed.clone();
        unknown.manifest.signing_key_id = "other-key".into();
        assert_eq!(
            policy.verify(&unknown, &Version::parse("0.2.0").unwrap(), ARTIFACT),
            Err(ReleaseError::UnknownKey)
        );

        let mut malformed = signed.clone();
        malformed.manifest.product = "Other".into();
        assert_eq!(
            policy.verify(&malformed, &Version::parse("0.2.0").unwrap(), ARTIFACT),
            Err(ReleaseError::MalformedManifest)
        );

        let mut tampered = signed.clone();
        tampered.manifest.licenses_sha256 = "5".repeat(64);
        assert_eq!(
            policy.verify(&tampered, &Version::parse("0.2.0").unwrap(), ARTIFACT),
            Err(ReleaseError::InvalidSignature)
        );

        assert_eq!(
            policy.verify(&signed, &Version::parse("0.2.0").unwrap(), b"tampered"),
            Err(ReleaseError::ArtifactMismatch)
        );
    }

    #[test]
    fn rejects_http_unknown_host_downgrade_and_dev_channel() {
        let (policy, signed) = signed_fixture();
        for source in [
            "http://updates.example.test/vpn-hub-0.3.0-setup.exe",
            "https://evil.example/vpn-hub-0.3.0-setup.exe",
        ] {
            let mut candidate = signed.clone();
            candidate.manifest.source_url = source.into();
            assert_eq!(
                policy.verify(&candidate, &Version::parse("0.2.0").unwrap(), ARTIFACT),
                Err(ReleaseError::UntrustedSource)
            );
        }
        assert_eq!(
            policy.verify(&signed, &Version::parse("0.3.0").unwrap(), ARTIFACT),
            Err(ReleaseError::RollbackRejected)
        );
        let mut prerelease = signed.clone();
        prerelease.manifest.version = "0.4.0-rc.1".into();
        assert_eq!(
            policy.verify(&prerelease, &Version::parse("0.3.0").unwrap(), ARTIFACT),
            Err(ReleaseError::InvalidVersion)
        );
        let mut development = signed.clone();
        development.manifest.channel = ReleaseChannel::Dev;
        assert_eq!(
            policy.verify(&development, &Version::parse("0.2.0").unwrap(), ARTIFACT),
            Err(ReleaseError::DevelopmentArtifact)
        );
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[derive(Default)]
    struct FakeMigrationBackend {
        completed: Vec<ReleaseOperation>,
        rolled_back: Vec<ReleaseOperation>,
        fail_on: Option<MigrationComponent>,
    }

    impl ReleaseMigrationBackend for FakeMigrationBackend {
        type Error = MigrationComponent;

        fn execute(&mut self, operation: &ReleaseOperation) -> Result<(), Self::Error> {
            if let ReleaseOperation::Migrate { component } = operation
                && self.fail_on == Some(*component)
            {
                return Err(*component);
            }
            self.completed.push(operation.clone());
            Ok(())
        }

        fn rollback_owned(&mut self, completed: &[ReleaseOperation]) -> Result<(), Self::Error> {
            self.rolled_back = completed.to_vec();
            Ok(())
        }
    }

    #[test]
    fn fresh_and_upgrade_cover_all_components_without_system_proxy_or_tun() {
        for action in [
            ReleaseLifecycleAction::FreshInstall,
            ReleaseLifecycleAction::Upgrade,
        ] {
            let plan = ReleaseMigrationPlan::build(
                action,
                DataDisposition::Preserve,
                "install-a",
                &"a".repeat(64),
            )
            .unwrap();
            assert!(!plan.system_proxy_included);
            assert!(!plan.tun_executor_supported);
            for component in migration_components() {
                assert!(
                    plan.operations
                        .contains(&ReleaseOperation::Migrate { component })
                );
            }
            if action == ReleaseLifecycleAction::Upgrade {
                assert!(matches!(
                    plan.operations.as_slice(),
                    [
                        ReleaseOperation::HelperOperation {
                            helper_step: PlanOperation::EnterFailClosed
                        },
                        ReleaseOperation::HelperOperation {
                            helper_step: PlanOperation::StopOwnedJob
                        },
                        ReleaseOperation::HelperOperation {
                            helper_step: PlanOperation::RestoreTunSnapshot
                        },
                        ..
                    ]
                ));
                let snapshot = plan
                    .operations
                    .iter()
                    .position(|operation| operation == &ReleaseOperation::SnapshotOwnedData)
                    .unwrap();
                let replacement = plan
                    .operations
                    .iter()
                    .position(|operation| {
                        matches!(
                            operation,
                            ReleaseOperation::HelperOperation {
                                helper_step: PlanOperation::VerifySignedArtifact { .. }
                            }
                        )
                    })
                    .unwrap();
                assert!(snapshot < replacement);
            }
        }
    }

    #[test]
    fn partial_failure_rolls_back_only_completed_owned_mutations() {
        let plan = ReleaseMigrationPlan::build(
            ReleaseLifecycleAction::Upgrade,
            DataDisposition::Preserve,
            "install-a",
            &"a".repeat(64),
        )
        .unwrap();
        let mut backend = FakeMigrationBackend {
            fail_on: Some(MigrationComponent::Sqlite),
            ..FakeMigrationBackend::default()
        };
        assert_eq!(
            execute_release_migration(&plan, &mut backend),
            Err(MigrationExecutionError::Operation(
                MigrationComponent::Sqlite
            ))
        );
        assert!(!backend.rolled_back.is_empty());
        assert!(
            backend
                .rolled_back
                .iter()
                .all(ReleaseOperation::mutates_owned_state)
        );
        assert!(!backend.rolled_back.contains(&ReleaseOperation::Migrate {
            component: MigrationComponent::Sqlite
        }));
        assert!(
            !backend
                .rolled_back
                .contains(&ReleaseOperation::HelperOperation {
                    helper_step: PlanOperation::EnterFailClosed
                })
        );
    }

    #[test]
    fn uninstall_preserve_delete_and_orphan_detection_are_explicit() {
        for disposition in [DataDisposition::Preserve, DataDisposition::Delete] {
            let plan = ReleaseMigrationPlan::build(
                ReleaseLifecycleAction::Uninstall,
                disposition,
                "install-a",
                &"a".repeat(64),
            )
            .unwrap();
            for component in data_components() {
                let expected = match disposition {
                    DataDisposition::Preserve => ReleaseOperation::Preserve { component },
                    DataDisposition::Delete => ReleaseOperation::DeleteOwned { component },
                };
                assert!(plan.operations.contains(&expected));
            }
            assert!(plan.operations.contains(&ReleaseOperation::VerifyNoOrphans));
            if disposition == DataDisposition::Preserve {
                let preserve = plan
                    .operations
                    .iter()
                    .position(|operation| {
                        operation
                            == &ReleaseOperation::Preserve {
                                component: MigrationComponent::Sqlite,
                            }
                    })
                    .unwrap();
                let remove_tree = plan
                    .operations
                    .iter()
                    .position(|operation| {
                        matches!(
                            operation,
                            ReleaseOperation::HelperOperation {
                                helper_step: PlanOperation::RemoveProgramDataTree
                            }
                        )
                    })
                    .unwrap();
                assert!(preserve < remove_tree);
            }
        }
    }

    #[test]
    fn promotion_is_fail_closed_for_every_required_evidence_item() {
        let complete = PromotionEvidence {
            manifest_channel: ReleaseChannel::Stable,
            authenticode_chain: EvidenceStatus::Verified,
            authenticode_timestamp: EvidenceStatus::Verified,
            update_signature: EvidenceStatus::Verified,
            trusted_https_source: EvidenceStatus::Verified,
            artifact_hash: EvidenceStatus::Verified,
            rust_sbom: EvidenceStatus::Verified,
            frontend_sbom: EvidenceStatus::Verified,
            licenses: EvidenceStatus::Verified,
            reproducible_materials: EvidenceStatus::Verified,
            clean_windows_vm_acceptance: EvidenceStatus::Verified,
            system_proxy_included: false,
            tun_executor_supported: false,
        };
        assert_eq!(complete.validate(), Ok(()));

        let mut missing = complete.clone();
        missing.clean_windows_vm_acceptance = EvidenceStatus::Missing;
        assert_eq!(missing.validate(), Err(ReleaseError::PromotionBlocked));
        let mut dev = complete;
        dev.manifest_channel = ReleaseChannel::Dev;
        assert_eq!(dev.validate(), Err(ReleaseError::PromotionBlocked));
    }
}
