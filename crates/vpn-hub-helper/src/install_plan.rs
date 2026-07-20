use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AuthError, NamedPipeContract};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InstallAction {
    Install,
    Upgrade,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum AccountContract {
    LocalService,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedMaterialSide {
    ServiceProgramDataAclFile,
    ClientWindowsProtectedStore,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExistingArtifactMode {
    CreateIfMissingPreserveExisting,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum PlanOperation {
    VerifySignedArtifact {
        relative_path: String,
        sha256: String,
    },
    ApplyProgramDataAcl {
        relative_path: String,
        principals: Vec<String>,
    },
    ProvisionAuthorityLeaseFile,
    ProvisionEntrySwitchState {
        authority_relative_path: String,
        journal_relative_path: String,
        hmac_key_reference_name: String,
        hmac_key_side: ProtectedMaterialSide,
        existing_artifact_mode: ExistingArtifactMode,
        rollback_new_artifacts_on_failure: bool,
        principals: Vec<String>,
    },
    RecoverInteractiveUserEntrySwitchIfPresent {
        journal_relative_path: String,
    },
    ProvisionTunAuthorityLeaseFile,
    RegisterService {
        account: AccountContract,
        start_automatically: bool,
    },
    ConfigureNamedPipeAcl {
        pipe_name: String,
        principals: Vec<String>,
        reject_remote_clients: bool,
    },
    WriteProtectedReference {
        reference_name: String,
        side: ProtectedMaterialSide,
    },
    EnterFailClosed,
    StopOwnedJob,
    RestoreTunSnapshot,
    RemoveServiceRegistration,
    RemoveProtectedReference {
        reference_name: String,
    },
    RemoveProgramDataTree,
    VerifyNoOwnedJob,
    VerifyNoServiceRegistration,
    VerifyNoProtectedReferences,
    VerifyNoTunState,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstallPlan {
    pub schema_version: u16,
    pub action: InstallAction,
    pub install_id: String,
    pub dry_run: bool,
    pub requires_elevation_by_signed_installer: bool,
    pub helper_self_elevation: bool,
    /// The signed installer must execute this sequence in order and abort on
    /// the first failure. Later cleanup/removal operations must never run
    /// after fail-closed entry, owned-job stop, or TUN restoration fails.
    pub operations: Vec<PlanOperation>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InstallPlanError {
    #[error("invalid install identifier")]
    InvalidInstallId,
    #[error("invalid artifact hash")]
    InvalidHash,
    #[error("invalid named pipe contract")]
    InvalidPipe,
}

impl From<AuthError> for InstallPlanError {
    fn from(_: AuthError) -> Self {
        Self::InvalidPipe
    }
}

impl InstallPlan {
    #[allow(clippy::too_many_lines)]
    pub fn build(
        action: InstallAction,
        install_id: &str,
        helper_sha256: &str,
    ) -> Result<Self, InstallPlanError> {
        validate_install_inputs(install_id, helper_sha256)?;
        let pipe = NamedPipeContract::for_install(install_id)?;
        let protected_reference = format!("vpn-hub/helper/{install_id}/protocol-key");
        let entry_switch_reference = format!("vpn-hub/entry-switch/{install_id}/hmac-key");
        let operations = match action {
            InstallAction::Install => vec![
                PlanOperation::VerifySignedArtifact {
                    relative_path: "bin/vpn-hub-helper.exe".into(),
                    sha256: helper_sha256.into(),
                },
                PlanOperation::ApplyProgramDataAcl {
                    relative_path: ".".into(),
                    principals: vec![
                        "interactive-user-sid".into(),
                        "NT AUTHORITY\\LOCAL SERVICE".into(),
                        "SYSTEM".into(),
                    ],
                },
                entry_switch_state_operation(&entry_switch_reference),
                PlanOperation::ProvisionTunAuthorityLeaseFile,
                PlanOperation::ApplyProgramDataAcl {
                    relative_path: "tun-authority.lease".into(),
                    principals: vec![
                        "NT AUTHORITY\\LOCAL SERVICE".into(),
                        "SYSTEM".into(),
                        "BUILTIN\\Administrators".into(),
                    ],
                },
                PlanOperation::ProvisionAuthorityLeaseFile,
                PlanOperation::ApplyProgramDataAcl {
                    relative_path: "authority.lease".into(),
                    principals: vec![
                        "interactive-user-sid".into(),
                        "NT AUTHORITY\\LOCAL SERVICE".into(),
                        "SYSTEM".into(),
                    ],
                },
                PlanOperation::WriteProtectedReference {
                    reference_name: format!("{protected_reference}/service"),
                    side: ProtectedMaterialSide::ServiceProgramDataAclFile,
                },
                PlanOperation::WriteProtectedReference {
                    reference_name: format!("{protected_reference}/client"),
                    side: ProtectedMaterialSide::ClientWindowsProtectedStore,
                },
                PlanOperation::ConfigureNamedPipeAcl {
                    pipe_name: pipe.name,
                    principals: pipe
                        .allowed_principals
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    reject_remote_clients: true,
                },
                PlanOperation::RegisterService {
                    account: AccountContract::LocalService,
                    start_automatically: false,
                },
            ],
            InstallAction::Upgrade => vec![
                PlanOperation::RecoverInteractiveUserEntrySwitchIfPresent {
                    journal_relative_path: "entry-switch/entry-switch.json".into(),
                },
                PlanOperation::EnterFailClosed,
                PlanOperation::StopOwnedJob,
                PlanOperation::RestoreTunSnapshot,
                entry_switch_state_operation(&entry_switch_reference),
                PlanOperation::VerifySignedArtifact {
                    relative_path: "bin/vpn-hub-helper.exe".into(),
                    sha256: helper_sha256.into(),
                },
                PlanOperation::ApplyProgramDataAcl {
                    relative_path: ".".into(),
                    principals: vec![
                        "interactive-user-sid".into(),
                        "NT AUTHORITY\\LOCAL SERVICE".into(),
                        "SYSTEM".into(),
                    ],
                },
                PlanOperation::VerifyNoOwnedJob,
            ],
            InstallAction::Uninstall => vec![
                PlanOperation::RecoverInteractiveUserEntrySwitchIfPresent {
                    journal_relative_path: "entry-switch/entry-switch.json".into(),
                },
                PlanOperation::EnterFailClosed,
                PlanOperation::StopOwnedJob,
                PlanOperation::RestoreTunSnapshot,
                PlanOperation::RemoveServiceRegistration,
                PlanOperation::RemoveProtectedReference {
                    reference_name: format!("{protected_reference}/service"),
                },
                PlanOperation::RemoveProtectedReference {
                    reference_name: format!("{protected_reference}/client"),
                },
                PlanOperation::RemoveProtectedReference {
                    reference_name: entry_switch_reference,
                },
                PlanOperation::RemoveProgramDataTree,
                PlanOperation::VerifyNoOwnedJob,
                PlanOperation::VerifyNoServiceRegistration,
                PlanOperation::VerifyNoProtectedReferences,
                PlanOperation::VerifyNoTunState,
            ],
        };
        Ok(Self {
            schema_version: 2,
            action,
            install_id: install_id.into(),
            dry_run: true,
            requires_elevation_by_signed_installer: true,
            helper_self_elevation: false,
            operations,
        })
    }
}

fn entry_switch_state_operation(key_reference_name: &str) -> PlanOperation {
    PlanOperation::ProvisionEntrySwitchState {
        authority_relative_path: "entry-switch/authority.lease".into(),
        journal_relative_path: "entry-switch/entry-switch.json".into(),
        hmac_key_reference_name: key_reference_name.into(),
        hmac_key_side: ProtectedMaterialSide::ClientWindowsProtectedStore,
        existing_artifact_mode: ExistingArtifactMode::CreateIfMissingPreserveExisting,
        rollback_new_artifacts_on_failure: true,
        principals: vec!["interactive-user-sid".into(), "SYSTEM".into()],
    }
}

fn validate_install_inputs(install_id: &str, helper_sha256: &str) -> Result<(), InstallPlanError> {
    validate_id(install_id)?;
    validate_hash(helper_sha256)
}

fn validate_id(value: &str) -> Result<(), InstallPlanError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InstallPlanError::InvalidInstallId);
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), InstallPlanError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(InstallPlanError::InvalidHash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct FakeEntrySwitchInstall {
        authority_exists: bool,
        journal_exists: bool,
        journal_pending: bool,
        hmac_key: Option<String>,
        next_key: u64,
        recoveries: usize,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FailProvisionAt {
        Authority,
        Journal,
        Key,
    }

    fn apply_entry_switch_contract(
        plan: &InstallPlan,
        state: &mut FakeEntrySwitchInstall,
        fail_at: Option<FailProvisionAt>,
    ) -> Result<(), &'static str> {
        for operation in &plan.operations {
            match operation {
                PlanOperation::RecoverInteractiveUserEntrySwitchIfPresent { .. } => {
                    if state.journal_exists {
                        state.recoveries += 1;
                        state.journal_pending = false;
                    }
                }
                PlanOperation::ProvisionEntrySwitchState {
                    hmac_key_side,
                    existing_artifact_mode,
                    rollback_new_artifacts_on_failure,
                    ..
                } => {
                    assert_eq!(
                        hmac_key_side,
                        &ProtectedMaterialSide::ClientWindowsProtectedStore
                    );
                    assert_eq!(
                        existing_artifact_mode,
                        &ExistingArtifactMode::CreateIfMissingPreserveExisting
                    );
                    assert!(*rollback_new_artifacts_on_failure);

                    let before = state.clone();
                    state.authority_exists = true;
                    if fail_at == Some(FailProvisionAt::Authority) {
                        *state = before;
                        return Err("injected failure after authority");
                    }

                    state.journal_exists = true;
                    if fail_at == Some(FailProvisionAt::Journal) {
                        *state = before;
                        return Err("injected failure after journal");
                    }

                    if state.hmac_key.is_none() {
                        state.next_key += 1;
                        state.hmac_key = Some(format!("generated-key-{}", state.next_key));
                    }
                    if fail_at == Some(FailProvisionAt::Key) {
                        *state = before;
                        return Err("injected failure after key");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[test]
    fn install_is_local_service_without_self_elevation() {
        let plan =
            InstallPlan::build(InstallAction::Install, "install-a", &"a".repeat(64)).unwrap();
        assert!(plan.dry_run);
        assert!(plan.requires_elevation_by_signed_installer);
        assert!(!plan.helper_self_elevation);
        assert_eq!(plan.schema_version, 2);
        assert!(plan.operations.iter().any(|operation| matches!(
            operation,
            PlanOperation::RegisterService {
                account: AccountContract::LocalService,
                start_automatically: false
            }
        )));
        assert!(matches!(
            plan.operations.as_slice(),
            [
                PlanOperation::VerifySignedArtifact { .. },
                PlanOperation::ApplyProgramDataAcl { .. },
                PlanOperation::ProvisionEntrySwitchState { .. },
                PlanOperation::ProvisionTunAuthorityLeaseFile,
                PlanOperation::ApplyProgramDataAcl {
                    relative_path,
                    principals,
                },
                ..
            ] if relative_path == "tun-authority.lease"
                && principals == &[
                    "NT AUTHORITY\\LOCAL SERVICE",
                    "SYSTEM",
                    "BUILTIN\\Administrators",
                ]
        ));
        let rendered = serde_json::to_string(&plan).unwrap();
        assert!(!rendered.contains("LocalSystem"));
        assert!(!rendered.contains("protocol-key\":"));
    }

    #[test]
    fn upgrade_recovers_then_runs_tun_safety_prefix_before_provisioning() {
        let plan =
            InstallPlan::build(InstallAction::Upgrade, "install-a", &"b".repeat(64)).unwrap();
        assert!(matches!(
            plan.operations.first(),
            Some(PlanOperation::RecoverInteractiveUserEntrySwitchIfPresent { .. })
        ));
        assert!(matches!(
            &plan.operations[1..4],
            [
                PlanOperation::EnterFailClosed,
                PlanOperation::StopOwnedJob,
                PlanOperation::RestoreTunSnapshot
            ]
        ));
        assert!(matches!(
            plan.operations.get(4),
            Some(PlanOperation::ProvisionEntrySwitchState {
                hmac_key_side: ProtectedMaterialSide::ClientWindowsProtectedStore,
                existing_artifact_mode: ExistingArtifactMode::CreateIfMissingPreserveExisting,
                rollback_new_artifacts_on_failure: true,
                ..
            })
        ));
        assert!(matches!(
            plan.operations.last(),
            Some(PlanOperation::VerifyNoOwnedJob)
        ));
    }

    #[test]
    fn uninstall_plan_has_explicit_no_orphan_checks() {
        let plan =
            InstallPlan::build(InstallAction::Uninstall, "install-a", &"c".repeat(64)).unwrap();
        assert!(plan.operations.contains(&PlanOperation::VerifyNoOwnedJob));
        assert!(
            plan.operations
                .contains(&PlanOperation::VerifyNoServiceRegistration)
        );
        assert!(
            plan.operations
                .contains(&PlanOperation::VerifyNoProtectedReferences)
        );
        assert!(matches!(
            plan.operations.first(),
            Some(PlanOperation::RecoverInteractiveUserEntrySwitchIfPresent { .. })
        ));
        assert!(matches!(
            &plan.operations[1..4],
            [
                PlanOperation::EnterFailClosed,
                PlanOperation::StopOwnedJob,
                PlanOperation::RestoreTunSnapshot
            ]
        ));
        assert!(plan.operations.contains(&PlanOperation::VerifyNoTunState));
    }

    #[test]
    fn entry_switch_state_excludes_local_service_and_requires_user_recovery() {
        let install =
            InstallPlan::build(InstallAction::Install, "install-a", &"d".repeat(64)).unwrap();
        let state = install
            .operations
            .iter()
            .find_map(|operation| match operation {
                PlanOperation::ProvisionEntrySwitchState {
                    principals,
                    hmac_key_reference_name,
                    hmac_key_side,
                    existing_artifact_mode,
                    rollback_new_artifacts_on_failure,
                    ..
                } => Some((
                    principals,
                    hmac_key_reference_name,
                    hmac_key_side,
                    existing_artifact_mode,
                    rollback_new_artifacts_on_failure,
                )),
                _ => None,
            })
            .expect("entry switch state");
        assert_eq!(state.0, &["interactive-user-sid", "SYSTEM"]);
        assert!(
            !state
                .0
                .iter()
                .any(|principal| principal.contains("LOCAL SERVICE"))
        );
        assert_eq!(state.1, "vpn-hub/entry-switch/install-a/hmac-key");
        assert_eq!(state.2, &ProtectedMaterialSide::ClientWindowsProtectedStore);
        assert_eq!(
            state.3,
            &ExistingArtifactMode::CreateIfMissingPreserveExisting
        );
        assert!(state.4);
    }

    #[test]
    fn first_upgrade_from_legacy_install_creates_state_and_key() {
        let plan = InstallPlan::build(InstallAction::Upgrade, "legacy", &"e".repeat(64)).unwrap();
        let mut state = FakeEntrySwitchInstall::default();

        apply_entry_switch_contract(&plan, &mut state, None).unwrap();

        assert!(state.authority_exists);
        assert!(state.journal_exists);
        assert!(!state.journal_pending);
        assert_eq!(state.hmac_key.as_deref(), Some("generated-key-1"));
        assert_eq!(state.recoveries, 0);
    }

    #[test]
    fn upgrade_preserves_existing_key_across_repeated_runs() {
        let plan =
            InstallPlan::build(InstallAction::Upgrade, "install-a", &"f".repeat(64)).unwrap();
        let mut state = FakeEntrySwitchInstall {
            hmac_key: Some("existing-protected-key".into()),
            ..Default::default()
        };

        apply_entry_switch_contract(&plan, &mut state, None).unwrap();
        apply_entry_switch_contract(&plan, &mut state, None).unwrap();

        assert!(state.authority_exists);
        assert!(state.journal_exists);
        assert_eq!(state.hmac_key.as_deref(), Some("existing-protected-key"));
        assert_eq!(state.next_key, 0);
    }

    #[test]
    fn partial_state_retry_is_idempotent() {
        let plan =
            InstallPlan::build(InstallAction::Upgrade, "install-a", &"1".repeat(64)).unwrap();
        let mut state = FakeEntrySwitchInstall {
            authority_exists: true,
            hmac_key: Some("existing-protected-key".into()),
            ..Default::default()
        };

        apply_entry_switch_contract(&plan, &mut state, None).unwrap();
        let completed = state.clone();
        apply_entry_switch_contract(&plan, &mut state, None).unwrap();

        assert_eq!(state.authority_exists, completed.authority_exists);
        assert_eq!(state.journal_exists, completed.journal_exists);
        assert_eq!(state.hmac_key, completed.hmac_key);
        assert_eq!(state.next_key, completed.next_key);
    }

    #[test]
    fn provisioning_failure_rolls_back_only_new_artifacts() {
        let plan =
            InstallPlan::build(InstallAction::Upgrade, "install-a", &"2".repeat(64)).unwrap();
        let empty = FakeEntrySwitchInstall::default();
        for failure in [
            FailProvisionAt::Authority,
            FailProvisionAt::Journal,
            FailProvisionAt::Key,
        ] {
            let mut state = empty.clone();
            assert!(apply_entry_switch_contract(&plan, &mut state, Some(failure)).is_err());
            assert_eq!(state, empty);
        }

        let partial = FakeEntrySwitchInstall {
            authority_exists: true,
            hmac_key: Some("existing-protected-key".into()),
            ..Default::default()
        };
        let mut state = partial.clone();
        assert!(
            apply_entry_switch_contract(&plan, &mut state, Some(FailProvisionAt::Journal)).is_err()
        );
        assert_eq!(state, partial);
    }
}
