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
        principals: Vec<String>,
    },
    RequireInteractiveUserEntrySwitchRecovery {
        journal_relative_path: String,
    },
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
    StopOwnedJob,
    RemoveServiceRegistration,
    RemoveProtectedReference {
        reference_name: String,
    },
    RemoveProgramDataTree,
    VerifyNoOwnedJob,
    VerifyNoServiceRegistration,
    VerifyNoProtectedReferences,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstallPlan {
    pub schema_version: u16,
    pub action: InstallAction,
    pub install_id: String,
    pub dry_run: bool,
    pub requires_elevation_by_signed_installer: bool,
    pub helper_self_elevation: bool,
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
                entry_switch_state_operation(),
                entry_switch_key_operation(&entry_switch_reference),
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
                PlanOperation::RequireInteractiveUserEntrySwitchRecovery {
                    journal_relative_path: "entry-switch/entry-switch.json".into(),
                },
                PlanOperation::StopOwnedJob,
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
                PlanOperation::RequireInteractiveUserEntrySwitchRecovery {
                    journal_relative_path: "entry-switch/entry-switch.json".into(),
                },
                PlanOperation::StopOwnedJob,
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
            ],
        };
        Ok(Self {
            schema_version: 1,
            action,
            install_id: install_id.into(),
            dry_run: true,
            requires_elevation_by_signed_installer: true,
            helper_self_elevation: false,
            operations,
        })
    }
}

fn entry_switch_state_operation() -> PlanOperation {
    PlanOperation::ProvisionEntrySwitchState {
        authority_relative_path: "entry-switch/authority.lease".into(),
        journal_relative_path: "entry-switch/entry-switch.json".into(),
        principals: vec!["interactive-user-sid".into(), "SYSTEM".into()],
    }
}

fn entry_switch_key_operation(reference_name: &str) -> PlanOperation {
    PlanOperation::WriteProtectedReference {
        reference_name: reference_name.into(),
        side: ProtectedMaterialSide::ClientWindowsProtectedStore,
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

    #[test]
    fn install_is_local_service_without_self_elevation() {
        let plan =
            InstallPlan::build(InstallAction::Install, "install-a", &"a".repeat(64)).unwrap();
        assert!(plan.dry_run);
        assert!(plan.requires_elevation_by_signed_installer);
        assert!(!plan.helper_self_elevation);
        assert!(plan.operations.iter().any(|operation| matches!(
            operation,
            PlanOperation::RegisterService {
                account: AccountContract::LocalService,
                start_automatically: false
            }
        )));
        let rendered = serde_json::to_string(&plan).unwrap();
        assert!(!rendered.contains("LocalSystem"));
        assert!(!rendered.contains("protocol-key\":"));
    }

    #[test]
    fn upgrade_stops_owned_job_before_replacing_artifact() {
        let plan =
            InstallPlan::build(InstallAction::Upgrade, "install-a", &"b".repeat(64)).unwrap();
        assert!(matches!(
            plan.operations.first(),
            Some(PlanOperation::RequireInteractiveUserEntrySwitchRecovery { .. })
        ));
        assert!(matches!(
            plan.operations.get(1),
            Some(PlanOperation::StopOwnedJob)
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
            Some(PlanOperation::RequireInteractiveUserEntrySwitchRecovery { .. })
        ));
    }

    #[test]
    fn entry_switch_state_excludes_local_service_and_requires_user_recovery() {
        let install =
            InstallPlan::build(InstallAction::Install, "install-a", &"d".repeat(64)).unwrap();
        let state = install
            .operations
            .iter()
            .find_map(|operation| match operation {
                PlanOperation::ProvisionEntrySwitchState { principals, .. } => Some(principals),
                _ => None,
            })
            .expect("entry switch state");
        assert_eq!(state, &["interactive-user-sid", "SYSTEM"]);
        assert!(
            !state
                .iter()
                .any(|principal| principal.contains("LOCAL SERVICE"))
        );
        assert!(install.operations.iter().any(|operation| matches!(operation,
            PlanOperation::WriteProtectedReference { reference_name, side: ProtectedMaterialSide::ClientWindowsProtectedStore }
                if reference_name == "vpn-hub/entry-switch/install-a/hmac-key"
        )));
    }
}
