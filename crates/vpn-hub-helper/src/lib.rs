//! Security boundary for the optional VPN Hub Windows helper.
//!
//! The runtime supervises only its held child/job, authenticates local IPC and
//! performs fail-closed preflight checks. It never elevates, registers a
//! service, changes the system proxy, or manages arbitrary processes. Only the
//! signed installer may apply the emitted provisioning plans.
#![allow(clippy::missing_errors_doc)]

mod authority;
mod install_plan;
mod installation;
mod manifest;
mod ownership;
mod protocol;
mod runtime;
mod service_shell;
mod status;
mod supervisor;
mod transport;

pub use authority::{
    AuthorityError, AuthorityFileGuard, AuthorityLease, AuthorityRegistry, SupervisorAuthority,
};
pub use install_plan::{
    AccountContract, ExistingArtifactMode, InstallAction, InstallPlan, InstallPlanError,
    PlanOperation, ProtectedMaterialSide,
};
pub use installation::{
    InstallationReference, InstallationReferenceError, validate_installation_location,
};
pub use manifest::{
    CoreArtifact, EntrySummary, ManifestError, OutletHealthSummary, OutletKindSummary,
    OutletSummary, SupervisionManifest, load_manifest,
};
pub use ownership::{
    ChildControl, OwnedChildGuard, OwnedProcessIdentity, OwnershipError, ProcessObservation,
};
pub use protocol::{
    AuthError, AuthenticatedRequest, Command, ExpectedOwnership, NamedPipeContract, ProtocolKey,
    ReplayCache, SignedRequest, SignedResponse, UnsignedRequest, UnsignedResponse,
    authenticate_challenged_frame, authenticate_response_frame, pipe_name,
};
pub use runtime::{CoreBackend, HelperRuntime, ManifestProvider, RuntimeError, RuntimeReply};
#[cfg(target_os = "windows")]
pub use runtime::{ProgramDataManifestProvider, WindowsJobCoreBackend, run_windows_helper_loop};
pub use service_shell::{
    ServiceBody, ServiceShellContract, ServiceSignals, run_service_dispatcher,
    service_shell_contract,
};
pub use status::{AuthorityStatus, HelperStatus, OwnedProcessStatus};
pub use supervisor::{
    CircuitState, FailClosedReason, RecoverySignal, SupervisorEvent, SupervisorMachine,
    SupervisorState,
};
#[cfg(target_os = "windows")]
pub use transport::{NamedPipeClient, TransportError, serve_one_named_pipe_request};

/// Current helper protocol major version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Helper integration remains opt-in until a signed installer provisions it.
pub const HELPER_DEFAULT_ENABLED: bool = false;
