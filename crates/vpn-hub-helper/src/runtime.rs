use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AuthenticatedRequest, AuthorityLease, AuthorityRegistry, Command, FailClosedReason,
    OwnedProcessIdentity, SupervisionManifest, SupervisorAuthority, SupervisorEvent,
    SupervisorMachine,
};

pub trait ManifestProvider {
    fn load(&self) -> Result<SupervisionManifest, RuntimeError>;
}

pub trait CoreBackend {
    fn start_owned(
        &mut self,
        manifest: &SupervisionManifest,
        fencing_token: u64,
    ) -> Result<OwnedProcessIdentity, RuntimeError>;
    fn stop_owned(
        &mut self,
        identity: &OwnedProcessIdentity,
        fencing_token: u64,
    ) -> Result<(), RuntimeError>;
    fn reload_owned(
        &mut self,
        identity: &OwnedProcessIdentity,
        manifest: &SupervisionManifest,
        fencing_token: u64,
    ) -> Result<OwnedProcessIdentity, RuntimeError>;
    fn owned_child_alive(
        &mut self,
        identity: &OwnedProcessIdentity,
        fencing_token: u64,
    ) -> Result<bool, RuntimeError>;
    fn network_fingerprint(&self) -> Result<[u8; 32], RuntimeError>;
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("helper is not the active supervisor authority")]
    Authority,
    #[error("sanitized supervision manifest is invalid")]
    Manifest,
    #[error("core artifact verification failed")]
    Artifact,
    #[error("configured entry port is unavailable")]
    PortConflict,
    #[error("guardian database integrity check failed")]
    CorruptDatabase,
    #[error("owned core operation failed")]
    OwnedCore,
    #[error("supervisor is fail closed")]
    FailClosed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuntimeReply {
    pub ok: bool,
    pub state: String,
    pub generation: u64,
    pub authority: String,
    pub owned_pid: Option<u32>,
    pub entry_host: String,
    pub entry_port: u16,
    pub outlets: Vec<crate::OutletSummary>,
    pub circuit_open: bool,
    pub reason: Option<String>,
}

pub struct HelperRuntime<B: CoreBackend, P: ManifestProvider> {
    backend: B,
    provider: P,
    manifest: SupervisionManifest,
    authority: AuthorityRegistry,
    lease: AuthorityLease,
    supervisor: SupervisorMachine,
    owned: Option<OwnedProcessIdentity>,
    restart_due_ms: Option<i64>,
    started_at_ms: Option<i64>,
    network_fingerprint: [u8; 32],
    cross_process_guard: Option<crate::AuthorityFileGuard>,
}

#[cfg(target_os = "windows")]
pub async fn run_windows_helper_loop<B, P>(
    runtime: std::sync::Arc<std::sync::Mutex<HelperRuntime<B, P>>>,
    key: std::sync::Arc<crate::ProtocolKey>,
    install_id: String,
    interactive_user_sid: String,
    signals: std::sync::Arc<crate::ServiceSignals>,
) -> Result<(), RuntimeError>
where
    B: CoreBackend + Send + 'static,
    P: ManifestProvider + Send + 'static,
{
    let replay_cache = std::sync::Arc::new(tokio::sync::Mutex::new(crate::ReplayCache::default()));
    while !signals.should_stop() {
        {
            let mut runtime = runtime.lock().map_err(|_| RuntimeError::FailClosed)?;
            runtime.tick(unix_ms())?;
            if signals.take_resume() {
                runtime.recover_from_service_signal(unix_ms())?;
            }
        }
        let runtime_for_request = std::sync::Arc::clone(&runtime);
        let result = crate::serve_one_named_pipe_request(
            &install_id,
            &interactive_user_sid,
            std::sync::Arc::clone(&key),
            std::sync::Arc::clone(&replay_cache),
            move |request| {
                let response = runtime_for_request
                    .lock()
                    .map_err(|_| RuntimeError::FailClosed)
                    .and_then(|mut runtime| runtime.handle(&request, unix_ms()));
                match response {
                    Ok(response) => serde_json::to_vec(&response).unwrap_or_else(|_| {
                        br#"{"ok":false,"reason":"serialization-failed"}"#.to_vec()
                    }),
                    Err(_) => br#"{"ok":false,"reason":"fail-closed"}"#.to_vec(),
                }
            },
        )
        .await;
        if let Err(error) = result {
            if signals.should_stop() {
                break;
            }
            if matches!(error, crate::TransportError::Fatal) {
                return Err(RuntimeError::FailClosed);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

impl<B: CoreBackend, P: ManifestProvider> HelperRuntime<B, P> {
    pub fn acquire_helper(backend: B, provider: P, now_ms: i64) -> Result<Self, RuntimeError> {
        let manifest = provider.load()?;
        let network_fingerprint = backend.network_fingerprint()?;
        let mut authority = AuthorityRegistry::default();
        let lease = authority
            .acquire(
                &manifest.install_id,
                SupervisorAuthority::Helper,
                manifest.generation,
                now_ms,
                30_000,
            )
            .map_err(|_| RuntimeError::Authority)?;
        Ok(Self {
            supervisor: SupervisorMachine::new(manifest.generation),
            backend,
            provider,
            manifest,
            authority,
            lease,
            owned: None,
            restart_due_ms: None,
            started_at_ms: None,
            network_fingerprint,
            cross_process_guard: None,
        })
    }

    pub fn acquire_helper_with_authority_file(
        backend: B,
        provider: P,
        authority_path: &Path,
        now_ms: i64,
    ) -> Result<Self, RuntimeError> {
        let manifest = provider.load()?;
        let network_fingerprint = backend.network_fingerprint()?;
        let cross_process_guard = crate::AuthorityFileGuard::acquire_existing(
            authority_path,
            SupervisorAuthority::Helper,
            manifest.generation,
        )
        .map_err(|_| RuntimeError::Authority)?;
        let mut authority = AuthorityRegistry::default();
        let lease = authority
            .acquire(
                &manifest.install_id,
                SupervisorAuthority::Helper,
                manifest.generation,
                now_ms,
                30_000,
            )
            .map_err(|_| RuntimeError::Authority)?;
        Ok(Self {
            supervisor: SupervisorMachine::new(manifest.generation),
            backend,
            provider,
            manifest,
            authority,
            lease,
            owned: None,
            restart_due_ms: None,
            started_at_ms: None,
            network_fingerprint,
            cross_process_guard: Some(cross_process_guard),
        })
    }

    pub fn tick(&mut self, now_ms: i64) -> Result<(), RuntimeError> {
        self.lease = self
            .authority
            .renew(&self.lease, self.manifest.generation, now_ms, 30_000)
            .map_err(|_| RuntimeError::Authority)?;
        if let Some(identity) = &self.owned
            && !self
                .backend
                .owned_child_alive(identity, self.lease.fencing_token)?
        {
            self.owned = None;
            self.supervisor.apply(SupervisorEvent::OwnedChildExited);
            if let crate::SupervisorState::Backoff { delay_ms } = self.supervisor.state() {
                let delay_ms = i64::try_from(delay_ms).unwrap_or(i64::MAX);
                self.restart_due_ms = Some(now_ms.saturating_add(delay_ms));
            }
        }
        if let Ok(network_fingerprint) = self.backend.network_fingerprint()
            && network_fingerprint != self.network_fingerprint
        {
            self.network_fingerprint = network_fingerprint;
            self.supervisor.apply(SupervisorEvent::Recovery(
                crate::RecoverySignal::NetworkChanged(network_fingerprint),
            ));
            self.recover_owned(now_ms)?;
        }
        if self.restart_due_ms.is_some_and(|due| now_ms >= due) {
            self.restart_due_ms = None;
            self.supervisor.apply(SupervisorEvent::RestartTimer);
            if let Err(error) = self.start(now_ms) {
                if let crate::SupervisorState::Backoff { delay_ms } = self.supervisor.state() {
                    let delay_ms = i64::try_from(delay_ms).unwrap_or(i64::MAX);
                    self.restart_due_ms = Some(now_ms.saturating_add(delay_ms));
                }
                return match error {
                    RuntimeError::OwnedCore => Ok(()),
                    other => Err(other),
                };
            }
        }
        if self.owned.is_some()
            && self
                .started_at_ms
                .is_some_and(|started| now_ms.saturating_sub(started) >= 60_000)
        {
            self.supervisor.apply(SupervisorEvent::StableRun);
            self.started_at_ms = None;
        }
        Ok(())
    }

    pub fn handle(
        &mut self,
        request: &AuthenticatedRequest,
        now_ms: i64,
    ) -> Result<RuntimeReply, RuntimeError> {
        if self.cross_process_guard.is_none() && cfg!(not(test)) {
            return Err(RuntimeError::Authority);
        }
        self.authority
            .validate(&self.lease, now_ms)
            .map_err(|_| RuntimeError::Authority)?;
        if request.install_id != self.manifest.install_id {
            return Err(RuntimeError::Authority);
        }
        let operation = match request.command {
            Command::Status | Command::Version => Ok(()),
            Command::Start => self.start(now_ms),
            Command::Stop => self.stop(),
            Command::Restart => self.stop().and_then(|()| self.start(now_ms)),
            Command::Reload => self.reload(now_ms),
            Command::Resume => {
                self.supervisor
                    .apply(SupervisorEvent::Recovery(crate::RecoverySignal::Resume));
                Ok(())
            }
            Command::NetworkChanged => self.backend.network_fingerprint().map(|fingerprint| {
                self.network_fingerprint = fingerprint;
                self.supervisor.apply(SupervisorEvent::Recovery(
                    crate::RecoverySignal::NetworkChanged(fingerprint),
                ));
            }),
            Command::ResetCircuit => {
                self.supervisor.apply(SupervisorEvent::ExplicitReset);
                Ok(())
            }
        };
        let operation = operation.and_then(|()| {
            if matches!(request.command, Command::Resume | Command::NetworkChanged) {
                self.recover_owned(now_ms)
            } else {
                Ok(())
            }
        });
        if let Err(error) = operation {
            if matches!(
                error,
                RuntimeError::PortConflict
                    | RuntimeError::CorruptDatabase
                    | RuntimeError::Manifest
                    | RuntimeError::Artifact
            ) {
                return Ok(self.reply());
            }
            return Err(error);
        }
        Ok(self.reply())
    }

    pub fn recover_from_service_signal(&mut self, now_ms: i64) -> Result<(), RuntimeError> {
        self.supervisor
            .apply(SupervisorEvent::Recovery(crate::RecoverySignal::Resume));
        self.recover_owned(now_ms)
    }

    fn start(&mut self, now_ms: i64) -> Result<(), RuntimeError> {
        let current = self.provider.load().inspect_err(|error| {
            self.record_preflight_failure(error);
        })?;
        if current.install_id != self.manifest.install_id
            || current.generation < self.manifest.generation
        {
            self.supervisor.apply(SupervisorEvent::InvalidState(
                FailClosedReason::CorruptConfig,
            ));
            return Err(RuntimeError::Manifest);
        }
        if current.generation > self.manifest.generation {
            self.lease = self
                .authority
                .renew(&self.lease, current.generation, now_ms, 30_000)
                .map_err(|_| RuntimeError::Authority)?;
            self.manifest = current;
        }
        if self.owned.is_some() {
            return Ok(());
        }
        let identity = self
            .backend
            .start_owned(&self.manifest, self.lease.fencing_token)
            .map_err(|error| {
                match error {
                    RuntimeError::PortConflict => self.supervisor.apply(
                        SupervisorEvent::InvalidState(FailClosedReason::PortConflict),
                    ),
                    RuntimeError::CorruptDatabase => self.supervisor.apply(
                        SupervisorEvent::InvalidState(FailClosedReason::CorruptDatabase),
                    ),
                    RuntimeError::Manifest | RuntimeError::Artifact => self.supervisor.apply(
                        SupervisorEvent::InvalidState(FailClosedReason::CorruptConfig),
                    ),
                    _ => self.supervisor.apply(SupervisorEvent::StartFailed),
                }
                error
            })?;
        self.supervisor.apply(SupervisorEvent::StartSucceeded {
            pid: identity.pid,
            creation_identity: identity.creation_identity,
        });
        self.owned = Some(identity);
        self.restart_due_ms = None;
        self.started_at_ms = Some(now_ms);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), RuntimeError> {
        if let Some(identity) = self.owned.take() {
            self.backend
                .stop_owned(&identity, self.lease.fencing_token)?;
        }
        self.supervisor.apply(SupervisorEvent::ExplicitStop);
        self.restart_due_ms = None;
        self.started_at_ms = None;
        Ok(())
    }

    fn reload(&mut self, now_ms: i64) -> Result<(), RuntimeError> {
        let next = self.provider.load().inspect_err(|error| {
            self.record_preflight_failure(error);
        })?;
        if next.install_id != self.manifest.install_id || next.generation < self.manifest.generation
        {
            self.supervisor.apply(SupervisorEvent::InvalidState(
                FailClosedReason::CorruptConfig,
            ));
            return Err(RuntimeError::Manifest);
        }
        let had_owned = self.owned.is_some();
        self.lease = self
            .authority
            .renew(&self.lease, next.generation, now_ms, 30_000)
            .map_err(|_| RuntimeError::Authority)?;
        self.supervisor.apply(SupervisorEvent::Recovery(
            crate::RecoverySignal::ConfigGeneration(next.generation),
        ));
        self.manifest = next;
        if had_owned {
            self.replace_owned(now_ms)?;
        }
        Ok(())
    }

    fn record_preflight_failure(&mut self, error: &RuntimeError) {
        let reason = match error {
            RuntimeError::CorruptDatabase => FailClosedReason::CorruptDatabase,
            RuntimeError::PortConflict => FailClosedReason::PortConflict,
            _ => FailClosedReason::CorruptConfig,
        };
        self.supervisor.apply(SupervisorEvent::InvalidState(reason));
    }

    fn recover_owned(&mut self, now_ms: i64) -> Result<(), RuntimeError> {
        if self.owned.is_some() {
            self.replace_owned(now_ms)?;
        }
        Ok(())
    }

    fn replace_owned(&mut self, now_ms: i64) -> Result<(), RuntimeError> {
        let previous = self.owned.clone().ok_or(RuntimeError::OwnedCore)?;
        let replacement =
            self.backend
                .reload_owned(&previous, &self.manifest, self.lease.fencing_token)?;
        self.supervisor.apply(SupervisorEvent::StartSucceeded {
            pid: replacement.pid,
            creation_identity: replacement.creation_identity,
        });
        self.owned = Some(replacement);
        self.started_at_ms = Some(now_ms);
        self.restart_due_ms = None;
        Ok(())
    }

    fn reply(&self) -> RuntimeReply {
        let reason = match self.supervisor.state() {
            crate::SupervisorState::FailClosed(FailClosedReason::CorruptConfig) => {
                Some("corrupt-config".into())
            }
            crate::SupervisorState::FailClosed(FailClosedReason::CorruptDatabase) => {
                Some("corrupt-database".into())
            }
            crate::SupervisorState::FailClosed(FailClosedReason::PortConflict) => {
                Some("port-conflict".into())
            }
            crate::SupervisorState::FailClosed(FailClosedReason::OwnershipLost) => {
                Some("ownership-lost".into())
            }
            crate::SupervisorState::FailClosed(FailClosedReason::AuthorityLost) => {
                Some("authority-lost".into())
            }
            _ => None,
        };
        RuntimeReply {
            ok: reason.is_none(),
            state: if self.owned.is_some() {
                "running".into()
            } else {
                "stopped".into()
            },
            generation: self.manifest.generation,
            authority: "helper".into(),
            owned_pid: self.owned.as_ref().map(|identity| identity.pid),
            entry_host: self.manifest.entry.host.clone(),
            entry_port: self.manifest.entry.port,
            outlets: self.manifest.outlets.clone(),
            circuit_open: self.supervisor.circuit() == crate::CircuitState::Open,
            reason,
        }
    }
}

#[cfg(target_os = "windows")]
pub struct ProgramDataManifestProvider {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub install_id: String,
}

#[cfg(target_os = "windows")]
impl ManifestProvider for ProgramDataManifestProvider {
    fn load(&self) -> Result<SupervisionManifest, RuntimeError> {
        let manifest = crate::load_manifest(&self.root, &self.manifest_path, &self.install_id)
            .map_err(|_| RuntimeError::Manifest)?;
        validate_database(&manifest.guardian_database_path(&self.root))?;
        Ok(manifest)
    }
}

#[cfg(target_os = "windows")]
fn validate_database(path: &Path) -> Result<(), RuntimeError> {
    use rusqlite::{Connection, OpenFlags};

    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| RuntimeError::CorruptDatabase)?;
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| RuntimeError::CorruptDatabase)?;
    if result != "ok" {
        return Err(RuntimeError::CorruptDatabase);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub struct WindowsJobCoreBackend {
    program_data_root: PathBuf,
    child: Option<Box<dyn process_wrap::tokio::ChildWrapper>>,
    identity: Option<OwnedProcessIdentity>,
}

#[cfg(target_os = "windows")]
impl WindowsJobCoreBackend {
    #[must_use]
    pub fn new(program_data_root: PathBuf) -> Self {
        Self {
            program_data_root,
            child: None,
            identity: None,
        }
    }
}

#[cfg(target_os = "windows")]
impl CoreBackend for WindowsJobCoreBackend {
    fn start_owned(
        &mut self,
        manifest: &SupervisionManifest,
        fencing_token: u64,
    ) -> Result<OwnedProcessIdentity, RuntimeError> {
        use process_wrap::tokio::{CommandWrap, JobObject, KillOnDrop};

        if self.child.is_some() {
            return Err(RuntimeError::OwnedCore);
        }
        manifest
            .validate(&manifest.install_id)
            .map_err(|_| RuntimeError::Manifest)?;
        let executable = manifest.core_path(&self.program_data_root);
        if hash_file(&executable)? != manifest.core.sha256 {
            return Err(RuntimeError::Artifact);
        }
        let runtime_config = manifest.runtime_config_path(&self.program_data_root);
        if !runtime_config.is_file() {
            return Err(RuntimeError::Manifest);
        }
        let listener =
            std::net::TcpListener::bind((manifest.entry.host.as_str(), manifest.entry.port))
                .map_err(|_| RuntimeError::PortConflict)?;
        drop(listener);
        let mut command = CommandWrap::with_new(&executable, |command| {
            command
                .arg("-f")
                .arg(&runtime_config)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        });
        command.wrap(KillOnDrop);
        command.wrap(JobObject);
        let child = command.spawn().map_err(|_| RuntimeError::OwnedCore)?;
        let identity = OwnedProcessIdentity {
            pid: child.id().ok_or(RuntimeError::OwnedCore)?,
            creation_identity: vpn_hub_windows_security::process_creation_identity(
                child
                    .inner_child()
                    .raw_handle()
                    .ok_or(RuntimeError::OwnedCore)? as usize,
            )
            .map_err(|_| RuntimeError::OwnedCore)?,
            executable_sha256: manifest.core.sha256.clone(),
            fencing_token,
        };
        self.identity = Some(identity.clone());
        self.child = Some(child);
        Ok(identity)
    }

    fn stop_owned(
        &mut self,
        identity: &OwnedProcessIdentity,
        fencing_token: u64,
    ) -> Result<(), RuntimeError> {
        if self.identity.as_ref() != Some(identity) || identity.fencing_token != fencing_token {
            return Err(RuntimeError::OwnedCore);
        }
        let mut child = self.child.take().ok_or(RuntimeError::OwnedCore)?;
        let observed_creation = vpn_hub_windows_security::process_creation_identity(
            child
                .inner_child()
                .raw_handle()
                .ok_or(RuntimeError::OwnedCore)? as usize,
        )
        .map_err(|_| RuntimeError::OwnedCore)?;
        if child.id() != Some(identity.pid)
            || observed_creation != identity.creation_identity
            || hash_file(&self.program_data_root.join("bin/mihomo.exe"))?
                != identity.executable_sha256
        {
            self.child = Some(child);
            return Err(RuntimeError::OwnedCore);
        }
        child.start_kill().map_err(|_| RuntimeError::OwnedCore)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if child
                .try_wait()
                .map_err(|_| RuntimeError::OwnedCore)?
                .is_some()
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                self.child = Some(child);
                return Err(RuntimeError::OwnedCore);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.identity = None;
        Ok(())
    }

    fn reload_owned(
        &mut self,
        identity: &OwnedProcessIdentity,
        manifest: &SupervisionManifest,
        fencing_token: u64,
    ) -> Result<OwnedProcessIdentity, RuntimeError> {
        self.stop_owned(identity, fencing_token)?;
        self.start_owned(manifest, fencing_token)
    }

    fn owned_child_alive(
        &mut self,
        identity: &OwnedProcessIdentity,
        fencing_token: u64,
    ) -> Result<bool, RuntimeError> {
        if self.identity.as_ref() != Some(identity) || identity.fencing_token != fencing_token {
            return Err(RuntimeError::OwnedCore);
        }
        Ok(self
            .child
            .as_mut()
            .ok_or(RuntimeError::OwnedCore)?
            .try_wait()
            .map_err(|_| RuntimeError::OwnedCore)?
            .is_none())
    }

    fn network_fingerprint(&self) -> Result<[u8; 32], RuntimeError> {
        let records = vpn_hub_windows_security::network_state_records()
            .map_err(|_| RuntimeError::OwnedCore)?;
        let slices = records.iter().map(Vec::as_slice).collect::<Vec<_>>();
        Ok(SupervisorMachine::network_fingerprint(&slices))
    }
}

#[cfg(target_os = "windows")]
fn hash_file(path: &Path) -> Result<String, RuntimeError> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).map_err(|_| RuntimeError::Artifact)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|_| RuntimeError::Artifact)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CoreArtifact, EntrySummary, OutletHealthSummary, OutletKindSummary, OutletSummary,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeProvider(Arc<Mutex<SupervisionManifest>>);

    impl ManifestProvider for FakeProvider {
        fn load(&self) -> Result<SupervisionManifest, RuntimeError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Default)]
    struct FakeBackend {
        stopped: Vec<u32>,
        next_pid: u32,
        alive: bool,
        fail_start: bool,
        check_port: bool,
        fingerprint: [u8; 32],
        network_fail: bool,
        reloads: u32,
    }

    impl CoreBackend for FakeBackend {
        fn start_owned(
            &mut self,
            manifest: &SupervisionManifest,
            fencing_token: u64,
        ) -> Result<OwnedProcessIdentity, RuntimeError> {
            if self.fail_start {
                return Err(RuntimeError::OwnedCore);
            }
            if self.check_port
                && std::net::TcpListener::bind((manifest.entry.host.as_str(), manifest.entry.port))
                    .is_err()
            {
                return Err(RuntimeError::PortConflict);
            }
            self.next_pid = self.next_pid.max(40_000) + 1;
            self.alive = true;
            Ok(OwnedProcessIdentity {
                pid: self.next_pid,
                creation_identity: u64::from(self.next_pid) + 5,
                executable_sha256: manifest.core.sha256.clone(),
                fencing_token,
            })
        }

        fn stop_owned(
            &mut self,
            identity: &OwnedProcessIdentity,
            fencing_token: u64,
        ) -> Result<(), RuntimeError> {
            if identity.fencing_token != fencing_token {
                return Err(RuntimeError::OwnedCore);
            }
            self.stopped.push(identity.pid);
            self.alive = false;
            Ok(())
        }

        fn owned_child_alive(
            &mut self,
            identity: &OwnedProcessIdentity,
            fencing_token: u64,
        ) -> Result<bool, RuntimeError> {
            Ok(identity.fencing_token == fencing_token && self.alive)
        }

        fn reload_owned(
            &mut self,
            identity: &OwnedProcessIdentity,
            _manifest: &SupervisionManifest,
            fencing_token: u64,
        ) -> Result<OwnedProcessIdentity, RuntimeError> {
            if identity.fencing_token != fencing_token {
                return Err(RuntimeError::OwnedCore);
            }
            self.reloads = self.reloads.saturating_add(1);
            Ok(identity.clone())
        }

        fn network_fingerprint(&self) -> Result<[u8; 32], RuntimeError> {
            if self.network_fail {
                Err(RuntimeError::OwnedCore)
            } else {
                Ok(self.fingerprint)
            }
        }
    }

    fn manifest(generation: u64) -> SupervisionManifest {
        SupervisionManifest {
            schema_version: 1,
            install_id: "install-a".into(),
            generation,
            core: CoreArtifact {
                relative_path: "bin/mihomo.exe".into(),
                sha256: "a".repeat(64),
            },
            runtime_config_relative_path: "runtime/mihomo.yaml".into(),
            guardian_database_relative_path: "data/guardian.db".into(),
            entry: EntrySummary {
                host: "127.0.0.1".into(),
                port: 48_321,
            },
            outlets: vec![OutletSummary {
                outlet_id: "subscription-a".into(),
                kind: OutletKindSummary::Subscription,
                health: OutletHealthSummary::Healthy,
            }],
        }
    }

    fn request(command: Command) -> AuthenticatedRequest {
        AuthenticatedRequest {
            request_id: "request-a".into(),
            install_id: "install-a".into(),
            command,
        }
    }

    #[test]
    fn command_handler_only_stops_its_exact_owned_child() {
        let source = Arc::new(Mutex::new(manifest(1)));
        let provider = FakeProvider(source);
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), provider, 1_000).unwrap();
        let started = runtime.handle(&request(Command::Start), 1_001).unwrap();
        let owned_pid = started.owned_pid.unwrap();
        runtime.handle(&request(Command::Stop), 1_002).unwrap();
        assert_eq!(runtime.backend.stopped, vec![owned_pid]);
        assert!(!runtime.backend.stopped.contains(&99_999));
    }

    #[test]
    fn dynamic_generation_reload_preserves_authority_fencing() {
        let source = Arc::new(Mutex::new(manifest(1)));
        let provider = FakeProvider(Arc::clone(&source));
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), provider, 1_000).unwrap();
        runtime.handle(&request(Command::Start), 1_001).unwrap();
        let mut next = manifest(2);
        next.outlets.push(OutletSummary {
            outlet_id: "subscription-b".into(),
            kind: OutletKindSummary::Subscription,
            health: OutletHealthSummary::Unknown,
        });
        *source.lock().unwrap() = next;
        let reply = runtime.handle(&request(Command::Reload), 1_002).unwrap();
        assert_eq!(reply.generation, 2);
        assert_eq!(reply.entry_port, 48_321);
        assert_eq!(reply.outlets[0].outlet_id, "subscription-a");
        assert_eq!(reply.outlets[1].outlet_id, "subscription-b");
        let serialized = serde_json::to_string(&reply).unwrap();
        assert!(!serialized.contains("url"));
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("node"));
    }

    #[test]
    fn owned_crash_drives_bounded_backoff_and_restart() {
        let source = Arc::new(Mutex::new(manifest(1)));
        let provider = FakeProvider(source);
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), provider, 1_000).unwrap();
        let first = runtime.handle(&request(Command::Start), 1_001).unwrap();
        runtime.backend.alive = false;
        runtime.tick(1_100).unwrap();
        assert!(matches!(
            runtime.supervisor.state(),
            crate::SupervisorState::Backoff { .. }
        ));
        runtime.tick(2_100).unwrap();
        let restarted = runtime.handle(&request(Command::Status), 2_101).unwrap();
        assert_ne!(first.owned_pid, restarted.owned_pid);
    }

    #[test]
    fn repeated_restart_failures_reach_circuit_without_exiting_tick_loop() {
        let source = Arc::new(Mutex::new(manifest(1)));
        let provider = FakeProvider(source);
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), provider, 1_000).unwrap();
        runtime.handle(&request(Command::Start), 1_001).unwrap();
        runtime.backend.alive = false;
        runtime.backend.fail_start = true;
        runtime.tick(1_100).unwrap();
        for due in [2_100, 4_100, 8_100, 16_100] {
            runtime.tick(due).unwrap();
        }
        assert_eq!(runtime.supervisor.circuit(), crate::CircuitState::Open);
        assert!(matches!(
            runtime.supervisor.state(),
            crate::SupervisorState::FailClosed(FailClosedReason::OwnershipLost)
        ));
    }

    #[test]
    fn network_errors_keep_previous_state_and_real_change_recovers_once() {
        let source = Arc::new(Mutex::new(manifest(1)));
        let provider = FakeProvider(source);
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), provider, 1_000).unwrap();
        runtime.handle(&request(Command::Start), 1_001).unwrap();
        runtime.backend.network_fail = true;
        runtime.tick(1_100).unwrap();
        assert_eq!(runtime.backend.reloads, 0);
        runtime.backend.network_fail = false;
        runtime.tick(1_200).unwrap();
        assert_eq!(runtime.backend.reloads, 0);
        runtime.backend.fingerprint = [9; 32];
        runtime.tick(1_300).unwrap();
        assert_eq!(runtime.backend.reloads, 1);
        runtime.tick(1_400).unwrap();
        assert_eq!(runtime.backend.reloads, 1);
    }

    #[test]
    fn crash_and_network_change_in_one_tick_never_reload_dead_child() {
        let source = Arc::new(Mutex::new(manifest(1)));
        let provider = FakeProvider(source);
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), provider, 1_000).unwrap();
        runtime.handle(&request(Command::Start), 1_001).unwrap();
        runtime.backend.alive = false;
        runtime.backend.fingerprint = [7; 32];
        runtime.tick(1_100).unwrap();
        assert_eq!(runtime.backend.reloads, 0);
        assert!(runtime.owned.is_none());
    }

    #[test]
    fn occupied_dynamic_entry_port_returns_sanitized_fail_closed_reason() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut value = manifest(1);
        value.entry.port = port;
        let source = Arc::new(Mutex::new(value));
        let provider = FakeProvider(source);
        let backend = FakeBackend {
            check_port: true,
            ..FakeBackend::default()
        };
        let mut runtime = HelperRuntime::acquire_helper(backend, provider, 1_000).unwrap();
        let reply = runtime.handle(&request(Command::Start), 1_001).unwrap();
        assert!(!reply.ok);
        assert_eq!(reply.reason.as_deref(), Some("port-conflict"));
        assert!(reply.owned_pid.is_none());
        drop(listener);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn program_data_provider_rejects_a_corrupt_database_without_exposing_content() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("data")).unwrap();
        let database = temp.path().join("data/guardian.db");
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("CREATE TABLE health (id INTEGER PRIMARY KEY)", [])
            .unwrap();
        drop(connection);
        let manifest = manifest(1);
        let manifest_path = temp.path().join("supervision.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let provider = ProgramDataManifestProvider {
            root: temp.path().to_path_buf(),
            manifest_path: manifest_path.clone(),
            install_id: "install-a".into(),
        };
        assert!(provider.load().is_ok());
        let runtime_provider = ProgramDataManifestProvider {
            root: temp.path().to_path_buf(),
            manifest_path,
            install_id: "install-a".into(),
        };
        let mut runtime =
            HelperRuntime::acquire_helper(FakeBackend::default(), runtime_provider, 1_000).unwrap();
        runtime.handle(&request(Command::Start), 1_001).unwrap();
        runtime.handle(&request(Command::Stop), 1_002).unwrap();
        std::fs::write(&database, b"not a sqlite database").unwrap();
        assert!(matches!(
            provider.load(),
            Err(RuntimeError::CorruptDatabase)
        ));
        let reply = runtime.handle(&request(Command::Start), 1_003).unwrap();
        assert!(!reply.ok);
        assert_eq!(reply.reason.as_deref(), Some("corrupt-database"));
        assert!(reply.owned_pid.is_none());
    }
}
