use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::Write as _,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use vpn_hub_core::{
    ControllerClient, CredentialState, EntryConfig, FAIL_CLOSED_PROXY, GuardianConfig,
    GuardianStore, MASTER_SELECTOR, OutletConfig, OutletConfigSummary, OutletKind,
    PrivateRoutingConfig, ResolvedSubscriptionUrls, RouteDecision, RouteMode, RoutingEngine,
    RoutingSession, RoutingStateError, SafeSettingsView, SecretStore, SettingsDiff, SettingsDraft,
    SubscriptionCredentialStatus, SubscriptionSecrets, SystemSecretStore, UDP_SELECTOR,
    UdpCapabilityEvidence, UdpCapabilityMap, UdpProbeTarget, ValidationIssue,
    classify_subscription_udp, generate_controller_secret, generate_mihomo_config,
    generate_mihomo_config_with_udp_capabilities, generate_mihomo_startup_config,
    migrate_legacy_subscription, normalize_loopback_host, outlet_proxy_name,
    probe_authorized_socks5_udp, unknown_udp_evidence, validate_subscription_url,
};

const DEFAULT_GUARDIAN_CONFIG: &str = r#"database_path = "guardian-desktop.db"

[monitor]
interval_seconds = 180
connect_timeout_ms = 1500
request_timeout_ms = 8000
failure_threshold = 2
recovery_threshold = 3
"#;

#[derive(Debug, Clone, Serialize)]
pub struct PortSnapshot {
    pub host: String,
    pub port: u16,
    pub reachable: bool,
    pub owner_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoreStatus {
    pub state: String,
    pub managed: bool,
    pub pid: Option<u32>,
    pub started_at: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoutingStatus {
    pub mode: RouteMode,
    pub current_outlet: Option<String>,
    pub manual_outlet: Option<String>,
    pub controller_ready: bool,
    pub outlets: Vec<OutletConfigSummary>,
    pub message: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMutationAction {
    Set,
    Delete,
}

/// Deliberately does not implement `Debug` or `Serialize`: a credential only
/// exists in the inbound command and protected-store call path.
#[derive(Deserialize)]
pub struct CredentialMutation {
    pub subscription_id: String,
    pub action: CredentialMutationAction,
    pub credential: Option<String>,
}

#[derive(Deserialize)]
pub struct SettingsApplyRequest {
    pub draft: SettingsDraft,
    #[serde(default)]
    pub credential_mutations: Vec<CredentialMutation>,
    pub active_outlet_replacement: Option<String>,
    #[serde(default)]
    pub fail_closed_on_removed_active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsPreview {
    pub diff: SettingsDiff,
    pub issues: Vec<ValidationIssue>,
    pub can_apply: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsApplyResult {
    pub settings: SafeSettingsView,
    pub diff: SettingsDiff,
    pub removed_history_rows: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SettingsTransactionPhase {
    Prepared,
    BackupsReady,
    CredentialsStaged,
    PrivateCommitted,
    GuardianCommitted,
    CommitDecided,
    RolledBack,
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalSecretAction {
    Set,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalSecretOperation {
    current_ref: String,
    rollback_ref: String,
    previous_present: bool,
    backup_ready: bool,
    action: JournalSecretAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettingsTransactionJournal {
    version: u32,
    transaction_id: String,
    phase: SettingsTransactionPhase,
    file_existed: [bool; 4],
    target_retention_days: u32,
    secret_operations: Vec<JournalSecretOperation>,
}

struct PendingSecretOperation {
    journal: JournalSecretOperation,
    credential: Option<String>,
    previous: Option<String>,
}

pub struct AppState {
    workspace_root: PathBuf,
    guardian_config_path: PathBuf,
    private_config_path: PathBuf,
    runtime_directory: PathBuf,
    secret_store: Option<SystemSecretStore>,
    managed_core: Mutex<Option<ManagedCore>>,
    routing_engine: Mutex<RoutingEngine>,
    routing_transaction: RoutingTransaction,
    initialization_error: Option<String>,
    #[cfg(test)]
    entry_switch_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[derive(Default)]
struct RoutingTransaction {
    gate: tokio::sync::Mutex<()>,
}

impl RoutingTransaction {
    async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.gate.lock().await
    }
}

struct ManagedCore {
    child: Child,
    started_at: String,
    entry_host: String,
    entry_port: u16,
    controller_port: u16,
    controller_secret: String,
}

struct ProbePortLease {
    _listener: TcpListener,
    address: SocketAddr,
}

impl ProbePortLease {
    fn reserve() -> Result<Self, String> {
        Self::reserve_excluding(&[])
    }

    fn reserve_excluding(excluded: &[u16]) -> Result<Self, String> {
        Self::reserve_on(IpAddr::V4(Ipv4Addr::LOCALHOST), excluded)
    }

    fn reserve_on(ip: IpAddr, excluded: &[u16]) -> Result<Self, String> {
        if !ip.is_loopback() {
            return Err("隔离端口只允许绑定 loopback 地址".into());
        }
        for _ in 0..32 {
            let listener = TcpListener::bind(SocketAddr::new(ip, 0))
                .map_err(|_| "无法保留隔离 UDP 探测端口".to_string())?;
            let address = listener
                .local_addr()
                .map_err(|_| "无法读取隔离 UDP 探测端口".to_string())?;
            if !matches!(address.port(), 3_666 | 6_666) && !excluded.contains(&address.port()) {
                return Ok(Self {
                    _listener: listener,
                    address,
                });
            }
        }
        Err("无法获得安全的隔离 UDP 探测端口".into())
    }

    const fn port(&self) -> u16 {
        self.address.port()
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }
}

struct OwnedProbeCore {
    child: Child,
    controller: ControllerClient,
    entry_port: u16,
    _directory: tempfile::TempDir,
}

impl OwnedProbeCore {
    #[allow(clippy::too_many_arguments)]
    async fn start(
        executable: &Path,
        directory: tempfile::TempDir,
        config_path: &Path,
        entry_port: u16,
        controller_port: u16,
        secret: &str,
    ) -> Result<Self, String> {
        let validation = hidden_command(executable)
            .arg("-t")
            .arg("-d")
            .arg(directory.path())
            .arg("-f")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "无法启动固定 Mihomo 隔离配置检查".to_string())?;
        if !validation.success() {
            return Err("固定 Mihomo 拒绝隔离 UDP 配置".into());
        }
        let mut child = hidden_command(executable)
            .arg("-d")
            .arg(directory.path())
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "无法启动固定 Mihomo 隔离 UDP 进程".to_string())?;
        let Ok(controller) = ControllerClient::new(
            &format!("http://127.0.0.1:{controller_port}"),
            secret.into(),
            2_000,
        ) else {
            terminate_child(&mut child);
            return Err("无法创建隔离 UDP Controller".into());
        };
        let mut owned = Self {
            child,
            controller,
            entry_port,
            _directory: directory,
        };
        for _ in 0..100 {
            if owned
                .child
                .try_wait()
                .map_err(|_| "无法读取隔离 UDP 进程状态".to_string())?
                .is_some()
            {
                return Err("隔离 UDP 进程在就绪前退出".into());
            }
            let pid = owned.child.id();
            let owns_ports = owns_loopback_listeners(
                pid,
                &[
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), entry_port),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), controller_port),
                ],
            );
            if owns_ports && owned.controller.is_ready().await.unwrap_or(false) {
                return Ok(owned);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("隔离 UDP 进程就绪超时".into())
    }

    async fn wait_for_provider(&self, outlet: &OutletConfig, probe_targets: &[String]) -> bool {
        let Some(target) = probe_targets.first() else {
            return false;
        };
        let group = outlet_proxy_name(&outlet.id);
        let provider = format!("vpn-hub-provider-{}", outlet.id);
        let _ = self.controller.update_proxy_provider(&provider).await;
        for _ in 0..40 {
            if self
                .controller
                .select(MASTER_SELECTOR, &group)
                .await
                .is_ok()
                && probe_https_through_entry(self.entry_port, target, 1_500).await
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }
}

impl Drop for OwnedProbeCore {
    fn drop(&mut self) {
        terminate_child(&mut self.child);
    }
}

impl RoutingSession for AppState {
    fn current_outlet(&self) -> Result<Option<String>, RoutingStateError> {
        self.routing_engine
            .lock()
            .map_err(|_| RoutingStateError::Unavailable)
            .map(|engine| engine.current_outlet().map(str::to_owned))
    }

    fn evaluate_route(
        &self,
        now_ms: u64,
        health: &std::collections::BTreeMap<String, vpn_hub_core::OutletHealth>,
        policy: &vpn_hub_core::RoutingPolicy,
    ) -> Result<Option<RouteDecision>, RoutingStateError> {
        self.routing_engine
            .lock()
            .map_err(|_| RoutingStateError::Unavailable)
            .map(|engine| engine.evaluate(now_ms, health, policy))
    }

    fn apply_route(&self, decision: &RouteDecision, now_ms: u64) -> Result<(), RoutingStateError> {
        self.routing_engine
            .lock()
            .map_err(|_| RoutingStateError::Unavailable)?
            .apply(decision, now_ms);
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct MihomoLock {
    version: String,
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        let workspace_root = env::var_os("VPN_HUB_WORKSPACE").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."),
            PathBuf::from,
        );
        let workspace_root = workspace_root.canonicalize().unwrap_or(workspace_root);
        let data_directory = local_data_directory(&workspace_root);
        let guardian_override = env::var_os("VPN_HUB_CONFIG").map(PathBuf::from);
        Self::new_with_data_directory(workspace_root, &data_directory, guardian_override)
    }

    fn new_with_data_directory(
        workspace_root: PathBuf,
        data_directory: &Path,
        guardian_override: Option<PathBuf>,
    ) -> Self {
        let runtime_directory = data_directory.join("runtime");
        let mut initialization_error = initialize_runtime_security(&runtime_directory).err();
        let guardian_config_path = guardian_override
            .unwrap_or_else(|| prepare_local_guardian_config(data_directory, &workspace_root));
        let private_config_path = data_directory.join("private-routing.toml");
        let secret_store = if let Ok(store) = SystemSecretStore::new() {
            if recover_settings_transaction(
                &runtime_directory,
                &private_config_path,
                &guardian_config_path,
                &store,
            )
            .is_err()
            {
                initialization_error
                    .get_or_insert_with(|| "设置事务恢复失败；开发核心保持 Fail Closed".into());
            }
            if prepare_private_config(&private_config_path, &store).is_err() {
                initialization_error.get_or_insert_with(|| {
                    "本机路由配置恢复或受保护凭据迁移失败；开发核心保持 Fail Closed".into()
                });
            }
            Some(store)
        } else {
            let backup = private_config_path.with_extension("toml.bak");
            if !private_config_path.exists()
                && !backup.exists()
                && PrivateRoutingConfig::create_default(&private_config_path).is_err()
            {
                initialization_error
                    .get_or_insert_with(|| "无法创建本机路由配置；开发核心保持 Fail Closed".into());
            }
            initialization_error.get_or_insert_with(|| {
                "Windows 受保护凭据存储不可用；开发核心保持 Fail Closed".into()
            });
            None
        };
        let _ = harden_private_config_files(&private_config_path);
        let private_config = PrivateRoutingConfig::load(&private_config_path).unwrap_or_default();
        let routing_engine = RoutingEngine::new(
            private_config.route_mode,
            private_config.manual_outlet.clone(),
        );
        Self {
            workspace_root,
            guardian_config_path,
            private_config_path,
            runtime_directory,
            secret_store,
            managed_core: Mutex::new(None),
            routing_engine: Mutex::new(routing_engine),
            routing_transaction: RoutingTransaction::default(),
            initialization_error,
            #[cfg(test)]
            entry_switch_hook: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(workspace_root: PathBuf, data_directory: &Path) -> Self {
        Self::new_with_data_directory(workspace_root, data_directory, None)
    }

    #[cfg(test)]
    pub(crate) fn private_config_path_for_test(&self) -> &Path {
        &self.private_config_path
    }

    #[cfg(test)]
    pub(crate) fn set_entry_switch_hook_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self.entry_switch_hook.lock().expect("entry switch hook") = Some(Box::new(hook));
    }

    #[must_use]
    pub fn guardian_config_path(&self) -> PathBuf {
        self.guardian_config_path.clone()
    }

    #[must_use]
    pub fn history_export_path(&self, timestamp_ms: i64) -> PathBuf {
        self.runtime_directory
            .join(format!("history-export-{timestamp_ms}.csv"))
    }

    pub fn private_config(&self) -> Result<PrivateRoutingConfig, String> {
        PrivateRoutingConfig::load(&self.private_config_path)
            .map_err(|error| format!("无法加载本机私密路由配置：{error}"))
    }

    pub fn resolved_subscription_urls(
        &self,
        config: &PrivateRoutingConfig,
    ) -> Result<ResolvedSubscriptionUrls, String> {
        if !config
            .outlets
            .iter()
            .any(|outlet| outlet.secret_ref().is_some())
        {
            return Ok(ResolvedSubscriptionUrls::new());
        }
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        SubscriptionSecrets::new(store)
            .resolve(config)
            .map_err(|error| format!("无法解析订阅凭据：{error}"))
    }

    pub fn subscription_credential_statuses(
        &self,
    ) -> Result<Vec<SubscriptionCredentialStatus>, String> {
        let config = self.private_config()?;
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        Ok(SubscriptionSecrets::new(store).statuses(&config))
    }

    pub fn set_subscription_credential(
        &self,
        subscription_id: &str,
        credential: &str,
    ) -> Result<SubscriptionCredentialStatus, String> {
        let config = self.private_config()?;
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        SubscriptionSecrets::new(store)
            .set(&config, subscription_id, credential)
            .map_err(|error| format!("无法保存订阅凭据：{error}"))
    }

    pub fn delete_subscription_credential(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionCredentialStatus, String> {
        let config = self.private_config()?;
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        SubscriptionSecrets::new(store)
            .delete(&config, subscription_id)
            .map_err(|error| format!("无法删除订阅凭据：{error}"))
    }

    pub fn settings_view(&self) -> Result<SafeSettingsView, String> {
        let private = self.private_config()?;
        let guardian = GuardianConfig::load(&self.guardian_config_path)
            .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
        let store = GuardianStore::open(&guardian.database_path)
            .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
        let retention_days = store
            .retention_days()
            .map_err(|error| format!("无法读取历史保留策略：{error}"))?;
        let statuses = self.secret_store.as_ref().map_or_else(
            || {
                private
                    .outlets
                    .iter()
                    .filter_map(|outlet| {
                        outlet
                            .secret_ref()
                            .map(|secret_ref| SubscriptionCredentialStatus {
                                subscription_id: outlet.id.clone(),
                                secret_ref: secret_ref.into(),
                                state: CredentialState::Unavailable,
                            })
                    })
                    .collect()
            },
            |secret_store| SubscriptionSecrets::new(secret_store).statuses(&private),
        );
        Ok(SafeSettingsView::new(
            SettingsDraft::from_configs(&private, &guardian, retention_days),
            &statuses,
        ))
    }

    pub fn preview_settings(
        &self,
        draft: &SettingsDraft,
        active_outlet_replacement: Option<&str>,
        fail_closed_on_removed_active: bool,
    ) -> Result<SettingsPreview, String> {
        let current = self.private_config()?;
        let guardian = GuardianConfig::load(&self.guardian_config_path)
            .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
        let history = GuardianStore::open(&guardian.database_path)
            .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
        let retention = history
            .retention_days()
            .map_err(|error| format!("无法读取历史保留策略：{error}"))?;
        let current_draft = SettingsDraft::from_configs(&current, &guardian, retention);
        let diff = draft.diff(&current_draft);
        let mut issues = Vec::new();
        let candidate = match draft.private_candidate(&current) {
            Ok(candidate) => Some(candidate),
            Err(candidate_issues) => {
                issues.extend(candidate_issues);
                None
            }
        };
        if let Some(candidate) = candidate.as_ref() {
            if candidate.entry != current.entry
                && is_endpoint_reachable(&candidate.entry.host, candidate.entry.port)
            {
                issues.push(ValidationIssue::new(
                    "entry.port",
                    "entry_port_occupied",
                    "候选统一入口已被其他监听器占用；应用不会停止或接管该进程",
                ));
            }
            let current_active = self
                .routing_engine
                .lock()
                .map_err(|_| "路由策略状态锁已损坏".to_string())?
                .current_outlet()
                .map(str::to_owned);
            if let Some(current_active) = current_active
                && !candidate
                    .enabled_outlets()
                    .any(|outlet| outlet.id == current_active)
                && !fail_closed_on_removed_active
            {
                let replacement_valid = active_outlet_replacement.is_some_and(|replacement| {
                    candidate
                        .enabled_outlets()
                        .any(|outlet| outlet.id == replacement)
                });
                if !replacement_valid {
                    issues.push(ValidationIssue::new(
                        "active_outlet_replacement",
                        "active_outlet_replacement_required",
                        "删除或停用当前出口前，必须选择启用的替代出口或明确进入 Fail Closed",
                    ));
                }
            }
            let resolved = if let Ok(resolved) = self.resolved_subscription_urls(candidate) {
                Some(resolved)
            } else {
                issues.push(ValidationIssue::new(
                    "credentials",
                    "protected_store_unavailable",
                    "Windows 受保护凭据存储不可用，无法验证订阅设置",
                ));
                None
            };
            if let Some(resolved) = resolved
                && generate_mihomo_config(candidate, &resolved, &generate_controller_secret())
                    .is_err()
            {
                issues.push(ValidationIssue::new(
                    "routing",
                    "mihomo_candidate_invalid",
                    "候选路由无法生成安全的 Fail Closed Mihomo 配置",
                ));
            }
        }
        let managed_core_running = self
            .managed_core
            .lock()
            .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?
            .is_some();
        if managed_core_running && diff.runtime_changed {
            issues.push(ValidationIssue::new(
                "runtime",
                "managed_core_stop_required",
                "影响 Mihomo 的设置只能在停止本应用自管核心后应用；当前核心与最后有效配置保持不变",
            ));
        }
        Ok(SettingsPreview {
            can_apply: issues.is_empty() && !diff.changes.is_empty(),
            diff,
            issues,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn apply_settings(
        &self,
        request: SettingsApplyRequest,
    ) -> Result<SettingsApplyResult, String> {
        if !request.credential_mutations.is_empty()
            && self
                .managed_core
                .lock()
                .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?
                .is_some()
        {
            return Err(
                "覆盖或删除凭据前请先停止本应用自管核心；当前核心与最后有效配置保持不变".into(),
            );
        }
        let mut preview = self.preview_settings(
            &request.draft,
            request.active_outlet_replacement.as_deref(),
            request.fail_closed_on_removed_active,
        )?;
        if !request.credential_mutations.is_empty() {
            preview.diff.changes.push(vpn_hub_core::SettingsChange {
                code: "credentials_changed".into(),
                summary: "订阅凭据配置状态将更新；预览不包含凭据内容".into(),
            });
        }
        if !preview.issues.is_empty() {
            return Err(format!(
                "设置校验失败：{}",
                preview
                    .issues
                    .iter()
                    .map(|issue| issue.message.as_str())
                    .collect::<Vec<_>>()
                    .join("；")
            ));
        }
        if preview.diff.changes.is_empty() {
            return Err("设置没有可应用的变更".into());
        }
        let current = self.private_config()?;
        let candidate = request
            .draft
            .private_candidate(&current)
            .map_err(|_| "设置候选在提交前校验失败".to_string())?;
        let current_guardian = GuardianConfig::load(&self.guardian_config_path)
            .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
        let candidate_guardian = request.draft.guardian_candidate(&current_guardian);
        candidate_guardian
            .validate()
            .map_err(|error| format!("Guardian 候选校验失败：{error}"))?;
        let pending =
            self.prepare_secret_operations(&current, &candidate, request.credential_mutations)?;
        let journal =
            match self.prepare_settings_transaction(&pending, request.draft.retention_days) {
                Ok(journal) => journal,
                Err(error) => {
                    let store = self
                        .secret_store
                        .as_ref()
                        .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
                    recover_settings_transaction(
                        &self.runtime_directory,
                        &self.private_config_path,
                        &self.guardian_config_path,
                        store,
                    )?;
                    return Err(error);
                }
            };
        let transaction_result =
            self.execute_settings_transaction(journal, &pending, &candidate, &candidate_guardian);
        match transaction_result {
            Ok(removed_history_rows) => {
                self.routing_engine
                    .lock()
                    .map_err(|_| "路由策略状态锁已损坏".to_string())?
                    .set_mode(candidate.route_mode, candidate.manual_outlet.clone());
                Ok(SettingsApplyResult {
                    settings: self.settings_view()?,
                    diff: preview.diff,
                    removed_history_rows,
                })
            }
            Err(error) => {
                let committed = read_settings_journal(&self.runtime_directory)
                    .ok()
                    .is_some_and(|journal| {
                        matches!(
                            journal.phase,
                            SettingsTransactionPhase::CommitDecided
                                | SettingsTransactionPhase::Finalized
                        )
                    });
                recover_settings_transaction(
                    &self.runtime_directory,
                    &self.private_config_path,
                    &self.guardian_config_path,
                    self.secret_store
                        .as_ref()
                        .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?,
                )
                .map_err(|_| {
                    "设置提交失败且持久化恢复未完成；开发核心保持 Fail Closed".to_string()
                })?;
                if committed {
                    let applied = self.private_config()?;
                    self.routing_engine
                        .lock()
                        .map_err(|_| "路由策略状态锁已损坏".to_string())?
                        .set_mode(applied.route_mode, applied.manual_outlet.clone());
                    return Ok(SettingsApplyResult {
                        settings: self.settings_view()?,
                        diff: preview.diff,
                        removed_history_rows: 0,
                    });
                }
                Err(error)
            }
        }
    }

    fn prepare_secret_operations(
        &self,
        current: &PrivateRoutingConfig,
        candidate: &PrivateRoutingConfig,
        mutations: Vec<CredentialMutation>,
    ) -> Result<Vec<PendingSecretOperation>, String> {
        let candidate_refs = candidate
            .outlets
            .iter()
            .filter_map(|outlet| {
                outlet
                    .secret_ref()
                    .map(|secret_ref| (outlet.id.as_str(), secret_ref))
            })
            .collect::<HashMap<_, _>>();
        let mut requested = HashMap::<String, (JournalSecretAction, Option<String>)>::new();
        for mutation in mutations {
            let Some(secret_ref) = candidate_refs.get(mutation.subscription_id.as_str()) else {
                return Err("凭据变更引用了未知订阅".into());
            };
            let (action, credential) = match mutation.action {
                CredentialMutationAction::Set => {
                    let credential = mutation
                        .credential
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| "覆盖订阅凭据时必须提供新值".to_string())?;
                    validate_subscription_url(&credential)
                        .map_err(|_| "订阅凭据格式无效".to_string())?;
                    (JournalSecretAction::Set, Some(credential))
                }
                CredentialMutationAction::Delete => (JournalSecretAction::Delete, None),
            };
            if requested
                .insert((*secret_ref).to_owned(), (action, credential))
                .is_some()
            {
                return Err("同一订阅不能在一次应用中提交多个凭据动作".into());
            }
        }
        let retained_refs = candidate_refs.values().copied().collect::<HashSet<_>>();
        for outlet in &current.outlets {
            if let Some(secret_ref) = outlet.secret_ref()
                && !retained_refs.contains(secret_ref)
            {
                requested
                    .entry(secret_ref.to_owned())
                    .or_insert((JournalSecretAction::Delete, None));
            }
        }
        if requested.is_empty() {
            return Ok(Vec::new());
        }
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        let rollback_nonce = &generate_controller_secret()[..16];
        requested
            .into_iter()
            .enumerate()
            .map(|(index, (current_ref, (action, credential)))| {
                let previous = store
                    .get(&current_ref)
                    .map_err(|_| "无法为订阅凭据建立受保护回滚点".to_string())?;
                Ok(PendingSecretOperation {
                    journal: JournalSecretOperation {
                        current_ref,
                        rollback_ref: format!("rollback.settings.{rollback_nonce}.{index}"),
                        previous_present: previous.is_some(),
                        backup_ready: false,
                        action,
                    },
                    credential,
                    previous,
                })
            })
            .collect()
    }

    fn prepare_settings_transaction(
        &self,
        pending: &[PendingSecretOperation],
        target_retention_days: u32,
    ) -> Result<SettingsTransactionJournal, String> {
        fs::create_dir_all(&self.runtime_directory)
            .map_err(|_| "无法创建设置事务目录".to_string())?;
        harden_private_path(&self.runtime_directory)?;
        if settings_journal_path(&self.runtime_directory).exists() {
            return Err("存在尚未恢复的设置事务，拒绝开始新事务".into());
        }
        let transaction_id = generate_controller_secret()[..16].to_owned();
        let files =
            settings_transaction_files(&self.private_config_path, &self.guardian_config_path);
        let mut journal = SettingsTransactionJournal {
            version: 1,
            transaction_id,
            phase: SettingsTransactionPhase::Prepared,
            file_existed: std::array::from_fn(|index| files[index].exists()),
            target_retention_days,
            secret_operations: pending
                .iter()
                .map(|operation| operation.journal.clone())
                .collect(),
        };
        write_settings_journal(&self.runtime_directory, &journal)?;
        backup_settings_files(&self.runtime_directory, &journal, &files)?;
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        for (index, operation) in pending.iter().enumerate() {
            if let Some(previous) = operation.previous.as_deref() {
                store
                    .set(&operation.journal.rollback_ref, previous)
                    .map_err(|_| "无法写入受保护的凭据回滚点".to_string())?;
            }
            journal.secret_operations[index].backup_ready = true;
            write_settings_journal(&self.runtime_directory, &journal)?;
        }
        journal.phase = SettingsTransactionPhase::BackupsReady;
        write_settings_journal(&self.runtime_directory, &journal)?;
        Ok(journal)
    }

    fn execute_settings_transaction(
        &self,
        mut journal: SettingsTransactionJournal,
        pending: &[PendingSecretOperation],
        candidate: &PrivateRoutingConfig,
        candidate_guardian: &GuardianConfig,
    ) -> Result<u64, String> {
        let store = self
            .secret_store
            .as_ref()
            .ok_or_else(|| "Windows 受保护凭据存储不可用".to_string())?;
        for operation in pending {
            if operation.journal.action == JournalSecretAction::Set {
                store
                    .set(
                        &operation.journal.current_ref,
                        operation
                            .credential
                            .as_deref()
                            .ok_or_else(|| "订阅凭据动作缺少值".to_string())?,
                    )
                    .map_err(|_| "无法更新受保护订阅凭据".to_string())?;
            }
        }
        journal.phase = SettingsTransactionPhase::CredentialsStaged;
        write_settings_journal(&self.runtime_directory, &journal)?;

        let mut resolved = SubscriptionSecrets::new(store)
            .resolve(candidate)
            .map_err(|_| "无法解析候选订阅凭据".to_string())?;
        for operation in pending {
            if operation.journal.action == JournalSecretAction::Delete {
                resolved.remove(&operation.journal.current_ref);
            }
        }
        let (yaml, summary) =
            generate_mihomo_config(candidate, &resolved, &generate_controller_secret())
                .map_err(|_| "无法生成候选 Fail Closed Mihomo 配置".to_string())?;
        if summary.has_direct_fallback || yaml.lines().any(|line| line.trim() == "DIRECT") {
            return Err("候选 Mihomo 配置违反 Fail Closed 边界".into());
        }
        let validation_directory = tempfile::Builder::new()
            .prefix("settings-validation-")
            .tempdir_in(&self.runtime_directory)
            .map_err(|_| "无法创建隔离设置验证目录".to_string())?;
        harden_private_path(validation_directory.path())?;
        let candidate_path = validation_directory.path().join("mihomo.yaml");
        write_synced_file(&candidate_path, yaml.as_bytes())?;
        harden_private_path(&candidate_path)?;
        let executable = self.find_mihomo_executable()?;
        let validation = hidden_command(&executable)
            .arg("-t")
            .arg("-d")
            .arg(validation_directory.path())
            .arg("-f")
            .arg(&candidate_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "无法启动固定 Mihomo 候选检查".to_string())?;
        if !validation.success() {
            return Err("固定 Mihomo 拒绝候选配置".into());
        }

        candidate
            .save(&self.private_config_path)
            .map_err(|_| "无法原子提交私密路由配置".to_string())?;
        harden_private_config_files(&self.private_config_path)?;
        journal.phase = SettingsTransactionPhase::PrivateCommitted;
        write_settings_journal(&self.runtime_directory, &journal)?;
        candidate_guardian
            .save(&self.guardian_config_path)
            .map_err(|_| "无法原子提交 Guardian 配置".to_string())?;
        harden_private_config_files(&self.guardian_config_path)?;
        journal.phase = SettingsTransactionPhase::GuardianCommitted;
        write_settings_journal(&self.runtime_directory, &journal)?;

        // This durable decision is the cross-resource commit point. A crash
        // before it rolls back files and staged credentials; a crash after it
        // deterministically finishes deletions and retention on next startup.
        journal.phase = SettingsTransactionPhase::CommitDecided;
        write_settings_journal(&self.runtime_directory, &journal)?;
        for operation in pending {
            if operation.journal.action == JournalSecretAction::Delete {
                store
                    .delete(&operation.journal.current_ref)
                    .map_err(|_| "无法完成已提交的凭据删除".to_string())?;
            }
        }
        let mut history = GuardianStore::open(&candidate_guardian.database_path)
            .map_err(|_| "无法打开历史数据库以完成设置提交".to_string())?;
        let removed = history
            .set_retention_days(
                journal.target_retention_days,
                &chrono::Utc::now().to_rfc3339(),
            )
            .map_err(|_| "无法完成已提交的历史保留策略".to_string())?;
        journal.phase = SettingsTransactionPhase::Finalized;
        write_settings_journal(&self.runtime_directory, &journal)?;
        cleanup_settings_transaction(&self.runtime_directory, &journal, store)?;
        Ok(removed)
    }

    #[must_use]
    pub fn port_snapshot(host: &str, port: u16) -> PortSnapshot {
        PortSnapshot {
            host: host.into(),
            port,
            reachable: is_endpoint_reachable(host, port),
            owner_pid: loopback_socket_address(host, port).and_then(listening_owner_pid),
        }
    }

    pub fn routing_status(&self) -> Result<RoutingStatus, String> {
        let config = self.private_config()?;
        let resolved = self.resolved_subscription_urls(&config)?;
        let controller_ready = self.controller_client()?.is_some();
        let engine = self
            .routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())?;
        Ok(RoutingStatus {
            mode: engine.mode(),
            current_outlet: engine.current_outlet().map(str::to_owned),
            manual_outlet: engine.manual_outlet().map(str::to_owned),
            controller_ready,
            outlets: config.summary(&resolved).outlets,
            message: if controller_ready {
                "Mihomo Controller 已连接，模式会改变真实选择器".into()
            } else {
                "开发核心未运行，路由保持 Fail Closed".into()
            },
        })
    }

    fn udp_capability_map(
        &self,
        private_config: &PrivateRoutingConfig,
    ) -> Result<UdpCapabilityMap, String> {
        let guardian = GuardianConfig::load(&self.guardian_config_path)
            .map_err(|error| format!("无法加载 Guardian 开发配置：{error}"))?;
        let mut store = GuardianStore::open(&guardian.database_path)
            .map_err(|error| format!("无法打开 Guardian 数据库：{error}"))?;
        for outlet in private_config.enabled_outlets() {
            store
                .ensure_udp_capability(
                    &outlet.id,
                    &outlet.label,
                    &unknown_udp_evidence(outlet, "not_yet_validated"),
                )
                .map_err(|error| format!("无法初始化 UDP 能力状态：{error}"))?;
        }
        store
            .udp_capabilities()
            .map_err(|error| format!("无法读取 UDP 能力状态：{error}"))
            .map(|evidence| {
                evidence
                    .into_iter()
                    .map(|item| (item.outlet_id.clone(), item))
                    .collect()
            })
    }

    fn generate_runtime_config(
        &self,
        private_config: &PrivateRoutingConfig,
        controller_secret: &str,
    ) -> Result<String, String> {
        let resolved = self.resolved_subscription_urls(private_config)?;
        let udp_capabilities = self.udp_capability_map(private_config)?;
        generate_mihomo_config_with_udp_capabilities(
            private_config,
            &resolved,
            controller_secret,
            &udp_capabilities,
        )
        .map(|(yaml, _)| yaml)
        .map_err(|error| format!("无法生成 Mihomo 配置：{error}"))
    }

    fn generate_bootstrap_config(
        &self,
        private_config: &PrivateRoutingConfig,
        controller_secret: &str,
        startup_entry_port: u16,
    ) -> Result<String, String> {
        let resolved = self.resolved_subscription_urls(private_config)?;
        let udp_capabilities = self.udp_capability_map(private_config)?;
        generate_mihomo_startup_config(
            private_config,
            &resolved,
            controller_secret,
            &udp_capabilities,
            startup_entry_port,
        )
        .map(|(yaml, _)| yaml)
        .map_err(|error| format!("无法生成 Fail Closed 启动配置：{error}"))
    }

    #[allow(clippy::too_many_lines)]
    pub async fn revalidate_subscription_udp(
        &self,
        private: &PrivateRoutingConfig,
        outlet: &OutletConfig,
        targets: &[SocketAddr],
    ) -> Result<UdpCapabilityEvidence, String> {
        if !matches!(outlet.kind, OutletKind::Subscription { .. }) {
            return Ok(unknown_udp_evidence(
                outlet,
                "subscription_probe_not_applicable",
            ));
        }
        if targets.len() < 2 {
            return Ok(unknown_udp_evidence(
                outlet,
                "subscription_cross_validation_required",
            ));
        }
        if targets
            .iter()
            .any(|target| matches!(target.port(), 3_666 | 6_666))
        {
            return Ok(unknown_udp_evidence(
                outlet,
                "protected_udp_target_rejected",
            ));
        }

        fs::create_dir_all(&self.runtime_directory)
            .map_err(|_| "无法准备隔离 UDP 探测目录".to_string())?;
        harden_private_path(&self.runtime_directory)?;
        let directory = tempfile::Builder::new()
            .prefix("udp-subscription-")
            .tempdir_in(&self.runtime_directory)
            .map_err(|_| "无法创建隔离 UDP 探测目录".to_string())?;
        harden_private_path(directory.path())?;
        let entry = ProbePortLease::reserve()?;
        let controller_port = ProbePortLease::reserve_excluding(&[entry.port()])?;
        let startup_entry =
            ProbePortLease::reserve_excluding(&[entry.port(), controller_port.port()])?;
        let mut isolated = private.clone();
        isolated.entry = EntryConfig {
            host: Ipv4Addr::LOCALHOST.to_string(),
            port: entry.port(),
        };
        isolated.controller_port = controller_port.port();
        let mut probe_outlet = outlet.clone();
        if let OutletKind::Subscription {
            provider_update_seconds,
            ..
        } = &mut probe_outlet.kind
        {
            *provider_update_seconds = 60;
        }
        isolated.outlets = vec![probe_outlet.clone()];
        isolated.route_mode = RouteMode::Priority;
        isolated.manual_outlet = None;
        let resolved = self.resolved_subscription_urls(&isolated)?;
        let secret = generate_controller_secret();
        let mut candidate =
            unknown_udp_evidence(&probe_outlet, "isolated_subscription_probe_candidate");
        candidate.status = vpn_hub_core::UdpCapabilityStatus::Supported;
        let capabilities = UdpCapabilityMap::from([(outlet.id.clone(), candidate)]);
        let (bootstrap, _) = generate_mihomo_startup_config(
            &isolated,
            &resolved,
            &secret,
            &capabilities,
            startup_entry.port(),
        )
        .map_err(|error| format!("无法生成隔离 UDP 启动配置：{error}"))?;
        let bootstrap = bootstrap.replace("interval: 60", "interval: 1");
        let (full, _) = generate_mihomo_config_with_udp_capabilities(
            &isolated,
            &resolved,
            &secret,
            &capabilities,
        )
        .map_err(|error| format!("无法生成隔离 UDP 完整配置：{error}"))?;
        let full = full.replace("interval: 60", "interval: 1");
        let config_path = directory.path().join("mihomo.yaml");
        fs::write(&config_path, bootstrap).map_err(|_| "无法写入隔离 UDP 启动配置".to_string())?;
        harden_private_path(&config_path)?;
        let executable = self.find_mihomo_executable()?;
        let entry_port = entry.port();
        let controller_port_value = controller_port.port();
        let startup_entry_port = startup_entry.port();
        drop(entry);
        drop(controller_port);
        drop(startup_entry);
        let mut owned = OwnedProbeCore::start(
            &executable,
            directory,
            &config_path,
            startup_entry_port,
            controller_port_value,
            &secret,
        )
        .await?;
        let provider_ready = owned
            .wait_for_provider(&probe_outlet, &isolated.probe_targets)
            .await;
        owned
            .controller
            .select(MASTER_SELECTOR, FAIL_CLOSED_PROXY)
            .await
            .map_err(|_| "无法锁定隔离 TCP Fail Closed 选择器".to_string())?;
        owned
            .controller
            .select(UDP_SELECTOR, FAIL_CLOSED_PROXY)
            .await
            .map_err(|_| "无法锁定隔离 UDP Fail Closed 选择器".to_string())?;
        fs::write(&config_path, full).map_err(|_| "无法写入隔离 UDP 完整配置".to_string())?;
        harden_private_path(&config_path)?;
        owned
            .controller
            .reload_config(&config_path)
            .await
            .map_err(|_| "无法加载隔离 UDP 完整配置".to_string())?;
        for _ in 0..20 {
            if is_endpoint_reachable("127.0.0.1", entry_port)
                && !is_endpoint_reachable("127.0.0.1", startup_entry_port)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !is_endpoint_reachable("127.0.0.1", entry_port)
            || is_endpoint_reachable("127.0.0.1", startup_entry_port)
        {
            return Err("隔离 UDP 入口切换未完成".into());
        }
        owned.entry_port = entry_port;
        if !owned
            .controller
            .is_selected(UDP_SELECTOR, FAIL_CLOSED_PROXY)
            .await
            .map_err(|_| "无法确认隔离 UDP Fail Closed 状态".to_string())?
        {
            return Err("隔离 UDP 选择器未保持 Fail Closed".into());
        }

        if !provider_ready {
            return Ok(classify_subscription_udp(outlet, false, &[]));
        }
        owned
            .controller
            .select(UDP_SELECTOR, &outlet_proxy_name(&outlet.id))
            .await
            .map_err(|_| "无法选择隔离订阅 UDP 出口".to_string())?;
        let probes = targets
            .iter()
            .enumerate()
            .map(|(index, address)| {
                let request = format!(
                    "vpn-hub-subscription-udp-{index}-{}",
                    generate_controller_secret()
                )
                .into_bytes();
                UdpProbeTarget {
                    address: *address,
                    expected_response: request.clone(),
                    request,
                }
            })
            .collect::<Vec<_>>();
        let outcomes = tokio::task::spawn_blocking(move || {
            probe_authorized_socks5_udp(
                SocketAddr::from((Ipv4Addr::LOCALHOST, entry_port)),
                &probes,
                Duration::from_secs(2),
            )
        })
        .await
        .map_err(|_| "隔离订阅 UDP 探测任务失败".to_string())?
        .unwrap_or_default();
        Ok(classify_subscription_udp(outlet, true, &outcomes))
    }

    pub async fn lock_routing_transaction(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.routing_transaction.lock().await
    }

    pub fn set_route_mode(
        &self,
        mode: RouteMode,
        manual_outlet: Option<String>,
    ) -> Result<(), String> {
        if mode == RouteMode::Manual && manual_outlet.is_none() {
            return Err("手动模式必须选择一个出口".into());
        }
        let mut config = self.private_config()?;
        config.route_mode = mode;
        config.manual_outlet.clone_from(&manual_outlet);
        config
            .save(&self.private_config_path)
            .map_err(|error| format!("无法保存私密路由配置：{error}"))?;
        harden_private_config_files(&self.private_config_path)?;
        self.routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())?
            .set_mode(mode, manual_outlet);
        Ok(())
    }

    pub fn controller_client(&self) -> Result<Option<ControllerClient>, String> {
        let mut guard = self
            .managed_core
            .lock()
            .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
        let Some(core) = guard.as_mut() else {
            return Ok(None);
        };
        if core
            .child
            .try_wait()
            .map_err(|error| format!("无法读取 Mihomo 进程状态：{error}"))?
            .is_some()
        {
            *guard = None;
            drop(guard);
            self.reset_routing_session()?;
            return Ok(None);
        }
        ControllerClient::new(
            &format!("http://127.0.0.1:{}", core.controller_port),
            core.controller_secret.clone(),
            10_000,
        )
        .map(Some)
        .map_err(|error| format!("无法连接本机 Mihomo Controller：{error}"))
    }

    pub fn core_status(&self) -> Result<CoreStatus, String> {
        if let Some(client) = self.controller_client()? {
            drop(client);
            let guard = self
                .managed_core
                .lock()
                .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
            let core = guard
                .as_ref()
                .ok_or_else(|| "Mihomo 状态不一致".to_string())?;
            return Ok(CoreStatus {
                state: "running".into(),
                managed: true,
                pid: Some(core.child.id()),
                started_at: Some(core.started_at.clone()),
                message: format!("开发核心正在 {}:{} 运行", core.entry_host, core.entry_port),
            });
        }
        let config = self.private_config()?;
        if is_endpoint_reachable(&config.entry.host, config.entry.port) {
            return Ok(CoreStatus {
                state: "external".into(),
                managed: false,
                pid: loopback_socket_address(&config.entry.host, config.entry.port)
                    .and_then(listening_owner_pid),
                started_at: None,
                message: format!(
                    "{}:{} 已被其他进程占用，本应用不会停止它",
                    config.entry.host, config.entry.port
                ),
            });
        }
        Ok(CoreStatus {
            state: "stopped".into(),
            managed: false,
            pid: None,
            started_at: None,
            message: "开发核心已停止".into(),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub async fn start_development_core(&self) -> Result<CoreStatus, String> {
        self.ensure_runtime_ready()?;
        let private_config = self.private_config()?;
        let configured_entry_address =
            loopback_socket_address(&private_config.entry.host, private_config.entry.port)
                .ok_or_else(|| "配置入口必须是明确的 loopback socket 地址".to_string())?;
        let controller_address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            private_config.controller_port,
        );
        if is_endpoint_reachable(&private_config.entry.host, private_config.entry.port) {
            return Err(format!(
                "配置入口 {}:{} 已被占用；本应用不会接管未知进程",
                private_config.entry.host, private_config.entry.port
            ));
        }
        let already_running = {
            let guard = self
                .managed_core
                .lock()
                .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
            guard.is_some()
        };
        if already_running {
            return Err("本应用已经持有一个 Mihomo 开发进程".into());
        }

        if is_endpoint_reachable("127.0.0.1", private_config.controller_port) {
            return Err("本机 Controller 端口已被占用，拒绝接管未知进程".into());
        }
        fs::create_dir_all(&self.runtime_directory)
            .map_err(|error| format!("无法创建 Mihomo 运行目录：{error}"))?;
        harden_private_path(&self.runtime_directory)?;
        let controller_secret = generate_controller_secret();
        let startup_entry = ProbePortLease::reserve_on(
            configured_entry_address.ip(),
            &[private_config.entry.port, private_config.controller_port],
        )?;
        let startup_entry_port = startup_entry.port();
        let startup_entry_address = startup_entry.address();
        let yaml = self.generate_bootstrap_config(
            &private_config,
            &controller_secret,
            startup_entry_port,
        )?;
        let full_yaml = self.generate_runtime_config(&private_config, &controller_secret)?;
        let config_path = self.runtime_directory.join("mihomo.yaml");
        fs::write(&config_path, yaml).map_err(|_| "无法写入本机 Mihomo 运行配置".to_string())?;
        harden_private_path(&config_path)?;

        let executable = self.find_mihomo_executable()?;
        let validation = hidden_command(&executable)
            .arg("-t")
            .arg("-d")
            .arg(&self.runtime_directory)
            .arg("-f")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("无法验证 Mihomo 配置：{error}"))?;
        if !validation.success() {
            return Err(core_diagnostic(CoreDiagnostic::ValidationFailed).into());
        }

        drop(startup_entry);
        let mut child = hidden_command(&executable)
            .arg("-d")
            .arg(&self.runtime_directory)
            .arg("-f")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("无法启动 Mihomo：{error}"))?;

        let pid = child.id();
        for _ in 0..50 {
            if owns_loopback_listeners(pid, &[startup_entry_address, controller_address]) {
                break;
            }
            if child
                .try_wait()
                .map_err(|error| format!("无法读取 Mihomo 启动状态：{error}"))?
                .is_some()
            {
                return Err(core_diagnostic(CoreDiagnostic::ExitedBeforeReady).into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !owns_loopback_listeners(pid, &[startup_entry_address, controller_address]) {
            terminate_child(&mut child);
            return Err(format!(
                "Mihomo 启动超时，{}:{} 或本机 Controller 未就绪",
                private_config.entry.host, startup_entry_port
            ));
        }

        let controller = match ControllerClient::new(
            &format!("http://127.0.0.1:{}", private_config.controller_port),
            controller_secret.clone(),
            10_000,
        ) {
            Ok(controller) => controller,
            Err(error) => {
                terminate_child(&mut child);
                return Err(format!("无法连接本机 Mihomo Controller：{error}"));
            }
        };
        for selector in [MASTER_SELECTOR, UDP_SELECTOR] {
            if let Err(error) = controller.select(selector, FAIL_CLOSED_PROXY).await {
                terminate_child(&mut child);
                return Err(format!("无法锁定 {selector} Fail Closed 选择器：{error}"));
            }
        }
        if let Some(target) = private_config.probe_targets.first() {
            for outlet in private_config
                .enabled_outlets()
                .filter(|outlet| matches!(outlet.kind, OutletKind::Subscription { .. }))
            {
                let group = outlet_proxy_name(&outlet.id);
                if controller.select(MASTER_SELECTOR, &group).await.is_ok() {
                    let _ = probe_https_through_entry(startup_entry_port, target, 1_500).await;
                }
            }
            if let Err(error) = controller.select(MASTER_SELECTOR, FAIL_CLOSED_PROXY).await {
                terminate_child(&mut child);
                return Err(format!("无法恢复主 Fail Closed 选择器：{error}"));
            }
        }
        #[cfg(test)]
        if let Some(hook) = self
            .entry_switch_hook
            .lock()
            .expect("entry switch hook")
            .take()
        {
            hook();
        }
        if let Err(error) = fs::write(&config_path, full_yaml) {
            terminate_child(&mut child);
            return Err(format!("无法写入完整 Mihomo 运行配置：{error}"));
        }
        if let Err(error) = harden_private_path(&config_path) {
            terminate_child(&mut child);
            return Err(error);
        }
        if let Err(error) = controller.reload_config(&config_path).await {
            terminate_child(&mut child);
            return Err(format!("无法加载完整 Mihomo 配置：{error}"));
        }
        for _ in 0..20 {
            if listening_owner_pid(configured_entry_address) == Some(pid)
                && listening_owner_pid(controller_address) == Some(pid)
                && listening_owner_pid(startup_entry_address).is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if listening_owner_pid(configured_entry_address) != Some(pid)
            || listening_owner_pid(controller_address) != Some(pid)
            || listening_owner_pid(startup_entry_address).is_some()
        {
            terminate_child(&mut child);
            return Err("完整配置入口监听器不属于刚启动的 Mihomo；开发核心已安全停止".into());
        }
        match controller
            .is_selected(UDP_SELECTOR, FAIL_CLOSED_PROXY)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                terminate_child(&mut child);
                return Err("UDP 选择器未保持 Fail Closed；开发核心已停止".into());
            }
            Err(error) => {
                terminate_child(&mut child);
                return Err(format!("无法确认 UDP Fail Closed 初始状态：{error}"));
            }
        }
        match controller
            .is_selected(MASTER_SELECTOR, FAIL_CLOSED_PROXY)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                terminate_child(&mut child);
                return Err("主选择器未保持 Fail Closed；开发核心已停止".into());
            }
            Err(error) => {
                terminate_child(&mut child);
                return Err(format!("无法确认主选择器 Fail Closed 初始状态：{error}"));
            }
        }

        let started_at = chrono::Utc::now().to_rfc3339();
        if let Err(error) = self.reset_routing_session() {
            terminate_child(&mut child);
            return Err(error);
        }
        let mut guard = self
            .managed_core
            .lock()
            .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
        if guard.is_some() {
            terminate_child(&mut child);
            return Err("本应用已经持有一个 Mihomo 开发进程".into());
        }
        *guard = Some(ManagedCore {
            child,
            started_at: started_at.clone(),
            entry_host: private_config.entry.host.clone(),
            entry_port: private_config.entry.port,
            controller_port: private_config.controller_port,
            controller_secret,
        });
        Ok(CoreStatus {
            state: "running".into(),
            managed: true,
            pid: Some(pid),
            started_at: Some(started_at),
            message: format!(
                "开发核心已启动；{}:{} 初始为 Fail Closed，等待健康决策",
                private_config.entry.host, private_config.entry.port
            ),
        })
    }

    pub fn stop_development_core(&self) -> Result<CoreStatus, String> {
        let mut guard = self
            .managed_core
            .lock()
            .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
        let Some(mut core) = guard.take() else {
            return Err("没有由本应用启动的 Mihomo 进程；不会停止未知进程".into());
        };
        terminate_child(&mut core.child);
        self.reset_routing_session()?;
        Ok(CoreStatus {
            state: "stopped".into(),
            managed: false,
            pid: None,
            started_at: None,
            message: "开发核心已停止；未修改系统代理或第三方客户端".into(),
        })
    }

    fn find_mihomo_executable(&self) -> Result<PathBuf, String> {
        let lock_path = self.workspace_root.join("tools/mihomo.lock.json");
        let lock: MihomoLock = serde_json::from_slice(
            &fs::read(&lock_path).map_err(|error| format!("无法读取 Mihomo 锁文件：{error}"))?,
        )
        .map_err(|error| format!("无法解析 Mihomo 锁文件：{error}"))?;
        let version_path = self.workspace_root.join(".tools/mihomo").join(lock.version);
        let mut candidates = fs::read_dir(&version_path)
            .map_err(|error| format!("Mihomo 尚未下载：{error}"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("mihomo"))
                    && path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            });
        let executable = candidates
            .next()
            .ok_or_else(|| "Mihomo 可执行文件不存在，请先运行 fetch-mihomo.ps1".to_string())?;
        if candidates.next().is_some() {
            return Err("Mihomo 版本目录中存在多个可执行文件，拒绝猜测".into());
        }
        Ok(executable)
    }

    fn reset_routing_session(&self) -> Result<(), String> {
        reset_routing_engine(&self.routing_engine)
    }

    fn ensure_runtime_ready(&self) -> Result<(), String> {
        self.initialization_error
            .as_ref()
            .map_or(Ok(()), |error| Err(error.clone()))
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ManagedCore {
    fn drop(&mut self) {
        terminate_child(&mut self.child);
    }
}

fn local_data_directory(workspace_root: &Path) -> PathBuf {
    env::var_os("LOCALAPPDATA").map_or_else(
        || workspace_root.join("data/local-app"),
        |value| PathBuf::from(value).join("VPN Hub"),
    )
}

const LEGACY_RAW_LOGS: [&str; 2] = ["mihomo.log", "mihomo-desktop.log"];

fn initialize_runtime_security(runtime_directory: &Path) -> Result<(), String> {
    fs::create_dir_all(runtime_directory)
        .map_err(|_| "无法初始化 VPN Hub 私密运行目录".to_string())?;
    harden_private_path(runtime_directory)?;
    clear_legacy_raw_logs(runtime_directory)
}

fn clear_legacy_raw_logs(runtime_directory: &Path) -> Result<(), String> {
    for name in LEGACY_RAW_LOGS {
        let path = runtime_directory.join(name);
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法清理旧版 Mihomo 原始日志".into()),
        }
    }
    Ok(())
}

fn prepare_private_config<S: SecretStore + ?Sized>(path: &Path, store: &S) -> Result<(), String> {
    let backup = path.with_extension("toml.bak");
    if path.exists() || backup.exists() {
        migrate_legacy_subscription(path, store)
            .map(|_| ())
            .map_err(|_| "无法恢复本机路由配置或迁移旧凭据".to_string())
    } else {
        PrivateRoutingConfig::create_default(path).map_err(|_| "无法创建本机路由配置".to_string())
    }
}

fn settings_journal_path(runtime_directory: &Path) -> PathBuf {
    runtime_directory.join("settings-transaction.json")
}

fn settings_journal_backup_path(runtime_directory: &Path) -> PathBuf {
    runtime_directory.join("settings-transaction.json.bak")
}

fn settings_transaction_directory(runtime_directory: &Path, transaction_id: &str) -> PathBuf {
    runtime_directory.join(format!("settings-transaction-{transaction_id}"))
}

fn settings_transaction_files(private_path: &Path, guardian_path: &Path) -> [PathBuf; 4] {
    [
        private_path.to_owned(),
        private_path.with_extension("toml.bak"),
        guardian_path.to_owned(),
        guardian_path.with_extension("toml.bak"),
    ]
}

fn write_synced_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "无法创建私密事务目录".to_string())?;
    }
    let mut file = fs::File::create(path).map_err(|_| "无法写入私密事务文件".to_string())?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|_| "无法持久化私密事务文件".to_string())
}

fn write_settings_journal(
    runtime_directory: &Path,
    journal: &SettingsTransactionJournal,
) -> Result<(), String> {
    let path = settings_journal_path(runtime_directory);
    let backup = settings_journal_backup_path(runtime_directory);
    let temporary = runtime_directory.join("settings-transaction.json.tmp");
    let content = serde_json::to_vec(journal).map_err(|_| "无法序列化设置事务日志".to_string())?;
    write_synced_file(&temporary, &content)?;
    harden_private_path(&temporary)?;
    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup).map_err(|_| "无法轮换设置事务日志".to_string())?;
        }
        fs::rename(&path, &backup).map_err(|_| "无法备份设置事务日志".to_string())?;
    }
    if fs::rename(&temporary, &path).is_err() {
        if backup.exists() {
            let _ = fs::rename(&backup, &path);
        }
        let _ = fs::remove_file(&temporary);
        return Err("无法提交设置事务日志".into());
    }
    harden_private_path(&path)?;
    fs::copy(&path, &backup).map_err(|_| "无法复制设置事务日志备份".to_string())?;
    harden_private_path(&backup)
}

fn read_settings_journal(runtime_directory: &Path) -> Result<SettingsTransactionJournal, String> {
    for path in [
        settings_journal_path(runtime_directory),
        settings_journal_backup_path(runtime_directory),
    ] {
        let Ok(content) = fs::read(&path) else {
            continue;
        };
        let Ok(journal) = serde_json::from_slice::<SettingsTransactionJournal>(&content) else {
            continue;
        };
        let valid_id = journal.transaction_id.len() == 16
            && journal
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit());
        if journal.version == 1 && valid_id {
            return Ok(journal);
        }
    }
    Err("设置事务日志不存在或已损坏".into())
}

fn backup_settings_files(
    runtime_directory: &Path,
    journal: &SettingsTransactionJournal,
    files: &[PathBuf; 4],
) -> Result<(), String> {
    let directory = settings_transaction_directory(runtime_directory, &journal.transaction_id);
    fs::create_dir_all(&directory).map_err(|_| "无法创建设置事务备份目录".to_string())?;
    harden_private_path(&directory)?;
    for (index, file) in files.iter().enumerate() {
        if journal.file_existed[index] {
            let content = fs::read(file).map_err(|_| "无法读取设置事务文件快照".to_string())?;
            let snapshot = directory.join(format!("file-{index}.snapshot"));
            write_synced_file(&snapshot, &content)?;
            harden_private_path(&snapshot)?;
        }
    }
    Ok(())
}

fn restore_settings_files(
    runtime_directory: &Path,
    journal: &SettingsTransactionJournal,
    files: &[PathBuf; 4],
) -> Result<(), String> {
    let directory = settings_transaction_directory(runtime_directory, &journal.transaction_id);
    for (index, file) in files.iter().enumerate() {
        if journal.file_existed[index] {
            let snapshot = directory.join(format!("file-{index}.snapshot"));
            let content = fs::read(snapshot).map_err(|_| "设置事务文件快照不可用".to_string())?;
            write_synced_file(file, &content)?;
            harden_private_path(file)?;
        } else if file.exists() {
            fs::remove_file(file).map_err(|_| "无法移除未提交的设置文件".to_string())?;
        }
    }
    Ok(())
}

fn restore_settings_credentials<S: SecretStore + ?Sized>(
    journal: &SettingsTransactionJournal,
    store: &S,
) -> Result<(), String> {
    for operation in &journal.secret_operations {
        if !operation.backup_ready {
            continue;
        }
        if operation.previous_present {
            let previous = store
                .get(&operation.rollback_ref)
                .map_err(|_| "无法读取受保护凭据回滚点".to_string())?
                .ok_or_else(|| "受保护凭据回滚点缺失".to_string())?;
            store
                .set(&operation.current_ref, &previous)
                .map_err(|_| "无法恢复受保护订阅凭据".to_string())?;
        } else {
            store
                .delete(&operation.current_ref)
                .map_err(|_| "无法移除未提交的订阅凭据".to_string())?;
        }
    }
    Ok(())
}

fn finish_committed_settings<S: SecretStore + ?Sized>(
    runtime_directory: &Path,
    guardian_path: &Path,
    journal: &mut SettingsTransactionJournal,
    store: &S,
) -> Result<(), String> {
    for operation in &journal.secret_operations {
        if operation.action == JournalSecretAction::Delete {
            store
                .delete(&operation.current_ref)
                .map_err(|_| "无法完成已提交的凭据删除".to_string())?;
        }
    }
    let guardian = GuardianConfig::load(guardian_path)
        .map_err(|_| "无法读取已提交的 Guardian 配置".to_string())?;
    let mut history = GuardianStore::open(&guardian.database_path)
        .map_err(|_| "无法打开历史数据库以恢复设置事务".to_string())?;
    history
        .set_retention_days(
            journal.target_retention_days,
            &chrono::Utc::now().to_rfc3339(),
        )
        .map_err(|_| "无法完成已提交的历史保留策略".to_string())?;
    journal.phase = SettingsTransactionPhase::Finalized;
    write_settings_journal(runtime_directory, journal)
}

fn cleanup_settings_transaction<S: SecretStore + ?Sized>(
    runtime_directory: &Path,
    journal: &SettingsTransactionJournal,
    store: &S,
) -> Result<(), String> {
    for operation in &journal.secret_operations {
        store
            .delete(&operation.rollback_ref)
            .map_err(|_| "无法清理受保护凭据回滚点".to_string())?;
    }
    let directory = settings_transaction_directory(runtime_directory, &journal.transaction_id);
    if directory.exists() {
        fs::remove_dir_all(directory).map_err(|_| "无法清理设置事务备份目录".to_string())?;
    }
    for path in [
        settings_journal_path(runtime_directory),
        settings_journal_backup_path(runtime_directory),
        runtime_directory.join("settings-transaction.json.tmp"),
    ] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法清理设置事务日志".into()),
        }
    }
    Ok(())
}

fn recover_settings_transaction<S: SecretStore + ?Sized>(
    runtime_directory: &Path,
    private_path: &Path,
    guardian_path: &Path,
    store: &S,
) -> Result<(), String> {
    let primary = settings_journal_path(runtime_directory);
    let backup = settings_journal_backup_path(runtime_directory);
    if !primary.exists() && !backup.exists() {
        return Ok(());
    }
    let mut journal = read_settings_journal(runtime_directory)?;
    match journal.phase {
        SettingsTransactionPhase::CommitDecided => {
            finish_committed_settings(runtime_directory, guardian_path, &mut journal, store)?;
        }
        SettingsTransactionPhase::Finalized | SettingsTransactionPhase::RolledBack => {}
        SettingsTransactionPhase::Prepared => {
            journal.phase = SettingsTransactionPhase::RolledBack;
            write_settings_journal(runtime_directory, &journal)?;
        }
        SettingsTransactionPhase::BackupsReady
        | SettingsTransactionPhase::CredentialsStaged
        | SettingsTransactionPhase::PrivateCommitted
        | SettingsTransactionPhase::GuardianCommitted => {
            let files = settings_transaction_files(private_path, guardian_path);
            restore_settings_files(runtime_directory, &journal, &files)?;
            restore_settings_credentials(&journal, store)?;
            journal.phase = SettingsTransactionPhase::RolledBack;
            write_settings_journal(runtime_directory, &journal)?;
        }
    }
    cleanup_settings_transaction(runtime_directory, &journal, store)
}

fn harden_private_config_files(path: &Path) -> Result<(), String> {
    harden_private_path(path)?;
    let backup = path.with_extension("toml.bak");
    if backup.exists() {
        harden_private_path(&backup)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum CoreDiagnostic {
    ValidationFailed,
    ExitedBeforeReady,
}

const fn core_diagnostic(diagnostic: CoreDiagnostic) -> &'static str {
    match diagnostic {
        CoreDiagnostic::ValidationFailed => "Mihomo 配置验证失败（原始输出已丢弃）",
        CoreDiagnostic::ExitedBeforeReady => "Mihomo 在开发入口就绪前退出（原始输出已丢弃）",
    }
}

fn reset_routing_engine(engine: &Mutex<RoutingEngine>) -> Result<(), String> {
    engine
        .lock()
        .map_err(|_| "路由策略状态锁已损坏".to_string())?
        .restore_current(None, None);
    Ok(())
}

fn prepare_local_guardian_config(data_directory: &Path, workspace_root: &Path) -> PathBuf {
    let fallback = workspace_root.join("config/development.toml");
    if fs::create_dir_all(data_directory).is_err() {
        return fallback;
    }
    let config_path = data_directory.join("development.toml");
    if !config_path.exists() && fs::write(&config_path, DEFAULT_GUARDIAN_CONFIG).is_err() {
        return fallback;
    }
    config_path
}

fn terminate_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn is_endpoint_reachable(host: &str, port: u16) -> bool {
    let Some(ip) = normalize_loopback_host(host) else {
        return false;
    };
    let address = SocketAddr::new(ip, port);
    TcpStream::connect_timeout(&address, Duration::from_millis(180)).is_ok()
}

async fn probe_https_through_entry(entry_port: u16, target: &str, timeout_ms: u64) -> bool {
    let Ok(proxy) = reqwest::Proxy::all(format!("http://127.0.0.1:{entry_port}")) else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(Duration::from_millis(timeout_ms))
        .build()
    else {
        return false;
    };
    client
        .get(target)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

#[cfg(target_os = "windows")]
fn harden_private_path(path: &Path) -> Result<(), String> {
    let username = env::var("USERNAME").map_err(|_| "无法确定当前 Windows 用户".to_string())?;
    let mut command = hidden_command("icacls");
    command.arg(path).args(["/inheritance:r", "/grant:r"]);
    if path.is_dir() {
        command
            .arg(format!("{username}:(OI)(CI)F"))
            .arg("SYSTEM:(OI)(CI)F");
    } else {
        command.arg(format!("{username}:F")).arg("SYSTEM:F");
    }
    let output = command
        .output()
        .map_err(|error| format!("无法收敛本机私密文件权限：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err("无法收敛本机私密文件权限".into())
    }
}

#[cfg(not(target_os = "windows"))]
fn harden_private_path(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn loopback_socket_address(host: &str, port: u16) -> Option<SocketAddr> {
    normalize_loopback_host(host).map(|ip| SocketAddr::new(ip, port))
}

fn owns_loopback_listeners(pid: u32, addresses: &[SocketAddr]) -> bool {
    addresses
        .iter()
        .all(|address| listening_owner_pid(*address) == Some(pid))
}

fn netstat_listener_owner(output: &str, expected_address: SocketAddr) -> Option<u32> {
    if !expected_address.ip().is_loopback() {
        return None;
    }
    output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.len() >= 5
            && fields[0].eq_ignore_ascii_case("TCP")
            && fields[1].parse::<SocketAddr>().ok() == Some(expected_address)
            && fields[3].eq_ignore_ascii_case("LISTENING"))
        .then(|| fields[4].parse::<u32>().ok())
        .flatten()
    })
}

#[cfg(target_os = "windows")]
fn listening_owner_pid(address: SocketAddr) -> Option<u32> {
    let output = hidden_command("netstat").arg("-ano").output().ok()?;
    netstat_listener_owner(&String::from_utf8_lossy(&output.stdout), address)
}

#[cfg(not(target_os = "windows"))]
const fn listening_owner_pid(_address: SocketAddr) -> Option<u32> {
    None
}

#[cfg(target_os = "windows")]
fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    remove_proxy_environment(&mut command);
    command
}

#[cfg(not(target_os = "windows"))]
fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    remove_proxy_environment(&mut command);
    command
}

fn remove_proxy_environment(command: &mut Command) {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Arc};
    use vpn_hub_core::{
        HealthStatus, LocalProxyProtocol, MASTER_SELECTOR, MonitorConfig, OutletConfig,
        OutletHealth, OutletKind, RoutingPolicy, SecretStoreError, SettingsOutletDraft,
        generate_mihomo_config, outlet_proxy_name,
    };

    #[derive(Default)]
    struct TestSecretStore {
        values: Mutex<BTreeMap<String, String>>,
    }

    impl SecretStore for TestSecretStore {
        fn get(&self, secret_ref: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(self.values.lock().expect("values").get(secret_ref).cloned())
        }

        fn set(&self, secret_ref: &str, secret: &str) -> Result<(), SecretStoreError> {
            self.values
                .lock()
                .expect("values")
                .insert(secret_ref.into(), secret.into());
            Ok(())
        }

        fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError> {
            self.values.lock().expect("values").remove(secret_ref);
            Ok(())
        }
    }

    #[test]
    fn prepares_missing_primary_from_legacy_backup_before_default_creation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("private-routing.toml");
        let backup = path.with_extension("toml.bak");
        let credential = format!(
            "https://example.invalid/subscription/{}",
            generate_controller_secret()
        );
        fs::write(
            &backup,
            format!(
                r#"subscription_url = "{credential}"
provider_update_seconds = 180
controller_port = 39090
route_mode = "priority"
priority = ["subscription-a", "chaoshihui"]
cooldown_seconds = 60
minimum_improvement_ms = 150
probe_targets = ["https://example.com/a", "https://example.com/b"]
"#
            ),
        )
        .expect("legacy backup");
        let store = TestSecretStore::default();

        prepare_private_config(&path, &store).expect("recover before default");

        assert!(path.exists());
        for config_path in [&path, &backup] {
            let content = fs::read_to_string(config_path).expect("sanitized config");
            assert!(!content.contains(&credential));
            assert!(!content.contains("subscription_url"));
        }
        assert_eq!(store.values.lock().expect("values").len(), 1);
        assert_eq!(
            store.get("legacy.subscription-a").expect("migrated secret"),
            Some(credential)
        );
    }

    #[test]
    fn app_initialization_removes_raw_logs_and_keeps_diagnostics_sanitized() {
        let sensitive_url =
            "https://example.invalid/provider/credential-token-value/node-detail-value";
        let mut config = PrivateRoutingConfig::default();
        config.outlets.push(OutletConfig {
            id: "subscription-a".into(),
            label: "Subscription A".into(),
            enabled: true,
            kind: OutletKind::Subscription {
                secret_ref: "secret.a".into(),
                provider_update_seconds: 180,
            },
        });
        let resolved = [("secret.a".into(), sensitive_url.into())]
            .into_iter()
            .collect();
        let rejected_url = "https://user:credential-token-value@example.invalid/node-detail-value";
        let rejected = [("secret.a".into(), rejected_url.into())]
            .into_iter()
            .collect();
        let rejected_error = generate_mihomo_config(&config, &rejected, "controller-secret")
            .expect_err("userinfo must be rejected")
            .to_string();
        let ui_summary = serde_json::to_string(&config.summary(&resolved)).expect("summary");
        let diagnostics = [
            core_diagnostic(CoreDiagnostic::ValidationFailed),
            core_diagnostic(CoreDiagnostic::ExitedBeforeReady),
        ]
        .join(" ");
        for sensitive_part in [sensitive_url, "credential-token-value", "node-detail-value"] {
            assert!(!ui_summary.contains(sensitive_part));
            assert!(!diagnostics.contains(sensitive_part));
            assert!(!rejected_error.contains(sensitive_part));
        }
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let data_directory = directory.path().join("app-data");
        let runtime_directory = data_directory.join("runtime");
        fs::create_dir_all(&runtime_directory).expect("runtime directory");
        for name in LEGACY_RAW_LOGS {
            fs::write(runtime_directory.join(name), sensitive_url).expect("synthetic legacy log");
        }
        let state = AppState::new_for_test(workspace_root.clone(), &data_directory);
        state.ensure_runtime_ready().expect("safe initialization");
        assert!(state.managed_core.lock().expect("managed core").is_none());
        for name in LEGACY_RAW_LOGS {
            assert!(!runtime_directory.join(name).exists());
        }

        let blocked_data = directory.path().join("credential-token-value-private-data");
        let blocked_runtime = blocked_data.join("runtime");
        fs::create_dir_all(blocked_runtime.join(LEGACY_RAW_LOGS[0])).expect("blocking directory");
        let blocked = AppState::new_for_test(workspace_root, &blocked_data);
        let blocking_error = blocked
            .ensure_runtime_ready()
            .expect_err("raw log deletion failure must block core startup");
        assert_eq!(blocking_error, "无法清理旧版 Mihomo 原始日志");
        for sensitive_part in ["credential-token-value", sensitive_url, rejected_url] {
            assert!(!blocking_error.contains(sensitive_part));
        }
    }

    #[test]
    fn core_exit_and_restart_reset_current_route_session() {
        const OUTLET: &str = "local-a";
        let engine = Mutex::new(RoutingEngine::new(RouteMode::Priority, None));
        let health = [(
            OUTLET.to_owned(),
            OutletHealth {
                status: HealthStatus::Healthy,
                latency_ms: Some(100),
            },
        )]
        .into_iter()
        .collect();
        let policy = RoutingPolicy {
            priority: vec![OUTLET.into()],
            cooldown_ms: 60_000,
            minimum_improvement_ms: 100,
        };

        let decision = engine
            .lock()
            .expect("engine")
            .evaluate(100, &health, &policy)
            .expect("initial decision");
        engine.lock().expect("engine").apply(&decision, 100);
        reset_routing_engine(&engine).expect("unexpected exit reset");
        assert!(engine.lock().expect("engine").current_outlet().is_none());

        let restarted = engine
            .lock()
            .expect("engine")
            .evaluate(101, &health, &policy)
            .expect("new core must select through Controller again");
        engine.lock().expect("engine").apply(&restarted, 101);
        reset_routing_engine(&engine).expect("successful new core reset");
        assert!(engine.lock().expect("engine").current_outlet().is_none());
    }

    fn test_journal(
        transaction_id: &str,
        phase: SettingsTransactionPhase,
        files: &[PathBuf; 4],
        operation: JournalSecretOperation,
    ) -> SettingsTransactionJournal {
        SettingsTransactionJournal {
            version: 1,
            transaction_id: transaction_id.into(),
            phase,
            file_existed: std::array::from_fn(|index| files[index].exists()),
            target_retention_days: 45,
            secret_operations: vec![operation],
        }
    }

    #[test]
    fn every_precommit_crash_phase_restores_files_and_protected_secret() {
        let phases = [
            SettingsTransactionPhase::Prepared,
            SettingsTransactionPhase::BackupsReady,
            SettingsTransactionPhase::CredentialsStaged,
            SettingsTransactionPhase::PrivateCommitted,
            SettingsTransactionPhase::GuardianCommitted,
        ];
        for (index, phase) in phases.into_iter().enumerate() {
            let directory = tempfile::tempdir().expect("tempdir");
            let runtime = directory.path().join("runtime");
            fs::create_dir_all(&runtime).expect("runtime");
            let private = directory.path().join("private-routing.toml");
            let guardian = directory.path().join("guardian.toml");
            fs::write(&private, b"original-private").expect("private");
            fs::write(&guardian, b"original-guardian").expect("guardian");
            let files = settings_transaction_files(&private, &guardian);
            let current_ref = format!("settings.sub-{index}");
            let rollback_ref = format!("rollback.settings.abcdef1234567890.{index}");
            let store = TestSecretStore::default();
            store.set(&current_ref, "old-protected-value").expect("old");
            let mut operation = JournalSecretOperation {
                current_ref: current_ref.clone(),
                rollback_ref: rollback_ref.clone(),
                previous_present: true,
                backup_ready: phase != SettingsTransactionPhase::Prepared,
                action: JournalSecretAction::Set,
            };
            let id = format!("{:016x}", index + 1);
            let mut journal = test_journal(
                &id,
                SettingsTransactionPhase::Prepared,
                &files,
                operation.clone(),
            );
            write_settings_journal(&runtime, &journal).expect("journal");
            if phase != SettingsTransactionPhase::Prepared {
                backup_settings_files(&runtime, &journal, &files).expect("file snapshots");
                store
                    .set(&rollback_ref, "old-protected-value")
                    .expect("rollback secret");
                operation.backup_ready = true;
                journal.secret_operations[0] = operation;
                journal.phase = phase;
                write_settings_journal(&runtime, &journal).expect("phase");
                store
                    .set(&current_ref, "new-private-value")
                    .expect("staged");
                fs::write(&private, b"candidate-private").expect("candidate private");
                fs::write(&guardian, b"candidate-guardian").expect("candidate guardian");
            }

            recover_settings_transaction(&runtime, &private, &guardian, &store)
                .expect("restart recovery");

            assert_eq!(
                fs::read(&private).expect("private restored"),
                b"original-private"
            );
            assert_eq!(
                fs::read(&guardian).expect("guardian restored"),
                b"original-guardian"
            );
            assert_eq!(
                store.get(&current_ref).expect("secret"),
                Some("old-protected-value".into())
            );
            assert_eq!(store.get(&rollback_ref).expect("rollback cleanup"), None);
            assert!(!settings_journal_path(&runtime).exists());
        }
    }

    #[test]
    fn staged_new_secret_is_removed_after_restart_before_commit_decision() {
        let directory = tempfile::tempdir().expect("tempdir");
        let runtime = directory.path().join("runtime");
        fs::create_dir_all(&runtime).expect("runtime");
        let private = directory.path().join("private-routing.toml");
        let guardian = directory.path().join("guardian.toml");
        fs::write(&private, b"old").expect("private");
        fs::write(&guardian, b"old").expect("guardian");
        let files = settings_transaction_files(&private, &guardian);
        let current_ref = "settings.new-sub";
        let operation = JournalSecretOperation {
            current_ref: current_ref.into(),
            rollback_ref: "rollback.settings.abcdef1234567890.0".into(),
            previous_present: false,
            backup_ready: true,
            action: JournalSecretAction::Set,
        };
        let mut journal = test_journal(
            "abcdef1234567890",
            SettingsTransactionPhase::Prepared,
            &files,
            operation,
        );
        write_settings_journal(&runtime, &journal).expect("journal");
        backup_settings_files(&runtime, &journal, &files).expect("snapshots");
        journal.phase = SettingsTransactionPhase::CredentialsStaged;
        write_settings_journal(&runtime, &journal).expect("phase");
        let store = TestSecretStore::default();
        store.set(current_ref, "new-private-value").expect("new");

        recover_settings_transaction(&runtime, &private, &guardian, &store).expect("recovery");
        assert_eq!(store.get(current_ref).expect("secret"), None);
    }

    #[test]
    fn commit_decision_finishes_deletion_and_retention_after_restart() {
        let directory = tempfile::tempdir().expect("tempdir");
        let runtime = directory.path().join("runtime");
        fs::create_dir_all(&runtime).expect("runtime");
        let private = directory.path().join("private-routing.toml");
        let guardian_path = directory.path().join("guardian.toml");
        let database_path = directory.path().join("history.db");
        let mut original = PrivateRoutingConfig::default();
        original.outlets.push(OutletConfig {
            id: "local-old".into(),
            label: "Local old".into(),
            enabled: true,
            kind: OutletKind::LocalProxy {
                endpoint: "socks5h://127.0.0.1:45111".into(),
            },
        });
        original.save(&private).expect("private");
        let guardian = GuardianConfig {
            database_path: database_path.clone(),
            monitor: MonitorConfig {
                interval_seconds: 180,
                connect_timeout_ms: 1_500,
                request_timeout_ms: 8_000,
                failure_threshold: 2,
                recovery_threshold: 3,
            },
            outlets: Vec::new(),
        };
        guardian.save(&guardian_path).expect("guardian");
        GuardianStore::open(&database_path).expect("database");
        let files = settings_transaction_files(&private, &guardian_path);
        let store = TestSecretStore::default();
        store
            .set("settings.removed", "old-private-value")
            .expect("old");
        store
            .set("rollback.settings.abcdef1234567890.0", "old-private-value")
            .expect("rollback");
        let operation = JournalSecretOperation {
            current_ref: "settings.removed".into(),
            rollback_ref: "rollback.settings.abcdef1234567890.0".into(),
            previous_present: true,
            backup_ready: true,
            action: JournalSecretAction::Delete,
        };
        let mut journal = test_journal(
            "abcdef1234567890",
            SettingsTransactionPhase::Prepared,
            &files,
            operation,
        );
        write_settings_journal(&runtime, &journal).expect("journal");
        backup_settings_files(&runtime, &journal, &files).expect("snapshots");
        let mut candidate = original.clone();
        candidate.outlets[0].label = "Committed label".into();
        candidate.save(&private).expect("candidate");
        journal.phase = SettingsTransactionPhase::CommitDecided;
        write_settings_journal(&runtime, &journal).expect("commit decision");

        recover_settings_transaction(&runtime, &private, &guardian_path, &store)
            .expect("finish committed transaction");

        assert_eq!(store.get("settings.removed").expect("secret"), None);
        assert_eq!(
            PrivateRoutingConfig::load(&private)
                .expect("candidate kept")
                .outlets[0]
                .label,
            "Committed label"
        );
        assert_eq!(
            GuardianStore::open(&database_path)
                .expect("database")
                .retention_days()
                .expect("retention"),
            45
        );
        assert!(!settings_journal_path(&runtime).exists());
    }

    #[test]
    fn journal_and_safe_preview_never_serialize_credential_values() {
        let files = [
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
        ];
        let journal = test_journal(
            "abcdef1234567890",
            SettingsTransactionPhase::CredentialsStaged,
            &files,
            JournalSecretOperation {
                current_ref: "settings.sub-a".into(),
                rollback_ref: "rollback.settings.abcdef1234567890.0".into(),
                previous_present: true,
                backup_ready: true,
                action: JournalSecretAction::Set,
            },
        );
        let json = serde_json::to_string(&journal).expect("journal JSON");
        assert!(!json.contains("https://"));
        assert!(!json.contains("private-value"));
    }

    #[test]
    fn occupied_random_entry_is_rejected_without_stopping_unknown_listener() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_test(workspace_root, directory.path());
        let lease = ProbePortLease::reserve().expect("owned random listener");
        assert!(!matches!(lease.port(), 3_666 | 6_666));
        let mut config = state.private_config().expect("private");
        config.outlets = vec![OutletConfig {
            id: "local-a".into(),
            label: "Local A".into(),
            enabled: true,
            kind: OutletKind::LocalProxy {
                endpoint: "socks5h://127.0.0.1:45112".into(),
            },
        }];
        config.save(&state.private_config_path).expect("config");
        let mut draft = state.settings_view().expect("settings").draft;
        draft.entry.port = lease.port();
        draft.outlets = vec![SettingsOutletDraft::LocalProxy {
            outlet_id: "local-a".into(),
            label: "Local A".into(),
            enabled: true,
            protocol: LocalProxyProtocol::Socks5h,
            host: "127.0.0.1".into(),
            port: 45_112,
        }];
        let preview = state
            .preview_settings(&draft, None, false)
            .expect("preview");
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "entry_port_occupied")
        );
        assert!(TcpStream::connect(lease.address()).is_ok());
    }

    #[test]
    fn deleting_current_outlet_requires_replacement_or_explicit_fail_closed() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_test(workspace_root, directory.path());
        let local_a = ProbePortLease::reserve().expect("local a");
        let local_b = ProbePortLease::reserve_excluding(&[local_a.port()]).expect("local b");
        let (port_a, port_b) = (local_a.port(), local_b.port());
        assert!(!matches!(port_a, 3_666 | 6_666));
        assert!(!matches!(port_b, 3_666 | 6_666));
        drop(local_a);
        drop(local_b);
        let mut config = state.private_config().expect("private");
        config.outlets = vec![
            OutletConfig {
                id: "local-a".into(),
                label: "Local A".into(),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: format!("socks5h://127.0.0.1:{port_a}"),
                },
            },
            OutletConfig {
                id: "local-b".into(),
                label: "Local B".into(),
                enabled: true,
                kind: OutletKind::LocalProxy {
                    endpoint: format!("socks5h://127.0.0.1:{port_b}"),
                },
            },
        ];
        config.save(&state.private_config_path).expect("config");
        state.routing_engine.lock().expect("engine").apply(
            &RouteDecision {
                from_outlet: None,
                to_outlet: "local-a".into(),
                reason: "test".into(),
            },
            1,
        );
        let mut draft = state.settings_view().expect("settings").draft;
        draft.outlets.remove(0);

        let blocked = state
            .preview_settings(&draft, None, false)
            .expect("blocked preview");
        assert!(
            blocked
                .issues
                .iter()
                .any(|issue| issue.code == "active_outlet_replacement_required")
        );
        let replaced = state
            .preview_settings(&draft, Some("local-b"), false)
            .expect("replacement preview");
        assert!(
            replaced
                .issues
                .iter()
                .all(|issue| issue.code != "active_outlet_replacement_required")
        );
        let fail_closed = state
            .preview_settings(&draft, None, true)
            .expect("fail closed preview");
        assert!(
            fail_closed
                .issues
                .iter()
                .all(|issue| issue.code != "active_outlet_replacement_required")
        );
    }

    #[test]
    #[ignore = "requires repository-pinned Mihomo; validates only isolated files and random unbound loopback ports"]
    fn fixed_mihomo_validates_atomic_five_outlet_settings_apply() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_test(workspace_root, directory.path());
        let entry = ProbePortLease::reserve().expect("entry");
        let local_a = ProbePortLease::reserve_excluding(&[entry.port()]).expect("local a");
        let local_b =
            ProbePortLease::reserve_excluding(&[entry.port(), local_a.port()]).expect("local b");
        let (entry_port, first_local_port, second_local_port) =
            (entry.port(), local_a.port(), local_b.port());
        for port in [entry_port, first_local_port, second_local_port] {
            assert!(!matches!(port, 3_666 | 6_666));
        }
        drop(entry);
        drop(local_a);
        drop(local_b);
        let mut draft = state.settings_view().expect("settings").draft;
        draft.entry.port = entry_port;
        draft.outlets = vec![
            SettingsOutletDraft::Subscription {
                outlet_id: "sub-a".into(),
                label: "Subscription A".into(),
                enabled: true,
                provider_update_seconds: 180,
            },
            SettingsOutletDraft::Subscription {
                outlet_id: "sub-b".into(),
                label: "Subscription B".into(),
                enabled: true,
                provider_update_seconds: 180,
            },
            SettingsOutletDraft::Subscription {
                outlet_id: "sub-c".into(),
                label: "Subscription C".into(),
                enabled: false,
                provider_update_seconds: 180,
            },
            SettingsOutletDraft::LocalProxy {
                outlet_id: "local-a".into(),
                label: "Local A".into(),
                enabled: true,
                protocol: LocalProxyProtocol::Socks5h,
                host: "127.0.0.1".into(),
                port: first_local_port,
            },
            SettingsOutletDraft::LocalProxy {
                outlet_id: "local-b".into(),
                label: "Local B".into(),
                enabled: true,
                protocol: LocalProxyProtocol::Http,
                host: "127.0.0.2".into(),
                port: second_local_port,
            },
        ];
        let result = state
            .apply_settings(SettingsApplyRequest {
                draft,
                credential_mutations: Vec::new(),
                active_outlet_replacement: None,
                fail_closed_on_removed_active: true,
            })
            .expect("fixed Mihomo atomic apply");
        assert_eq!(result.settings.draft.outlets.len(), 5);
        assert!(!settings_journal_path(&state.runtime_directory).exists());
        let runtime_yaml = state.runtime_directory.join("mihomo.yaml");
        assert!(
            !runtime_yaml.exists(),
            "settings validation must not start or install a core"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn routing_transactions_serialize_probe_put_apply_order() {
        let transaction = Arc::new(RoutingTransaction::default());
        let events = Arc::new(tokio::sync::Mutex::new(Vec::<&'static str>::new()));
        let first_locked = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let second_attempted = Arc::new(tokio::sync::Notify::new());

        let first = {
            let transaction = Arc::clone(&transaction);
            let events = Arc::clone(&events);
            let first_locked = Arc::clone(&first_locked);
            let release_first = Arc::clone(&release_first);
            tokio::spawn(async move {
                let _guard = transaction.lock().await;
                events.lock().await.push("probe-1");
                first_locked.notify_one();
                release_first.notified().await;
                events.lock().await.extend(["put-1", "apply-1"]);
            })
        };
        first_locked.notified().await;
        let second = {
            let transaction = Arc::clone(&transaction);
            let events = Arc::clone(&events);
            let second_attempted = Arc::clone(&second_attempted);
            tokio::spawn(async move {
                second_attempted.notify_one();
                let _guard = transaction.lock().await;
                events.lock().await.extend(["probe-2", "put-2", "apply-2"]);
            })
        };
        second_attempted.notified().await;
        tokio::task::yield_now().await;
        assert_eq!(*events.lock().await, ["probe-1"]);
        release_first.notify_one();
        first.await.expect("first cycle");
        second.await.expect("second cycle");
        assert_eq!(
            *events.lock().await,
            ["probe-1", "put-1", "apply-1", "probe-2", "put-2", "apply-2"]
        );
    }

    #[test]
    fn listener_ownership_rejects_reachable_unknown_pid() {
        let lease = ProbePortLease::reserve().expect("random loopback lease");
        assert!(!matches!(lease.port(), 3_666 | 6_666));
        assert!(owns_loopback_listeners(
            std::process::id(),
            &[lease.address()]
        ));
        assert!(!owns_loopback_listeners(u32::MAX, &[lease.address()]));
    }

    #[test]
    fn netstat_parser_matches_non_default_ipv4_and_bracketed_ipv6_only() {
        let ipv4 = "127.0.0.2:45121".parse().expect("IPv4 socket");
        let ipv6 = "[::1]:45122".parse().expect("IPv6 socket");
        let output = "\
  TCP    127.0.0.2:45121      0.0.0.0:0      LISTENING       12001\n\
  TCP    [::1]:45122          [::]:0         LISTENING       12002\n\
  TCP    0.0.0.0:45123        0.0.0.0:0      LISTENING       12003\n\
  TCP    [::]:45124           [::]:0         LISTENING       12004\n";
        assert_eq!(netstat_listener_owner(output, ipv4), Some(12_001));
        assert_eq!(netstat_listener_owner(output, ipv6), Some(12_002));
        assert_eq!(
            netstat_listener_owner(output, "0.0.0.0:45123".parse().expect("wildcard")),
            None
        );
        assert_eq!(
            netstat_listener_owner(output, "192.0.2.1:45121".parse().expect("remote")),
            None
        );
        assert!(loopback_socket_address("127.0.0.2", 45_121).is_some());
        assert!(loopback_socket_address("::1", 45_122).is_some());
        assert_eq!(
            loopback_socket_address("localhost", 45_125),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45_125))
        );
        assert!(loopback_socket_address("0.0.0.0", 45_123).is_none());
        assert!(loopback_socket_address("example.invalid", 45_124).is_none());
    }

    #[test]
    fn localhost_normalization_wires_lease_snapshot_and_pid_ownership() {
        let normalized = loopback_socket_address("localhost", 0).expect("normalized localhost");
        assert_eq!(normalized.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let lease = ProbePortLease::reserve_on(normalized.ip(), &[]).expect("localhost lease");
        assert!(!matches!(lease.port(), 3_666 | 6_666));
        assert!(owns_loopback_listeners(
            std::process::id(),
            &[lease.address()]
        ));
        let snapshot = AppState::port_snapshot("localhost", lease.port());
        assert!(snapshot.reachable);
        assert_eq!(snapshot.owner_pid, Some(std::process::id()));
    }

    #[test]
    fn non_default_ipv4_loopback_listener_ownership_is_detected() {
        let lease = ProbePortLease::reserve_on(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), &[])
            .expect("Windows must support the IPv4 loopback block");
        assert!(!matches!(lease.port(), 3_666 | 6_666));
        for _ in 0..20 {
            if listening_owner_pid(lease.address()) == Some(std::process::id()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("non-default IPv4 loopback listener owner was not detected");
    }

    #[test]
    fn ipv6_loopback_listener_ownership_is_detected_when_available() {
        let Ok(lease) = ProbePortLease::reserve_on(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), &[])
        else {
            eprintln!("SKIP: IPv6 loopback is unavailable on this Windows host");
            return;
        };
        assert!(!matches!(lease.port(), 3_666 | 6_666));
        for _ in 0..20 {
            if listening_owner_pid(lease.address()) == Some(std::process::id()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("IPv6 loopback listener bound but its owner was not detected");
    }

    #[tokio::test]
    #[ignore = "requires repository-pinned Mihomo binary; uses only owned random loopback ports and a deterministic unknown-owner race"]
    async fn final_entry_port_race_fails_without_terminating_unknown_owner() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let data_directory = directory.path().join("entry-ownership-race");
        let state = AppState::new_for_test(workspace_root, &data_directory);
        let entry = ProbePortLease::reserve().expect("entry lease");
        let entry_port = entry.port();
        let controller =
            ProbePortLease::reserve_excluding(&[entry_port]).expect("controller lease");
        let controller_port = controller.port();
        assert!(!matches!(entry_port, 3_666 | 6_666));
        assert!(!matches!(controller_port, 3_666 | 6_666));
        drop(entry);
        drop(controller);

        let mut config = PrivateRoutingConfig::default();
        config.entry = EntryConfig {
            host: "127.0.0.1".into(),
            port: entry_port,
        };
        config.controller_port = controller_port;
        config.outlets.clear();
        config
            .save(state.private_config_path_for_test())
            .expect("save isolated random-port config");
        let unknown_listener = Arc::new(Mutex::new(None::<TcpListener>));
        let captured_listener = Arc::clone(&unknown_listener);
        state.set_entry_switch_hook_for_test(move || {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, entry_port))
                .expect("unknown owner must deterministically win final entry race");
            *captured_listener.lock().expect("captured listener") = Some(listener);
        });

        let error = state
            .start_development_core()
            .await
            .expect_err("mismatched final entry owner must fail closed");
        assert!(
            error.contains("入口监听器不属于刚启动的 Mihomo"),
            "ownership failure must be explicit and sanitized: {error}"
        );
        assert_eq!(
            listening_owner_pid(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), entry_port)),
            Some(std::process::id())
        );
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, entry_port)).is_ok());
        assert!(state.managed_core.lock().expect("managed core").is_none());
        drop(unknown_listener.lock().expect("unknown listener").take());
    }

    #[tokio::test]
    #[ignore = "requires repository-pinned Mihomo binary; uses only owned random loopback ports and no external traffic"]
    async fn localhost_entry_startup_uses_normalized_socket_ownership() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory = tempfile::tempdir().expect("tempdir");
        let data_directory = directory.path().join("localhost-entry-startup");
        let state = AppState::new_for_test(workspace_root, &data_directory);
        let entry = ProbePortLease::reserve().expect("entry lease");
        let entry_port = entry.port();
        let controller =
            ProbePortLease::reserve_excluding(&[entry_port]).expect("controller lease");
        let controller_port = controller.port();
        assert!(!matches!(entry_port, 3_666 | 6_666));
        assert!(!matches!(controller_port, 3_666 | 6_666));
        drop(entry);
        drop(controller);

        let mut config = PrivateRoutingConfig::default();
        config.entry = EntryConfig {
            host: "localhost".into(),
            port: entry_port,
        };
        config.controller_port = controller_port;
        config.outlets.clear();
        config
            .save(state.private_config_path_for_test())
            .expect("localhost must pass shared config validation");

        let running = state
            .start_development_core()
            .await
            .expect("localhost startup must use normalized ownership");
        let pid = running.pid.expect("managed PID");
        let normalized = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), entry_port);
        assert_eq!(listening_owner_pid(normalized), Some(pid));
        assert_eq!(
            AppState::port_snapshot("localhost", entry_port).owner_pid,
            Some(pid)
        );
        state
            .stop_development_core()
            .expect("owned localhost core must stop");
    }

    #[tokio::test]
    #[ignore = "requires the pinned Mihomo binary and a configured live local outlet"]
    async fn starts_and_stops_only_the_isolated_development_core() {
        let state = AppState::new();
        let config = state.private_config().expect("config");
        assert!(!is_endpoint_reachable(
            &config.entry.host,
            config.entry.port
        ));
        let running = state.start_development_core().await.expect("start core");
        assert_eq!(running.state, "running");
        assert!(is_endpoint_reachable(&config.entry.host, config.entry.port));
        let stopped = state.stop_development_core().expect("stop core");
        assert_eq!(stopped.state, "stopped");
        assert!(!is_endpoint_reachable(
            &config.entry.host,
            config.entry.port
        ));
    }

    #[tokio::test]
    #[ignore = "requires the pinned Mihomo binary, a configured live local outlet, and external HTTPS"]
    async fn controller_selects_local_outlet_for_real_https() {
        let state = AppState::new();
        let config = state.private_config().expect("config");
        let local_id = config
            .enabled_outlets()
            .find(|outlet| matches!(outlet.kind, OutletKind::LocalProxy { .. }))
            .map(|outlet| outlet.id.clone())
            .expect("configured local outlet");
        assert!(!is_endpoint_reachable(
            &config.entry.host,
            config.entry.port
        ));
        state.start_development_core().await.expect("start core");
        let controller = state
            .controller_client()
            .expect("controller state")
            .expect("controller");
        controller
            .select(MASTER_SELECTOR, &outlet_proxy_name(&local_id))
            .await
            .expect("select local outlet");
        let response = hidden_command("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "20",
                "--proxy",
                &format!("socks5h://{}:{}", config.entry.host, config.entry.port),
                "https://www.gstatic.com/generate_204",
            ])
            .status()
            .expect("curl");
        assert!(response.success());
        state.stop_development_core().expect("stop core");
    }

    #[tokio::test]
    #[ignore = "requires the pinned Mihomo binary and external HTTPS"]
    async fn initial_selector_is_fail_closed() {
        let state = AppState::new();
        let config = state.private_config().expect("config");
        assert!(!is_endpoint_reachable(
            &config.entry.host,
            config.entry.port
        ));
        state.start_development_core().await.expect("start core");
        let response = hidden_command("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--proxy",
                &format!("socks5h://{}:{}", config.entry.host, config.entry.port),
                "https://www.gstatic.com/generate_204",
            ])
            .status()
            .expect("curl");
        assert!(!response.success());
        state.stop_development_core().expect("stop core");
    }
}
