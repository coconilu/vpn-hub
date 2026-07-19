use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use vpn_hub_core::{
    ControllerClient, EntryConfig, FAIL_CLOSED_PROXY, GuardianConfig, GuardianStore,
    MASTER_SELECTOR, OutletConfig, OutletConfigSummary, OutletKind, PrivateRoutingConfig,
    ResolvedSubscriptionUrls, RouteDecision, RouteMode, RoutingEngine, RoutingSession,
    RoutingStateError, SecretStore, SubscriptionCredentialStatus, SubscriptionSecrets,
    SystemSecretStore, UDP_SELECTOR, UdpCapabilityEvidence, UdpCapabilityMap, UdpProbeTarget,
    classify_subscription_udp, generate_controller_secret,
    generate_mihomo_config_with_udp_capabilities, generate_mihomo_startup_config,
    migrate_legacy_subscription, outlet_proxy_name, probe_authorized_socks5_udp,
    unknown_udp_evidence,
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
    port: u16,
}

impl ProbePortLease {
    fn reserve() -> Result<Self, String> {
        Self::reserve_excluding(&[])
    }

    fn reserve_excluding(excluded: &[u16]) -> Result<Self, String> {
        for _ in 0..32 {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .map_err(|_| "无法保留隔离 UDP 探测端口".to_string())?;
            let port = listener
                .local_addr()
                .map_err(|_| "无法读取隔离 UDP 探测端口".to_string())?
                .port();
            if !matches!(port, 3_666 | 6_666) && !excluded.contains(&port) {
                return Ok(Self {
                    _listener: listener,
                    port,
                });
            }
        }
        Err("无法获得安全的隔离 UDP 探测端口".into())
    }

    const fn port(&self) -> u16 {
        self.port
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
            let owns_ports = owns_loopback_listeners(pid, &[entry_port, controller_port]);
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

    #[must_use]
    pub fn port_snapshot(host: &str, port: u16) -> PortSnapshot {
        PortSnapshot {
            host: host.into(),
            port,
            reachable: is_endpoint_reachable(host, port),
            owner_pid: listening_owner_pid(port),
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
                pid: listening_owner_pid(config.entry.port),
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
        let startup_entry = ProbePortLease::reserve_excluding(&[
            private_config.entry.port,
            private_config.controller_port,
        ])?;
        let startup_entry_port = startup_entry.port();
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
            if owns_loopback_listeners(pid, &[startup_entry_port, private_config.controller_port]) {
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
        if !owns_loopback_listeners(pid, &[startup_entry_port, private_config.controller_port]) {
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
            if listening_owner_pid(private_config.entry.port) == Some(pid)
                && listening_owner_pid(private_config.controller_port) == Some(pid)
                && listening_owner_pid(startup_entry_port).is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if listening_owner_pid(private_config.entry.port) != Some(pid)
            || listening_owner_pid(private_config.controller_port) != Some(pid)
            || listening_owner_pid(startup_entry_port).is_some()
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
    let ip = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else if let Ok(ip) = host.parse() {
        ip
    } else {
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

fn owns_loopback_listeners(pid: u32, ports: &[u16]) -> bool {
    ports
        .iter()
        .all(|port| listening_owner_pid(*port) == Some(pid))
}

#[cfg(target_os = "windows")]
fn listening_owner_pid(port: u16) -> Option<u32> {
    let output = hidden_command("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .ok()?;
    let expected_address = format!("127.0.0.1:{port}");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 5
                && fields[0].eq_ignore_ascii_case("TCP")
                && fields[1] == expected_address
                && fields[3].eq_ignore_ascii_case("LISTENING"))
            .then(|| fields[4].parse::<u32>().ok())
            .flatten()
        })
}

#[cfg(not(target_os = "windows"))]
const fn listening_owner_pid(_port: u16) -> Option<u32> {
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
        HealthStatus, MASTER_SELECTOR, OutletConfig, OutletHealth, OutletKind, RoutingPolicy,
        SecretStoreError, generate_mihomo_config, outlet_proxy_name,
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

    #[tokio::test]
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
        assert_eq!(listening_owner_pid(entry_port), Some(std::process::id()));
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, entry_port)).is_ok());
        assert!(state.managed_core.lock().expect("managed core").is_none());
        drop(unknown_listener.lock().expect("unknown listener").take());
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
