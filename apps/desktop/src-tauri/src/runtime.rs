use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use vpn_hub_core::{
    ControllerClient, PrivateConfigSummary, PrivateRoutingConfig, RouteDecision, RouteMode,
    RoutingEngine, generate_controller_secret, generate_mihomo_config,
};

const PROTECTED_PORT: u16 = 6_666;
const DEVELOPMENT_PORT: u16 = 36_666;
const DEFAULT_GUARDIAN_CONFIG: &str = r#"database_path = "guardian-desktop.db"

[monitor]
interval_seconds = 180
connect_timeout_ms = 1500
request_timeout_ms = 8000
failure_threshold = 2
recovery_threshold = 3

[[outlets]]
id = "chaoshihui"
label = "超实惠"
proxy_url = "socks5h://127.0.0.1:16666"
probe_url = "https://www.gstatic.com/generate_204"
degraded_latency_ms = 2500
enabled = true
"#;

#[derive(Debug, Clone, Serialize)]
pub struct PortSnapshot {
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
    pub subscription_configured: bool,
    pub provider_update_seconds: u64,
    pub message: String,
}

pub struct AppState {
    workspace_root: PathBuf,
    guardian_config_path: PathBuf,
    private_config_path: PathBuf,
    runtime_directory: PathBuf,
    managed_core: Mutex<Option<ManagedCore>>,
    routing_engine: Mutex<RoutingEngine>,
    routing_transaction: RoutingTransaction,
    initialization_error: Option<String>,
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
    protected_owner_pid: u32,
    started_at: String,
    controller_port: u16,
    controller_secret: String,
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
        let initialization_error = initialize_runtime_security(&runtime_directory).err();
        let guardian_config_path = guardian_override
            .unwrap_or_else(|| prepare_local_guardian_config(data_directory, &workspace_root));
        let private_config_path = data_directory.join("private-routing.toml");
        let _ = PrivateRoutingConfig::create_default(&private_config_path);
        let _ = harden_private_path(&private_config_path);
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
            managed_core: Mutex::new(None),
            routing_engine: Mutex::new(routing_engine),
            routing_transaction: RoutingTransaction::default(),
            initialization_error,
        }
    }

    #[cfg(test)]
    fn new_for_test(workspace_root: PathBuf, data_directory: &Path) -> Self {
        Self::new_with_data_directory(workspace_root, data_directory, None)
    }

    #[must_use]
    pub fn guardian_config_path(&self) -> PathBuf {
        self.guardian_config_path.clone()
    }

    pub fn private_config(&self) -> Result<PrivateRoutingConfig, String> {
        PrivateRoutingConfig::load(&self.private_config_path)
            .map_err(|error| format!("无法加载本机私密路由配置：{error}"))
    }

    #[must_use]
    pub fn port_snapshot(port: u16) -> PortSnapshot {
        PortSnapshot {
            port,
            reachable: is_port_reachable(port),
            owner_pid: listening_owner_pid(port),
        }
    }

    pub fn routing_status(&self) -> Result<RoutingStatus, String> {
        let config = self.private_config()?;
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
            subscription_configured: config.subscription_configured(),
            provider_update_seconds: config.provider_update_seconds,
            message: if controller_ready {
                "Mihomo Controller 已连接，模式会改变真实选择器".into()
            } else {
                "开发核心未运行，路由保持 Fail Closed".into()
            },
        })
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
        harden_private_path(&self.private_config_path)?;
        self.routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())?
            .set_mode(mode, manual_outlet);
        Ok(())
    }

    pub fn save_subscription_url(&self, value: &str) -> Result<PrivateConfigSummary, String> {
        if self.controller_client()?.is_some() {
            return Err("请先停止开发核心，再更新订阅配置".into());
        }
        let mut config = self.private_config()?;
        config
            .set_subscription_url(value)
            .map_err(|error| format!("订阅配置无效：{error}"))?;
        config
            .save(&self.private_config_path)
            .map_err(|error| format!("无法保存订阅配置：{error}"))?;
        harden_private_path(&self.private_config_path)?;
        Ok(config.summary())
    }

    pub fn evaluate_route(
        &self,
        now_ms: u64,
        health: &std::collections::BTreeMap<String, vpn_hub_core::OutletHealth>,
        policy: &vpn_hub_core::RoutingPolicy,
    ) -> Result<Option<RouteDecision>, String> {
        self.routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())
            .map(|engine| engine.evaluate(now_ms, health, policy))
    }

    pub fn apply_route(&self, decision: &RouteDecision, now_ms: u64) -> Result<(), String> {
        self.routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())?
            .apply(decision, now_ms);
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
                message: "开发核心正在 36666 运行".into(),
            });
        }
        if is_port_reachable(DEVELOPMENT_PORT) {
            return Ok(CoreStatus {
                state: "external".into(),
                managed: false,
                pid: listening_owner_pid(DEVELOPMENT_PORT),
                started_at: None,
                message: "36666 已被其他进程占用，本应用不会停止它".into(),
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

    pub fn start_development_core(&self) -> Result<CoreStatus, String> {
        self.ensure_runtime_ready()?;
        let protected_owner_pid = listening_owner_pid(PROTECTED_PORT)
            .ok_or_else(|| "受保护端口 6666 当前没有监听者，拒绝启动开发核心".to_string())?;
        if is_port_reachable(DEVELOPMENT_PORT) {
            return Err("开发端口 36666 已被占用；本应用不会接管未知进程".into());
        }
        let mut guard = self
            .managed_core
            .lock()
            .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
        if guard.is_some() {
            return Err("本应用已经持有一个 Mihomo 开发进程".into());
        }

        let private_config = self.private_config()?;
        if is_port_reachable(private_config.controller_port) {
            return Err("本机 Controller 端口已被占用，拒绝接管未知进程".into());
        }
        fs::create_dir_all(&self.runtime_directory)
            .map_err(|error| format!("无法创建 Mihomo 运行目录：{error}"))?;
        harden_private_path(&self.runtime_directory)?;
        let controller_secret = generate_controller_secret();
        let (yaml, _) = generate_mihomo_config(&private_config, &controller_secret)
            .map_err(|error| format!("无法生成 Mihomo 配置：{error}"))?;
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

        for _ in 0..50 {
            if is_port_reachable(DEVELOPMENT_PORT)
                && is_port_reachable(private_config.controller_port)
            {
                break;
            }
            if child
                .try_wait()
                .map_err(|error| format!("无法读取 Mihomo 启动状态：{error}"))?
                .is_some()
            {
                return Err(core_diagnostic(CoreDiagnostic::ExitedBeforeReady).into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !is_port_reachable(DEVELOPMENT_PORT)
            || !is_port_reachable(private_config.controller_port)
        {
            terminate_child(&mut child);
            return Err("Mihomo 启动超时，36666 或本机 Controller 未就绪".into());
        }
        if listening_owner_pid(PROTECTED_PORT) != Some(protected_owner_pid) {
            terminate_child(&mut child);
            return Err("启动期间 6666 所有者发生变化；开发核心已停止".into());
        }

        let pid = child.id();
        let started_at = chrono::Utc::now().to_rfc3339();
        if let Err(error) = self.reset_routing_session() {
            terminate_child(&mut child);
            return Err(error);
        }
        *guard = Some(ManagedCore {
            child,
            protected_owner_pid,
            started_at: started_at.clone(),
            controller_port: private_config.controller_port,
            controller_secret,
        });
        Ok(CoreStatus {
            state: "running".into(),
            managed: true,
            pid: Some(pid),
            started_at: Some(started_at),
            message: "开发核心已启动；36666 初始为 Fail Closed，等待健康决策".into(),
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
        if listening_owner_pid(PROTECTED_PORT) != Some(core.protected_owner_pid) {
            return Err("开发核心停止后检测到 6666 所有者发生变化".into());
        }
        self.reset_routing_session()?;
        Ok(CoreStatus {
            state: "stopped".into(),
            managed: false,
            pid: None,
            started_at: None,
            message: "开发核心已停止；6666 所有者保持不变".into(),
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

fn is_port_reachable(port: u16) -> bool {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&address, Duration::from_millis(180)).is_ok()
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
    command
}

#[cfg(not(target_os = "windows"))]
fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    Command::new(program)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vpn_hub_core::{
        HealthStatus, LOCAL_OUTLET, LOCAL_PROXY, MASTER_SELECTOR, OutletHealth, RoutingPolicy,
    };

    #[test]
    fn app_initialization_removes_raw_logs_and_keeps_diagnostics_sanitized() {
        let sensitive_url =
            "https://example.invalid/provider/credential-token-value/node-detail-value";
        let mut config = PrivateRoutingConfig::default();
        config
            .set_subscription_url(sensitive_url)
            .expect("synthetic URL");
        let rejected_url = "https://user:credential-token-value@example.invalid/node-detail-value";
        let rejected_error = config
            .set_subscription_url(rejected_url)
            .expect_err("userinfo must be rejected")
            .to_string();
        let ui_summary = serde_json::to_string(&config.summary()).expect("summary");
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
        let engine = Mutex::new(RoutingEngine::new(RouteMode::Priority, None));
        let health = [(
            LOCAL_OUTLET.to_owned(),
            OutletHealth {
                status: HealthStatus::Healthy,
                latency_ms: Some(100),
            },
        )]
        .into_iter()
        .collect();
        let policy = RoutingPolicy {
            priority: vec![LOCAL_OUTLET.into()],
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

    #[test]
    #[ignore = "requires the pinned Mihomo binary and live local outlet on 16666"]
    fn starts_and_stops_only_the_isolated_development_core() {
        let protected_owner_before = listening_owner_pid(PROTECTED_PORT)
            .expect("protected port 6666 must already have an owner");
        assert!(!is_port_reachable(DEVELOPMENT_PORT));
        let state = AppState::new();
        let running = state.start_development_core().expect("start core");
        assert_eq!(running.state, "running");
        assert!(is_port_reachable(DEVELOPMENT_PORT));
        assert_eq!(
            listening_owner_pid(PROTECTED_PORT),
            Some(protected_owner_before)
        );
        let stopped = state.stop_development_core().expect("stop core");
        assert_eq!(stopped.state, "stopped");
        assert!(!is_port_reachable(DEVELOPMENT_PORT));
        assert_eq!(
            listening_owner_pid(PROTECTED_PORT),
            Some(protected_owner_before)
        );
    }

    #[test]
    #[ignore = "requires the pinned Mihomo binary, live local outlet on 16666, and external HTTPS"]
    fn controller_selects_local_outlet_for_real_https() {
        let protected_owner_before = listening_owner_pid(PROTECTED_PORT)
            .expect("protected port 6666 must already have an owner");
        assert!(!is_port_reachable(DEVELOPMENT_PORT));
        let state = AppState::new();
        state.start_development_core().expect("start core");
        let controller = state
            .controller_client()
            .expect("controller state")
            .expect("controller");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime
            .block_on(controller.select(MASTER_SELECTOR, LOCAL_PROXY))
            .expect("select local outlet");
        let response = hidden_command("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "20",
                "--proxy",
                "socks5h://127.0.0.1:36666",
                "https://www.gstatic.com/generate_204",
            ])
            .status()
            .expect("curl");
        assert!(response.success());
        state.stop_development_core().expect("stop core");
        assert_eq!(
            listening_owner_pid(PROTECTED_PORT),
            Some(protected_owner_before)
        );
    }

    #[test]
    #[ignore = "requires the pinned Mihomo binary and external HTTPS"]
    fn initial_selector_is_fail_closed() {
        let protected_owner_before = listening_owner_pid(PROTECTED_PORT)
            .expect("protected port 6666 must already have an owner");
        assert!(!is_port_reachable(DEVELOPMENT_PORT));
        let state = AppState::new();
        state.start_development_core().expect("start core");
        let response = hidden_command("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--proxy",
                "socks5h://127.0.0.1:36666",
                "https://www.gstatic.com/generate_204",
            ])
            .status()
            .expect("curl");
        assert!(!response.success());
        state.stop_development_core().expect("stop core");
        assert_eq!(
            listening_owner_pid(PROTECTED_PORT),
            Some(protected_owner_before)
        );
    }
}
