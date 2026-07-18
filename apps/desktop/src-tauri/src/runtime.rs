use std::{
    env,
    fs::{self, File, OpenOptions},
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
        let guardian_config_path = env::var_os("VPN_HUB_CONFIG").map_or_else(
            || prepare_local_guardian_config(&data_directory, &workspace_root),
            PathBuf::from,
        );
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
            runtime_directory: data_directory.join("runtime"),
            managed_core: Mutex::new(None),
            routing_engine: Mutex::new(routing_engine),
        }
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
        let engine = self
            .routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())?;
        let controller_ready = self.controller_client()?.is_some();
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
            .output()
            .map_err(|error| format!("无法验证 Mihomo 配置：{error}"))?;
        if !validation.status.success() {
            return Err("Mihomo 配置验证失败；详细信息仅保留在本机运行目录".into());
        }

        let log_path = self.runtime_directory.join("mihomo.log");
        let stdout = append_log(&log_path)?;
        let stderr = stdout
            .try_clone()
            .map_err(|error| format!("无法复制 Mihomo 日志句柄：{error}"))?;
        let mut child = hidden_command(&executable)
            .arg("-d")
            .arg(&self.runtime_directory)
            .arg("-f")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
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
                return Err("Mihomo 在开发入口就绪前退出".into());
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
        self.routing_engine
            .lock()
            .map_err(|_| "路由策略状态锁已损坏".to_string())?
            .restore_current(None, None);
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

fn append_log(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("无法打开 Mihomo 本机日志：{error}"))
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
    use vpn_hub_core::{LOCAL_PROXY, MASTER_SELECTOR};

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
