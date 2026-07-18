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

pub struct AppState {
    workspace_root: PathBuf,
    guardian_config_path: PathBuf,
    managed_core: Mutex<Option<ManagedCore>>,
}

struct ManagedCore {
    child: Child,
    protected_owner_pid: u32,
    started_at: String,
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
        let guardian_config_path = env::var_os("VPN_HUB_CONFIG").map_or_else(
            || prepare_local_guardian_config(&workspace_root),
            PathBuf::from,
        );
        Self {
            workspace_root,
            guardian_config_path,
            managed_core: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn guardian_config_path(&self) -> PathBuf {
        self.guardian_config_path.clone()
    }

    #[must_use]
    pub fn port_snapshot(port: u16) -> PortSnapshot {
        PortSnapshot {
            port,
            reachable: is_port_reachable(port),
            owner_pid: listening_owner_pid(port),
        }
    }

    pub fn core_status(&self) -> Result<CoreStatus, String> {
        let mut guard = self
            .managed_core
            .lock()
            .map_err(|_| "Mihomo 进程状态锁已损坏".to_string())?;
        if let Some(core) = guard.as_mut() {
            if core
                .child
                .try_wait()
                .map_err(|error| format!("无法读取 Mihomo 进程状态：{error}"))?
                .is_none()
            {
                return Ok(CoreStatus {
                    state: "running".into(),
                    managed: true,
                    pid: Some(core.child.id()),
                    started_at: Some(core.started_at.clone()),
                    message: "开发核心正在 36666 运行".into(),
                });
            }
            *guard = None;
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

        let executable = self.find_mihomo_executable()?;
        let config_path = self.workspace_root.join("config/mihomo/development.yaml");
        let runtime_path = self.workspace_root.join(".tools/mihomo/runtime-desktop");
        fs::create_dir_all(&runtime_path)
            .map_err(|error| format!("无法创建 Mihomo 运行目录：{error}"))?;

        let validation = hidden_command(&executable)
            .arg("-t")
            .arg("-d")
            .arg(&runtime_path)
            .arg("-f")
            .arg(&config_path)
            .output()
            .map_err(|error| format!("无法验证 Mihomo 配置：{error}"))?;
        if !validation.status.success() {
            let stderr = String::from_utf8_lossy(&validation.stderr);
            return Err(format!("Mihomo 配置验证失败：{}", stderr.trim()));
        }

        let log_path = runtime_path.join("mihomo-desktop.log");
        let stdout = append_log(&log_path)?;
        let stderr = stdout
            .try_clone()
            .map_err(|error| format!("无法复制 Mihomo 日志句柄：{error}"))?;
        let mut child = hidden_command(&executable)
            .arg("-d")
            .arg(&runtime_path)
            .arg("-f")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| format!("无法启动 Mihomo：{error}"))?;

        for _ in 0..50 {
            if is_port_reachable(DEVELOPMENT_PORT) {
                break;
            }
            if child
                .try_wait()
                .map_err(|error| format!("无法读取 Mihomo 启动状态：{error}"))?
                .is_some()
            {
                return Err("Mihomo 在 36666 就绪前已经退出，请检查运行日志".into());
            }
            thread::sleep(Duration::from_millis(100));
        }

        if !is_port_reachable(DEVELOPMENT_PORT) {
            terminate_child(&mut child);
            return Err("Mihomo 启动超时，36666 未开始监听".into());
        }
        if listening_owner_pid(PROTECTED_PORT) != Some(protected_owner_pid) {
            terminate_child(&mut child);
            return Err("启动期间 6666 所有者发生变化；开发核心已被停止".into());
        }

        let pid = child.id();
        let started_at = chrono::Utc::now().to_rfc3339();
        *guard = Some(ManagedCore {
            child,
            protected_owner_pid,
            started_at: started_at.clone(),
        });
        Ok(CoreStatus {
            state: "running".into(),
            managed: true,
            pid: Some(pid),
            started_at: Some(started_at),
            message: "开发核心已启动；6666 所有者保持不变".into(),
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

fn append_log(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("无法打开 Mihomo 日志：{error}"))
}

fn prepare_local_guardian_config(workspace_root: &Path) -> PathBuf {
    let fallback = workspace_root.join("config/development.toml");
    let Some(local_app_data) = env::var_os("LOCALAPPDATA") else {
        return fallback;
    };
    let config_directory = PathBuf::from(local_app_data).join("VPN Hub");
    if fs::create_dir_all(&config_directory).is_err() {
        return fallback;
    }
    let config_path = config_directory.join("development.toml");
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

    #[test]
    #[ignore = "requires the pinned Mihomo binary and live local outlet on 16666"]
    fn starts_and_stops_only_the_isolated_development_core() {
        let protected_owner_before = listening_owner_pid(PROTECTED_PORT)
            .expect("protected port 6666 must already have an owner");
        assert!(!is_port_reachable(DEVELOPMENT_PORT));

        let state = AppState::new();
        let running = state.start_development_core().expect("start core");
        assert_eq!(running.state, "running");
        assert!(running.managed);
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
}
