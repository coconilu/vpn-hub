#![cfg(windows)]
#![allow(clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde::Deserialize;
use tempfile::TempDir;
use vpn_hub_core::{
    ControllerClient, EntryConfig, FAIL_CLOSED_OUTLET, FAIL_CLOSED_PROXY, GuardianStore,
    HealthStatus, MASTER_SELECTOR, MonitorConfig, OutletConfig, OutletKind, PrivateRoutingConfig,
    ProbeOutletConfig, ProbeResult, ResolvedSubscriptionUrls, RouteMode, RoutingEngine,
    generate_controller_secret, generate_mihomo_config, outlet_proxy_name,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FORBIDDEN_PORTS: [u16; 2] = [3_666, 6_666];
const SUB_A: &str = "fixture-sub-a";
const SUB_B: &str = "fixture-sub-b";
const LOCAL: &str = "fixture-local";
const PLACEHOLDER_SUB_A: &str = "https://fixture.invalid/sub-a";
const PLACEHOLDER_SUB_B: &str = "https://fixture.invalid/sub-b";
const PLACEHOLDER_PROBE_A: &str = "https://fixture.invalid/probe-a";
const PLACEHOLDER_PROBE_B: &str = "https://fixture.invalid/probe-b";

#[derive(Debug, Deserialize)]
struct MihomoLock {
    version: String,
}

struct PortLease {
    listener: TcpListener,
    port: u16,
}

impl PortLease {
    fn reserve() -> Self {
        loop {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("dynamic loopback port reservation must succeed");
            let port = listener
                .local_addr()
                .expect("reserved listener has an address")
                .port();
            if !FORBIDDEN_PORTS.contains(&port) {
                return Self { listener, port };
            }
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn release(self) {
        drop(self.listener);
    }
}

struct FixtureServer {
    address: SocketAddr,
    response: Arc<RwLock<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    fn static_response(body: &str, content_type: &str) -> Self {
        Self::spawn(Self::response(body, content_type))
    }

    fn response(body: &str, content_type: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn target() -> Self {
        Self::spawn(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                .to_vec(),
        )
    }

    fn spawn(response: Vec<u8>) -> Self {
        let lease = PortLease::reserve();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, lease.port()));
        let listener = lease.listener;
        listener
            .set_nonblocking(true)
            .expect("fixture listener must become nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let response = Arc::new(RwLock::new(response));
        let thread_stop = Arc::clone(&stop);
        let thread_response = Arc::clone(&response);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let bytes = thread_response
                            .read()
                            .expect("fixture response lock must be readable")
                            .clone();
                        thread::spawn(move || serve_static(stream, &bytes));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            response,
            stop,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port())
    }

    fn probe_url(&self, path: &str) -> String {
        format!("http://fixture.invalid:{}{path}", self.port())
    }

    fn set_static_response(&self, body: &str, content_type: &str) {
        *self
            .response
            .write()
            .expect("fixture response lock must be writable") = Self::response(body, content_type);
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct ControlledTcpRelay {
    address: SocketAddr,
    delay_ms: Arc<AtomicU64>,
    available: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledTcpRelay {
    fn spawn(upstream_port: u16, delay_ms: u64) -> Self {
        let lease = PortLease::reserve();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, lease.port()));
        let upstream = SocketAddr::from((Ipv4Addr::LOCALHOST, upstream_port));
        let listener = lease.listener;
        listener
            .set_nonblocking(true)
            .expect("controlled relay listener must become nonblocking");
        let delay_ms = Arc::new(AtomicU64::new(delay_ms));
        let available = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_delay = Arc::clone(&delay_ms);
        let thread_available = Arc::clone(&available);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let delay = Arc::clone(&thread_delay);
                        let available = Arc::clone(&thread_available);
                        thread::spawn(move || {
                            serve_controlled_relay(stream, upstream, &delay, &available);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            delay_ms,
            available,
            stop,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn set_delay(&self, delay_ms: u64) {
        self.delay_ms.store(delay_ms, Ordering::Release);
    }

    fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::Release);
    }
}

impl Drop for ControlledTcpRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_controlled_relay(
    mut client: TcpStream,
    upstream_address: SocketAddr,
    delay_ms: &AtomicU64,
    available: &AtomicBool,
) {
    if !available.load(Ordering::Acquire) {
        return;
    }
    thread::sleep(Duration::from_millis(delay_ms.load(Ordering::Acquire)));
    if !available.load(Ordering::Acquire) {
        return;
    }
    let Ok(mut upstream) =
        TcpStream::connect_timeout(&upstream_address, Duration::from_millis(250))
    else {
        return;
    };
    let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(2)));
    let Ok(mut client_reply) = client.try_clone() else {
        return;
    };
    let Ok(mut upstream_request) = upstream.try_clone() else {
        return;
    };
    let reverse = thread::spawn(move || {
        let _ = std::io::copy(&mut upstream, &mut client_reply);
        let _ = client_reply.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut client, &mut upstream_request);
    let _ = upstream_request.shutdown(Shutdown::Write);
    let _ = reverse.join();
}

fn serve_static(mut stream: TcpStream, response: &[u8]) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut request = [0_u8; 4_096];
    let _ = stream.read(&mut request);
    let _ = stream.write_all(response);
}

struct OwnedMihomo {
    child: Option<Child>,
    owned_ports: Vec<u16>,
}

impl OwnedMihomo {
    async fn start(
        executable: &Path,
        runtime_directory: &Path,
        config_path: &Path,
        entry_port: u16,
        controller_port: u16,
        controller_secret: &str,
    ) -> Result<Self, String> {
        let validation = hidden_command(executable)
            .arg("-t")
            .arg("-d")
            .arg(runtime_directory)
            .arg("-f")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("pinned Mihomo validation must start");
        assert!(validation.success(), "isolated Mihomo config must validate");
        let child = hidden_command(executable)
            .arg("-d")
            .arg(runtime_directory)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "pinned Mihomo did not start".to_string())?;
        let mut owned = Self {
            child: Some(child),
            owned_ports: vec![entry_port, controller_port],
        };
        if let Err(error) = wait_for_owned_runtime(
            owned.child.as_mut().expect("owned child is present"),
            entry_port,
            controller_port,
            controller_secret,
        )
        .await
        {
            owned.best_effort_stop();
            return Err(error);
        }
        Ok(owned)
    }

    fn best_effort_stop(&mut self) {
        best_effort_stop_child(&mut self.child);
    }

    fn finish(&mut self) -> Result<(), String> {
        self.best_effort_stop();
        wait_for_owned_ports_to_close(&self.owned_ports)
    }
}

impl Drop for OwnedMihomo {
    fn drop(&mut self) {
        self.best_effort_stop();
    }
}

struct OwnedFixtureProxy {
    port: u16,
    controller_port: u16,
    child: Option<Child>,
}

impl OwnedFixtureProxy {
    async fn start(executable: &Path, directory: &Path, upstream_port: Option<u16>) -> Self {
        let mut last_error = "owned fixture sidecar did not start".to_string();
        for attempt in 0..3 {
            let proxy = PortLease::reserve();
            let controller = PortLease::reserve();
            let port = proxy.port();
            let controller_port = controller.port();
            let secret = generate_controller_secret();
            let attempt_directory = directory.join(format!("attempt-{attempt}"));
            let config_path = Self::prepare_config(
                executable,
                &attempt_directory,
                port,
                controller_port,
                &secret,
                upstream_port,
            );
            proxy.release();
            controller.release();
            match Self::start_prepared(
                executable,
                &attempt_directory,
                &config_path,
                port,
                controller_port,
                &secret,
            )
            .await
            {
                Ok(owned) => return owned,
                Err(error) => last_error = error,
            }
        }
        panic!("owned fixture sidecar failed bounded startup retries: {last_error}")
    }

    async fn try_start_on_port(
        executable: &Path,
        directory: &Path,
        port: u16,
    ) -> Result<Self, String> {
        let controller = PortLease::reserve();
        let controller_port = controller.port();
        let secret = generate_controller_secret();
        let config_path =
            Self::prepare_config(executable, directory, port, controller_port, &secret, None);
        controller.release();
        Self::start_prepared(
            executable,
            directory,
            &config_path,
            port,
            controller_port,
            &secret,
        )
        .await
    }

    async fn start_prepared(
        executable: &Path,
        directory: &Path,
        config_path: &Path,
        port: u16,
        controller_port: u16,
        secret: &str,
    ) -> Result<Self, String> {
        let child = Self::spawn_child(executable, directory, config_path)
            .map_err(|_| "owned fixture sidecar did not start".to_string())?;
        let mut owned = Self {
            port,
            controller_port,
            child: Some(child),
        };
        if let Err(error) = wait_for_owned_runtime(
            owned.child.as_mut().expect("owned child is present"),
            port,
            controller_port,
            secret,
        )
        .await
        {
            owned.best_effort_stop();
            return Err(error);
        }
        Ok(owned)
    }

    fn prepare_config(
        executable: &Path,
        directory: &Path,
        port: u16,
        controller_port: u16,
        secret: &str,
        upstream_port: Option<u16>,
    ) -> PathBuf {
        fs::create_dir_all(directory).expect("fixture sidecar directory must be created");
        let config_path = directory.join("mihomo.yaml");
        let routing = upstream_port.map_or_else(
            || {
                "rules:\n  - DOMAIN,fixture.invalid,DIRECT\n  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n  - MATCH,REJECT\n".to_string()
            },
            |upstream_port| {
                format!(
                    "proxies:\n  - name: controlled-gate\n    type: http\n    server: 127.0.0.1\n    port: {upstream_port}\nrules:\n  - MATCH,controlled-gate\n"
                )
            },
        );
        let config = format!(
            "mixed-port: {port}\nexternal-controller: 127.0.0.1:{controller_port}\nsecret: '{secret}'\nbind-address: 127.0.0.1\nallow-lan: false\nmode: rule\nlog-level: silent\nipv6: false\nfind-process-mode: off\nhosts:\n  fixture.invalid: 127.0.0.1\n{routing}"
        );
        fs::write(&config_path, config).expect("fixture sidecar config must be written");
        let validation = hidden_command(executable)
            .arg("-t")
            .arg("-d")
            .arg(directory)
            .arg("-f")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("fixture sidecar validation must start");
        assert!(
            validation.success(),
            "loopback-only fixture sidecar config must validate"
        );
        config_path
    }

    fn spawn_child(
        executable: &Path,
        directory: &Path,
        config_path: &Path,
    ) -> std::io::Result<Child> {
        hidden_command(executable)
            .arg("-d")
            .arg(directory)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn best_effort_stop(&mut self) {
        best_effort_stop_child(&mut self.child);
    }

    fn finish(&mut self) -> Result<(), String> {
        self.best_effort_stop();
        wait_for_owned_ports_to_close(&[self.port, self.controller_port])
    }
}

impl Drop for OwnedFixtureProxy {
    fn drop(&mut self) {
        self.best_effort_stop();
    }
}

fn hidden_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

fn best_effort_stop_child(child: &mut Option<Child>) {
    let Some(mut child) = child.take() else {
        return;
    };
    let _ = child.kill();
    for _ in 0..50 {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn wait_for_owned_ports_to_close(ports: &[u16]) -> Result<(), String> {
    for _ in 0..50 {
        if ports
            .iter()
            .all(|port| listening_owner_pid(*port).is_none())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("owned listener did not close within the bounded cleanup window".into())
}

fn listening_owner_pid(port: u16) -> Option<u32> {
    let mut command = Command::new("netstat");
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command.args(["-ano", "-p", "tcp"]).output().ok()?;
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

async fn wait_for_owned_runtime(
    child: &mut Child,
    proxy_port: u16,
    controller_port: u16,
    controller_secret: &str,
) -> Result<(), String> {
    let pid = child.id();
    let mut authenticated = false;
    let mut saw_proxy_ownership = false;
    let mut saw_controller_ownership = false;
    let controller = ControllerClient::new(
        &format!("http://127.0.0.1:{controller_port}"),
        controller_secret.to_owned(),
        250,
    )
    .map_err(|_| "owned Controller address was invalid".to_string())?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if child
            .try_wait()
            .map_err(|_| "owned child status was unreadable".to_string())?
            .is_some()
        {
            return Err("owned child exited before authenticated readiness".into());
        }
        if controller.is_ready().await.unwrap_or(false) {
            authenticated = true;
            let proxy_pid = listening_owner_pid(proxy_port);
            let controller_pid = listening_owner_pid(controller_port);
            if proxy_pid.is_some_and(|owner| owner != pid)
                || controller_pid.is_some_and(|owner| owner != pid)
            {
                return Err("listener ownership conflict detected".into());
            }
            saw_proxy_ownership = proxy_pid == Some(pid);
            saw_controller_ownership = controller_pid == Some(pid);
            if proxy_pid == Some(pid) && controller_pid == Some(pid) {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!(
        "owned runtime readiness timed out: authenticated={authenticated} proxy_owned={saw_proxy_ownership} controller_owned={saw_controller_ownership}"
    ))
}

fn pinned_mihomo(workspace: &Path) -> PathBuf {
    let lock: MihomoLock = serde_json::from_slice(
        &fs::read(workspace.join("tools/mihomo.lock.json")).expect("Mihomo lock must exist"),
    )
    .expect("Mihomo lock must be valid");
    let version_directory = workspace.join(".tools/mihomo").join(lock.version);
    let mut candidates = fs::read_dir(version_directory)
        .expect("pinned Mihomo must be fetched before the isolated acceptance run")
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
        .expect("pinned Mihomo executable must exist");
    assert!(
        candidates.next().is_none(),
        "Mihomo version must be unambiguous"
    );
    executable
}

fn subscription(id: &str, secret_ref: &str) -> OutletConfig {
    OutletConfig {
        id: id.into(),
        label: format!("Synthetic {id}"),
        enabled: true,
        kind: OutletKind::Subscription {
            secret_ref: secret_ref.into(),
            provider_update_seconds: 60,
        },
    }
}

fn local(id: &str, port: u16) -> OutletConfig {
    OutletConfig {
        id: id.into(),
        label: format!("Synthetic {id}"),
        enabled: true,
        kind: OutletKind::LocalProxy {
            endpoint: format!("socks5h://127.0.0.1:{port}"),
        },
    }
}

fn local_http(id: &str, port: u16) -> OutletConfig {
    OutletConfig {
        id: id.into(),
        label: format!("Synthetic {id}"),
        enabled: true,
        kind: OutletKind::LocalProxy {
            endpoint: format!("http://127.0.0.1:{port}"),
        },
    }
}

fn private_config(entry_port: u16, controller_port: u16, local_port: u16) -> PrivateRoutingConfig {
    let mut config = PrivateRoutingConfig::default();
    config.version = vpn_hub_core::CURRENT_CONFIG_VERSION;
    config.entry = EntryConfig {
        host: Ipv4Addr::LOCALHOST.to_string(),
        port: entry_port,
    };
    config.controller_port = controller_port;
    config.route_mode = RouteMode::Priority;
    config.manual_outlet = None;
    config.cooldown_seconds = 1;
    config.minimum_improvement_ms = 50;
    config.probe_targets = vec![PLACEHOLDER_PROBE_A.into(), PLACEHOLDER_PROBE_B.into()];
    config.outlets = vec![
        subscription(SUB_A, "fixture.subscription.a"),
        subscription(SUB_B, "fixture.subscription.b"),
        local(LOCAL, local_port),
    ];
    config
}

fn fastest_config(entry_port: u16, controller_port: u16, local_port: u16) -> PrivateRoutingConfig {
    let mut config = private_config(entry_port, controller_port, local_port);
    config.route_mode = RouteMode::Fastest;
    config.outlets[2] = local_http(LOCAL, local_port);
    config
}

fn resolved_subscriptions() -> ResolvedSubscriptionUrls {
    BTreeMap::from([
        ("fixture.subscription.a".into(), PLACEHOLDER_SUB_A.into()),
        ("fixture.subscription.b".into(), PLACEHOLDER_SUB_B.into()),
    ])
}

fn synthetic_provider(nodes: &[(&str, u16)], proxy_type: &str) -> String {
    let mut document = "proxies:\n".to_string();
    for (node_name, proxy_port) in nodes {
        let _ = write!(
            document,
            "  - name: {node_name}\n    type: {proxy_type}\n    server: 127.0.0.1\n    port: {proxy_port}\n"
        );
    }
    document
}

fn fixture_runtime_yaml(
    config: &PrivateRoutingConfig,
    provider_a: &FixtureServer,
    provider_b: &FixtureServer,
    target: &FixtureServer,
) -> String {
    let (yaml, summary) = generate_mihomo_config(
        config,
        &resolved_subscriptions(),
        &generate_controller_secret(),
    )
    .expect("production runtime config generation must succeed");
    assert_eq!(summary.enabled_outlet_count, 3);
    assert_eq!(summary.configured_subscription_count, 2);
    assert!(!summary.has_direct_fallback);
    let yaml = yaml
        .replace(PLACEHOLDER_SUB_A, &provider_a.url("/subscription-a.yaml"))
        .replace(PLACEHOLDER_SUB_B, &provider_b.url("/subscription-b.yaml"))
        .replace(PLACEHOLDER_PROBE_A, &target.probe_url("/probe-a"))
        .replace(PLACEHOLDER_PROBE_B, &target.probe_url("/probe-b"))
        .replace("interval: 60", "interval: 1");
    let yaml = format!("hosts:\n  fixture.invalid: 127.0.0.1\n{yaml}");
    for placeholder in [
        PLACEHOLDER_SUB_A,
        PLACEHOLDER_SUB_B,
        PLACEHOLDER_PROBE_A,
        PLACEHOLDER_PROBE_B,
    ] {
        assert!(!yaml.contains(placeholder));
    }
    assert!(!yaml.contains("DIRECT"));
    yaml
}

async fn wait_for_outlets(controller: &ControllerClient, entry_port: u16, target: &str) {
    let mut last_failures = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        last_failures.clear();
        for outlet_id in [SUB_A, SUB_B, LOCAL] {
            let proxy_name = outlet_proxy_name(outlet_id);
            controller
                .select(MASTER_SELECTOR, &proxy_name)
                .await
                .expect("isolated readiness selection must succeed");
            if !entry_request_succeeds_with_timeout(entry_port, target, Duration::from_millis(500))
                .await
            {
                last_failures.push(outlet_id.to_string());
            }
        }
        if last_failures.is_empty() {
            controller
                .select(MASTER_SELECTOR, FAIL_CLOSED_PROXY)
                .await
                .expect("readiness setup must restore fail-closed master");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "isolated outlet fixtures did not become ready: {}",
        last_failures.join(", ")
    );
}

async fn wait_for_outlet_selected(
    controller: &ControllerClient,
    entry_port: u16,
    outlet_id: &str,
    target: &str,
    restore_outlet: &str,
) {
    let proxy_name = outlet_proxy_name(outlet_id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        controller
            .select(MASTER_SELECTOR, &proxy_name)
            .await
            .expect("recovery readiness selection must succeed");
        if entry_request_succeeds_with_timeout(entry_port, target, Duration::from_millis(500)).await
        {
            controller
                .select(MASTER_SELECTOR, &outlet_proxy_name(restore_outlet))
                .await
                .expect("recovery readiness must restore routed master");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("isolated subscription outlet did not select its recovered fixture");
}

async fn wait_for_outlet_unavailable(
    controller: &ControllerClient,
    entry_port: u16,
    outlet_id: &str,
    target: &str,
    restore_outlet: &str,
) {
    let proxy_name = outlet_proxy_name(outlet_id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        controller
            .select(MASTER_SELECTOR, &proxy_name)
            .await
            .expect("fault readiness selection must succeed");
        if !entry_request_succeeds_with_timeout(entry_port, target, Duration::from_millis(500))
            .await
        {
            controller
                .select(MASTER_SELECTOR, &outlet_proxy_name(restore_outlet))
                .await
                .expect("fault readiness must restore routed master");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("isolated subscription outlet did not apply its disabled fixture provider");
}

fn monitor() -> MonitorConfig {
    MonitorConfig {
        interval_seconds: 1,
        connect_timeout_ms: 500,
        request_timeout_ms: 750,
        failure_threshold: 2,
        recovery_threshold: 3,
    }
}

async fn run_production_cycle(
    controller: &ControllerClient,
    config: &PrivateRoutingConfig,
    store: &mut GuardianStore,
    engine: &std::sync::Mutex<RoutingEngine>,
    now_ms: u64,
) -> String {
    vpn_hub_core::run_controller_guardian_cycle(
        controller,
        config,
        &resolved_subscriptions(),
        &monitor(),
        store,
        engine,
        now_ms,
    )
    .await
    .expect("production Guardian cycle must succeed");
    let final_outlet = engine
        .lock()
        .expect("routing state must remain readable")
        .current_outlet()
        .unwrap_or(FAIL_CLOSED_OUTLET)
        .to_owned();
    let selected = outlet_proxy_name(&final_outlet);
    assert!(
        controller
            .is_selected(MASTER_SELECTOR, &selected)
            .await
            .expect("real Controller selector state must be readable")
    );
    selected
}

async fn entry_request_succeeds(entry_port: u16, target: &str) -> bool {
    entry_request_succeeds_with_timeout(entry_port, target, Duration::from_secs(2)).await
}

async fn entry_request_succeeds_with_timeout(
    entry_port: u16,
    target: &str,
    timeout: Duration,
) -> bool {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{entry_port}"))
        .expect("isolated entry proxy URL must be valid");
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .build()
        .expect("isolated entry client must build");
    client
        .get(target)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

async fn fixture_proxy_succeeds(proxy_url: &str, target: &str) -> bool {
    let proxy = reqwest::Proxy::all(proxy_url).expect("fixture proxy URL must be valid");
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(Duration::from_secs(2))
        .build()
        .expect("fixture proxy client must build");
    client
        .get(target)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

#[test]
fn stable_outlet_ids_survive_reorder_remove_and_readd() {
    let data = TempDir::new().expect("stable-id data directory must exist");
    let entry = PortLease::reserve();
    let controller = PortLease::reserve();
    let local_proxy = PortLease::reserve();
    let config_path = data.path().join("private-routing.toml");
    let database_path = data.path().join("guardian.db");
    let initial = private_config(entry.port(), controller.port(), local_proxy.port());
    initial
        .save(&config_path)
        .expect("initial config must save");
    let mut loaded = PrivateRoutingConfig::load(&config_path).expect("initial config must load");
    let mut store = GuardianStore::open(&database_path).expect("history database must open");
    record_stable_id_history(&mut store, &loaded, 1);

    loaded.outlets.rotate_right(1);
    loaded
        .save(&config_path)
        .expect("reordered config must save");
    let mut loaded = PrivateRoutingConfig::load(&config_path).expect("reordered config must load");
    assert_eq!(
        loaded.priority(),
        vec![LOCAL.to_string(), SUB_A.to_string(), SUB_B.to_string()]
    );

    let removed = loaded
        .outlets
        .iter()
        .find(|outlet| outlet.id == SUB_A)
        .cloned()
        .expect("subscription A exists");
    loaded.outlets.retain(|outlet| outlet.id != SUB_A);
    loaded.save(&config_path).expect("reduced config must save");
    let mut loaded = PrivateRoutingConfig::load(&config_path).expect("reduced config must load");
    record_stable_id_history(&mut store, &loaded, 2);

    loaded.outlets.push(removed);
    loaded
        .save(&config_path)
        .expect("re-added config must save");
    let loaded = PrivateRoutingConfig::load(&config_path).expect("re-added config must load");
    record_stable_id_history(&mut store, &loaded, 3);

    let samples = store
        .recent_samples(32)
        .expect("stable history samples must load");
    let counts = samples.iter().fold(BTreeMap::new(), |mut counts, sample| {
        *counts.entry(sample.outlet_id.as_str()).or_insert(0_u32) += 1;
        counts
    });
    assert_eq!(counts.get(SUB_A), Some(&2));
    assert_eq!(counts.get(SUB_B), Some(&3));
    assert_eq!(counts.get(LOCAL), Some(&3));
    assert!(
        samples
            .iter()
            .all(|sample| { [SUB_A, SUB_B, LOCAL].contains(&sample.outlet_id.as_str()) })
    );
    drop(store);
    let database = fs::read(database_path).expect("stable history database must be readable");
    for forbidden in [
        b"fixture.subscription".as_slice(),
        b"socks5h://".as_slice(),
        PLACEHOLDER_SUB_A.as_bytes(),
        PLACEHOLDER_SUB_B.as_bytes(),
    ] {
        assert!(
            !database
                .windows(forbidden.len())
                .any(|item| item == forbidden)
        );
    }
}

fn record_stable_id_history(
    store: &mut GuardianStore,
    config: &PrivateRoutingConfig,
    sequence: u32,
) {
    for outlet in config.enabled_outlets() {
        let virtual_outlet = ProbeOutletConfig {
            id: outlet.id.clone(),
            label: outlet.label.clone(),
            proxy_url: "http://127.0.0.1:1".into(),
            probe_url: "https://fixture.invalid/probe".into(),
            degraded_latency_ms: 2_500,
            enabled: true,
        };
        let result = ProbeResult {
            outlet_id: outlet.id.clone(),
            label: outlet.label.clone(),
            observed_at: format!("2026-07-19T00:00:0{sequence}.000Z"),
            port_reachable: true,
            status: HealthStatus::Healthy,
            http_status: None,
            latency_ms: Some(u64::from(sequence)),
            error_code: None,
            successful_targets: 2,
            total_targets: 2,
        };
        store
            .record_probe(&virtual_outlet, &result, 1, 1)
            .expect("stable-id history must record");
    }
}

#[test]
fn dynamic_reservations_never_reuse_an_occupied_candidate() {
    let occupied = PortLease::reserve();
    let replacement = PortLease::reserve();
    assert_ne!(occupied.port(), replacement.port());
    assert!(!FORBIDDEN_PORTS.contains(&occupied.port()));
    assert!(!FORBIDDEN_PORTS.contains(&replacement.port()));
}

#[test]
fn controlled_tcp_relay_is_protocol_agnostic_and_can_fail_closed() {
    let upstream = PortLease::reserve();
    let upstream_port = upstream.port();
    let listener = upstream.listener;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("raw upstream must accept");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .expect("raw upstream must receive bytes");
        assert_eq!(&request, b"ping");
        stream
            .write_all(b"pong")
            .expect("raw upstream must return bytes");
    });
    let relay = ControlledTcpRelay::spawn(upstream_port, 0);
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, relay.port()));
    let mut client = TcpStream::connect_timeout(&address, Duration::from_millis(200))
        .expect("raw relay connection must open");
    client.write_all(b"ping").expect("raw bytes must write");
    let mut response = [0_u8; 4];
    client
        .read_exact(&mut response)
        .expect("raw bytes must relay back");
    assert_eq!(&response, b"pong");
    server.join().expect("raw upstream must finish");

    relay.set_available(false);
    let mut blocked = TcpStream::connect_timeout(&address, Duration::from_millis(200))
        .expect("fail-closed relay listener remains owned");
    blocked
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("blocked read timeout must set");
    blocked.write_all(b"ping").expect("blocked bytes may write");
    let mut byte = [0_u8; 1];
    assert!(!matches!(blocked.read(&mut byte), Ok(1)));
}

#[tokio::test]
#[ignore = "requires the repository-pinned Mihomo binary; uses only owned loopback fixtures and random ports"]
async fn occupied_listener_is_rejected_without_terminating_its_owner() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must resolve");
    let executable = pinned_mihomo(&workspace);
    let data = TempDir::new().expect("conflict data directory must exist");
    let occupied = PortLease::reserve();
    let port = occupied.port();
    assert_eq!(listening_owner_pid(port), Some(std::process::id()));

    let attempt = OwnedFixtureProxy::try_start_on_port(
        &executable,
        &data.path().join("conflicting-sidecar"),
        port,
    )
    .await;
    assert!(
        attempt.is_err(),
        "occupied listener must fail owned readiness"
    );
    assert_eq!(
        listening_owner_pid(port),
        Some(std::process::id()),
        "failed startup must not terminate or replace the unknown listener"
    );
    assert!(
        TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_millis(100)
        )
        .is_ok(),
        "unknown listener must remain reachable after safe failure"
    );
}

#[tokio::test]
#[ignore = "requires the repository-pinned Mihomo binary; uses only owned loopback fixtures and random ports"]
async fn panic_unwind_cleanup_remains_bounded_and_non_panicking() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must resolve");
    let executable = pinned_mihomo(&workspace);
    let data = TempDir::new().expect("unwind data directory must exist");
    let target = FixtureServer::target();
    let proxy_a = OwnedFixtureProxy::start(&executable, &data.path().join("unwind-a"), None).await;
    let proxy_b = OwnedFixtureProxy::start(&executable, &data.path().join("unwind-b"), None).await;
    let owned_ports = vec![
        target.port(),
        proxy_a.port,
        proxy_a.controller_port,
        proxy_b.port,
        proxy_b.controller_port,
    ];
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned_resources = (target, proxy_a, proxy_b);
        panic!("intentional cleanup regression unwind");
    }));
    std::panic::set_hook(original_hook);
    assert!(unwind.is_err());
    wait_for_owned_ports_to_close(&owned_ports)
        .expect("all remaining owned resources must clean up after unwind");
}

#[tokio::test]
#[ignore = "requires the repository-pinned Mihomo binary; uses only owned loopback fixtures and random ports"]
async fn isolated_dynamic_fault_runtime() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must resolve");
    let executable = pinned_mihomo(&workspace);
    let data = TempDir::new().expect("isolated data directory must be created");
    let runtime_directory = data.path().join("runtime");
    fs::create_dir_all(&runtime_directory).expect("isolated runtime directory must be created");

    let target = FixtureServer::target();
    let closed_entry = PortLease::reserve();
    let closed_entry_port = closed_entry.port();
    closed_entry.release();
    assert!(
        !entry_request_succeeds(closed_entry_port, &target.probe_url("/proxy-self-check")).await,
        "isolated request helper must not bypass its explicit proxy"
    );
    let mut proxy_a =
        OwnedFixtureProxy::start(&executable, &data.path().join("fixture-proxy-a"), None).await;
    let mut proxy_b =
        OwnedFixtureProxy::start(&executable, &data.path().join("fixture-proxy-b"), None).await;
    let mut proxy_local =
        OwnedFixtureProxy::start(&executable, &data.path().join("fixture-proxy-local"), None).await;
    for proxy in [&proxy_a, &proxy_b, &proxy_local] {
        assert!(
            fixture_proxy_succeeds(
                &format!("socks5h://127.0.0.1:{}", proxy.port()),
                &target.url("/fixture-self-check")
            )
            .await,
            "owned proxy fixture must pass its sidecar-to-gate self-check"
        );
    }
    let provider_a = FixtureServer::static_response(
        &synthetic_provider(&[("synthetic-a-primary", proxy_a.port())], "http"),
        "application/yaml",
    );
    let provider_b = FixtureServer::static_response(
        &synthetic_provider(&[("synthetic-b", proxy_b.port())], "http"),
        "application/yaml",
    );
    let entry = PortLease::reserve();
    let controller = PortLease::reserve();
    let all_ports = [
        target.port(),
        proxy_a.port(),
        proxy_b.port(),
        proxy_local.port(),
        provider_a.port(),
        provider_b.port(),
        entry.port(),
        controller.port(),
    ];
    assert_eq!(all_ports.into_iter().collect::<HashSet<_>>().len(), 8);
    assert!(all_ports.iter().all(|port| !FORBIDDEN_PORTS.contains(port)));

    let mut config = private_config(entry.port(), controller.port(), proxy_local.port());
    let yaml = fixture_runtime_yaml(&config, &provider_a, &provider_b, &target);
    config.probe_targets = vec![target.url("/probe-a"), target.url("/probe-b")];
    let config_path = runtime_directory.join("mihomo.yaml");
    fs::write(&config_path, yaml).expect("isolated Mihomo config must be written");
    let entry_port = entry.port();
    let controller_port = controller.port();
    entry.release();
    controller.release();

    let controller_secret = extract_controller_secret(&config_path);
    let mut mihomo = OwnedMihomo::start(
        &executable,
        &runtime_directory,
        &config_path,
        entry_port,
        controller_port,
        &controller_secret,
    )
    .await
    .expect("isolated outer Mihomo must pass owned readiness");
    let controller = ControllerClient::new(
        &format!("http://127.0.0.1:{controller_port}"),
        controller_secret,
        2_000,
    )
    .expect("isolated Controller client must be created");
    wait_for_outlets(&controller, entry_port, &target.probe_url("/ready")).await;
    assert!(
        controller
            .is_selected(&outlet_proxy_name(SUB_A), "synthetic-a-primary")
            .await
            .expect("subscription A selected member must be readable"),
        "subscription A group must expose its warmed selected member"
    );
    assert!(
        controller
            .is_selected(&outlet_proxy_name(SUB_B), "synthetic-b")
            .await
            .expect("subscription B selected member must be readable"),
        "subscription B group must expose its warmed selected member"
    );

    let database_path = data.path().join("guardian.db");
    let mut store = GuardianStore::open(&database_path).expect("isolated SQLite must open");
    let engine = std::sync::Mutex::new(RoutingEngine::new(RouteMode::Priority, None));

    controller
        .select(MASTER_SELECTOR, FAIL_CLOSED_PROXY)
        .await
        .expect("isolated master must select REJECT");
    assert!(
        controller
            .is_selected(MASTER_SELECTOR, FAIL_CLOSED_PROXY)
            .await
            .expect("isolated master state must be readable")
    );
    assert!(
        !entry_request_succeeds(entry_port, &target.probe_url("/reject-self-check")).await,
        "outer REJECT must block the isolated entry request"
    );

    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 0).await;
    assert_eq!(selected, outlet_proxy_name(SUB_A));
    assert!(entry_request_succeeds(entry_port, &target.url("/initial")).await);

    proxy_a.finish().expect("owned subscription A must stop");
    controller
        .select(MASTER_SELECTOR, &outlet_proxy_name(SUB_A))
        .await
        .expect("failed subscription fixture must remain selectable for an isolated probe");
    assert!(
        controller
            .is_selected(MASTER_SELECTOR, &outlet_proxy_name(SUB_A))
            .await
            .expect("isolated master state must be readable")
    );
    assert!(
        controller
            .is_selected(&outlet_proxy_name(SUB_A), "synthetic-a-primary")
            .await
            .expect("isolated subscription group state must be readable")
    );
    assert!(
        !entry_request_succeeds(entry_port, &target.probe_url("/fault-confirmation")).await,
        "disabled owned subscription fixture must fail through Controller-selected entry traffic"
    );
    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 100).await;
    assert_eq!(selected, outlet_proxy_name(SUB_A));
    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 200).await;
    assert_eq!(selected, outlet_proxy_name(SUB_B));
    assert!(entry_request_succeeds(entry_port, &target.url("/subscription-failover")).await);

    provider_a.set_static_response(
        &synthetic_provider(&[("synthetic-a-recovery", proxy_b.port())], "http"),
        "application/yaml",
    );
    controller
        .update_proxy_provider("vpn-hub-provider-fixture-sub-a")
        .await
        .expect("isolated subscription provider refresh must succeed");
    wait_for_outlet_selected(
        &controller,
        entry_port,
        SUB_A,
        &target.probe_url("/recovery-ready"),
        SUB_B,
    )
    .await;
    for now_ms in [300, 400, 500] {
        let selected =
            run_production_cycle(&controller, &config, &mut store, &engine, now_ms).await;
        assert_eq!(selected, outlet_proxy_name(SUB_B));
    }
    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 1_201).await;
    assert_eq!(selected, outlet_proxy_name(SUB_A));

    provider_a.set_static_response(
        &synthetic_provider(&[("synthetic-a-disabled", proxy_a.port())], "http"),
        "application/yaml",
    );
    controller
        .update_proxy_provider("vpn-hub-provider-fixture-sub-a")
        .await
        .expect("isolated subscription provider disable refresh must succeed");
    wait_for_outlet_unavailable(
        &controller,
        entry_port,
        SUB_A,
        &target.probe_url("/disabled-ready"),
        SUB_A,
    )
    .await;
    let _ = run_production_cycle(&controller, &config, &mut store, &engine, 1_300).await;
    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 1_400).await;
    assert_eq!(selected, outlet_proxy_name(SUB_B));
    proxy_b.finish().expect("owned subscription B must stop");
    let _ = run_production_cycle(&controller, &config, &mut store, &engine, 1_500).await;
    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 1_600).await;
    assert_eq!(selected, outlet_proxy_name(LOCAL));
    assert!(entry_request_succeeds(entry_port, &target.url("/local-fallback")).await);

    proxy_local.finish().expect("owned local proxy must stop");
    let _ = run_production_cycle(&controller, &config, &mut store, &engine, 1_700).await;
    let selected = run_production_cycle(&controller, &config, &mut store, &engine, 1_800).await;
    assert_eq!(selected, FAIL_CLOSED_PROXY);
    assert_eq!(
        engine
            .lock()
            .expect("routing state must remain readable")
            .current_outlet(),
        Some(FAIL_CLOSED_OUTLET)
    );
    assert!(!entry_request_succeeds(entry_port, &target.url("/all-down")).await);

    let summaries = store.summaries().expect("sanitized summaries must load");
    assert_eq!(summaries.len(), 3);
    assert_eq!(
        summaries
            .iter()
            .map(|summary| summary.outlet_id.as_str())
            .collect::<HashSet<_>>(),
        HashSet::from([SUB_A, SUB_B, LOCAL])
    );
    let switches = store
        .recent_route_switches(32)
        .expect("sanitized route switches must load");
    assert!(
        switches
            .iter()
            .any(|event| event.to_outlet == FAIL_CLOSED_OUTLET)
    );
    assert!(
        switches
            .iter()
            .all(|event| event.reason == "priority_policy")
    );
    let state_events = store
        .recent_events(64)
        .expect("sanitized state events must load");
    assert!(state_events.iter().any(|event| {
        event.outlet_id == SUB_A
            && event.from_status == HealthStatus::Down
            && event.to_status == HealthStatus::Healthy
    }));
    drop(store);
    let database = fs::read(&database_path).expect("isolated SQLite evidence must be readable");
    for forbidden in [
        PLACEHOLDER_SUB_A.as_bytes(),
        PLACEHOLDER_SUB_B.as_bytes(),
        b"synthetic-a".as_slice(),
        b"synthetic-b".as_slice(),
    ] {
        assert!(
            !database
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }

    println!(
        "isolated acceptance PASS: outlets=3 subscriptions=2 local=1 all_down=REJECT direct_fallback=false"
    );
    proxy_a
        .finish()
        .expect("owned subscription A sidecar must stop");
    proxy_b
        .finish()
        .expect("owned subscription B sidecar must stop");
    proxy_local.finish().expect("owned local sidecar must stop");
    mihomo.finish().expect("owned outer Mihomo must stop");
}

#[tokio::test]
#[ignore = "requires the repository-pinned Mihomo binary; uses only owned loopback fixtures and random ports"]
async fn isolated_fastest_hysteresis_runtime() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must resolve");
    let executable = pinned_mihomo(&workspace);
    let data = TempDir::new().expect("Fastest data directory must be created");
    let runtime_directory = data.path().join("runtime");
    fs::create_dir_all(&runtime_directory).expect("Fastest runtime directory must exist");

    let target = FixtureServer::target();
    let mut proxy_a =
        OwnedFixtureProxy::start(&executable, &data.path().join("fastest-proxy-a"), None).await;
    let mut proxy_b =
        OwnedFixtureProxy::start(&executable, &data.path().join("fastest-proxy-b"), None).await;
    let mut proxy_local =
        OwnedFixtureProxy::start(&executable, &data.path().join("fastest-proxy-local"), None).await;
    let gate_a = ControlledTcpRelay::spawn(proxy_a.port(), 100);
    let gate_b = ControlledTcpRelay::spawn(proxy_b.port(), 150);
    let gate_local = ControlledTcpRelay::spawn(proxy_local.port(), 220);
    let provider_a = FixtureServer::static_response(
        &synthetic_provider(&[("fastest-a", gate_a.port())], "http"),
        "application/yaml",
    );
    let provider_b = FixtureServer::static_response(
        &synthetic_provider(&[("fastest-b", gate_b.port())], "http"),
        "application/yaml",
    );
    let entry = PortLease::reserve();
    let controller_port_lease = PortLease::reserve();
    let all_ports = [
        target.port(),
        gate_a.port(),
        gate_b.port(),
        gate_local.port(),
        proxy_a.port(),
        proxy_a.controller_port,
        proxy_b.port(),
        proxy_b.controller_port,
        proxy_local.port(),
        proxy_local.controller_port,
        provider_a.port(),
        provider_b.port(),
        entry.port(),
        controller_port_lease.port(),
    ];
    assert_eq!(all_ports.into_iter().collect::<HashSet<_>>().len(), 14);
    assert!(all_ports.iter().all(|port| !FORBIDDEN_PORTS.contains(port)));

    let mut config = fastest_config(
        entry.port(),
        controller_port_lease.port(),
        gate_local.port(),
    );
    let yaml = fixture_runtime_yaml(&config, &provider_a, &provider_b, &target);
    config.probe_targets = vec![target.url("/fastest-a"), target.url("/fastest-b")];
    let config_path = runtime_directory.join("mihomo.yaml");
    fs::write(&config_path, yaml).expect("Fastest Mihomo config must be written");
    let entry_port = entry.port();
    let controller_port = controller_port_lease.port();
    entry.release();
    controller_port_lease.release();
    let controller_secret = extract_controller_secret(&config_path);
    let mut mihomo = OwnedMihomo::start(
        &executable,
        &runtime_directory,
        &config_path,
        entry_port,
        controller_port,
        &controller_secret,
    )
    .await
    .expect("Fastest outer Mihomo must pass owned readiness");
    let controller = ControllerClient::new(
        &format!("http://127.0.0.1:{controller_port}"),
        controller_secret,
        2_000,
    )
    .expect("Fastest Controller client must be created");
    wait_for_outlets(&controller, entry_port, &target.probe_url("/fastest-ready")).await;

    let mut store = GuardianStore::open(data.path().join("fastest-guardian.db"))
        .expect("Fastest SQLite must open");
    let engine = std::sync::Mutex::new(RoutingEngine::new(RouteMode::Fastest, None));
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 0).await,
        outlet_proxy_name(SUB_A)
    );

    gate_b.set_delay(70);
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 1_200).await,
        outlet_proxy_name(SUB_A),
        "an improvement below minimum_improvement_ms must not switch"
    );
    gate_b.set_delay(10);
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 1_300).await,
        outlet_proxy_name(SUB_B),
        "an improvement above minimum_improvement_ms must switch after cooldown"
    );

    gate_a.set_delay(0);
    gate_b.set_delay(100);
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 1_500).await,
        outlet_proxy_name(SUB_B),
        "cooldown must suppress even a large non-emergency improvement"
    );
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 2_301).await,
        outlet_proxy_name(SUB_A)
    );

    gate_a.set_available(false);
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 2_400).await,
        outlet_proxy_name(SUB_A),
        "first failure must be held by the production failure threshold"
    );
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 2_500).await,
        outlet_proxy_name(SUB_B),
        "confirmed failure must bypass cooldown as an emergency"
    );
    gate_a.set_available(true);
    wait_for_outlet_selected(
        &controller,
        entry_port,
        SUB_A,
        &target.probe_url("/fastest-recovery-ready"),
        SUB_B,
    )
    .await;
    for now_ms in [2_600, 2_700, 2_800] {
        assert_eq!(
            run_production_cycle(&controller, &config, &mut store, &engine, now_ms).await,
            outlet_proxy_name(SUB_B),
            "recovery threshold and cooldown must keep the stable current outlet"
        );
    }
    assert_eq!(
        run_production_cycle(&controller, &config, &mut store, &engine, 3_501).await,
        outlet_proxy_name(SUB_A),
        "recovered faster outlet must switch only after threshold and cooldown"
    );
    assert!(entry_request_succeeds(entry_port, &target.url("/fastest-final")).await);
    let switches = store
        .recent_route_switches(16)
        .expect("Fastest route switches must load");
    assert!(
        switches
            .iter()
            .all(|event| { event.mode == "fastest" && event.reason == "lowest_latency_policy" })
    );
    println!(
        "isolated fastest PASS: minimum_improvement_ms=50 cooldown_ms=1000 failure_threshold=2 recovery_threshold=3"
    );
    proxy_a
        .finish()
        .expect("Fastest subscription A sidecar must stop");
    proxy_b
        .finish()
        .expect("Fastest subscription B sidecar must stop");
    proxy_local
        .finish()
        .expect("Fastest local sidecar must stop");
    mihomo.finish().expect("Fastest outer Mihomo must stop");
}

fn extract_controller_secret(config_path: &Path) -> String {
    let yaml = fs::read_to_string(config_path).expect("isolated config must be readable");
    let document = serde_yaml::from_str::<serde_yaml::Value>(&yaml)
        .expect("isolated config must remain valid YAML");
    document
        .get("secret")
        .and_then(serde_yaml::Value::as_str)
        .expect("isolated config must contain a controller secret")
        .to_owned()
}
