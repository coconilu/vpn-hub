#![cfg(windows)]
#![allow(clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use tempfile::TempDir;
use vpn_hub_core::{
    ControllerClient, EntryConfig, FAIL_CLOSED_OUTLET, FAIL_CLOSED_PROXY, GuardianStore,
    HealthStatus, MASTER_SELECTOR, MonitorConfig, OutletConfig, OutletHealth, OutletKind,
    PrivateRoutingConfig, ProbeOutletConfig, ProbeResult, ResolvedSubscriptionUrls, RouteMode,
    RouteSwitchEvent, RoutingEngine, RoutingPolicy, generate_controller_secret,
    generate_mihomo_config, outlet_proxy_name,
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

fn serve_static(mut stream: TcpStream, response: &[u8]) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut request = [0_u8; 4_096];
    let _ = stream.read(&mut request);
    let _ = stream.write_all(response);
}

struct OwnedMihomo {
    child: Child,
}

impl OwnedMihomo {
    fn start(executable: &Path, runtime_directory: &Path, config_path: &Path) -> Self {
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
            .expect("pinned Mihomo must start in the isolated runtime");
        Self { child }
    }
}

impl Drop for OwnedMihomo {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct OwnedFixtureProxy {
    port: u16,
    child: Option<Child>,
}

impl OwnedFixtureProxy {
    fn start(executable: &Path, directory: &Path) -> Self {
        let reservation = PortLease::reserve();
        let port = reservation.port();
        let config_path = Self::prepare_config(executable, directory, port);
        reservation.release();
        let mut child = Self::spawn_child(executable, directory, &config_path);
        wait_for_owned_child_port(&mut child, port);
        Self {
            port,
            child: Some(child),
        }
    }

    fn prepare_config(executable: &Path, directory: &Path, port: u16) -> PathBuf {
        fs::create_dir_all(directory).expect("fixture sidecar directory must be created");
        let config_path = directory.join("mihomo.yaml");
        let config = format!(
            "mixed-port: {port}\nbind-address: 127.0.0.1\nallow-lan: false\nmode: rule\nlog-level: silent\nipv6: false\nfind-process-mode: off\nhosts:\n  fixture.invalid: 127.0.0.1\nrules:\n  - DOMAIN,fixture.invalid,DIRECT\n  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n  - MATCH,REJECT\n"
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

    fn spawn_child(executable: &Path, directory: &Path, config_path: &Path) -> Child {
        hidden_command(executable)
            .arg("-d")
            .arg(directory)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("owned fixture sidecar must start")
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        for _ in 0..50 {
            if TcpStream::connect_timeout(&address, Duration::from_millis(20)).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("owned fixture sidecar listener did not stop");
    }
}

impl Drop for OwnedFixtureProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn hidden_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
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

fn resolved_subscriptions() -> ResolvedSubscriptionUrls {
    BTreeMap::from([
        ("fixture.subscription.a".into(), PLACEHOLDER_SUB_A.into()),
        ("fixture.subscription.b".into(), PLACEHOLDER_SUB_B.into()),
    ])
}

fn synthetic_provider(nodes: &[(&str, u16)]) -> String {
    let mut document = "proxies:\n".to_string();
    for (node_name, proxy_port) in nodes {
        let _ = write!(
            document,
            "  - name: {node_name}\n    type: http\n    server: 127.0.0.1\n    port: {proxy_port}\n"
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

fn wait_for_port(port: u16) {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..100 {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("isolated runtime listener did not become ready");
}

fn wait_for_owned_child_port(child: &mut Child, port: u16) {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..100 {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            return;
        }
        if child
            .try_wait()
            .expect("owned fixture sidecar status must be readable")
            .is_some()
        {
            panic!("owned fixture sidecar exited before its listener became ready");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("owned fixture sidecar listener did not become ready");
}

async fn wait_for_outlets(controller: &ControllerClient, entry_port: u16, target: &str) {
    let mut last_failures = Vec::new();
    for _ in 0..100 {
        last_failures.clear();
        for outlet_id in [SUB_A, SUB_B, LOCAL] {
            let proxy_name = outlet_proxy_name(outlet_id);
            controller
                .select(MASTER_SELECTOR, &proxy_name)
                .await
                .expect("isolated readiness probe selection must succeed");
            if !entry_request_succeeds(entry_port, target).await {
                last_failures.push(outlet_id.to_string());
            }
        }
        if last_failures.is_empty() {
            return;
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
) {
    let proxy_name = outlet_proxy_name(outlet_id);
    for _ in 0..100 {
        controller
            .select(MASTER_SELECTOR, &proxy_name)
            .await
            .expect("isolated recovery probe selection must succeed");
        if entry_request_succeeds(entry_port, target).await {
            return;
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
) {
    let proxy_name = outlet_proxy_name(outlet_id);
    for _ in 0..100 {
        controller
            .select(MASTER_SELECTOR, &proxy_name)
            .await
            .expect("isolated disabled probe selection must succeed");
        if !entry_request_succeeds(entry_port, target).await {
            return;
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

async fn probe_outlet(
    controller: &ControllerClient,
    outlet: &OutletConfig,
    targets: &[String],
    entry_port: u16,
) -> ProbeResult {
    let mut delays = Vec::new();
    for target in targets {
        let proxy_name = outlet_proxy_name(&outlet.id);
        controller
            .select(MASTER_SELECTOR, &proxy_name)
            .await
            .expect("isolated targeted probe selection must succeed");
        let started = Instant::now();
        if entry_request_succeeds(entry_port, target).await {
            delays.push(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        }
    }
    delays.sort_unstable();
    let quorum = targets.len() / 2 + 1;
    let latency_ms = delays.get(delays.len() / 2).copied();
    let status = if delays.len() < quorum {
        HealthStatus::Down
    } else if delays.len() < targets.len() {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };
    ProbeResult {
        outlet_id: outlet.id.clone(),
        label: outlet.label.clone(),
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        port_reachable: true,
        status,
        http_status: None,
        latency_ms,
        error_code: (status == HealthStatus::Down).then(|| "multi_target_quorum_failed".into()),
        successful_targets: u32::try_from(delays.len()).unwrap_or(u32::MAX),
        total_targets: u32::try_from(targets.len()).unwrap_or(u32::MAX),
    }
}

async fn run_cycle(
    controller: &ControllerClient,
    config: &PrivateRoutingConfig,
    store: &mut GuardianStore,
    engine: &mut RoutingEngine,
    now_ms: u64,
) -> String {
    let monitor = monitor();
    let mut latest_latency = BTreeMap::new();
    for outlet in config.enabled_outlets() {
        let result =
            probe_outlet(controller, outlet, &config.probe_targets, config.entry.port).await;
        latest_latency.insert(outlet.id.clone(), result.latency_ms);
        let virtual_outlet = ProbeOutletConfig {
            id: outlet.id.clone(),
            label: outlet.label.clone(),
            proxy_url: format!("http://127.0.0.1:{}", config.entry.port),
            probe_url: "http://fixture.invalid/".into(),
            degraded_latency_ms: 2_500,
            enabled: true,
        };
        store
            .record_probe(
                &virtual_outlet,
                &result,
                monitor.failure_threshold,
                monitor.recovery_threshold,
            )
            .expect("sanitized probe must be recorded");
    }
    let health = store
        .summaries()
        .expect("stable outlet summaries must load")
        .into_iter()
        .map(|summary| {
            let latency_ms = latest_latency
                .get(summary.outlet_id.as_str())
                .copied()
                .flatten();
            (
                summary.outlet_id,
                OutletHealth {
                    status: summary.last_status,
                    latency_ms,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let policy = RoutingPolicy {
        priority: config.priority(),
        cooldown_ms: config.cooldown_seconds.saturating_mul(1_000),
        minimum_improvement_ms: config.minimum_improvement_ms,
    };
    if let Some(decision) = engine.evaluate(now_ms, &health, &policy) {
        let started = Instant::now();
        controller
            .select(MASTER_SELECTOR, &outlet_proxy_name(&decision.to_outlet))
            .await
            .expect("real Controller selector change must succeed");
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        engine.apply(&decision, now_ms);
        store
            .record_route_switch(&RouteSwitchEvent {
                occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                from_outlet: decision.from_outlet,
                to_outlet: decision.to_outlet,
                mode: config.route_mode.as_str().into(),
                reason: decision.reason,
                duration_ms,
            })
            .expect("confirmed selector switch must be recorded");
    }
    let final_outlet = engine.current_outlet().unwrap_or(FAIL_CLOSED_OUTLET);
    let selected = outlet_proxy_name(final_outlet);
    controller
        .select(MASTER_SELECTOR, &selected)
        .await
        .expect("isolated targeted probes must restore the routed master selection");
    assert!(
        controller
            .is_selected(MASTER_SELECTOR, &selected)
            .await
            .expect("real Controller selector state must be readable")
    );
    selected
}

async fn entry_request_succeeds(entry_port: u16, target: &str) -> bool {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{entry_port}"))
        .expect("isolated entry proxy URL must be valid");
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(Duration::from_secs(2))
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
    let first = vec![SUB_A, SUB_B, LOCAL];
    let reordered = vec![LOCAL, SUB_A, SUB_B];
    let removed_and_readded = vec![SUB_B, LOCAL, SUB_A];
    let expected = first
        .into_iter()
        .map(|id| (id, outlet_proxy_name(id)))
        .collect::<BTreeMap<_, _>>();
    for order in [reordered, removed_and_readded] {
        for id in order {
            assert_eq!(expected.get(id), Some(&outlet_proxy_name(id)));
        }
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
    let proxy_a = OwnedFixtureProxy::start(&executable, &data.path().join("fixture-proxy-a"));
    let proxy_b = OwnedFixtureProxy::start(&executable, &data.path().join("fixture-proxy-b"));
    let proxy_local =
        OwnedFixtureProxy::start(&executable, &data.path().join("fixture-proxy-local"));
    assert!(
        fixture_proxy_succeeds(
            &format!("http://127.0.0.1:{}", proxy_local.port()),
            &target.url("/fixture-self-check")
        )
        .await,
        "owned local proxy fixture must pass its direct self-check"
    );
    let provider_a = FixtureServer::static_response(
        &synthetic_provider(&[("synthetic-a-primary", proxy_a.port())]),
        "application/yaml",
    );
    let provider_b = FixtureServer::static_response(
        &synthetic_provider(&[("synthetic-b", proxy_b.port())]),
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
    config.probe_targets = vec![target.probe_url("/probe-a"), target.probe_url("/probe-b")];
    let config_path = runtime_directory.join("mihomo.yaml");
    fs::write(&config_path, yaml).expect("isolated Mihomo config must be written");
    let entry_port = entry.port();
    let controller_port = controller.port();
    entry.release();
    controller.release();

    let _mihomo = OwnedMihomo::start(&executable, &runtime_directory, &config_path);
    wait_for_port(entry_port);
    wait_for_port(controller_port);
    let controller = ControllerClient::new(
        &format!("http://127.0.0.1:{controller_port}"),
        extract_controller_secret(&config_path),
        2_000,
    )
    .expect("isolated Controller client must be created");
    wait_for_outlets(&controller, entry_port, &target.probe_url("/ready")).await;

    let database_path = data.path().join("guardian.db");
    let mut store = GuardianStore::open(&database_path).expect("isolated SQLite must open");
    let mut engine = RoutingEngine::new(RouteMode::Priority, None);

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

    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 0).await;
    assert_eq!(selected, outlet_proxy_name(SUB_A));
    assert!(entry_request_succeeds(entry_port, &target.url("/initial")).await);

    let mut proxy_a = proxy_a;
    proxy_a.stop();
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
    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 100).await;
    assert_eq!(selected, outlet_proxy_name(SUB_A));
    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 200).await;
    assert_eq!(selected, outlet_proxy_name(SUB_B));
    assert!(entry_request_succeeds(entry_port, &target.url("/subscription-failover")).await);

    provider_a.set_static_response(
        &synthetic_provider(&[("synthetic-a-recovery", proxy_b.port())]),
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
    )
    .await;
    for now_ms in [300, 400, 500] {
        let selected = run_cycle(&controller, &config, &mut store, &mut engine, now_ms).await;
        assert_eq!(selected, outlet_proxy_name(SUB_B));
    }
    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 1_201).await;
    assert_eq!(selected, outlet_proxy_name(SUB_A));

    provider_a.set_static_response(
        &synthetic_provider(&[("synthetic-a-disabled", proxy_a.port())]),
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
    )
    .await;
    let _ = run_cycle(&controller, &config, &mut store, &mut engine, 1_300).await;
    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 1_400).await;
    assert_eq!(selected, outlet_proxy_name(SUB_B));
    let mut proxy_b = proxy_b;
    proxy_b.stop();
    let _ = run_cycle(&controller, &config, &mut store, &mut engine, 1_500).await;
    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 1_600).await;
    assert_eq!(selected, outlet_proxy_name(LOCAL));
    assert!(entry_request_succeeds(entry_port, &target.url("/local-fallback")).await);

    let mut proxy_local = proxy_local;
    proxy_local.stop();
    let _ = run_cycle(&controller, &config, &mut store, &mut engine, 1_700).await;
    let selected = run_cycle(&controller, &config, &mut store, &mut engine, 1_800).await;
    assert_eq!(selected, FAIL_CLOSED_PROXY);
    assert_eq!(engine.current_outlet(), Some(FAIL_CLOSED_OUTLET));
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
