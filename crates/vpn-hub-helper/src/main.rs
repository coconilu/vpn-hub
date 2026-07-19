use std::{process::ExitCode, sync::Arc};

#[cfg(target_os = "windows")]
use vpn_hub_windows_security::ProtectedPathPolicy::{
    Executable, Immutable, Mutable, SecretMaterial,
};

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("vpn-hub-helper {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--dry-run-install") => {
            eprintln!(
                "dry-run requires an installer-owned manifest; this binary never registers itself"
            );
            ExitCode::from(2)
        }
        Some("--service") | None => {
            match vpn_hub_helper::run_service_dispatcher(provisioned_service) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(4)
                }
            }
        }
        Some(_) => {
            eprintln!(
                "vpn-hub-helper is disabled until a signed installer provisions the LocalService contract"
            );
            ExitCode::from(3)
        }
    }
}

#[cfg(target_os = "windows")]
fn provisioned_service(signals: Arc<vpn_hub_helper::ServiceSignals>) -> Result<(), String> {
    use vpn_hub_helper::{
        HelperRuntime, ProgramDataManifestProvider, ProtocolKey, WindowsJobCoreBackend,
        run_windows_helper_loop,
    };

    let executable = std::env::current_exe().map_err(|_| "helper location unavailable")?;
    let root = executable
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("helper installation root unavailable")?
        .to_path_buf();
    let install_id = read_bounded_text(&root.join("install-id"), 128)?;
    let interactive_user_sid = read_bounded_text(&root.join("interactive-user.sid"), 184)?;
    let program_data = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .ok_or("ProgramData is unavailable")?;
    vpn_hub_helper::InstallationReference {
        schema_version: 1,
        install_id: install_id.clone(),
        helper_enabled: true,
        program_data_root: root.clone(),
        client_secret_ref: "runtime-validation-only".into(),
    }
    .validate(&program_data)
    .map_err(|_| "helper installation root invalid")?;
    if executable.parent() != Some(root.join("bin").as_path()) {
        return Err("helper executable location invalid".into());
    }
    let critical_paths = [
        (root.join("install-id"), Immutable),
        (root.join("interactive-user.sid"), Immutable),
        (root.join("helper.key"), SecretMaterial),
        (root.join("supervision.json"), Mutable),
        (root.join("bin/mihomo.exe"), Executable),
        (executable, Executable),
        (root.join("runtime/mihomo.yaml"), Mutable),
        (root.join("data/guardian.db"), Mutable),
        (root.join("authority.lease"), Mutable),
    ];
    vpn_hub_windows_security::validate_protected_installation(
        &root,
        &critical_paths,
        &interactive_user_sid,
    )
    .map_err(|_| "helper installation permissions invalid")?;
    let key_bytes = zeroize::Zeroizing::new(
        std::fs::read(root.join("helper.key"))
            .map_err(|_| "helper provisioning material unavailable")?,
    );
    let key_array = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| "helper provisioning material invalid")?,
    );
    let provider = ProgramDataManifestProvider {
        root: root.clone(),
        manifest_path: root.join("supervision.json"),
        install_id: install_id.clone(),
    };
    let now_ms = unix_ms();
    let runtime = HelperRuntime::acquire_helper_with_authority_file(
        WindowsJobCoreBackend::new(root.clone()),
        provider,
        &root.join("authority.lease"),
        now_ms,
    )
    .map_err(|_| "helper runtime failed closed")?;
    let runtime = Arc::new(std::sync::Mutex::new(runtime));
    let key = Arc::new(ProtocolKey::from_bytes(*key_array));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "helper async runtime unavailable")?
        .block_on(run_windows_helper_loop(
            runtime,
            key,
            install_id,
            interactive_user_sid,
            signals,
        ))
        .map_err(|_| "helper runtime failed closed".to_owned())
}

#[cfg(not(target_os = "windows"))]
fn provisioned_service(_signals: Arc<vpn_hub_helper::ServiceSignals>) -> Result<(), String> {
    Err("Windows helper is unavailable on this platform".into())
}

#[cfg(target_os = "windows")]
fn read_bounded_text(path: &std::path::Path, max_bytes: usize) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|_| "helper provisioning metadata unavailable")?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err("helper provisioning metadata invalid".into());
    }
    let value = String::from_utf8(bytes).map_err(|_| "helper provisioning metadata invalid")?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err("helper provisioning metadata invalid".into());
    }
    Ok(value)
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
