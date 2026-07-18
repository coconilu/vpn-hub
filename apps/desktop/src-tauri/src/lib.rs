mod commands;
mod runtime;

use runtime::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the VPN Hub desktop runtime.
///
/// # Panics
///
/// Panics when Tauri cannot initialize the application runtime.
pub fn run() {
    let state = AppState::new();
    let guardian_config_path = state.guardian_config_path();
    tauri::Builder::default()
        .manage(state)
        .setup(move |_app| {
            tauri::async_runtime::spawn(commands::monitor_guardian(guardian_config_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard_snapshot,
            commands::refresh_guardian,
            commands::start_development_core,
            commands::stop_development_core,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run VPN Hub desktop application");
}
