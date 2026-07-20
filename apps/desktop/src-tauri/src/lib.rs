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
    tauri::Builder::default()
        .manage(state)
        .setup(move |app| {
            tauri::async_runtime::spawn(commands::monitor_guardian(app.handle().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard_snapshot,
            commands::refresh_guardian,
            commands::revalidate_udp_capabilities,
            commands::set_route_mode,
            commands::list_subscription_credentials,
            commands::set_subscription_credential,
            commands::delete_subscription_credential,
            commands::start_development_core,
            commands::stop_development_core,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run VPN Hub desktop application");
}
