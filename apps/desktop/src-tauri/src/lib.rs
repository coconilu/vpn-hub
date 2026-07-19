mod commands;
#[cfg(target_os = "windows")]
mod entry_switch_windows;
mod lifecycle;
mod runtime;

use lifecycle::{DesktopCoordinator, LifecycleEvent};
use runtime::AppState;
use tauri::Manager as _;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the VPN Hub desktop runtime.
///
/// # Panics
///
/// Panics when Tauri cannot initialize the application runtime.
pub fn run() {
    let state = AppState::new();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(state)
        .manage(DesktopCoordinator::new())
        .setup(|app| {
            lifecycle::install_tray(app)?;
            app.state::<DesktopCoordinator>()
                .start(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                lifecycle::dispatch(window.app_handle(), LifecycleEvent::WindowClose);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard_snapshot,
            commands::get_history,
            commands::export_history,
            commands::set_history_retention,
            commands::get_settings,
            commands::preview_settings,
            commands::apply_settings,
            commands::refresh_guardian,
            commands::revalidate_udp_capabilities,
            commands::set_route_mode,
            commands::list_subscription_credentials,
            commands::set_subscription_credential,
            commands::delete_subscription_credential,
            commands::start_development_core,
            commands::stop_development_core,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build VPN Hub desktop application");
    app.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let coordinator = app.state::<DesktopCoordinator>();
            if !coordinator.exit_permitted() {
                api.prevent_exit();
                coordinator.dispatch(LifecycleEvent::OsShutdown);
            }
        }
    });
}
