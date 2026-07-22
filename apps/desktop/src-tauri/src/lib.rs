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
            commands::preview_entry_switch,
            commands::apply_entry_switch,
            commands::get_subscription_node_catalog,
            commands::retry_subscription_provider,
            commands::select_subscription_node,
            commands::test_subscription_node_latency,
            commands::test_subscription_node_latencies,
            commands::cancel_subscription_node_latency_batch,
            commands::preview_settings,
            commands::apply_settings,
            commands::cancel_foreground_operation,
            commands::get_foreground_operation_status,
            commands::get_fast_path_performance,
            commands::get_settings_terminal_status,
            commands::recover_settings_terminal,
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
