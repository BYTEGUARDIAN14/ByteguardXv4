//! ByteGuardX Desktop - Tauri Application Entry Point
//! 
//! This is the main entry point for the ByteGuardX desktop application.
//! It initializes the Tauri application with custom commands and security settings.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod commands;
mod storage;
mod python_bridge;
mod menu;
mod sandbox;

use tauri::Manager;
use log::{info, error};

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    
    info!("Starting ByteGuardX Desktop v{}", env!("CARGO_PKG_VERSION"));

    tauri::Builder::default()
        .setup(|app| {
            info!("Application setup started");
            
            // Initialize application state
            let app_handle = app.handle();
            
            // Ensure app data directory exists
            if let Some(app_dir) = app.path_resolver().app_data_dir() {
                if !app_dir.exists() {
                    std::fs::create_dir_all(&app_dir).map_err(|e| {
                        error!("Failed to create app data directory: {}", e);
                        e
                    })?;
                }
                info!("App data directory: {:?}", app_dir);
            }
            
            // Initialize Python engine manager
            let engine_manager = python_bridge::PythonEngineManager::new(app_handle.clone());
            app.manage(engine_manager);
            
            // Initialize settings storage
            let storage = storage::SettingsStorage::new(app_handle.clone())?;
            app.manage(storage);
            
            info!("Application setup complete");
            Ok(())
        })
        .menu(menu::create_menu())
        .on_menu_event(menu::handle_menu_event)
        .invoke_handler(tauri::generate_handler![
            // Scan commands
            commands::run_scan,
            commands::get_scan_status,
            commands::cancel_scan,
            commands::get_scan_results,
            commands::list_scans,
            
            // Settings commands
            commands::get_setting,
            commands::set_setting,
            commands::get_all_settings,
            commands::reset_settings,
            
            // Plugin commands
            commands::list_plugins,
            commands::install_plugin_local,
            commands::uninstall_plugin,
            commands::verify_plugin_checksum,
            commands::get_dashboard_stats,
            commands::get_plugin_stats,
            
            // Report commands
            commands::export_report,
            commands::get_report_formats,
            
            // System commands
            commands::get_app_version,
            commands::get_system_info,
            commands::check_python_available,
            commands::get_health_status,
            
            // File operations
            commands::read_file_safe,
            commands::write_file_safe,
        ])
        .on_window_event(|event| {
            match event.event() {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    info!("Window close requested");
                    // Allow the window to close
                    // Could add cleanup logic here
                }
                tauri::WindowEvent::Destroyed => {
                    info!("Window destroyed");
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running ByteGuardX application");
}
