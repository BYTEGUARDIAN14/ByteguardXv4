//! ByteGuardX Desktop - Native Menu
//!
//! Creates native application menus that match the original Electron implementation.

use tauri::{
    CustomMenuItem, Menu, MenuItem, Submenu,
    WindowMenuEvent, Manager,
};
use log::info;

/// Create the application menu
pub fn create_menu() -> Menu {
    let file_menu = Submenu::new("File", Menu::new()
        .add_item(CustomMenuItem::new("new_scan", "New Scan").accelerator("CmdOrCtrl+N"))
        .add_item(CustomMenuItem::new("open_project", "Open Project...").accelerator("CmdOrCtrl+O"))
        .add_native_item(MenuItem::Separator)
        .add_item(CustomMenuItem::new("export_report", "Export Report").accelerator("CmdOrCtrl+E"))
        .add_native_item(MenuItem::Separator)
        .add_item(CustomMenuItem::new("settings", "Settings").accelerator("CmdOrCtrl+,"))
        .add_native_item(MenuItem::Separator)
        .add_native_item(MenuItem::Quit)
    );
    
    let edit_menu = Submenu::new("Edit", Menu::new()
        .add_native_item(MenuItem::Undo)
        .add_native_item(MenuItem::Redo)
        .add_native_item(MenuItem::Separator)
        .add_native_item(MenuItem::Cut)
        .add_native_item(MenuItem::Copy)
        .add_native_item(MenuItem::Paste)
        .add_native_item(MenuItem::SelectAll)
    );
    
    let view_menu = Submenu::new("View", Menu::new()
        .add_item(CustomMenuItem::new("reload", "Reload").accelerator("CmdOrCtrl+R"))
        .add_item(CustomMenuItem::new("force_reload", "Force Reload").accelerator("CmdOrCtrl+Shift+R"))
        .add_item(CustomMenuItem::new("toggle_devtools", "Toggle Developer Tools").accelerator("F12"))
        .add_native_item(MenuItem::Separator)
        .add_item(CustomMenuItem::new("zoom_in", "Zoom In").accelerator("CmdOrCtrl+Plus"))
        .add_item(CustomMenuItem::new("zoom_out", "Zoom Out").accelerator("CmdOrCtrl+-"))
        .add_item(CustomMenuItem::new("reset_zoom", "Reset Zoom").accelerator("CmdOrCtrl+0"))
        .add_native_item(MenuItem::Separator)
        .add_native_item(MenuItem::EnterFullScreen)
    );
    
    let scan_menu = Submenu::new("Scan", Menu::new()
        .add_item(CustomMenuItem::new("quick_scan", "Quick Scan").accelerator("CmdOrCtrl+Shift+Q"))
        .add_item(CustomMenuItem::new("deep_scan", "Deep Scan").accelerator("CmdOrCtrl+Shift+D"))
        .add_native_item(MenuItem::Separator)
        .add_item(CustomMenuItem::new("scan_settings", "Scan Settings"))
    );
    
    let tools_menu = Submenu::new("Tools", Menu::new()
        .add_item(CustomMenuItem::new("dashboard", "Security Dashboard").accelerator("CmdOrCtrl+D"))
        .add_item(CustomMenuItem::new("vulnerability_db", "Vulnerability Database"))
        .add_native_item(MenuItem::Separator)
        .add_item(CustomMenuItem::new("plugins", "Plugin Manager"))
    );
    
    let help_menu = Submenu::new("Help", Menu::new()
        .add_item(CustomMenuItem::new("documentation", "Documentation"))
        .add_item(CustomMenuItem::new("report_issue", "Report Issue"))
        .add_native_item(MenuItem::Separator)
        .add_item(CustomMenuItem::new("about", "About ByteGuardX"))
    );
    
    // Build menu based on platform
    #[cfg(target_os = "macos")]
    {
        Menu::new()
            .add_submenu(Submenu::new("ByteGuardX", Menu::new()
                .add_native_item(MenuItem::About("ByteGuardX".to_string(), Default::default()))
                .add_native_item(MenuItem::Separator)
                .add_item(CustomMenuItem::new("settings", "Preferences...").accelerator("CmdOrCtrl+,"))
                .add_native_item(MenuItem::Separator)
                .add_native_item(MenuItem::Services)
                .add_native_item(MenuItem::Separator)
                .add_native_item(MenuItem::Hide)
                .add_native_item(MenuItem::HideOthers)
                .add_native_item(MenuItem::ShowAll)
                .add_native_item(MenuItem::Separator)
                .add_native_item(MenuItem::Quit)
            ))
            .add_submenu(file_menu)
            .add_submenu(edit_menu)
            .add_submenu(view_menu)
            .add_submenu(scan_menu)
            .add_submenu(tools_menu)
            .add_submenu(help_menu)
    }
    
    #[cfg(not(target_os = "macos"))]
    {
        Menu::new()
            .add_submenu(file_menu)
            .add_submenu(edit_menu)
            .add_submenu(view_menu)
            .add_submenu(scan_menu)
            .add_submenu(tools_menu)
            .add_submenu(help_menu)
    }
}

/// Handle menu item clicks
pub fn handle_menu_event(event: WindowMenuEvent) {
    let window = event.window();
    let menu_id = event.menu_item_id();
    
    info!("Menu event: {}", menu_id);
    
    match menu_id {
        // File menu
        "new_scan" => {
            window.emit("menu-new-scan", ()).unwrap_or_default();
        }
        "open_project" => {
            window.emit("menu-open-project", ()).unwrap_or_default();
        }
        "export_report" => {
            window.emit("menu-export-report", ()).unwrap_or_default();
        }
        "settings" => {
            window.emit("menu-settings", ()).unwrap_or_default();
        }
        
        // View menu
        "reload" => {
            let _ = window.eval("window.location.reload()");
        }
        "force_reload" => {
            let _ = window.eval("window.location.reload(true)");
        }
        "toggle_devtools" => {
            if window.is_devtools_open() {
                window.close_devtools();
            } else {
                window.open_devtools();
            }
        }
        "zoom_in" => {
            window.emit("menu-zoom-in", ()).unwrap_or_default();
        }
        "zoom_out" => {
            window.emit("menu-zoom-out", ()).unwrap_or_default();
        }
        "reset_zoom" => {
            window.emit("menu-reset-zoom", ()).unwrap_or_default();
        }
        
        // Scan menu
        "quick_scan" => {
            window.emit("menu-quick-scan", ()).unwrap_or_default();
        }
        "deep_scan" => {
            window.emit("menu-deep-scan", ()).unwrap_or_default();
        }
        "scan_settings" => {
            window.emit("menu-scan-settings", ()).unwrap_or_default();
        }
        
        // Tools menu
        "dashboard" => {
            window.emit("menu-dashboard", ()).unwrap_or_default();
        }
        "vulnerability_db" => {
            window.emit("menu-vulnerability-db", ()).unwrap_or_default();
        }
        "plugins" => {
            window.emit("menu-plugins", ()).unwrap_or_default();
        }
        
        // Help menu
        "documentation" => {
            window.emit("menu-documentation", ()).unwrap_or_default();
        }
        "report_issue" => {
            window.emit("menu-report-issue", ()).unwrap_or_default();
        }
        "about" => {
            window.emit("menu-about", ()).unwrap_or_default();
        }
        
        _ => {
            info!("Unhandled menu item: {}", menu_id);
        }
    }
}
