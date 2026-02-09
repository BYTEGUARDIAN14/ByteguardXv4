//! ByteGuardX Desktop - Settings Storage
//!
//! Manages persistent settings storage using JSON files in the app data directory.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::AppHandle;
use tokio::sync::RwLock;
use log::{info, warn, error};

use crate::commands::ScanResult;

/// Thread-safe settings storage
pub struct SettingsStorage {
    app_handle: AppHandle,
    settings: Arc<RwLock<HashMap<String, Value>>>,
    scans: Arc<RwLock<Vec<ScanResult>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettingsFile {
    version: u32,
    settings: HashMap<String, Value>,
}

impl SettingsStorage {
    /// Create a new settings storage instance
    pub fn new(app_handle: AppHandle) -> Result<Self, String> {
        let storage = Self {
            app_handle,
            settings: Arc::new(RwLock::new(HashMap::new())),
            scans: Arc::new(RwLock::new(Vec::new())),
        };
        
        // Load existing settings in a blocking manner during initialization
        let settings_path = storage.settings_path()?;
        if settings_path.exists() {
            match std::fs::read_to_string(&settings_path) {
                Ok(content) => {
                    if let Ok(file) = serde_json::from_str::<SettingsFile>(&content) {
                        let settings = storage.settings.clone();
                        tokio::task::block_in_place(|| {
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(async {
                                let mut guard = settings.write().await;
                                *guard = file.settings;
                            });
                        });
                        info!("Loaded existing settings");
                    }
                }
                Err(e) => {
                    warn!("Could not load settings: {}", e);
                }
            }
        } else {
            // Initialize with defaults
            info!("Initializing with default settings");
        }
        
        Ok(storage)
    }
    
    /// Get the path to the settings file
    fn settings_path(&self) -> Result<PathBuf, String> {
        self.app_handle
            .path_resolver()
            .app_data_dir()
            .map(|p| p.join("settings.json"))
            .ok_or_else(|| "Could not determine app data directory".to_string())
    }
    
    /// Get the path to the scans history file
    fn scans_path(&self) -> Result<PathBuf, String> {
        self.app_handle
            .path_resolver()
            .app_data_dir()
            .map(|p| p.join("scans.json"))
            .ok_or_else(|| "Could not determine app data directory".to_string())
    }
    
    /// Get a setting by key
    pub async fn get(&self, key: &str) -> Result<Value, String> {
        let settings = self.settings.read().await;
        settings
            .get(key)
            .cloned()
            .ok_or_else(|| format!("Setting '{}' not found", key))
    }
    
    /// Set a setting
    pub async fn set(&self, key: &str, value: Value) -> Result<(), String> {
        {
            let mut settings = self.settings.write().await;
            settings.insert(key.to_string(), value);
        }
        
        self.save().await
    }
    
    /// Get all settings
    pub async fn get_all(&self) -> Result<HashMap<String, Value>, String> {
        let settings = self.settings.read().await;
        Ok(settings.clone())
    }
    
    /// Reset settings to defaults
    pub async fn reset(&self) -> Result<(), String> {
        let defaults = Self::default_settings();
        
        {
            let mut settings = self.settings.write().await;
            *settings = defaults;
        }
        
        self.save().await
    }
    
    /// Get default settings
    fn default_settings() -> HashMap<String, Value> {
        let mut defaults = HashMap::new();
        
        // Privacy & Network
        defaults.insert("allowUpdateCheck".to_string(), Value::Bool(false));
        defaults.insert("allowTelemetry".to_string(), Value::Bool(false));
        
        // Scanning
        defaults.insert("scanSecrets".to_string(), Value::Bool(true));
        defaults.insert("scanDependencies".to_string(), Value::Bool(true));
        defaults.insert("scanAiPatterns".to_string(), Value::Bool(true));
        defaults.insert("maxFileSizeMb".to_string(), Value::Number(10.into()));
        
        // UI
        defaults.insert("theme".to_string(), Value::String("dark".to_string()));
        defaults.insert("showNotifications".to_string(), Value::Bool(true));
        
        // Advanced
        defaults.insert("enablePlugins".to_string(), Value::Bool(true));
        defaults.insert("pluginSandboxEnabled".to_string(), Value::Bool(true));
        
        defaults
    }
    
    /// Save settings to disk
    async fn save(&self) -> Result<(), String> {
        let settings = self.settings.read().await;
        
        let file = SettingsFile {
            version: 1,
            settings: settings.clone(),
        };
        
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;
        
        let path = self.settings_path()?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create settings directory: {}", e))?;
        }
        
        tokio::fs::write(&path, content)
            .await
            .map_err(|e| format!("Failed to write settings: {}", e))?;
        
        info!("Settings saved to {:?}", path);
        Ok(())
    }
    
    /// List recent scans
    pub async fn list_scans(&self, limit: u32) -> Result<Vec<ScanResult>, String> {
        let scans = self.scans.read().await;
        let limit = limit as usize;
        
        Ok(scans.iter().take(limit).cloned().collect())
    }
    
    /// Add a scan to history
    pub async fn add_scan(&self, scan: ScanResult) -> Result<(), String> {
        {
            let mut scans = self.scans.write().await;
            scans.insert(0, scan);
            
            // Keep only last 100 scans
            if scans.len() > 100 {
                scans.truncate(100);
            }
        }
        
        self.save_scans().await
    }
    
    /// Save scans to disk
    async fn save_scans(&self) -> Result<(), String> {
        let scans = self.scans.read().await;
        
        let content = serde_json::to_string_pretty(&*scans)
            .map_err(|e| format!("Failed to serialize scans: {}", e))?;
        
        let path = self.scans_path()?;
        
        tokio::fs::write(&path, content)
            .await
            .map_err(|e| format!("Failed to write scans: {}", e))?;
        
        Ok(())
    }
}
