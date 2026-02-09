//! ByteGuardX Desktop - Tauri Command Handlers
//!
//! This module contains all IPC command handlers that the frontend can invoke.
//! All inputs are validated before processing.

use serde::{Deserialize, Serialize};
use tauri::{command, State, AppHandle};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use log::{info, warn, error};

use crate::storage::SettingsStorage;
use crate::python_bridge::PythonEngineManager;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub scan_secrets: bool,
    pub scan_dependencies: bool,
    pub scan_ai_patterns: bool,
    pub max_file_size: Option<u64>,
    pub excluded_paths: Option<Vec<String>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_secrets: true,
            scan_dependencies: true,
            scan_ai_patterns: true,
            max_file_size: Some(10 * 1024 * 1024), // 10MB
            excluded_paths: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub files_scanned: u32,
    pub vulnerabilities: Vec<Vulnerability>,
    pub secrets_found: Vec<SecretFinding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub id: String,
    pub secret_type: String,
    pub file_path: String,
    pub line_number: u32,
    pub masked_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_files: u32,
    pub total_vulnerabilities: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub secrets_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub version: String,
    pub python_available: bool,
    pub python_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub python_engine: bool,
    pub storage: bool,
    pub plugins: bool,
    pub last_check: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub summary: DashboardSummary,
    pub recent_scans: Vec<RecentScan>,
    pub trends: DashboardTrends,
    pub security_score: u32,
    pub active_threats: u32,
    pub scan_coverage: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSummary {
    pub total_scans: u32,
    pub total_findings: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub last_scan_time: Option<DateTime<Utc>>,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentScan {
    pub id: String,
    pub path: String,
    pub status: String,
    pub findings: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardTrends {
    pub weekly_findings: Vec<u32>,
    pub scan_frequency: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStats {
    pub total_executions: u32,
    pub success_rate: f32,
    pub average_execution_time: f32,
}

// ============================================================================
// Scan Commands
// ============================================================================

/// Start a new scan on the specified path
#[command]
pub async fn run_scan(
    path: String,
    options: Option<ScanOptions>,
    engine: State<'_, PythonEngineManager>,
) -> Result<ScanResult, String> {
    // Validate path
    let path = validate_path(&path)?;
    let options = options.unwrap_or_default();
    
    info!("Starting scan on path: {}", path);
    
    // Create scan request
    let scan_id = Uuid::new_v4().to_string();
    
    // Execute scan via Python engine
    engine.run_scan(&scan_id, &path, &options).await
        .map_err(|e| {
            error!("Scan failed: {}", e);
            format!("Scan failed: {}", e)
        })
}

/// Get the current status of a running scan
#[command]
pub async fn get_scan_status(
    scan_id: String,
    engine: State<'_, PythonEngineManager>,
) -> Result<ScanStatus, String> {
    let scan_id = validate_scan_id(&scan_id)?;
    engine.get_status(&scan_id).await
}

/// Cancel a running scan
#[command]
pub async fn cancel_scan(
    scan_id: String,
    engine: State<'_, PythonEngineManager>,
) -> Result<bool, String> {
    let scan_id = validate_scan_id(&scan_id)?;
    info!("Cancelling scan: {}", scan_id);
    engine.cancel_scan(&scan_id).await
}

/// Get results of a completed scan
#[command]
pub async fn get_scan_results(
    scan_id: String,
    engine: State<'_, PythonEngineManager>,
) -> Result<ScanResult, String> {
    let scan_id = validate_scan_id(&scan_id)?;
    engine.get_results(&scan_id).await
}

/// List all scans (recent history)
#[command]
pub async fn list_scans(
    limit: Option<u32>,
    storage: State<'_, SettingsStorage>,
) -> Result<Vec<ScanResult>, String> {
    let limit = limit.unwrap_or(50).min(100);
    storage.list_scans(limit).await
}

/// Get dashboard statistics
#[command]
pub async fn get_dashboard_stats(
    storage: State<'_, SettingsStorage>,
) -> Result<DashboardStats, String> {
    let scans = storage.list_scans(1000).await?;
    
    let total_scans = scans.len() as u32;
    let mut total_findings = 0;
    let mut critical_findings = 0;
    let mut high_findings = 0;
    let mut medium_findings = 0;
    let mut low_findings = 0;
    let mut last_scan_time = None;
    
    let mut recent_scans = Vec::new();
    
    for (i, scan) in scans.iter().enumerate() {
        if i < 5 {
            recent_scans.push(RecentScan {
                id: scan.scan_id.clone(),
                path: "Directory scan".to_string(), // Simplified for now
                status: match scan.status {
                    ScanStatus::Completed => "completed".to_string(),
                    ScanStatus::Running => "running".to_string(),
                    ScanStatus::Failed => "failed".to_string(),
                    _ => "pending".to_string(),
                },
                findings: scan.summary.total_vulnerabilities,
                timestamp: scan.started_at,
            });
        }
        
        total_findings += scan.summary.total_vulnerabilities;
        critical_findings += scan.summary.critical_count;
        high_findings += scan.summary.high_count;
        medium_findings += scan.summary.medium_count;
        low_findings += scan.summary.low_count;
        
        if last_scan_time.is_none() || scan.started_at > last_scan_time.unwrap() {
            last_scan_time = Some(scan.started_at);
        }
    }
    
    // Calculate risk score (simple logic)
    let risk_base = 100.0;
    let risk_deduction = (critical_findings as f32 * 10.0) + (high_findings as f32 * 5.0) + (medium_findings as f32 * 2.0);
    let risk_score = (risk_base - risk_deduction).max(0.0) as u32;

    Ok(DashboardStats {
        summary: DashboardSummary {
            total_scans,
            total_findings,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            last_scan_time,
            risk_score,
        },
        recent_scans,
        trends: DashboardTrends {
            weekly_findings: vec![12, 8, 15, 6, 9, 11, 7], // Mock trends for now
            scan_frequency: vec![3, 5, 2, 4, 6, 3, 4],     // Mock trends for now
        },
        security_score: risk_score,
        active_threats: critical_findings + high_findings,
        scan_coverage: 95.0, // Mock
    })
}

/// Get plugin statistics
#[command]
pub async fn get_plugin_stats(
    _storage: State<'_, SettingsStorage>,
) -> Result<PluginStats, String> {
    // Mock plugin stats for now
    Ok(PluginStats {
        total_executions: 1247,
        success_rate: 0.985,
        average_execution_time: 1.2,
    })
}

// ============================================================================
// Settings Commands
// ============================================================================

/// Get a specific setting by key
#[command]
pub async fn get_setting(
    key: String,
    storage: State<'_, SettingsStorage>,
) -> Result<serde_json::Value, String> {
    let key = validate_setting_key(&key)?;
    storage.get(&key).await
}

/// Set a specific setting
#[command]
pub async fn set_setting(
    key: String,
    value: serde_json::Value,
    storage: State<'_, SettingsStorage>,
) -> Result<(), String> {
    let key = validate_setting_key(&key)?;
    storage.set(&key, value).await
}

/// Get all settings as a map
#[command]
pub async fn get_all_settings(
    storage: State<'_, SettingsStorage>,
) -> Result<HashMap<String, serde_json::Value>, String> {
    storage.get_all().await
}

/// Reset settings to defaults
#[command]
pub async fn reset_settings(
    storage: State<'_, SettingsStorage>,
) -> Result<(), String> {
    warn!("Resetting all settings to defaults");
    storage.reset().await
}

// ============================================================================
// Plugin Commands
// ============================================================================

/// List all installed plugins
#[command]
pub async fn list_plugins(
    engine: State<'_, PythonEngineManager>,
) -> Result<Vec<PluginInfo>, String> {
    engine.list_plugins().await
}

/// Install a plugin from a local file
#[command]
pub async fn install_plugin_local(
    path: String,
    engine: State<'_, PythonEngineManager>,
) -> Result<PluginInfo, String> {
    let path = validate_path(&path)?;
    info!("Installing plugin from: {}", path);
    engine.install_plugin(&path).await
}

/// Uninstall a plugin by ID
#[command]
pub async fn uninstall_plugin(
    plugin_id: String,
    engine: State<'_, PythonEngineManager>,
) -> Result<bool, String> {
    let plugin_id = validate_plugin_id(&plugin_id)?;
    warn!("Uninstalling plugin: {}", plugin_id);
    engine.uninstall_plugin(&plugin_id).await
}

/// Verify plugin checksum
#[command]
pub async fn verify_plugin_checksum(
    path: String,
    expected_hash: String,
) -> Result<bool, String> {
    use sha2::{Sha256, Digest};
    
    let path = validate_path(&path)?;
    
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());
    
    Ok(hash == expected_hash.to_lowercase())
}

// ============================================================================
// Report Commands
// ============================================================================

/// Export scan results to a report file
#[command]
pub async fn export_report(
    scan_id: String,
    format: String,
    output_path: String,
    engine: State<'_, PythonEngineManager>,
) -> Result<String, String> {
    let scan_id = validate_scan_id(&scan_id)?;
    let format = validate_report_format(&format)?;
    let output_path = validate_path(&output_path)?;
    
    info!("Exporting report for scan {} as {} to {}", scan_id, format, output_path);
    engine.export_report(&scan_id, &format, &output_path).await
}

/// Get available report formats
#[command]
pub fn get_report_formats() -> Vec<String> {
    vec![
        "pdf".to_string(),
        "html".to_string(),
        "json".to_string(),
        "csv".to_string(),
    ]
}

// ============================================================================
// System Commands
// ============================================================================

/// Get application version
#[command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get system information
#[command]
pub async fn get_system_info(
    engine: State<'_, PythonEngineManager>,
) -> Result<SystemInfo, String> {
    let python_info = engine.get_python_version().await;
    
    Ok(SystemInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        python_available: python_info.is_ok(),
        python_version: python_info.ok(),
    })
}

/// Check if Python is available
#[command]
pub async fn check_python_available(
    engine: State<'_, PythonEngineManager>,
) -> Result<bool, String> {
    engine.get_python_version().await.map(|_| true).or(Ok(false))
}

/// Get health status
#[command]
pub async fn get_health_status(
    engine: State<'_, PythonEngineManager>,
    storage: State<'_, SettingsStorage>,
) -> Result<HealthStatus, String> {
    let python_ok = engine.get_python_version().await.is_ok();
    let storage_ok = storage.get_all().await.is_ok();
    let plugins_ok = engine.list_plugins().await.is_ok();
    
    Ok(HealthStatus {
        healthy: python_ok && storage_ok,
        python_engine: python_ok,
        storage: storage_ok,
        plugins: plugins_ok,
        last_check: Utc::now(),
    })
}

// ============================================================================
// File Operations
// ============================================================================

/// Read a file safely (with size limits and path validation)
#[command]
pub async fn read_file_safe(
    path: String,
    max_size: Option<u64>,
) -> Result<String, String> {
    let path = validate_path(&path)?;
    let max_size = max_size.unwrap_or(10 * 1024 * 1024); // 10MB default
    
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| format!("Failed to read file metadata: {}", e))?;
    
    if metadata.len() > max_size {
        return Err(format!("File too large: {} bytes (max: {} bytes)", metadata.len(), max_size));
    }
    
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("Failed to read file: {}", e))
}

/// Write content to a file safely
#[command]
pub async fn write_file_safe(
    path: String,
    content: String,
) -> Result<(), String> {
    let path = validate_path(&path)?;
    
    tokio::fs::write(&path, content)
        .await
        .map_err(|e| format!("Failed to write file: {}", e))
}

// ============================================================================
// Validation Helpers
// ============================================================================

fn validate_path(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err("Path cannot be empty".to_string());
    }
    
    // Prevent path traversal attacks
    if path.contains("..") {
        return Err("Path traversal not allowed".to_string());
    }
    
    // Normalize path
    let path = path.replace('\\', "/");
    
    Ok(path)
}

fn validate_scan_id(scan_id: &str) -> Result<String, String> {
    // UUID v4 format
    if scan_id.len() != 36 {
        return Err("Invalid scan ID format".to_string());
    }
    
    Uuid::parse_str(scan_id)
        .map(|_| scan_id.to_string())
        .map_err(|_| "Invalid scan ID".to_string())
}

fn validate_setting_key(key: &str) -> Result<String, String> {
    if key.is_empty() || key.len() > 100 {
        return Err("Invalid setting key".to_string());
    }
    
    // Only allow alphanumeric, underscore, dot
    if !key.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') {
        return Err("Setting key contains invalid characters".to_string());
    }
    
    Ok(key.to_string())
}

fn validate_plugin_id(plugin_id: &str) -> Result<String, String> {
    if plugin_id.is_empty() || plugin_id.len() > 100 {
        return Err("Invalid plugin ID".to_string());
    }
    
    if !plugin_id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Plugin ID contains invalid characters".to_string());
    }
    
    Ok(plugin_id.to_string())
}

fn validate_report_format(format: &str) -> Result<String, String> {
    let valid_formats = ["pdf", "html", "json", "csv"];
    let format = format.to_lowercase();
    
    if valid_formats.contains(&format.as_str()) {
        Ok(format)
    } else {
        Err(format!("Invalid report format. Valid formats: {:?}", valid_formats))
    }
}
