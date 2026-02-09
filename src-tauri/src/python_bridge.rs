//! ByteGuardX Desktop - Python Engine Bridge
//!
//! Manages communication with the Python scanning engine via stdin/stdout IPC.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tauri::AppHandle;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use log::{info, warn, error, debug};
use chrono::Utc;

use crate::commands::{
    ScanOptions, ScanResult, ScanStatus, ScanSummary, 
    PluginInfo, Vulnerability, SecretFinding
};

/// Manages the Python engine process
pub struct PythonEngineManager {
    app_handle: AppHandle,
    process: Arc<Mutex<Option<Child>>>,
    active_scans: Arc<RwLock<HashMap<String, ScanStatus>>>,
    results_cache: Arc<RwLock<HashMap<String, ScanResult>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineRequest {
    cmd: String,
    args: Value,
    request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineResponse {
    success: bool,
    data: Option<Value>,
    error: Option<String>,
    request_id: String,
}

impl PythonEngineManager {
    /// Create a new Python engine manager
    pub fn new(app_handle: AppHandle) -> Self {
        Self {
            app_handle,
            process: Arc::new(Mutex::new(None)),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            results_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Get Python executable path
    fn python_path() -> &'static str {
        if cfg!(target_os = "windows") {
            "python"
        } else {
            "python3"
        }
    }
    
    /// Get the engine CLI script path
    fn engine_script_path(&self) -> Result<String, String> {
        // Try to find the engine script relative to the app
        let possible_paths = [
            "engine/cli.py",
            "../engine/cli.py",
            "byteguardx/engine/cli.py",
        ];
        
        for path in &possible_paths {
            if std::path::Path::new(path).exists() {
                return Ok(path.to_string());
            }
        }
        
        // Fallback: use the byteguardx module directly
        Ok("-m byteguardx.engine.cli".to_string())
    }
    
    /// Check if Python is available and get version
    pub async fn get_python_version(&self) -> Result<String, String> {
        let output = Command::new(Self::python_path())
            .arg("--version")
            .output()
            .await
            .map_err(|e| format!("Failed to run Python: {}", e))?;
        
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout);
            Ok(version.trim().to_string())
        } else {
            Err("Python not available".to_string())
        }
    }
    
    /// Send a command to the engine and get response
    async fn send_command(&self, cmd: &str, args: Value) -> Result<Value, String> {
        let request_id = uuid::Uuid::new_v4().to_string();
        
        let request = EngineRequest {
            cmd: cmd.to_string(),
            args,
            request_id: request_id.clone(),
        };
        
        let request_json = serde_json::to_string(&request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;
        
        debug!("Sending command to engine: {}", cmd);
        
        // For now, spawn a new process for each command
        // In production, we'd maintain a persistent process
        let output = Command::new(Self::python_path())
            .args(["-c", &format!(r#"
import sys
import json

# Read request
request = json.loads('{}')
cmd = request['cmd']
args = request['args']

# Process command
if cmd == 'health':
    result = {{'status': 'ok', 'version': '1.0.0'}}
elif cmd == 'scan':
    result = {{'status': 'completed', 'files_scanned': 10, 'vulnerabilities': []}}
else:
    result = {{'error': 'Unknown command'}}

# Write response
response = {{'success': True, 'data': result, 'error': None, 'request_id': request['request_id']}}
print(json.dumps(response))
"#, request_json.replace('\\', "\\\\").replace('\'', "\\'"))])
            .output()
            .await
            .map_err(|e| format!("Failed to execute Python: {}", e))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Python command failed: {}", stderr));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let response: EngineResponse = serde_json::from_str(&stdout)
            .map_err(|e| format!("Failed to parse response: {} (raw: {})", e, stdout))?;
        
        if response.success {
            response.data.ok_or_else(|| "No data in response".to_string())
        } else {
            Err(response.error.unwrap_or_else(|| "Unknown error".to_string()))
        }
    }
    
    /// Run a scan
    pub async fn run_scan(
        &self,
        scan_id: &str,
        path: &str,
        options: &ScanOptions,
    ) -> Result<ScanResult, String> {
        info!("Running scan {} on {}", scan_id, path);
        
        // Mark scan as running
        {
            let mut scans = self.active_scans.write().await;
            scans.insert(scan_id.to_string(), ScanStatus::Running);
        }
        
        // Execute scan via Python engine
        let args = serde_json::json!({
            "path": path,
            "scan_secrets": options.scan_secrets,
            "scan_dependencies": options.scan_dependencies,
            "scan_ai_patterns": options.scan_ai_patterns,
            "max_file_size": options.max_file_size,
            "excluded_paths": options.excluded_paths,
        });
        
        let started_at = Utc::now();
        
        // For now, create a mock result
        // In production, this would call the actual Python engine
        let result = self.execute_scan_mock(scan_id, path, options, started_at).await?;
        
        // Cache results
        {
            let mut cache = self.results_cache.write().await;
            cache.insert(scan_id.to_string(), result.clone());
        }
        
        // Mark as completed
        {
            let mut scans = self.active_scans.write().await;
            scans.insert(scan_id.to_string(), ScanStatus::Completed);
        }
        
        Ok(result)
    }
    
    /// Mock scan execution (replace with actual engine call)
    async fn execute_scan_mock(
        &self,
        scan_id: &str,
        path: &str,
        options: &ScanOptions,
        started_at: chrono::DateTime<Utc>,
    ) -> Result<ScanResult, String> {
        // Simulate scan delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        Ok(ScanResult {
            scan_id: scan_id.to_string(),
            status: ScanStatus::Completed,
            started_at,
            completed_at: Some(Utc::now()),
            files_scanned: 0,
            vulnerabilities: vec![],
            secrets_found: vec![],
            summary: ScanSummary {
                total_files: 0,
                total_vulnerabilities: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                secrets_count: 0,
            },
        })
    }
    
    /// Get scan status
    pub async fn get_status(&self, scan_id: &str) -> Result<ScanStatus, String> {
        let scans = self.active_scans.read().await;
        scans
            .get(scan_id)
            .cloned()
            .ok_or_else(|| format!("Scan {} not found", scan_id))
    }
    
    /// Cancel a running scan
    pub async fn cancel_scan(&self, scan_id: &str) -> Result<bool, String> {
        let mut scans = self.active_scans.write().await;
        
        if let Some(status) = scans.get_mut(scan_id) {
            if matches!(status, ScanStatus::Running) {
                *status = ScanStatus::Cancelled;
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Get scan results
    pub async fn get_results(&self, scan_id: &str) -> Result<ScanResult, String> {
        let cache = self.results_cache.read().await;
        cache
            .get(scan_id)
            .cloned()
            .ok_or_else(|| format!("Results for scan {} not found", scan_id))
    }
    
    /// List installed plugins
    pub async fn list_plugins(&self) -> Result<Vec<PluginInfo>, String> {
        // In production, this would query the Python engine
        Ok(vec![])
    }
    
    /// Install a plugin from local file
    pub async fn install_plugin(&self, path: &str) -> Result<PluginInfo, String> {
        info!("Installing plugin from {}", path);
        
        // Validate file exists
        if !std::path::Path::new(path).exists() {
            return Err("Plugin file not found".to_string());
        }
        
        // In production, this would:
        // 1. Verify checksum
        // 2. Validate manifest
        // 3. Copy to plugins directory
        // 4. Register with engine
        
        Err("Plugin installation not yet implemented".to_string())
    }
    
    /// Uninstall a plugin
    pub async fn uninstall_plugin(&self, plugin_id: &str) -> Result<bool, String> {
        warn!("Uninstalling plugin: {}", plugin_id);
        
        // In production, this would:
        // 1. Stop plugin if running
        // 2. Remove from registry
        // 3. Delete files
        
        Err("Plugin uninstallation not yet implemented".to_string())
    }
    
    /// Export scan results to a report
    pub async fn export_report(
        &self,
        scan_id: &str,
        format: &str,
        output_path: &str,
    ) -> Result<String, String> {
        let results = self.get_results(scan_id).await?;
        
        let content = match format {
            "json" => serde_json::to_string_pretty(&results)
                .map_err(|e| format!("Failed to serialize: {}", e))?,
            "csv" => {
                // Simple CSV export
                let mut csv = String::from("ID,Severity,Title,File,Line\n");
                for vuln in &results.vulnerabilities {
                    csv.push_str(&format!(
                        "{},{},{},{},{}\n",
                        vuln.id,
                        vuln.severity,
                        vuln.title.replace(',', ";"),
                        vuln.file_path.replace(',', ";"),
                        vuln.line_number.unwrap_or(0)
                    ));
                }
                csv
            }
            "html" => {
                // Simple HTML export
                format!(r#"<!DOCTYPE html>
<html>
<head><title>ByteGuardX Report - {}</title></head>
<body>
<h1>Security Scan Report</h1>
<p>Scan ID: {}</p>
<p>Files Scanned: {}</p>
<p>Vulnerabilities: {}</p>
</body>
</html>"#,
                    scan_id,
                    scan_id,
                    results.files_scanned,
                    results.vulnerabilities.len()
                )
            }
            _ => return Err(format!("Unsupported format: {}", format)),
        };
        
        tokio::fs::write(output_path, &content)
            .await
            .map_err(|e| format!("Failed to write report: {}", e))?;
        
        info!("Exported report to {}", output_path);
        Ok(output_path.to_string())
    }
}
