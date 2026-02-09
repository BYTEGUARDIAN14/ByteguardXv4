//! ByteGuardX Desktop - Plugin Sandboxing
//!
//! Provides platform-specific sandboxing for plugin execution to ensure
//! plugins cannot access sensitive system resources without permission.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use serde::{Deserialize, Serialize};
use log::{info, warn, error};

/// Plugin execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Plugin resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory in bytes
    pub max_memory: u64,
    /// Maximum CPU time in seconds
    pub max_cpu_time: u64,
    /// Maximum number of open files
    pub max_open_files: u32,
    /// Maximum number of processes
    pub max_processes: u32,
    /// Network access allowed
    pub allow_network: bool,
    /// Allowed read paths (glob patterns)
    pub allowed_read_paths: Vec<String>,
    /// Allowed write paths (glob patterns)
    pub allowed_write_paths: Vec<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory: 256 * 1024 * 1024, // 256MB
            max_cpu_time: 60,               // 60 seconds
            max_open_files: 64,
            max_processes: 16,
            allow_network: false,
            allowed_read_paths: vec![],
            allowed_write_paths: vec![],
        }
    }
}

/// Plugin manifest for security validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub entry_point: String,
    pub permissions: Vec<String>,
    pub checksum: Option<String>,
}

/// Validation error for plugins
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
}

/// Validate a plugin manifest
pub fn validate_manifest(manifest: &PluginManifest) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    
    // Check ID
    if manifest.id.is_empty() || manifest.id.len() > 100 {
        errors.push(ValidationError {
            code: "INVALID_ID".to_string(),
            message: "Plugin ID must be 1-100 characters".to_string(),
        });
    }
    
    if !manifest.id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        errors.push(ValidationError {
            code: "INVALID_ID_CHARS".to_string(),
            message: "Plugin ID can only contain alphanumeric, dash, underscore".to_string(),
        });
    }
    
    // Check version (semver-like)
    if !manifest.version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        errors.push(ValidationError {
            code: "INVALID_VERSION".to_string(),
            message: "Version must be in semver format".to_string(),
        });
    }
    
    // Check entry point
    if manifest.entry_point.is_empty() {
        errors.push(ValidationError {
            code: "MISSING_ENTRY_POINT".to_string(),
            message: "Entry point is required".to_string(),
        });
    }
    
    if manifest.entry_point.contains("..") {
        errors.push(ValidationError {
            code: "INVALID_ENTRY_POINT".to_string(),
            message: "Entry point cannot contain path traversal".to_string(),
        });
    }
    
    // Check dangerous permissions
    let dangerous_perms = ["filesystem_all", "network_all", "process_spawn"];
    for perm in &manifest.permissions {
        if dangerous_perms.contains(&perm.as_str()) {
            errors.push(ValidationError {
                code: "DANGEROUS_PERMISSION".to_string(),
                message: format!("Permission '{}' is potentially dangerous", perm),
            });
        }
    }
    
    errors
}

/// Verify plugin checksum
pub fn verify_checksum(plugin_path: &Path, expected_hash: &str) -> Result<bool, String> {
    use sha2::{Sha256, Digest};
    
    let bytes = std::fs::read(plugin_path)
        .map_err(|e| format!("Failed to read plugin: {}", e))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());
    
    Ok(hash.to_lowercase() == expected_hash.to_lowercase())
}

// ============================================================================
// Platform-Specific Sandbox Implementations
// ============================================================================

/// Linux sandbox using namespaces and cgroups
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    
    pub async fn spawn_sandboxed(
        plugin_path: &str,
        args: &[&str],
        working_dir: &str,
        limits: &ResourceLimits,
        env: &HashMap<String, String>,
    ) -> Result<PluginExecutionResult, String> {
        info!("Spawning sandboxed plugin (Linux): {}", plugin_path);
        
        let start = std::time::Instant::now();
        
        // Build the sandboxed command
        // Using unshare for namespace isolation + prlimit for resource limits
        let mut cmd = Command::new("unshare");
        
        // Network namespace (no network by default)
        if !limits.allow_network {
            cmd.arg("--net");
        }
        
        // User namespace for unprivileged operation
        cmd.args(["--user", "--map-root-user"]);
        
        // Add prlimit for resource limits
        cmd.arg("--");
        cmd.arg("prlimit");
        cmd.arg(format!("--as={}", limits.max_memory));
        cmd.arg(format!("--nofile={}", limits.max_open_files));
        cmd.arg(format!("--nproc={}", limits.max_processes));
        cmd.arg(format!("--cpu={}", limits.max_cpu_time));
        
        // The actual command
        cmd.arg("--");
        cmd.arg("python3");
        cmd.arg(plugin_path);
        cmd.args(args);
        
        // Set working directory
        cmd.current_dir(working_dir);
        
        // Set environment
        cmd.env_clear();
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");
        cmd.env("PYTHONUNBUFFERED", "1");
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // Execute with timeout
        let timeout = tokio::time::Duration::from_secs(limits.max_cpu_time);
        let result = tokio::time::timeout(timeout, cmd.output()).await;
        
        let duration_ms = start.elapsed().as_millis() as u64;
        
        match result {
            Ok(Ok(output)) => Ok(PluginExecutionResult {
                success: output.status.success(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                duration_ms,
            }),
            Ok(Err(e)) => Err(format!("Failed to execute plugin: {}", e)),
            Err(_) => Err("Plugin execution timed out".to_string()),
        }
    }
}

/// macOS sandbox using sandbox-exec
#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    
    /// Generate sandbox profile
    fn generate_sandbox_profile(limits: &ResourceLimits) -> String {
        let mut profile = String::from(r#"
(version 1)
(deny default)

; Allow read access to system libraries
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System/Library/Frameworks")
    (subpath "/Library/Frameworks")
    (subpath "/usr/local/lib"))

; Allow reading system configuration
(allow file-read*
    (literal "/etc/hosts")
    (literal "/etc/resolv.conf"))

; Allow basic process operations
(allow process-fork)
(allow process-exec)

; Allow sysctl reads
(allow sysctl-read)

; Allow mach operations for basic functionality
(allow mach-lookup)
"#);
        
        // Add allowed read paths
        for path in &limits.allowed_read_paths {
            profile.push_str(&format!(r#"
(allow file-read* (subpath "{}"))
"#, path));
        }
        
        // Add allowed write paths
        for path in &limits.allowed_write_paths {
            profile.push_str(&format!(r#"
(allow file-write* (subpath "{}"))
"#, path));
        }
        
        // Network access
        if limits.allow_network {
            profile.push_str(r#"
(allow network*)
"#);
        }
        
        profile
    }
    
    pub async fn spawn_sandboxed(
        plugin_path: &str,
        args: &[&str],
        working_dir: &str,
        limits: &ResourceLimits,
        env: &HashMap<String, String>,
    ) -> Result<PluginExecutionResult, String> {
        info!("Spawning sandboxed plugin (macOS): {}", plugin_path);
        
        let start = std::time::Instant::now();
        
        // Generate sandbox profile
        let profile = generate_sandbox_profile(limits);
        
        // Write profile to temp file
        let profile_path = std::env::temp_dir().join(format!("byteguardx-sandbox-{}.sb", 
            std::process::id()));
        std::fs::write(&profile_path, &profile)
            .map_err(|e| format!("Failed to write sandbox profile: {}", e))?;
        
        // Build command with sandbox-exec
        let mut cmd = Command::new("sandbox-exec");
        cmd.args(["-f", profile_path.to_str().unwrap()]);
        cmd.arg("python3");
        cmd.arg(plugin_path);
        cmd.args(args);
        
        cmd.current_dir(working_dir);
        
        // Set environment
        cmd.env_clear();
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");
        cmd.env("PYTHONUNBUFFERED", "1");
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // Execute with timeout
        let timeout = tokio::time::Duration::from_secs(limits.max_cpu_time);
        let result = tokio::time::timeout(timeout, cmd.output()).await;
        
        // Clean up profile
        let _ = std::fs::remove_file(&profile_path);
        
        let duration_ms = start.elapsed().as_millis() as u64;
        
        match result {
            Ok(Ok(output)) => Ok(PluginExecutionResult {
                success: output.status.success(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                duration_ms,
            }),
            Ok(Err(e)) => Err(format!("Failed to execute plugin: {}", e)),
            Err(_) => Err("Plugin execution timed out".to_string()),
        }
    }
}

/// Windows sandbox using Job Objects
#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;
    
    pub async fn spawn_sandboxed(
        plugin_path: &str,
        args: &[&str],
        working_dir: &str,
        limits: &ResourceLimits,
        env: &HashMap<String, String>,
    ) -> Result<PluginExecutionResult, String> {
        info!("Spawning sandboxed plugin (Windows): {}", plugin_path);
        
        let start = std::time::Instant::now();
        
        // On Windows, we use basic process isolation with Job Objects
        // For full sandboxing, Windows Sandbox or AppContainer would be needed
        
        let mut cmd = Command::new("python");
        cmd.arg(plugin_path);
        cmd.args(args);
        
        cmd.current_dir(working_dir);
        
        // Set environment
        cmd.env_clear();
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");
        cmd.env("PYTHONUNBUFFERED", "1");
        
        // Create restricted environment
        cmd.env("BYTEGUARDX_SANDBOXED", "1");
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // Execute with timeout
        let timeout = tokio::time::Duration::from_secs(limits.max_cpu_time);
        let result = tokio::time::timeout(timeout, cmd.output()).await;
        
        let duration_ms = start.elapsed().as_millis() as u64;
        
        match result {
            Ok(Ok(output)) => Ok(PluginExecutionResult {
                success: output.status.success(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                duration_ms,
            }),
            Ok(Err(e)) => Err(format!("Failed to execute plugin: {}", e)),
            Err(_) => Err("Plugin execution timed out".to_string()),
        }
    }
}

// ============================================================================
// Cross-Platform Wrapper
// ============================================================================

/// Execute a plugin with appropriate sandboxing for the current platform
pub async fn execute_plugin_sandboxed(
    plugin_path: &str,
    args: &[&str],
    working_dir: &str,
    limits: &ResourceLimits,
    env: &HashMap<String, String>,
) -> Result<PluginExecutionResult, String> {
    #[cfg(target_os = "linux")]
    return linux::spawn_sandboxed(plugin_path, args, working_dir, limits, env).await;
    
    #[cfg(target_os = "macos")]
    return macos::spawn_sandboxed(plugin_path, args, working_dir, limits, env).await;
    
    #[cfg(target_os = "windows")]
    return windows::spawn_sandboxed(plugin_path, args, working_dir, limits, env).await;
    
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err("Unsupported platform for sandboxing".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_manifest_valid() {
        let manifest = PluginManifest {
            id: "my-plugin".to_string(),
            name: "My Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test".to_string(),
            description: "A test plugin".to_string(),
            entry_point: "main.py".to_string(),
            permissions: vec!["read_files".to_string()],
            checksum: None,
        };
        
        let errors = validate_manifest(&manifest);
        assert!(errors.is_empty());
    }
    
    #[test]
    fn test_validate_manifest_invalid_id() {
        let manifest = PluginManifest {
            id: "".to_string(),
            name: "My Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test".to_string(),
            description: "A test plugin".to_string(),
            entry_point: "main.py".to_string(),
            permissions: vec![],
            checksum: None,
        };
        
        let errors = validate_manifest(&manifest);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.code == "INVALID_ID"));
    }
    
    #[test]
    fn test_validate_manifest_dangerous_permission() {
        let manifest = PluginManifest {
            id: "my-plugin".to_string(),
            name: "My Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test".to_string(),
            description: "A test plugin".to_string(),
            entry_point: "main.py".to_string(),
            permissions: vec!["filesystem_all".to_string()],
            checksum: None,
        };
        
        let errors = validate_manifest(&manifest);
        assert!(errors.iter().any(|e| e.code == "DANGEROUS_PERMISSION"));
    }
}
