#!/usr/bin/env python3
"""
ByteGuardX Engine CLI - JSON-RPC style command interface

This module provides a CLI wrapper for the ByteGuardX scanning engine,
accepting JSON commands on stdin and returning JSON responses on stdout.

Protocol:
- Input: One JSON object per line (newline-delimited JSON)
- Output: One JSON response per line

Request format:
{
    "cmd": "scan",
    "args": {"path": "/project", "options": {}},
    "request_id": "uuid-string"
}

Response format:
{
    "success": true,
    "data": {...},
    "error": null,
    "request_id": "uuid-string"
}
"""

import sys
import json
import os
import logging
import traceback
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging to stderr (stdout is for JSON responses)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger('byteguardx.engine')


class EngineError(Exception):
    """Engine-specific error"""
    def __init__(self, message: str, code: str = "ENGINE_ERROR"):
        super().__init__(message)
        self.code = code


class ByteGuardXEngine:
    """Main engine class for vulnerability scanning"""
    
    def __init__(self):
        self.version = "1.0.0"
        self._scanner = None
        self._plugin_manager = None
        
    def _lazy_load_scanner(self):
        """Lazily load scanner to avoid import errors"""
        if self._scanner is None:
            try:
                from byteguardx.core.file_processor import FileProcessor
                from byteguardx.scanners.secret_scanner import SecretScanner
                self._scanner = {
                    'file_processor': FileProcessor(),
                    'secret_scanner': SecretScanner()
                }
                logger.info("Scanner modules loaded successfully")
            except ImportError as e:
                logger.warning(f"Could not load scanner modules: {e}")
                self._scanner = {}
        return self._scanner
    
    def handle_command(self, cmd_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a command and return structured response"""
        cmd = cmd_data.get("cmd", "")
        args = cmd_data.get("args", {})
        request_id = cmd_data.get("request_id", "")
        
        try:
            if cmd == "health":
                result = self.cmd_health(args)
            elif cmd == "scan":
                result = self.cmd_scan(args)
            elif cmd == "scan_status":
                result = self.cmd_scan_status(args)
            elif cmd == "list_plugins":
                result = self.cmd_list_plugins(args)
            elif cmd == "install_plugin":
                result = self.cmd_install_plugin(args)
            elif cmd == "uninstall_plugin":
                result = self.cmd_uninstall_plugin(args)
            elif cmd == "get_version":
                result = {"version": self.version}
            else:
                raise EngineError(f"Unknown command: {cmd}", "UNKNOWN_COMMAND")
            
            return {
                "success": True,
                "data": result,
                "error": None,
                "request_id": request_id
            }
            
        except EngineError as e:
            logger.error(f"Engine error: {e}")
            return {
                "success": False,
                "data": None,
                "error": {"message": str(e), "code": e.code},
                "request_id": request_id
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
            return {
                "success": False,
                "data": None,
                "error": {"message": str(e), "code": "INTERNAL_ERROR"},
                "request_id": request_id
            }
    
    def cmd_health(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Health check command"""
        return {
            "status": "ok",
            "version": self.version,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def cmd_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a path for vulnerabilities"""
        path = args.get("path")
        if not path:
            raise EngineError("Path is required", "MISSING_PATH")
        
        path = Path(path)
        if not path.exists():
            raise EngineError(f"Path does not exist: {path}", "PATH_NOT_FOUND")
        
        # Get scan options
        scan_secrets = args.get("scan_secrets", True)
        scan_dependencies = args.get("scan_dependencies", True)
        scan_ai_patterns = args.get("scan_ai_patterns", True)
        max_file_size = args.get("max_file_size", 10 * 1024 * 1024)  # 10MB
        excluded_paths = args.get("excluded_paths", [])
        
        logger.info(f"Starting scan on {path}")
        
        # Initialize results
        vulnerabilities = []
        secrets_found = []
        files_scanned = 0
        
        try:
            scanner = self._lazy_load_scanner()
            
            # Collect files
            if path.is_file():
                files = [path]
            else:
                files = list(path.rglob("*"))
            
            # Filter files
            files = [f for f in files if f.is_file() and f.stat().st_size <= max_file_size]
            files = [f for f in files if not any(ex in str(f) for ex in excluded_paths)]
            
            # Scan each file
            for file_path in files:
                try:
                    files_scanned += 1
                    
                    # Read file content
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                    except Exception:
                        continue
                    
                    # Secret scanning
                    if scan_secrets and 'secret_scanner' in scanner:
                        try:
                            file_secrets = scanner['secret_scanner'].scan_content(content, str(file_path))
                            for secret in file_secrets:
                                secrets_found.append({
                                    "id": f"secret-{len(secrets_found)+1}",
                                    "secret_type": secret.get("type", "unknown"),
                                    "file_path": str(file_path),
                                    "line_number": secret.get("line", 0),
                                    "masked_value": secret.get("masked", "***")
                                })
                        except Exception as e:
                            logger.debug(f"Secret scan failed for {file_path}: {e}")
                    
                    # Simple vulnerability detection (pattern-based)
                    vulns = self._detect_vulnerabilities(str(file_path), content)
                    vulnerabilities.extend(vulns)
                    
                except Exception as e:
                    logger.warning(f"Error scanning {file_path}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            raise EngineError(str(e), "SCAN_ERROR")
        
        # Build summary
        summary = {
            "total_files": files_scanned,
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": len([v for v in vulnerabilities if v["severity"] == "critical"]),
            "high_count": len([v for v in vulnerabilities if v["severity"] == "high"]),
            "medium_count": len([v for v in vulnerabilities if v["severity"] == "medium"]),
            "low_count": len([v for v in vulnerabilities if v["severity"] == "low"]),
            "secrets_count": len(secrets_found)
        }
        
        return {
            "status": "completed",
            "files_scanned": files_scanned,
            "vulnerabilities": vulnerabilities,
            "secrets_found": secrets_found,
            "summary": summary
        }
    
    def _detect_vulnerabilities(self, file_path: str, content: str) -> list:
        """Simple pattern-based vulnerability detection"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Patterns to detect
        patterns = [
            {
                "pattern": "eval(",
                "severity": "high",
                "title": "Dangerous eval() usage",
                "description": "eval() can execute arbitrary code",
                "recommendation": "Use safer alternatives like JSON.parse()"
            },
            {
                "pattern": "exec(",
                "severity": "high", 
                "title": "Dangerous exec() usage",
                "description": "exec() can execute arbitrary code",
                "recommendation": "Avoid dynamic code execution"
            },
            {
                "pattern": "password = ",
                "severity": "medium",
                "title": "Hardcoded password",
                "description": "Password appears to be hardcoded",
                "recommendation": "Use environment variables or secure vault"
            },
            {
                "pattern": "TODO: fix security",
                "severity": "low",
                "title": "Security TODO found",
                "description": "Security-related TODO comment",
                "recommendation": "Address security TODO items"
            },
        ]
        
        for i, line in enumerate(lines, 1):
            for p in patterns:
                if p["pattern"].lower() in line.lower():
                    vulnerabilities.append({
                        "id": f"vuln-{len(vulnerabilities)+1}",
                        "severity": p["severity"],
                        "title": p["title"],
                        "description": p["description"],
                        "file_path": file_path,
                        "line_number": i,
                        "recommendation": p.get("recommendation")
                    })
        
        return vulnerabilities
    
    def cmd_scan_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan status"""
        scan_id = args.get("scan_id")
        if not scan_id:
            raise EngineError("scan_id is required", "MISSING_SCAN_ID")
        
        # For now, return completed since we run scans synchronously
        return {
            "scan_id": scan_id,
            "status": "completed"
        }
    
    def cmd_list_plugins(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List installed plugins"""
        plugins = []
        
        # Check plugins directory
        plugins_dir = Path(__file__).parent.parent / "data" / "plugins"
        if plugins_dir.exists():
            for plugin_dir in plugins_dir.iterdir():
                if plugin_dir.is_dir():
                    manifest_path = plugin_dir / "manifest.json"
                    if manifest_path.exists():
                        try:
                            manifest = json.loads(manifest_path.read_text())
                            plugins.append({
                                "id": manifest.get("id", plugin_dir.name),
                                "name": manifest.get("name", plugin_dir.name),
                                "version": manifest.get("version", "1.0.0"),
                                "description": manifest.get("description", ""),
                                "author": manifest.get("author", "Unknown"),
                                "enabled": manifest.get("enabled", True)
                            })
                        except Exception as e:
                            logger.warning(f"Could not load plugin manifest: {e}")
        
        return {"plugins": plugins}
    
    def cmd_install_plugin(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Install a plugin from a local file"""
        path = args.get("path")
        if not path:
            raise EngineError("path is required", "MISSING_PATH")
        
        path = Path(path)
        if not path.exists():
            raise EngineError(f"Plugin file not found: {path}", "FILE_NOT_FOUND")
        
        # Verify checksum if provided
        expected_checksum = args.get("checksum")
        if expected_checksum:
            import hashlib
            actual_checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_checksum != expected_checksum:
                raise EngineError("Checksum verification failed", "CHECKSUM_MISMATCH")
        
        # TODO: Implement actual plugin installation
        raise EngineError("Plugin installation not yet implemented", "NOT_IMPLEMENTED")
    
    def cmd_uninstall_plugin(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Uninstall a plugin"""
        plugin_id = args.get("plugin_id")
        if not plugin_id:
            raise EngineError("plugin_id is required", "MISSING_PLUGIN_ID")
        
        # TODO: Implement actual plugin uninstallation
        raise EngineError("Plugin uninstallation not yet implemented", "NOT_IMPLEMENTED")


def main():
    """Main entry point - read commands from stdin, write responses to stdout"""
    engine = ByteGuardXEngine()
    
    # Log to stderr
    logger.info("ByteGuardX Engine started")
    logger.info(f"Python {sys.version}")
    
    # Check if running interactively or with piped input
    if sys.stdin.isatty():
        logger.info("Running in interactive mode (type JSON commands)")
    
    # Process commands line by line
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            cmd_data = json.loads(line)
            response = engine.handle_command(cmd_data)
        except json.JSONDecodeError as e:
            response = {
                "success": False,
                "data": None,
                "error": {"message": f"Invalid JSON: {e}", "code": "PARSE_ERROR"},
                "request_id": ""
            }
        
        # Output response as JSON
        print(json.dumps(response), flush=True)
    
    logger.info("ByteGuardX Engine stopped")


if __name__ == "__main__":
    main()
