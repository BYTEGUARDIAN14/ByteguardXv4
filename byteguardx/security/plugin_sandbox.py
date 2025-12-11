"""
Plugin Sandbox Security System for ByteGuardX
Provides secure execution environment for untrusted plugins using Docker containers
"""

import os
import json
import logging
import tempfile
import hashlib
import subprocess
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import docker
from docker.errors import DockerException
import time
import signal

logger = logging.getLogger(__name__)

class PluginSandboxError(Exception):
    """Custom exception for plugin sandbox errors"""
    pass

class PluginValidator:
    """Validates plugin code for security issues"""
    
    # Dangerous function calls that should be blocked
    DANGEROUS_CALLS = [
        'eval', 'exec', 'compile', '__import__',
        'open("/etc', 'open("/proc', 'open("/sys',
        'os.system', 'subprocess.call', 'subprocess.run',
        'subprocess.Popen', 'commands.getoutput',
        'socket.socket', 'urllib.request', 'requests.get',
        'requests.post', 'http.client', 'ftplib',
        'smtplib', 'telnetlib', 'paramiko',
        'pickle.loads', 'marshal.loads', 'shelve.open',
        'ctypes', 'cffi', 'numpy.ctypeslib',
        'multiprocessing', 'threading.Thread',
        'asyncio.create_subprocess', 'concurrent.futures'
    ]
    
    # Required security headers for plugins
    REQUIRED_HEADERS = [
        'name', 'version', 'author', 'description',
        'permissions', 'trusted', 'hash'
    ]
    
    def validate_plugin_code(self, plugin_code: str, plugin_type: str = 'python') -> Tuple[bool, List[str]]:
        """
        Validate plugin code for security issues
        Returns: (is_safe, issues)
        """
        issues = []
        
        try:
            if plugin_type == 'python':
                issues.extend(self._validate_python_code(plugin_code))
            elif plugin_type == 'javascript':
                issues.extend(self._validate_javascript_code(plugin_code))
            
            return len(issues) == 0, issues
            
        except Exception as e:
            logger.error(f"Plugin validation error: {e}")
            return False, [f"Validation error: {str(e)}"]
    
    def validate_plugin_manifest(self, manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate plugin manifest"""
        issues = []
        
        # Check required headers
        for header in self.REQUIRED_HEADERS:
            if header not in manifest:
                issues.append(f"Missing required header: {header}")
        
        # Validate permissions
        permissions = manifest.get('permissions', [])
        if not isinstance(permissions, list):
            issues.append("Permissions must be a list")
        else:
            for permission in permissions:
                if not self._is_valid_permission(permission):
                    issues.append(f"Invalid permission: {permission}")
        
        # Validate hash
        if 'hash' in manifest:
            if not isinstance(manifest['hash'], str) or len(manifest['hash']) != 64:
                issues.append("Invalid hash format (must be SHA-256)")
        
        return len(issues) == 0, issues
    
    def _validate_python_code(self, code: str) -> List[str]:
        """Validate Python plugin code"""
        issues = []
        
        # Check for dangerous function calls
        for dangerous_call in self.DANGEROUS_CALLS:
            if dangerous_call in code:
                issues.append(f"Dangerous function call detected: {dangerous_call}")
        
        # Check for import statements
        import_issues = self._validate_python_imports(code)
        issues.extend(import_issues)
        
        # Try to compile code
        try:
            compile(code, '<plugin>', 'exec')
        except SyntaxError as e:
            issues.append(f"Syntax error: {str(e)}")
        
        return issues
    
    def _validate_javascript_code(self, code: str) -> List[str]:
        """Validate JavaScript plugin code"""
        issues = []
        
        dangerous_js_calls = [
            'eval(', 'Function(', 'setTimeout(', 'setInterval(',
            'require(', 'import(', 'fetch(', 'XMLHttpRequest',
            'WebSocket', 'Worker(', 'SharedWorker(',
            'document.', 'window.', 'global.', 'process.'
        ]
        
        for dangerous_call in dangerous_js_calls:
            if dangerous_call in code:
                issues.append(f"Dangerous JavaScript call detected: {dangerous_call}")
        
        return issues
    
    def _validate_python_imports(self, code: str) -> List[str]:
        """Validate Python import statements"""
        issues = []
        
        dangerous_modules = [
            'os', 'sys', 'subprocess', 'socket', 'urllib',
            'requests', 'http', 'ftplib', 'smtplib',
            'pickle', 'marshal', 'shelve', 'ctypes',
            'multiprocessing', 'threading', 'asyncio'
        ]
        
        lines = code.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                for dangerous_module in dangerous_modules:
                    if dangerous_module in line:
                        issues.append(f"Dangerous import on line {line_num}: {line}")
        
        return issues
    
    def _is_valid_permission(self, permission: str) -> bool:
        """Check if permission is valid"""
        valid_permissions = [
            'read_files', 'write_files', 'network_access',
            'system_info', 'user_data', 'scan_results'
        ]
        return permission in valid_permissions

class PluginSandbox:
    """Docker-based plugin sandbox for secure execution"""
    
    def __init__(self):
        self.docker_client = None
        self.temp_dir = Path(tempfile.gettempdir()) / "byteguardx_plugins"
        self.temp_dir.mkdir(exist_ok=True)
        self.validator = PluginValidator()
        
        # Initialize Docker client
        self._init_docker()
    
    def _init_docker(self):
        """Initialize Docker client"""
        try:
            self.docker_client = docker.from_env()
            # Test Docker connection
            self.docker_client.ping()
            logger.info("Docker client initialized successfully")
        except DockerException as e:
            logger.warning(f"Docker not available: {e}")
            self.docker_client = None
    
    def execute_plugin(self, plugin_code: str, plugin_manifest: Dict[str, Any],
                      input_data: Dict[str, Any] = None,
                      timeout: int = 30) -> Tuple[bool, Dict[str, Any]]:
        """
        Execute plugin in secure sandbox
        Returns: (success, result)
        """
        try:
            # Validate plugin
            is_safe, issues = self.validator.validate_plugin_code(plugin_code)
            if not is_safe:
                return False, {'error': 'Plugin validation failed', 'issues': issues}
            
            is_valid, manifest_issues = self.validator.validate_plugin_manifest(plugin_manifest)
            if not is_valid:
                return False, {'error': 'Manifest validation failed', 'issues': manifest_issues}
            
            # Check if plugin is trusted
            if plugin_manifest.get('trusted', False):
                return self._execute_trusted_plugin(plugin_code, input_data)
            else:
                return self._execute_sandboxed_plugin(plugin_code, plugin_manifest, input_data, timeout)
                
        except Exception as e:
            logger.error(f"Plugin execution error: {e}")
            return False, {'error': f'Execution failed: {str(e)}'}
    
    def _execute_trusted_plugin(self, plugin_code: str, input_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Execute trusted plugin in current process"""
        try:
            # Create restricted globals
            restricted_globals = {
                '__builtins__': {
                    'len': len, 'str': str, 'int': int, 'float': float,
                    'bool': bool, 'list': list, 'dict': dict, 'tuple': tuple,
                    'set': set, 'range': range, 'enumerate': enumerate,
                    'zip': zip, 'map': map, 'filter': filter,
                    'sorted': sorted, 'reversed': reversed,
                    'min': min, 'max': max, 'sum': sum, 'abs': abs,
                    'round': round, 'pow': pow, 'divmod': divmod
                },
                'input_data': input_data or {},
                'result': {}
            }
            
            # Execute plugin code
            exec(plugin_code, restricted_globals)
            
            return True, restricted_globals.get('result', {})
            
        except Exception as e:
            logger.error(f"Trusted plugin execution error: {e}")
            return False, {'error': f'Execution failed: {str(e)}'}
    
    def _execute_sandboxed_plugin(self, plugin_code: str, plugin_manifest: Dict[str, Any],
                                input_data: Dict[str, Any], timeout: int) -> Tuple[bool, Dict[str, Any]]:
        """Execute untrusted plugin in Docker sandbox"""
        if not self.docker_client:
            return False, {'error': 'Docker not available for sandboxing'}
        
        try:
            # Create temporary files
            plugin_id = hashlib.md5(plugin_code.encode()).hexdigest()[:8]
            plugin_dir = self.temp_dir / plugin_id
            plugin_dir.mkdir(exist_ok=True)
            
            plugin_file = plugin_dir / "plugin.py"
            input_file = plugin_dir / "input.json"
            output_file = plugin_dir / "output.json"
            
            # Write plugin and input files
            with open(plugin_file, 'w') as f:
                f.write(plugin_code)
            
            with open(input_file, 'w') as f:
                json.dump(input_data or {}, f)
            
            # Create Docker container
            container = self._create_sandbox_container(plugin_dir, timeout)
            
            # Execute plugin
            result = self._run_container(container, output_file, timeout)
            
            # Cleanup
            self._cleanup_container(container)
            self._cleanup_files(plugin_dir)
            
            return result
            
        except Exception as e:
            logger.error(f"Sandboxed plugin execution error: {e}")
            return False, {'error': f'Sandbox execution failed: {str(e)}'}
    
    def _create_sandbox_container(self, plugin_dir: Path, timeout: int):
        """Create Docker container for plugin execution"""
        # Create Dockerfile
        dockerfile_content = f"""
FROM python:3.9-alpine
RUN adduser -D -s /bin/sh pluginuser
WORKDIR /plugin
COPY . .
RUN chown -R pluginuser:pluginuser /plugin
USER pluginuser
CMD ["python", "plugin.py"]
"""
        
        dockerfile_path = plugin_dir / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
        # Build image
        image_tag = f"byteguardx-plugin-{int(time.time())}"
        self.docker_client.images.build(
            path=str(plugin_dir),
            tag=image_tag,
            rm=True
        )
        
        # Create container with security constraints
        container = self.docker_client.containers.create(
            image_tag,
            detach=True,
            mem_limit='128m',  # 128MB memory limit
            cpu_quota=50000,   # 50% CPU limit
            network_disabled=True,  # No network access
            read_only=True,    # Read-only filesystem
            security_opt=['no-new-privileges'],
            user='pluginuser'
        )
        
        return container
    
    def _run_container(self, container, output_file: Path, timeout: int) -> Tuple[bool, Dict[str, Any]]:
        """Run container and collect results"""
        try:
            # Start container
            container.start()
            
            # Wait for completion
            result = container.wait(timeout=timeout)
            
            # Get logs
            logs = container.logs().decode('utf-8')
            
            # Check exit code
            if result['StatusCode'] != 0:
                return False, {'error': f'Plugin failed with exit code {result["StatusCode"]}', 'logs': logs}
            
            # Read output file if it exists
            if output_file.exists():
                with open(output_file, 'r') as f:
                    output_data = json.load(f)
            else:
                output_data = {'logs': logs}
            
            return True, output_data
            
        except Exception as e:
            logger.error(f"Container execution error: {e}")
            return False, {'error': f'Container execution failed: {str(e)}'}
    
    def _cleanup_container(self, container):
        """Clean up Docker container and image"""
        try:
            container.remove(force=True)
            # Note: Image cleanup could be added here if needed
        except Exception as e:
            logger.warning(f"Container cleanup error: {e}")
    
    def _cleanup_files(self, plugin_dir: Path):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(plugin_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"File cleanup error: {e}")

# Global instance
plugin_sandbox = PluginSandbox()
