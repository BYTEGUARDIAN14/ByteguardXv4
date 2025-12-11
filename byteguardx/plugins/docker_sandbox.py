"""
Docker-based Plugin Sandbox for Enhanced Security
Provides isolated execution environment using Docker containers
"""

import os
import json
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import time
import shutil

from .sandbox import SandboxResult, PluginPermissions, SandboxViolation

logger = logging.getLogger(__name__)

@dataclass
class DockerSandboxConfig:
    """Configuration for Docker sandbox"""
    image: str = "python:3.9-alpine"
    memory_limit: str = "50m"  # 50MB memory limit
    cpu_limit: str = "0.25"    # 25% CPU limit
    timeout: int = 15          # 15 seconds timeout
    network_mode: str = "none" # No network access
    read_only: bool = True     # Read-only filesystem
    no_new_privileges: bool = True
    user: str = "nobody"       # Run as non-root user

class DockerPluginSandbox:
    """Docker-based secure plugin execution sandbox"""
    
    def __init__(self, config: Optional[DockerSandboxConfig] = None):
        self.config = config or DockerSandboxConfig()
        self.docker_available = self._check_docker_available()
        
        if not self.docker_available:
            logger.warning("Docker not available, falling back to process sandbox")
    
    def _check_docker_available(self) -> bool:
        """Check if Docker is available and accessible"""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def _prepare_sandbox_environment(self, plugin_code: str, plugin_data: Dict[str, Any]) -> Path:
        """Prepare isolated environment for plugin execution"""
        # Create temporary directory
        temp_dir = Path(tempfile.mkdtemp(prefix="byteguardx_docker_"))
        
        try:
            # Create plugin file
            plugin_file = temp_dir / "plugin.py"
            with open(plugin_file, 'w', encoding='utf-8') as f:
                f.write(plugin_code)
            
            # Create data file
            data_file = temp_dir / "data.json"
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(plugin_data, f)
            
            # Create execution wrapper
            wrapper_code = '''
import json
import sys
import traceback
import signal
import time
from pathlib import Path

def timeout_handler(signum, frame):
    raise TimeoutError("Plugin execution timed out")

def main():
    # Set up timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(15)  # 15 second timeout
    
    try:
        # Load data
        with open('/sandbox/data.json', 'r') as f:
            data = json.load(f)
        
        # Import and execute plugin
        sys.path.insert(0, '/sandbox')
        import plugin
        
        # Execute plugin main function
        if hasattr(plugin, 'main'):
            result = plugin.main(data)
        elif hasattr(plugin, 'execute'):
            result = plugin.execute(data)
        else:
            result = {"error": "Plugin must have main() or execute() function"}
        
        # Output result
        print(json.dumps({
            "success": True,
            "result": result,
            "execution_time": time.time()
        }))
        
    except TimeoutError:
        print(json.dumps({
            "success": False,
            "error": "Plugin execution timed out",
            "violations": ["execution_timeout"]
        }))
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "violations": ["execution_error"]
        }))
    finally:
        signal.alarm(0)  # Cancel timeout

if __name__ == "__main__":
    main()
'''
            
            wrapper_file = temp_dir / "wrapper.py"
            with open(wrapper_file, 'w', encoding='utf-8') as f:
                f.write(wrapper_code)
            
            # Set permissions
            os.chmod(plugin_file, 0o644)
            os.chmod(data_file, 0o644)
            os.chmod(wrapper_file, 0o755)
            
            return temp_dir
            
        except Exception as e:
            # Cleanup on error
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Failed to prepare sandbox environment: {e}")
    
    def execute_plugin(self, plugin_code: str, plugin_data: Dict[str, Any], 
                      permissions: PluginPermissions) -> SandboxResult:
        """Execute plugin in Docker sandbox"""
        if not self.docker_available:
            return SandboxResult(
                success=False,
                error="Docker sandbox not available",
                violations=["docker_unavailable"]
            )
        
        temp_dir = None
        start_time = time.time()
        
        try:
            # Prepare sandbox environment
            temp_dir = self._prepare_sandbox_environment(plugin_code, plugin_data)
            
            # Build Docker command
            docker_cmd = [
                'docker', 'run',
                '--rm',  # Remove container after execution
                '--read-only',  # Read-only filesystem
                '--no-new-privileges',  # No privilege escalation
                '--user', self.config.user,  # Run as non-root
                '--network', self.config.network_mode,  # No network
                '--memory', self.config.memory_limit,  # Memory limit
                '--cpus', self.config.cpu_limit,  # CPU limit
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=10m',  # Temp filesystem
                '--volume', f'{temp_dir}:/sandbox:ro',  # Mount sandbox directory
                '--workdir', '/sandbox',
                '--security-opt', 'no-new-privileges:true',
                '--cap-drop', 'ALL',  # Drop all capabilities
                self.config.image,
                'python', 'wrapper.py'
            ]
            
            # Execute in Docker
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout + 5,  # Extra buffer for Docker overhead
                cwd=temp_dir
            )
            
            execution_time = time.time() - start_time
            
            # Parse result
            if result.returncode == 0:
                try:
                    output_data = json.loads(result.stdout.strip())
                    
                    return SandboxResult(
                        success=output_data.get('success', False),
                        result=output_data.get('result'),
                        error=output_data.get('error'),
                        execution_time=execution_time,
                        memory_usage=0,  # Docker doesn't provide easy memory stats
                        violations=output_data.get('violations', [])
                    )
                    
                except json.JSONDecodeError:
                    return SandboxResult(
                        success=False,
                        error=f"Invalid plugin output: {result.stdout}",
                        execution_time=execution_time,
                        violations=["invalid_output"]
                    )
            else:
                # Docker execution failed
                error_msg = result.stderr or "Docker execution failed"
                violations = ["docker_error"]
                
                if "timeout" in error_msg.lower():
                    violations.append("execution_timeout")
                if "memory" in error_msg.lower():
                    violations.append("memory_limit")
                if "cpu" in error_msg.lower():
                    violations.append("cpu_limit")
                
                return SandboxResult(
                    success=False,
                    error=error_msg,
                    execution_time=execution_time,
                    violations=violations
                )
        
        except subprocess.TimeoutExpired:
            return SandboxResult(
                success=False,
                error="Docker execution timed out",
                execution_time=time.time() - start_time,
                violations=["execution_timeout", "docker_timeout"]
            )
        
        except Exception as e:
            return SandboxResult(
                success=False,
                error=f"Docker sandbox error: {str(e)}",
                execution_time=time.time() - start_time,
                violations=["sandbox_error"]
            )
        
        finally:
            # Cleanup
            if temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def validate_plugin_code(self, plugin_code: str) -> List[str]:
        """Validate plugin code for dangerous patterns"""
        violations = []
        
        # Dangerous imports
        dangerous_imports = [
            'os', 'sys', 'subprocess', 'socket', 'urllib', 'requests',
            'shutil', 'tempfile', 'pickle', 'marshal', 'imp', 'importlib',
            'ctypes', 'multiprocessing', 'threading', '__builtin__', 'builtins'
        ]
        
        for dangerous in dangerous_imports:
            if f'import {dangerous}' in plugin_code or f'from {dangerous}' in plugin_code:
                violations.append(f"dangerous_import_{dangerous}")
        
        # Dangerous function calls
        dangerous_calls = [
            'eval(', 'exec(', 'compile(', '__import__(', 'open(',
            'file(', 'input(', 'raw_input(', 'execfile('
        ]
        
        for dangerous in dangerous_calls:
            if dangerous in plugin_code:
                violations.append(f"dangerous_call_{dangerous.rstrip('(')}")
        
        # Check for network operations
        network_patterns = ['socket', 'urllib', 'requests', 'http', 'ftp']
        for pattern in network_patterns:
            if pattern in plugin_code.lower():
                violations.append(f"network_access_{pattern}")
        
        return violations
    
    def get_sandbox_info(self) -> Dict[str, Any]:
        """Get information about sandbox capabilities"""
        return {
            "type": "docker",
            "available": self.docker_available,
            "config": {
                "image": self.config.image,
                "memory_limit": self.config.memory_limit,
                "cpu_limit": self.config.cpu_limit,
                "timeout": self.config.timeout,
                "network_mode": self.config.network_mode,
                "read_only": self.config.read_only,
                "user": self.config.user
            },
            "security_features": [
                "process_isolation",
                "filesystem_isolation",
                "network_isolation",
                "resource_limits",
                "capability_dropping",
                "read_only_filesystem",
                "non_root_execution"
            ]
        }

# Global Docker sandbox instance
docker_sandbox = DockerPluginSandbox()
