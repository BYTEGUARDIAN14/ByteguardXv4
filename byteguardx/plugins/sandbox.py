"""
Plugin Sandbox Isolation System for ByteGuardX
Provides secure, isolated execution environment for plugins
"""

import os
import sys
import time
import signal
import logging
import tempfile
import subprocess
import multiprocessing
try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    RESOURCE_AVAILABLE = False
import json
import pickle
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import threading
import queue
import traceback

logger = logging.getLogger(__name__)

class SandboxViolation(Exception):
    """Raised when a plugin violates sandbox restrictions"""
    pass

class PermissionType(Enum):
    """Types of permissions for plugins"""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_ACCESS = "network_access"
    SUBPROCESS = "subprocess"
    IMPORT_MODULES = "import_modules"
    SYSTEM_INFO = "system_info"

@dataclass
class PluginPermissions:
    """Plugin permission configuration"""
    file_read: bool = False
    file_write: bool = False
    network_access: bool = False
    subprocess: bool = False
    import_modules: List[str] = None
    system_info: bool = False
    max_memory_mb: int = 100
    max_execution_time: int = 30
    allowed_paths: List[str] = None
    
    def __post_init__(self):
        if self.import_modules is None:
            self.import_modules = []
        if self.allowed_paths is None:
            self.allowed_paths = []

@dataclass
class SandboxResult:
    """Result from sandbox execution"""
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    memory_used: float = 0.0
    violations: List[str] = None
    
    def __post_init__(self):
        if self.violations is None:
            self.violations = []

class ResourceMonitor:
    """Monitor resource usage during plugin execution"""
    
    def __init__(self, max_memory_mb: int = 100, max_time: int = 30):
        self.max_memory_mb = max_memory_mb
        self.max_time = max_time
        self.start_time = None
        self.peak_memory = 0
        self.violations = []
    
    def start_monitoring(self):
        """Start resource monitoring"""
        self.start_time = time.time()
        
        # Set memory limit (Unix only)
        if RESOURCE_AVAILABLE and hasattr(resource, 'RLIMIT_AS'):
            try:
                # Set virtual memory limit
                memory_limit = self.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            except (OSError, ValueError) as e:
                logger.warning(f"Could not set memory limit: {e}")

        # Set CPU time limit
        if RESOURCE_AVAILABLE and hasattr(resource, 'RLIMIT_CPU'):
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (self.max_time, self.max_time))
            except (OSError, ValueError) as e:
                logger.warning(f"Could not set CPU time limit: {e}")
    
    def check_limits(self):
        """Check if resource limits are exceeded"""
        current_time = time.time()
        
        # Check execution time
        if self.start_time and (current_time - self.start_time) > self.max_time:
            self.violations.append(f"Execution time exceeded: {current_time - self.start_time:.2f}s > {self.max_time}s")
            raise SandboxViolation("Execution time limit exceeded")
        
        # Check memory usage
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.peak_memory = max(self.peak_memory, memory_mb)
            
            if memory_mb > self.max_memory_mb:
                self.violations.append(f"Memory limit exceeded: {memory_mb:.2f}MB > {self.max_memory_mb}MB")
                raise SandboxViolation("Memory limit exceeded")
        except ImportError:
            # psutil not available, skip memory monitoring
            pass
    
    def get_stats(self) -> Dict[str, float]:
        """Get resource usage statistics"""
        execution_time = time.time() - self.start_time if self.start_time else 0
        return {
            'execution_time': execution_time,
            'peak_memory_mb': self.peak_memory,
            'violations': len(self.violations)
        }

class SecureImportHook:
    """Custom import hook to restrict module imports"""
    
    def __init__(self, allowed_modules: List[str]):
        self.allowed_modules = set(allowed_modules)
        self.blocked_modules = {
            'os', 'sys', 'subprocess', 'socket', 'urllib', 'requests',
            'shutil', 'tempfile', 'pickle', 'marshal', 'imp', 'importlib'
        }
        self.original_import = None
    
    def install(self):
        """Install the import hook"""
        self.original_import = __builtins__['__import__']
        __builtins__['__import__'] = self.secure_import
    
    def uninstall(self):
        """Uninstall the import hook"""
        if self.original_import:
            __builtins__['__import__'] = self.original_import
    
    def secure_import(self, name, globals=None, locals=None, fromlist=(), level=0):
        """Secure import function that checks permissions"""
        # Allow standard library modules that are safe
        safe_modules = {
            'json', 'datetime', 'time', 'math', 'random', 'string',
            'collections', 'itertools', 'functools', 're', 'hashlib',
            'base64', 'uuid', 'typing'
        }
        
        # Check if module is explicitly allowed
        if name in self.allowed_modules or name in safe_modules:
            return self.original_import(name, globals, locals, fromlist, level)
        
        # Check if module is blocked
        if name in self.blocked_modules or name.startswith(tuple(self.blocked_modules)):
            raise ImportError(f"Import of '{name}' is not allowed in sandbox")
        
        # Allow submodules of allowed modules
        for allowed in self.allowed_modules:
            if name.startswith(f"{allowed}."):
                return self.original_import(name, globals, locals, fromlist, level)
        
        # Block everything else by default
        raise ImportError(f"Import of '{name}' is not allowed in sandbox")

class FileSystemSandbox:
    """Sandbox for file system access"""
    
    def __init__(self, permissions: PluginPermissions):
        self.permissions = permissions
        self.allowed_paths = set(permissions.allowed_paths)
        self.temp_dir = None
    
    def __enter__(self):
        """Enter sandbox context"""
        # Create temporary directory for plugin
        self.temp_dir = tempfile.mkdtemp(prefix="byteguardx_plugin_")
        self.allowed_paths.add(self.temp_dir)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit sandbox context"""
        # Cleanup temporary directory
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            try:
                shutil.rmtree(self.temp_dir)
            except OSError as e:
                logger.warning(f"Failed to cleanup temp directory: {e}")
    
    def check_path_access(self, path: str, operation: str):
        """Check if path access is allowed"""
        abs_path = os.path.abspath(path)
        
        # Check if path is in allowed paths
        allowed = False
        for allowed_path in self.allowed_paths:
            if abs_path.startswith(os.path.abspath(allowed_path)):
                allowed = True
                break
        
        if not allowed:
            raise SandboxViolation(f"Access to path '{path}' not allowed for operation '{operation}'")
        
        # Check operation permissions
        if operation == 'read' and not self.permissions.file_read:
            raise SandboxViolation("File read permission not granted")
        
        if operation in ['write', 'create', 'delete'] and not self.permissions.file_write:
            raise SandboxViolation("File write permission not granted")

class PluginSandbox:
    """Main plugin sandbox implementation"""
    
    def __init__(self, permissions: PluginPermissions):
        self.permissions = permissions
        self.monitor = ResourceMonitor(
            max_memory_mb=permissions.max_memory_mb,
            max_time=permissions.max_execution_time
        )
        self.import_hook = SecureImportHook(permissions.import_modules)
        self.fs_sandbox = FileSystemSandbox(permissions)
    
    def execute_plugin(self, plugin_code: str, plugin_data: Dict[str, Any]) -> SandboxResult:
        """Execute plugin code in sandbox"""
        if multiprocessing.current_process().name == 'MainProcess':
            # Execute in separate process for isolation
            return self._execute_in_process(plugin_code, plugin_data)
        else:
            # Already in subprocess, execute directly
            return self._execute_directly(plugin_code, plugin_data)
    
    def _execute_in_process(self, plugin_code: str, plugin_data: Dict[str, Any]) -> SandboxResult:
        """Execute plugin in separate process"""
        try:
            # Create process with timeout
            ctx = multiprocessing.get_context('spawn')  # Use spawn for better isolation
            result_queue = ctx.Queue()
            
            process = ctx.Process(
                target=self._process_worker,
                args=(plugin_code, plugin_data, self.permissions, result_queue)
            )
            
            start_time = time.time()
            process.start()
            
            try:
                # Wait for result with timeout
                result = result_queue.get(timeout=self.permissions.max_execution_time + 5)
                process.join(timeout=5)
                
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                    if process.is_alive():
                        process.kill()
                
                execution_time = time.time() - start_time
                result.execution_time = execution_time
                
                return result
                
            except queue.Empty:
                # Timeout occurred
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
                
                return SandboxResult(
                    success=False,
                    error="Plugin execution timed out",
                    execution_time=time.time() - start_time,
                    violations=["execution_timeout"]
                )
        
        except Exception as e:
            return SandboxResult(
                success=False,
                error=f"Sandbox execution failed: {str(e)}",
                violations=["sandbox_error"]
            )
    
    @staticmethod
    def _process_worker(plugin_code: str, plugin_data: Dict[str, Any], 
                       permissions: PluginPermissions, result_queue):
        """Worker function for subprocess execution"""
        try:
            sandbox = PluginSandbox(permissions)
            result = sandbox._execute_directly(plugin_code, plugin_data)
            result_queue.put(result)
        except Exception as e:
            result = SandboxResult(
                success=False,
                error=f"Process worker error: {str(e)}",
                violations=["process_error"]
            )
            result_queue.put(result)
    
    def _execute_directly(self, plugin_code: str, plugin_data: Dict[str, Any]) -> SandboxResult:
        """Execute plugin code directly in current process"""
        start_time = time.time()
        
        try:
            # Set up sandbox environment
            self.monitor.start_monitoring()
            self.import_hook.install()
            
            with self.fs_sandbox:
                # Create restricted execution environment
                sandbox_globals = {
                    '__builtins__': {
                        'len': len, 'str': str, 'int': int, 'float': float,
                        'bool': bool, 'list': list, 'dict': dict, 'tuple': tuple,
                        'set': set, 'range': range, 'enumerate': enumerate,
                        'zip': zip, 'map': map, 'filter': filter,
                        'min': min, 'max': max, 'sum': sum, 'abs': abs,
                        'round': round, 'sorted': sorted, 'reversed': reversed,
                        'print': self._safe_print,
                        'open': self._safe_open,
                    },
                    'plugin_data': plugin_data,
                    'temp_dir': self.fs_sandbox.temp_dir,
                }
                
                sandbox_locals = {}
                
                # Execute plugin code
                exec(plugin_code, sandbox_globals, sandbox_locals)
                
                # Check for result
                result = sandbox_locals.get('result', None)
                
                # Validate result schema
                self._validate_result_schema(result)
                
                execution_time = time.time() - start_time
                stats = self.monitor.get_stats()
                
                return SandboxResult(
                    success=True,
                    result=result,
                    execution_time=execution_time,
                    memory_used=stats['peak_memory_mb'],
                    violations=self.monitor.violations
                )
        
        except SandboxViolation as e:
            return SandboxResult(
                success=False,
                error=f"Sandbox violation: {str(e)}",
                execution_time=time.time() - start_time,
                violations=self.monitor.violations + [str(e)]
            )
        
        except Exception as e:
            return SandboxResult(
                success=False,
                error=f"Plugin execution error: {str(e)}",
                execution_time=time.time() - start_time,
                violations=self.monitor.violations
            )
        
        finally:
            # Cleanup sandbox environment
            self.import_hook.uninstall()
    
    def _safe_print(self, *args, **kwargs):
        """Safe print function for sandbox"""
        # Limit output and log instead of printing to stdout
        output = ' '.join(str(arg) for arg in args)
        if len(output) > 1000:
            output = output[:1000] + "... [truncated]"
        logger.debug(f"Plugin output: {output}")
    
    def _safe_open(self, filename, mode='r', **kwargs):
        """Safe file open function for sandbox"""
        # Check file access permissions
        operation = 'read' if 'r' in mode else 'write'
        self.fs_sandbox.check_path_access(filename, operation)
        
        # Limit file size for reads
        if 'r' in mode:
            file_size = os.path.getsize(filename) if os.path.exists(filename) else 0
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                raise SandboxViolation("File too large to read in sandbox")
        
        return open(filename, mode, **kwargs)
    
    def _validate_result_schema(self, result: Any):
        """Validate plugin result schema to prevent injection"""
        if result is None:
            return
        
        # Check result size
        try:
            result_str = str(result)
            if len(result_str) > 1024 * 1024:  # 1MB limit
                raise SandboxViolation("Plugin result too large")
        except Exception:
            raise SandboxViolation("Plugin result cannot be serialized")
        
        # Check for dangerous types
        dangerous_types = (type, type(lambda: None), type(exec))
        if isinstance(result, dangerous_types):
            raise SandboxViolation("Plugin result contains dangerous types")
        
        # Recursively check collections
        if isinstance(result, (list, tuple)):
            for item in result:
                self._validate_result_schema(item)
        elif isinstance(result, dict):
            for key, value in result.items():
                self._validate_result_schema(key)
                self._validate_result_schema(value)

def create_default_permissions() -> PluginPermissions:
    """Create default safe permissions for plugins"""
    return PluginPermissions(
        file_read=False,
        file_write=False,
        network_access=False,
        subprocess=False,
        import_modules=['json', 'datetime', 're', 'math'],
        system_info=False,
        max_memory_mb=50,
        max_execution_time=15,
        allowed_paths=[]
    )

def create_scanner_permissions() -> PluginPermissions:
    """Create permissions for scanner plugins"""
    return PluginPermissions(
        file_read=True,
        file_write=False,
        network_access=False,
        subprocess=False,
        import_modules=['json', 'datetime', 're', 'math', 'hashlib'],
        system_info=False,
        max_memory_mb=100,
        max_execution_time=30,
        allowed_paths=[]
    )

def create_rule_permissions() -> PluginPermissions:
    """Create permissions for rule plugins"""
    return PluginPermissions(
        file_read=True,
        file_write=False,
        network_access=False,
        subprocess=False,
        import_modules=['json', 're', 'math'],
        system_info=False,
        max_memory_mb=50,
        max_execution_time=15,
        allowed_paths=[]
    )
