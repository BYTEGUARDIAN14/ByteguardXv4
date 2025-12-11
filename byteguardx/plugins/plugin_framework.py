"""
ByteGuardX Plugin Framework
Advanced plugin architecture with Docker sandboxing and security validation
"""

import json
import logging
import hashlib
import time
import docker
import subprocess
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import resource
import signal
import os

logger = logging.getLogger(__name__)

class PluginStatus(Enum):
    """Plugin execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    QUARANTINED = "quarantined"

class PluginCategory(Enum):
    """Plugin categories for organization"""
    CLOUD_SECURITY = "cloud_security"
    WEB_APPLICATION = "web_application"
    BINARY_ANALYSIS = "binary_analysis"
    NETWORK_SECURITY = "network_security"
    SOURCE_CODE = "source_code"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    MALWARE_DETECTION = "malware_detection"

@dataclass
class PluginManifest:
    """Plugin manifest structure"""
    name: str
    version: str
    author: str
    description: str
    category: PluginCategory
    supported_languages: List[str]
    supported_file_types: List[str]
    requires_network: bool
    requires_filesystem: bool
    max_memory_mb: int
    max_cpu_percent: int
    timeout_seconds: int
    trust_level: str
    dependencies: List[str]
    api_version: str
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['category'] = self.category.value
        return result

@dataclass
class PluginResult:
    """Standardized plugin result structure"""
    plugin_name: str
    plugin_version: str
    status: PluginStatus
    findings: List[Dict[str, Any]]
    execution_time_ms: float
    memory_used_mb: float
    cpu_used_percent: float
    error_message: Optional[str]
    metadata: Dict[str, Any]
    trust_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        return result

class BasePlugin(ABC):
    """Base class for all ByteGuardX plugins"""
    
    def __init__(self, manifest: PluginManifest):
        self.manifest = manifest
        self.start_time = None
        self.resource_monitor = None
        
    @abstractmethod
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main scanning method - must be implemented by all plugins"""
        pass
    
    @abstractmethod
    def validate_input(self, content: str, file_path: str) -> bool:
        """Validate input before processing"""
        pass
    
    def get_manifest(self) -> PluginManifest:
        """Get plugin manifest"""
        return self.manifest
    
    def get_supported_file_types(self) -> List[str]:
        """Get supported file types"""
        return self.manifest.supported_file_types
    
    def get_supported_languages(self) -> List[str]:
        """Get supported programming languages"""
        return self.manifest.supported_languages

class PluginSandbox:
    """Docker-based plugin sandbox for secure execution"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.docker_client = None
        self.active_containers = {}
        self.resource_limits = {
            'memory': '512m',
            'cpu_quota': 50000,  # 50% CPU
            'cpu_period': 100000,
            'network_mode': 'none',  # No network by default
            'read_only': True,
            'security_opt': ['no-new-privileges:true'],
            'cap_drop': ['ALL'],
            'user': '1000:1000'  # Non-root user
        }
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
    
    def execute_plugin(self, plugin: BasePlugin, content: str, file_path: str, 
                      context: Dict[str, Any]) -> PluginResult:
        """Execute plugin in secure sandbox"""
        
        if not self.docker_client:
            return self._create_error_result(plugin, "Docker not available")
        
        start_time = time.time()
        container = None
        
        try:
            # Create sandbox environment
            container_config = self._create_container_config(plugin)
            
            # Prepare input data
            input_data = {
                'content': content,
                'file_path': file_path,
                'context': context,
                'manifest': plugin.manifest.to_dict()
            }
            
            # Create and start container
            container = self.docker_client.containers.run(
                image='byteguardx/plugin-runtime:latest',
                command=['python', '/app/plugin_runner.py'],
                **container_config,
                detach=True
            )
            
            self.active_containers[container.id] = {
                'plugin': plugin.manifest.name,
                'start_time': start_time,
                'timeout': plugin.manifest.timeout_seconds
            }
            
            # Send input data to container
            self._send_input_to_container(container, input_data)
            
            # Monitor execution
            result = self._monitor_execution(container, plugin, start_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            return self._create_error_result(plugin, str(e))
        
        finally:
            if container:
                try:
                    container.stop(timeout=5)
                    container.remove()
                    if container.id in self.active_containers:
                        del self.active_containers[container.id]
                except Exception as e:
                    logger.error(f"Failed to cleanup container: {e}")
    
    def _create_container_config(self, plugin: BasePlugin) -> Dict[str, Any]:
        """Create container configuration based on plugin requirements"""
        
        config = self.resource_limits.copy()
        
        # Adjust memory limit based on plugin requirements
        if plugin.manifest.max_memory_mb > 0:
            config['mem_limit'] = f"{min(plugin.manifest.max_memory_mb, 1024)}m"
        
        # Adjust CPU limit
        if plugin.manifest.max_cpu_percent > 0:
            cpu_quota = min(plugin.manifest.max_cpu_percent * 1000, 100000)
            config['cpu_quota'] = cpu_quota
        
        # Network access if required
        if plugin.manifest.requires_network:
            config['network_mode'] = 'bridge'
            # Add network restrictions
            config['cap_add'] = ['NET_ADMIN']
        
        # Filesystem access if required
        if plugin.manifest.requires_filesystem:
            config['read_only'] = False
            config['tmpfs'] = {'/tmp': 'size=100m,noexec'}
        
        # Environment variables
        config['environment'] = {
            'PLUGIN_NAME': plugin.manifest.name,
            'PLUGIN_VERSION': plugin.manifest.version,
            'BYTEGUARDX_SANDBOX': 'true',
            'PYTHONPATH': '/app'
        }
        
        # Volume mounts for plugin code
        config['volumes'] = {
            '/tmp/plugin_input': {'bind': '/app/input', 'mode': 'ro'},
            '/tmp/plugin_output': {'bind': '/app/output', 'mode': 'rw'}
        }
        
        return config
    
    def _send_input_to_container(self, container, input_data: Dict[str, Any]):
        """Send input data to container"""
        try:
            # Create input file
            input_file = '/tmp/plugin_input/input.json'
            os.makedirs('/tmp/plugin_input', exist_ok=True)
            
            with open(input_file, 'w') as f:
                json.dump(input_data, f)
            
        except Exception as e:
            logger.error(f"Failed to send input to container: {e}")
            raise
    
    def _monitor_execution(self, container, plugin: BasePlugin, start_time: float) -> PluginResult:
        """Monitor plugin execution and collect results"""
        
        timeout = plugin.manifest.timeout_seconds
        
        try:
            # Wait for completion with timeout
            exit_code = container.wait(timeout=timeout)
            
            execution_time = (time.time() - start_time) * 1000
            
            # Get resource usage
            stats = container.stats(stream=False)
            memory_used = self._extract_memory_usage(stats)
            cpu_used = self._extract_cpu_usage(stats)
            
            # Read output
            output_data = self._read_container_output()
            
            # Create result
            if exit_code['StatusCode'] == 0:
                return PluginResult(
                    plugin_name=plugin.manifest.name,
                    plugin_version=plugin.manifest.version,
                    status=PluginStatus.COMPLETED,
                    findings=output_data.get('findings', []),
                    execution_time_ms=execution_time,
                    memory_used_mb=memory_used,
                    cpu_used_percent=cpu_used,
                    error_message=None,
                    metadata=output_data.get('metadata', {}),
                    trust_score=self._calculate_trust_score(plugin, output_data)
                )
            else:
                return self._create_error_result(plugin, f"Plugin exited with code {exit_code['StatusCode']}")
                
        except docker.errors.ContainerError as e:
            return self._create_error_result(plugin, f"Container error: {e}")
        
        except Exception as e:
            return self._create_error_result(plugin, f"Execution error: {e}")
    
    def _read_container_output(self) -> Dict[str, Any]:
        """Read output from container"""
        try:
            output_file = '/tmp/plugin_output/output.json'
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Failed to read container output: {e}")
            return {}
    
    def _extract_memory_usage(self, stats: Dict[str, Any]) -> float:
        """Extract memory usage from container stats"""
        try:
            memory_stats = stats.get('memory_stats', {})
            usage = memory_stats.get('usage', 0)
            return usage / (1024 * 1024)  # Convert to MB
        except Exception:
            return 0.0
    
    def _extract_cpu_usage(self, stats: Dict[str, Any]) -> float:
        """Extract CPU usage from container stats"""
        try:
            cpu_stats = stats.get('cpu_stats', {})
            cpu_usage = cpu_stats.get('cpu_usage', {})
            total_usage = cpu_usage.get('total_usage', 0)
            system_usage = cpu_stats.get('system_cpu_usage', 1)
            
            if system_usage > 0:
                return (total_usage / system_usage) * 100
            return 0.0
        except Exception:
            return 0.0
    
    def _calculate_trust_score(self, plugin: BasePlugin, output_data: Dict[str, Any]) -> float:
        """Calculate trust score based on plugin behavior"""
        base_score = 0.8
        
        # Adjust based on resource usage
        findings_count = len(output_data.get('findings', []))
        if findings_count > 1000:  # Suspiciously high findings
            base_score -= 0.2
        
        # Adjust based on execution time
        if output_data.get('execution_time_ms', 0) > plugin.manifest.timeout_seconds * 1000:
            base_score -= 0.1
        
        return max(0.0, min(1.0, base_score))
    
    def _create_error_result(self, plugin: BasePlugin, error_message: str) -> PluginResult:
        """Create error result"""
        return PluginResult(
            plugin_name=plugin.manifest.name,
            plugin_version=plugin.manifest.version,
            status=PluginStatus.FAILED,
            findings=[],
            execution_time_ms=0.0,
            memory_used_mb=0.0,
            cpu_used_percent=0.0,
            error_message=error_message,
            metadata={},
            trust_score=0.0
        )
    
    def cleanup_containers(self):
        """Cleanup any remaining containers"""
        for container_id, info in list(self.active_containers.items()):
            try:
                container = self.docker_client.containers.get(container_id)
                container.stop(timeout=5)
                container.remove()
                del self.active_containers[container_id]
            except Exception as e:
                logger.error(f"Failed to cleanup container {container_id}: {e}")

class PluginManager:
    """Manages plugin lifecycle, registration, and execution"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.plugins = {}
        self.sandbox = PluginSandbox(config)
        self.plugin_stats = {}
        self.quarantined_plugins = set()
        
    def register_plugin(self, plugin: BasePlugin) -> bool:
        """Register a new plugin"""
        try:
            # Validate plugin
            if not self._validate_plugin(plugin):
                return False
            
            # Security scan of plugin code
            if not self._security_scan_plugin(plugin):
                logger.warning(f"Plugin {plugin.manifest.name} failed security scan")
                return False
            
            # Register plugin
            plugin_key = f"{plugin.manifest.name}:{plugin.manifest.version}"
            self.plugins[plugin_key] = plugin
            
            # Initialize stats
            self.plugin_stats[plugin_key] = {
                'executions': 0,
                'successes': 0,
                'failures': 0,
                'avg_execution_time': 0.0,
                'total_findings': 0,
                'trust_score': 1.0,
                'last_executed': None
            }
            
            logger.info(f"Plugin registered: {plugin_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register plugin: {e}")
            return False
    
    def execute_plugin(self, plugin_name: str, content: str, file_path: str, 
                      context: Dict[str, Any] = None) -> PluginResult:
        """Execute a specific plugin"""
        
        context = context or {}
        
        # Find plugin
        plugin = self._find_plugin(plugin_name)
        if not plugin:
            return self._create_error_result(plugin_name, "Plugin not found")
        
        plugin_key = f"{plugin.manifest.name}:{plugin.manifest.version}"
        
        # Check if plugin is quarantined
        if plugin_key in self.quarantined_plugins:
            return self._create_error_result(plugin_name, "Plugin is quarantined")
        
        # Validate input
        if not plugin.validate_input(content, file_path):
            return self._create_error_result(plugin_name, "Invalid input")
        
        # Execute in sandbox
        result = self.sandbox.execute_plugin(plugin, content, file_path, context)
        
        # Update statistics
        self._update_plugin_stats(plugin_key, result)
        
        # Check for quarantine conditions
        self._check_quarantine_conditions(plugin_key, result)
        
        return result
    
    def get_available_plugins(self, category: Optional[PluginCategory] = None) -> List[Dict[str, Any]]:
        """Get list of available plugins"""
        plugins = []
        
        for plugin_key, plugin in self.plugins.items():
            if plugin_key in self.quarantined_plugins:
                continue
                
            if category and plugin.manifest.category != category:
                continue
            
            plugin_info = plugin.manifest.to_dict()
            plugin_info['stats'] = self.plugin_stats.get(plugin_key, {})
            plugins.append(plugin_info)
        
        return plugins
    
    def _validate_plugin(self, plugin: BasePlugin) -> bool:
        """Validate plugin structure and requirements"""
        try:
            # Check required methods
            if not hasattr(plugin, 'scan') or not callable(plugin.scan):
                logger.error("Plugin missing scan method")
                return False
            
            if not hasattr(plugin, 'validate_input') or not callable(plugin.validate_input):
                logger.error("Plugin missing validate_input method")
                return False
            
            # Validate manifest
            manifest = plugin.manifest
            if not manifest.name or not manifest.version:
                logger.error("Plugin manifest missing name or version")
                return False
            
            # Check resource limits
            if manifest.max_memory_mb > 2048:  # Max 2GB
                logger.error("Plugin memory requirement too high")
                return False
            
            if manifest.timeout_seconds > 300:  # Max 5 minutes
                logger.error("Plugin timeout too high")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Plugin validation failed: {e}")
            return False
    
    def _security_scan_plugin(self, plugin: BasePlugin) -> bool:
        """Perform security scan of plugin code"""
        # This would implement static analysis of plugin code
        # For now, return True (implement based on security requirements)
        return True
    
    def _find_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Find plugin by name (latest version)"""
        matching_plugins = [
            (key, plugin) for key, plugin in self.plugins.items()
            if plugin.manifest.name == plugin_name
        ]
        
        if not matching_plugins:
            return None
        
        # Return latest version
        return max(matching_plugins, key=lambda x: x[0])[1]
    
    def _update_plugin_stats(self, plugin_key: str, result: PluginResult):
        """Update plugin execution statistics"""
        stats = self.plugin_stats.get(plugin_key, {})
        
        stats['executions'] = stats.get('executions', 0) + 1
        stats['last_executed'] = datetime.now().isoformat()
        
        if result.status == PluginStatus.COMPLETED:
            stats['successes'] = stats.get('successes', 0) + 1
            stats['total_findings'] = stats.get('total_findings', 0) + len(result.findings)
            
            # Update average execution time
            current_avg = stats.get('avg_execution_time', 0.0)
            executions = stats['executions']
            stats['avg_execution_time'] = ((current_avg * (executions - 1)) + result.execution_time_ms) / executions
        else:
            stats['failures'] = stats.get('failures', 0) + 1
        
        # Update trust score
        success_rate = stats['successes'] / stats['executions']
        stats['trust_score'] = min(1.0, success_rate * result.trust_score)
        
        self.plugin_stats[plugin_key] = stats
    
    def _check_quarantine_conditions(self, plugin_key: str, result: PluginResult):
        """Check if plugin should be quarantined"""
        stats = self.plugin_stats.get(plugin_key, {})
        
        # Quarantine conditions
        failure_rate = stats.get('failures', 0) / max(stats.get('executions', 1), 1)
        trust_score = stats.get('trust_score', 1.0)
        
        if failure_rate > 0.5 or trust_score < 0.3:
            self.quarantined_plugins.add(plugin_key)
            logger.warning(f"Plugin quarantined: {plugin_key}")
    
    def _create_error_result(self, plugin_name: str, error_message: str) -> PluginResult:
        """Create error result for plugin manager errors"""
        return PluginResult(
            plugin_name=plugin_name,
            plugin_version="unknown",
            status=PluginStatus.FAILED,
            findings=[],
            execution_time_ms=0.0,
            memory_used_mb=0.0,
            cpu_used_percent=0.0,
            error_message=error_message,
            metadata={},
            trust_score=0.0
        )

# Global plugin manager instance
plugin_manager = PluginManager()
