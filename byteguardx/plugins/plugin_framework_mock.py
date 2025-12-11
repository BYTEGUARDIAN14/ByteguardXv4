"""
ByteGuardX Plugin Framework (Mock Version)
Simplified plugin architecture without Docker dependencies for demonstration
"""

import json
import logging
import hashlib
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

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

class MockPluginSandbox:
    """Mock plugin sandbox for demonstration (no Docker required)"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.active_plugins = {}
    
    def execute_plugin(self, plugin: BasePlugin, content: str, file_path: str, 
                      context: Dict[str, Any]) -> PluginResult:
        """Execute plugin in mock sandbox"""
        
        start_time = time.time()
        
        try:
            # Validate input
            if not plugin.validate_input(content, file_path):
                return self._create_error_result(plugin, "Invalid input")
            
            # Execute plugin scan method directly
            findings = plugin.scan(content, file_path, context)
            
            execution_time = (time.time() - start_time) * 1000
            
            # Create successful result
            return PluginResult(
                plugin_name=plugin.manifest.name,
                plugin_version=plugin.manifest.version,
                status=PluginStatus.COMPLETED,
                findings=findings,
                execution_time_ms=execution_time,
                memory_used_mb=50.0,  # Mock value
                cpu_used_percent=10.0,  # Mock value
                error_message=None,
                metadata={"mock_execution": True},
                trust_score=0.9
            )
            
        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            return self._create_error_result(plugin, str(e))
    
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

class MockPluginManager:
    """Mock plugin manager for demonstration"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.plugins = {}
        self.sandbox = MockPluginSandbox(config)
        self.plugin_stats = {}
        self.quarantined_plugins = set()
        
    def register_plugin(self, plugin: BasePlugin) -> bool:
        """Register a new plugin"""
        try:
            # Validate plugin
            if not self._validate_plugin(plugin):
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
        
        # Execute in sandbox
        result = self.sandbox.execute_plugin(plugin, content, file_path, context)
        
        # Update statistics
        self._update_plugin_stats(plugin_key, result)
        
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
            
            return True
            
        except Exception as e:
            logger.error(f"Plugin validation failed: {e}")
            return False
    
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
plugin_manager = MockPluginManager()
