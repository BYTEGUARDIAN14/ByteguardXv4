"""
Plugin Manager for ByteGuardX
Manages plugin lifecycle, registration, and execution
"""

import os
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Type, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import importlib.util
import sys

from .base_plugin import BasePlugin, PluginType, PluginStatus, PluginResult, ScannerPlugin, RulePlugin
from .sandbox import PluginSandbox, PluginPermissions, create_scanner_permissions, create_rule_permissions
from .signature_verification import plugin_signature_verifier, PluginSignature

logger = logging.getLogger(__name__)

@dataclass
class PluginMetadata:
    """Plugin metadata information"""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    file_path: str
    class_name: str
    enabled: bool = True
    installed_at: datetime = None
    last_updated: datetime = None
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.installed_at is None:
            self.installed_at = datetime.now()
        if self.dependencies is None:
            self.dependencies = []

class PluginRegistry:
    """Registry for managing plugin metadata and state"""
    
    def __init__(self, registry_file: str = "data/plugins/registry.json"):
        self.registry_file = Path(registry_file)
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        self.plugins: Dict[str, PluginMetadata] = {}
        self.lock = threading.RLock()
        self._load_registry()
    
    def _load_registry(self):
        """Load plugin registry from file"""
        try:
            if self.registry_file.exists():
                with open(self.registry_file, 'r') as f:
                    data = json.load(f)
                
                for plugin_name, plugin_data in data.items():
                    metadata = PluginMetadata(
                        name=plugin_data['name'],
                        version=plugin_data['version'],
                        description=plugin_data['description'],
                        author=plugin_data['author'],
                        plugin_type=PluginType(plugin_data['plugin_type']),
                        file_path=plugin_data['file_path'],
                        class_name=plugin_data['class_name'],
                        enabled=plugin_data.get('enabled', True),
                        installed_at=datetime.fromisoformat(plugin_data['installed_at']),
                        last_updated=datetime.fromisoformat(plugin_data['last_updated']) if plugin_data.get('last_updated') else None,
                        dependencies=plugin_data.get('dependencies', [])
                    )
                    self.plugins[plugin_name] = metadata
                
                logger.info(f"Loaded {len(self.plugins)} plugins from registry")
        
        except Exception as e:
            logger.error(f"Failed to load plugin registry: {e}")
    
    def _save_registry(self):
        """Save plugin registry to file"""
        try:
            with self.lock:
                data = {}
                for plugin_name, metadata in self.plugins.items():
                    data[plugin_name] = {
                        'name': metadata.name,
                        'version': metadata.version,
                        'description': metadata.description,
                        'author': metadata.author,
                        'plugin_type': metadata.plugin_type.value,
                        'file_path': metadata.file_path,
                        'class_name': metadata.class_name,
                        'enabled': metadata.enabled,
                        'installed_at': metadata.installed_at.isoformat(),
                        'last_updated': metadata.last_updated.isoformat() if metadata.last_updated else None,
                        'dependencies': metadata.dependencies
                    }
                
                with open(self.registry_file, 'w') as f:
                    json.dump(data, f, indent=2)
        
        except Exception as e:
            logger.error(f"Failed to save plugin registry: {e}")
    
    def register_plugin(self, metadata: PluginMetadata) -> bool:
        """Register a plugin in the registry"""
        try:
            with self.lock:
                self.plugins[metadata.name] = metadata
                self._save_registry()
                logger.info(f"Registered plugin: {metadata.name}")
                return True
        except Exception as e:
            logger.error(f"Failed to register plugin {metadata.name}: {e}")
            return False
    
    def unregister_plugin(self, plugin_name: str) -> bool:
        """Unregister a plugin from the registry"""
        try:
            with self.lock:
                if plugin_name in self.plugins:
                    del self.plugins[plugin_name]
                    self._save_registry()
                    logger.info(f"Unregistered plugin: {plugin_name}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to unregister plugin {plugin_name}: {e}")
            return False
    
    def get_plugin_metadata(self, plugin_name: str) -> Optional[PluginMetadata]:
        """Get metadata for a specific plugin"""
        return self.plugins.get(plugin_name)
    
    def list_plugins(self, plugin_type: Optional[PluginType] = None, 
                    enabled_only: bool = False) -> List[PluginMetadata]:
        """List plugins with optional filtering"""
        plugins = list(self.plugins.values())
        
        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]
        
        if enabled_only:
            plugins = [p for p in plugins if p.enabled]
        
        return plugins
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        try:
            with self.lock:
                if plugin_name in self.plugins:
                    self.plugins[plugin_name].enabled = True
                    self._save_registry()
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to enable plugin {plugin_name}: {e}")
            return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        try:
            with self.lock:
                if plugin_name in self.plugins:
                    self.plugins[plugin_name].enabled = False
                    self._save_registry()
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to disable plugin {plugin_name}: {e}")
            return False

class PluginManager:
    """Main plugin manager for ByteGuardX"""
    
    def __init__(self, plugins_dir: str = "data/plugins", 
                 registry: Optional[PluginRegistry] = None):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        
        self.registry = registry or PluginRegistry()
        self.loaded_plugins: Dict[str, BasePlugin] = {}
        self.lock = threading.RLock()
        
        # Plugin execution statistics
        self.execution_stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'average_execution_time': 0.0
        }
    
    def discover_plugins(self, directory: Optional[str] = None) -> List[str]:
        """Discover plugins in the specified directory"""
        search_dir = Path(directory) if directory else self.plugins_dir
        discovered = []
        
        try:
            for plugin_file in search_dir.glob("*.py"):
                if plugin_file.name.startswith("__"):
                    continue
                
                try:
                    # Load the module to inspect it
                    spec = importlib.util.spec_from_file_location(
                        plugin_file.stem, plugin_file
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for plugin classes
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        
                        if (isinstance(attr, type) and 
                            issubclass(attr, BasePlugin) and 
                            attr != BasePlugin):
                            
                            discovered.append(str(plugin_file))
                            logger.info(f"Discovered plugin: {attr_name} in {plugin_file}")
                            break
                
                except Exception as e:
                    logger.warning(f"Failed to inspect plugin file {plugin_file}: {e}")
            
            return discovered
        
        except Exception as e:
            logger.error(f"Plugin discovery failed: {e}")
            return []
    
    def install_plugin(self, plugin_file: str, plugin_class_name: str = None,
                      signature: PluginSignature = None, force_install: bool = False) -> bool:
        """Install a plugin from file with signature verification"""
        try:
            plugin_path = Path(plugin_file)

            if not plugin_path.exists():
                logger.error(f"Plugin file not found: {plugin_file}")
                return False

            # Verify plugin signature if provided
            if signature and not force_install:
                is_valid, error_msg = plugin_signature_verifier.verify_plugin_signature(
                    str(plugin_path), signature
                )
                if not is_valid:
                    logger.error(f"Plugin signature verification failed: {error_msg}")
                    return False
                logger.info(f"Plugin signature verified successfully")
            elif not signature and not force_install:
                logger.warning(f"Installing unsigned plugin: {plugin_path}")
                # In production, you might want to reject unsigned plugins
                # return False

            # Load the plugin module
            spec = importlib.util.spec_from_file_location(
                plugin_path.stem, plugin_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            
            if plugin_class_name:
                if hasattr(module, plugin_class_name):
                    plugin_class = getattr(module, plugin_class_name)
            else:
                # Auto-discover plugin class
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    if (isinstance(attr, type) and 
                        issubclass(attr, BasePlugin) and 
                        attr != BasePlugin):
                        plugin_class = attr
                        plugin_class_name = attr_name
                        break
            
            if not plugin_class:
                logger.error(f"No valid plugin class found in {plugin_file}")
                return False
            
            # Create plugin instance to get metadata
            plugin_instance = plugin_class()
            
            # Create metadata
            metadata = PluginMetadata(
                name=plugin_instance.name,
                version=plugin_instance.version,
                description=plugin_instance.description,
                author=plugin_instance.author,
                plugin_type=plugin_instance.plugin_type,
                file_path=str(plugin_path),
                class_name=plugin_class_name
            )
            
            # Register the plugin
            if self.registry.register_plugin(metadata):
                logger.info(f"Successfully installed plugin: {plugin_instance.name}")
                return True
            else:
                logger.error(f"Failed to register plugin: {plugin_instance.name}")
                return False
        
        except Exception as e:
            logger.error(f"Plugin installation failed: {e}")
            return False
    
    def load_plugin(self, plugin_name: str, config: Dict[str, Any] = None) -> bool:
        """Load and initialize a plugin"""
        try:
            with self.lock:
                # Check if already loaded
                if plugin_name in self.loaded_plugins:
                    logger.warning(f"Plugin {plugin_name} is already loaded")
                    return True
                
                # Get plugin metadata
                metadata = self.registry.get_plugin_metadata(plugin_name)
                if not metadata:
                    logger.error(f"Plugin {plugin_name} not found in registry")
                    return False
                
                if not metadata.enabled:
                    logger.warning(f"Plugin {plugin_name} is disabled")
                    return False
                
                # Load the plugin module
                spec = importlib.util.spec_from_file_location(
                    plugin_name, metadata.file_path
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Get plugin class
                plugin_class = getattr(module, metadata.class_name)
                
                # Create plugin instance
                plugin_instance = plugin_class(config)
                
                # Initialize the plugin
                if plugin_instance.initialize():
                    self.loaded_plugins[plugin_name] = plugin_instance
                    logger.info(f"Successfully loaded plugin: {plugin_name}")
                    return True
                else:
                    logger.error(f"Failed to initialize plugin: {plugin_name}")
                    return False
        
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        try:
            with self.lock:
                if plugin_name not in self.loaded_plugins:
                    logger.warning(f"Plugin {plugin_name} is not loaded")
                    return True
                
                plugin = self.loaded_plugins[plugin_name]
                
                # Cleanup the plugin
                if plugin.cleanup():
                    del self.loaded_plugins[plugin_name]
                    logger.info(f"Successfully unloaded plugin: {plugin_name}")
                    return True
                else:
                    logger.error(f"Failed to cleanup plugin: {plugin_name}")
                    return False
        
        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    def get_loaded_plugins(self, plugin_type: Optional[PluginType] = None) -> List[BasePlugin]:
        """Get list of loaded plugins"""
        plugins = list(self.loaded_plugins.values())
        
        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]
        
        return plugins
    
    def execute_scanner_plugins(self, content: str, file_path: str = "", 
                               file_type: str = "") -> List[PluginResult]:
        """Execute all loaded scanner plugins on content"""
        results = []
        scanner_plugins = self.get_loaded_plugins(PluginType.SCANNER)
        
        for plugin in scanner_plugins:
            if isinstance(plugin, ScannerPlugin):
                try:
                    # Check if plugin can scan this file type
                    if plugin.can_scan_file(file_path, file_type):
                        result = plugin.scan_content(content, file_path, file_type)
                        results.append(result)
                        
                        # Update statistics
                        self._update_execution_stats(result)
                    
                except Exception as e:
                    logger.error(f"Scanner plugin {plugin.name} failed: {e}")
                    plugin.set_status(PluginStatus.ERROR, str(e))
        
        return results
    
    def execute_rule_plugins(self, content: str, file_path: str = "") -> List[PluginResult]:
        """Execute all loaded rule plugins on content"""
        results = []
        rule_plugins = self.get_loaded_plugins(PluginType.RULE)
        
        for plugin in rule_plugins:
            if isinstance(plugin, RulePlugin):
                try:
                    result = plugin.apply_rules(content, file_path)
                    results.append(result)
                    
                    # Update statistics
                    self._update_execution_stats(result)
                
                except Exception as e:
                    logger.error(f"Rule plugin {plugin.name} failed: {e}")
                    plugin.set_status(PluginStatus.ERROR, str(e))
        
        return results
    
    def _update_execution_stats(self, result: PluginResult):
        """Update plugin execution statistics"""
        self.execution_stats['total_executions'] += 1
        
        if result.success:
            self.execution_stats['successful_executions'] += 1
        else:
            self.execution_stats['failed_executions'] += 1
        
        # Update average execution time
        total_time = (self.execution_stats['average_execution_time'] * 
                     (self.execution_stats['total_executions'] - 1) + 
                     result.execution_time)
        self.execution_stats['average_execution_time'] = total_time / self.execution_stats['total_executions']
    
    def get_plugin_status(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get status information for a plugin"""
        if plugin_name in self.loaded_plugins:
            plugin = self.loaded_plugins[plugin_name]
            return plugin.get_metadata()
        
        metadata = self.registry.get_plugin_metadata(plugin_name)
        if metadata:
            return {
                'name': metadata.name,
                'version': metadata.version,
                'type': metadata.plugin_type.value,
                'enabled': metadata.enabled,
                'loaded': False,
                'status': 'not_loaded'
            }
        
        return None
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get plugin execution statistics"""
        return self.execution_stats.copy()
    
    def reload_plugin(self, plugin_name: str, config: Dict[str, Any] = None) -> bool:
        """Reload a plugin"""
        if self.unload_plugin(plugin_name):
            return self.load_plugin(plugin_name, config)
        return False

# Global plugin manager instance
plugin_manager = PluginManager()
