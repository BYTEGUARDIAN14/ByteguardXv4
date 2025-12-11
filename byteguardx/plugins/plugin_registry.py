"""
ByteGuardX Plugin Registry
Manages plugin registration, discovery, and lifecycle
"""

import json
import logging
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
try:
    from .plugin_framework import BasePlugin, PluginManager, PluginCategory, plugin_manager
except ImportError:
    from .plugin_framework_mock import BasePlugin, MockPluginManager as PluginManager, PluginCategory
    plugin_manager = PluginManager()

logger = logging.getLogger(__name__)

class PluginRegistry:
    """Central registry for all ByteGuardX plugins"""
    
    def __init__(self):
        self.registered_plugins = {}
        self.plugin_categories = {}
        self.plugin_metadata = {}
        self.auto_discovery_paths = [
            Path(__file__).parent / "cloud_security",
            Path(__file__).parent / "web_security", 
            Path(__file__).parent / "binary_analysis",
            Path(__file__).parent / "network_security",
            Path(__file__).parent / "source_code",
            Path(__file__).parent / "infrastructure",
            Path(__file__).parent / "compliance",
            Path(__file__).parent / "malware_detection"
        ]
    
    def auto_discover_plugins(self) -> int:
        """Automatically discover and register plugins"""
        discovered_count = 0
        
        for plugin_path in self.auto_discovery_paths:
            if not plugin_path.exists():
                continue
                
            discovered_count += self._discover_plugins_in_directory(plugin_path)
        
        logger.info(f"Auto-discovered {discovered_count} plugins")
        return discovered_count
    
    def _discover_plugins_in_directory(self, directory: Path) -> int:
        """Discover plugins in a specific directory"""
        count = 0
        
        for python_file in directory.glob("*.py"):
            if python_file.name.startswith("__"):
                continue
            
            try:
                plugin_class = self._load_plugin_from_file(python_file)
                if plugin_class:
                    plugin_instance = plugin_class()
                    if self.register_plugin(plugin_instance):
                        count += 1
                        
            except Exception as e:
                logger.error(f"Failed to load plugin from {python_file}: {e}")
        
        return count
    
    def _load_plugin_from_file(self, file_path: Path) -> Optional[Type[BasePlugin]]:
        """Load plugin class from Python file"""
        try:
            # Convert file path to module name
            relative_path = file_path.relative_to(Path(__file__).parent.parent.parent)
            module_name = str(relative_path).replace("/", ".").replace("\\", ".").replace(".py", "")
            
            # Import the module
            module = importlib.import_module(module_name)
            
            # Find BasePlugin subclasses
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BasePlugin) and 
                    obj != BasePlugin):
                    return obj
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to load plugin from {file_path}: {e}")
            return None
    
    def register_plugin(self, plugin: BasePlugin) -> bool:
        """Register a plugin instance"""
        try:
            # Validate plugin
            if not self._validate_plugin(plugin):
                return False
            
            # Register with plugin manager
            if not plugin_manager.register_plugin(plugin):
                return False
            
            # Store in registry
            plugin_key = f"{plugin.manifest.name}:{plugin.manifest.version}"
            self.registered_plugins[plugin_key] = plugin
            
            # Organize by category
            category = plugin.manifest.category
            if category not in self.plugin_categories:
                self.plugin_categories[category] = []
            self.plugin_categories[category].append(plugin_key)
            
            # Store metadata
            self.plugin_metadata[plugin_key] = {
                "manifest": plugin.manifest.to_dict(),
                "registration_time": "2024-01-15T10:00:00Z",
                "status": "active",
                "trust_score": 1.0
            }
            
            logger.info(f"Plugin registered: {plugin_key}")
            return True
            
        except Exception as e:
            logger.error(f"Plugin registration failed: {e}")
            return False
    
    def _validate_plugin(self, plugin: BasePlugin) -> bool:
        """Validate plugin before registration"""
        try:
            # Check required methods
            if not hasattr(plugin, 'scan') or not callable(plugin.scan):
                logger.error(f"Plugin {plugin.manifest.name} missing scan method")
                return False
            
            if not hasattr(plugin, 'validate_input') or not callable(plugin.validate_input):
                logger.error(f"Plugin {plugin.manifest.name} missing validate_input method")
                return False
            
            # Validate manifest
            manifest = plugin.manifest
            if not manifest.name or not manifest.version:
                logger.error("Plugin manifest missing name or version")
                return False
            
            if not isinstance(manifest.category, PluginCategory):
                logger.error("Plugin manifest has invalid category")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Plugin validation failed: {e}")
            return False
    
    def get_plugins_by_category(self, category: PluginCategory) -> List[Dict[str, Any]]:
        """Get all plugins in a specific category"""
        plugin_keys = self.plugin_categories.get(category, [])
        plugins = []
        
        for key in plugin_keys:
            if key in self.plugin_metadata:
                plugins.append(self.plugin_metadata[key])
        
        return plugins
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific plugin"""
        for key, metadata in self.plugin_metadata.items():
            if metadata["manifest"]["name"] == plugin_name:
                return metadata
        return None
    
    def get_all_plugins(self) -> Dict[str, Any]:
        """Get information about all registered plugins"""
        return {
            "total_plugins": len(self.registered_plugins),
            "by_category": {
                category.value: len(plugins) 
                for category, plugins in self.plugin_categories.items()
            },
            "plugins": list(self.plugin_metadata.values())
        }
    
    def execute_plugin(self, plugin_name: str, content: str, file_path: str, 
                      context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a specific plugin"""
        return plugin_manager.execute_plugin(plugin_name, content, file_path, context)

# Global plugin registry instance
plugin_registry = PluginRegistry()

def initialize_plugin_system():
    """Initialize the plugin system and return summary"""
    try:
        discovered = plugin_registry.auto_discover_plugins()

        # Generate mock data for demonstration
        return {
            'total_plugins': 22,
            'discovered_plugins': discovered,
            'by_category': {
                'cloud_security': 3,
                'web_application': 5,
                'binary_analysis': 3,
                'infrastructure': 3,
                'source_code': 4,
                'network_security': 3,
                'compliance': 1
            },
            'status': 'initialized'
        }
    except Exception as e:
        logger.error(f"Plugin system initialization failed: {e}")
        return {
            'total_plugins': 0,
            'discovered_plugins': 0,
            'by_category': {},
            'status': 'failed',
            'error': str(e)
        }

def get_plugin_marketplace_data():
    """Get plugin marketplace data for frontend"""
    try:
        # Mock marketplace data
        categories = [
            {
                'name': 'cloud_security',
                'display_name': 'Cloud Security',
                'description': 'AWS, GCP, Azure security scanners',
                'plugin_count': 3,
                'plugins': [
                    {
                        'manifest': {
                            'name': 'aws_s3_exposure_scanner',
                            'version': '1.0.0',
                            'description': 'Detects AWS S3 bucket misconfigurations',
                            'category': 'cloud_security',
                            'trust_level': 'high'
                        },
                        'trust_score': 0.95,
                        'stats': {'executions': 156, 'trust_score': 0.95}
                    },
                    {
                        'manifest': {
                            'name': 'gcp_iam_weakness_detector',
                            'version': '1.0.0',
                            'description': 'Finds GCP IAM privilege escalation risks',
                            'category': 'cloud_security',
                            'trust_level': 'high'
                        },
                        'trust_score': 0.92,
                        'stats': {'executions': 89, 'trust_score': 0.92}
                    },
                    {
                        'manifest': {
                            'name': 'azure_keyvault_scanner',
                            'version': '1.0.0',
                            'description': 'Scans Azure KeyVault configurations',
                            'category': 'cloud_security',
                            'trust_level': 'high'
                        },
                        'trust_score': 0.90,
                        'stats': {'executions': 67, 'trust_score': 0.90}
                    }
                ]
            },
            {
                'name': 'web_application',
                'display_name': 'Web Application',
                'description': 'Web security vulnerability scanners',
                'plugin_count': 5,
                'plugins': [
                    {
                        'manifest': {
                            'name': 'ssrf_detector',
                            'version': '1.0.0',
                            'description': 'Detects Server-Side Request Forgery vulnerabilities',
                            'category': 'web_application',
                            'trust_level': 'high'
                        },
                        'trust_score': 0.96,
                        'stats': {'executions': 234, 'trust_score': 0.96}
                    },
                    {
                        'manifest': {
                            'name': 'jwt_security_validator',
                            'version': '1.0.0',
                            'description': 'Validates JWT security configurations',
                            'category': 'web_application',
                            'trust_level': 'high'
                        },
                        'trust_score': 0.94,
                        'stats': {'executions': 178, 'trust_score': 0.94}
                    }
                ]
            }
        ]

        # Add more categories with mock data
        for cat_name, display_name, desc, count in [
            ('binary_analysis', 'Binary Analysis', 'Malware and binary security analysis', 3),
            ('infrastructure', 'Infrastructure', 'Infrastructure as Code security', 3),
            ('source_code', 'Source Code', 'Source code security patterns', 4),
            ('network_security', 'Network Security', 'Network security scanners', 3),
            ('compliance', 'Compliance', 'Regulatory compliance checkers', 1)
        ]:
            categories.append({
                'name': cat_name,
                'display_name': display_name,
                'description': desc,
                'plugin_count': count,
                'plugins': []  # Would be populated with actual plugins
            })

        return {
            'statistics': {
                'total_plugins': 22,
                'active_plugins': 22,
                'categories': 7
            },
            'categories': categories,
            'featured_plugins': categories[0]['plugins'] + categories[1]['plugins']
        }

    except Exception as e:
        logger.error(f"Failed to get marketplace data: {e}")
        return {
            'statistics': {'total_plugins': 0, 'active_plugins': 0, 'categories': 0},
            'categories': [],
            'featured_plugins': []
        }

def get_plugin_execution_stats():
    """Get plugin execution statistics"""
    try:
        return {
            'total_executions': 1247,
            'success_rate': 0.985,
            'average_execution_time': 1.2,
            'plugin_performance': [
                {
                    'plugin': 'aws_s3_exposure_scanner:1.0.0',
                    'executions': 156,
                    'success_rate': 0.95,
                    'avg_time': 1.8
                },
                {
                    'plugin': 'ssrf_detector:1.0.0',
                    'executions': 234,
                    'success_rate': 0.96,
                    'avg_time': 0.9
                },
                {
                    'plugin': 'jwt_security_validator:1.0.0',
                    'executions': 178,
                    'success_rate': 0.94,
                    'avg_time': 0.7
                },
                {
                    'plugin': 'terraform_security_scanner:1.0.0',
                    'executions': 123,
                    'success_rate': 0.98,
                    'avg_time': 2.1
                },
                {
                    'plugin': 'dockerfile_security_analyzer:1.0.0',
                    'executions': 98,
                    'success_rate': 0.97,
                    'avg_time': 1.5
                }
            ]
        }
    except Exception as e:
        logger.error(f"Failed to get execution stats: {e}")
        return {
            'total_executions': 0,
            'success_rate': 0.0,
            'average_execution_time': 0.0,
            'plugin_performance': []
        }

def initialize_plugin_system():
    """Initialize the plugin system with all available plugins"""
    logger.info("Initializing ByteGuardX Plugin System...")
    
    # Auto-discover and register plugins
    discovered_count = plugin_registry.auto_discover_plugins()
    
    # Register built-in plugins manually if auto-discovery fails
    if discovered_count == 0:
        _register_builtin_plugins()
    
    logger.info(f"Plugin system initialized with {len(plugin_registry.registered_plugins)} plugins")
    
    return plugin_registry.get_all_plugins()

def _register_builtin_plugins():
    """Register built-in plugins manually"""
    try:
        # Cloud Security Plugins
        from .cloud_security.aws_s3_exposure_scanner import AWSS3ExposureScanner
        from .cloud_security.gcp_iam_weakness_detector import GCPIAMWeaknessDetector
        
        # Web Security Plugins
        from .web_security.ssrf_detector import SSRFDetector
        
        # Binary Analysis Plugins
        from .binary_analysis.elf_pe_malware_scanner import ELFPEMalwareScanner
        
        # Register plugins
        builtin_plugins = [
            AWSS3ExposureScanner(),
            GCPIAMWeaknessDetector(),
            SSRFDetector(),
            ELFPEMalwareScanner()
        ]
        
        for plugin in builtin_plugins:
            plugin_registry.register_plugin(plugin)
            
    except Exception as e:
        logger.error(f"Failed to register built-in plugins: {e}")

def get_plugin_marketplace_data() -> Dict[str, Any]:
    """Get data for plugin marketplace UI"""
    all_plugins = plugin_registry.get_all_plugins()
    
    # Organize plugins by category for marketplace
    marketplace_data = {
        "categories": [],
        "featured_plugins": [],
        "statistics": {
            "total_plugins": all_plugins["total_plugins"],
            "categories": len(all_plugins["by_category"]),
            "active_plugins": all_plugins["total_plugins"]  # All are active for now
        }
    }
    
    # Build category data
    for category in PluginCategory:
        category_plugins = plugin_registry.get_plugins_by_category(category)
        
        if category_plugins:  # Only include categories with plugins
            marketplace_data["categories"].append({
                "name": category.value,
                "display_name": category.value.replace("_", " ").title(),
                "plugin_count": len(category_plugins),
                "plugins": category_plugins[:5],  # Show first 5 plugins
                "description": _get_category_description(category)
            })
    
    # Select featured plugins (highest trust scores)
    all_plugin_list = []
    for plugins in plugin_registry.plugin_categories.values():
        for plugin_key in plugins:
            if plugin_key in plugin_registry.plugin_metadata:
                all_plugin_list.append(plugin_registry.plugin_metadata[plugin_key])
    
    # Sort by trust score and take top 6
    featured = sorted(all_plugin_list, 
                     key=lambda x: x.get("trust_score", 0), 
                     reverse=True)[:6]
    marketplace_data["featured_plugins"] = featured
    
    return marketplace_data

def _get_category_description(category: PluginCategory) -> str:
    """Get description for plugin category"""
    descriptions = {
        PluginCategory.CLOUD_SECURITY: "Detect cloud misconfigurations and security issues in AWS, GCP, Azure",
        PluginCategory.WEB_APPLICATION: "Find web application vulnerabilities like SSRF, XSS, and injection flaws",
        PluginCategory.BINARY_ANALYSIS: "Analyze binary files for malware, packers, and suspicious patterns",
        PluginCategory.NETWORK_SECURITY: "Scan for network vulnerabilities and exposure issues",
        PluginCategory.SOURCE_CODE: "Detect code-level security issues and dangerous patterns",
        PluginCategory.INFRASTRUCTURE: "Analyze infrastructure as code for security misconfigurations",
        PluginCategory.COMPLIANCE: "Check compliance with security frameworks and standards",
        PluginCategory.MALWARE_DETECTION: "Advanced malware detection and analysis capabilities"
    }
    
    return descriptions.get(category, "Security scanning plugins")

def get_plugin_execution_stats() -> Dict[str, Any]:
    """Get plugin execution statistics"""
    stats = {
        "total_executions": 0,
        "success_rate": 0.0,
        "average_execution_time": 0.0,
        "plugin_performance": [],
        "category_usage": {}
    }
    
    # Get stats from plugin manager
    for plugin_key, plugin_stats in plugin_manager.plugin_stats.items():
        stats["total_executions"] += plugin_stats.get("executions", 0)
        
        # Calculate success rate
        successes = plugin_stats.get("successes", 0)
        executions = plugin_stats.get("executions", 1)
        success_rate = successes / executions if executions > 0 else 0
        
        # Add to plugin performance
        stats["plugin_performance"].append({
            "plugin": plugin_key,
            "executions": executions,
            "success_rate": success_rate,
            "avg_time": plugin_stats.get("avg_execution_time", 0),
            "trust_score": plugin_stats.get("trust_score", 0)
        })
    
    # Calculate overall success rate
    total_successes = sum(p["success_rate"] * p["executions"] for p in stats["plugin_performance"])
    stats["success_rate"] = total_successes / max(stats["total_executions"], 1)
    
    # Calculate average execution time
    total_time = sum(p["avg_time"] * p["executions"] for p in stats["plugin_performance"])
    stats["average_execution_time"] = total_time / max(stats["total_executions"], 1)
    
    # Sort plugin performance by executions
    stats["plugin_performance"].sort(key=lambda x: x["executions"], reverse=True)
    
    return stats
