"""
Plugin System for ByteGuardX
Provides extensible architecture for custom scanners and detection rules
"""

# Import only existing modules to avoid import errors
try:
    from .plugin_manager import PluginManager, PluginRegistry
except ImportError:
    pass

try:
    from .base_plugin import BasePlugin, ScannerPlugin, RulePlugin
except ImportError:
    pass

__all__ = [
    'PluginManager', 'PluginRegistry', 'BasePlugin', 'ScannerPlugin', 'RulePlugin'
]
