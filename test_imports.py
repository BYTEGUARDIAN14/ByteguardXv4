#!/usr/bin/env python3
"""
Test ByteGuardX imports
"""

import sys
import os

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test critical imports"""
    
    print("🔍 Testing ByteGuardX Imports")
    print("=" * 40)
    
    tests = [
        ('byteguardx.plugins.plugin_registry', 'Plugin Registry'),
        ('byteguardx.plugins.plugin_framework_mock', 'Plugin Framework Mock'),
        ('byteguardx.core.unified_scanner', 'Unified Scanner'),
        ('byteguardx.api.app', 'API App')
    ]
    
    for module_name, description in tests:
        try:
            __import__(module_name)
            print(f"✅ {description}: OK")
        except Exception as e:
            print(f"❌ {description}: {e}")
    
    # Test specific functions
    print("\n🔧 Testing Plugin Registry Functions")
    print("-" * 30)
    
    try:
        from byteguardx.plugins.plugin_registry import (
            initialize_plugin_system,
            get_plugin_marketplace_data,
            get_plugin_execution_stats
        )
        
        print("✅ Plugin registry functions imported")
        
        # Test function calls
        try:
            result = initialize_plugin_system()
            print(f"✅ initialize_plugin_system: {result['total_plugins']} plugins")
        except Exception as e:
            print(f"❌ initialize_plugin_system: {e}")
        
        try:
            result = get_plugin_marketplace_data()
            print(f"✅ get_plugin_marketplace_data: {result['statistics']['total_plugins']} plugins")
        except Exception as e:
            print(f"❌ get_plugin_marketplace_data: {e}")
        
        try:
            result = get_plugin_execution_stats()
            print(f"✅ get_plugin_execution_stats: {result['total_executions']} executions")
        except Exception as e:
            print(f"❌ get_plugin_execution_stats: {e}")
            
    except Exception as e:
        print(f"❌ Plugin registry functions: {e}")

if __name__ == "__main__":
    test_imports()
