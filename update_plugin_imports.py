#!/usr/bin/env python3
"""
Script to update plugin imports to use mock framework
"""

import os
import re
from pathlib import Path

def update_plugin_imports():
    """Update all plugin files to use mock framework fallback"""
    
    plugin_dirs = [
        "byteguardx/plugins/cloud_security",
        "byteguardx/plugins/web_security", 
        "byteguardx/plugins/binary_analysis",
        "byteguardx/plugins/network_security",
        "byteguardx/plugins/source_code",
        "byteguardx/plugins/infrastructure",
        "byteguardx/plugins/compliance"
    ]
    
    old_import = "from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory"
    new_import = """try:
    from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory"""
    
    updated_files = []
    
    for plugin_dir in plugin_dirs:
        if not os.path.exists(plugin_dir):
            continue
            
        for python_file in Path(plugin_dir).glob("*.py"):
            if python_file.name.startswith("__"):
                continue
                
            try:
                with open(python_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if old_import in content:
                    updated_content = content.replace(old_import, new_import)
                    
                    with open(python_file, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
                    
                    updated_files.append(str(python_file))
                    print(f"✅ Updated: {python_file}")
                    
            except Exception as e:
                print(f"❌ Failed to update {python_file}: {e}")
    
    print(f"\n🎉 Updated {len(updated_files)} plugin files")
    return updated_files

if __name__ == "__main__":
    update_plugin_imports()
