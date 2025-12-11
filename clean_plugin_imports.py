#!/usr/bin/env python3
"""
Script to clean up plugin import issues
"""

import os
import re
from pathlib import Path

def clean_plugin_imports():
    """Clean up all plugin import issues"""
    
    plugin_dirs = [
        "byteguardx/plugins/cloud_security",
        "byteguardx/plugins/web_security", 
        "byteguardx/plugins/binary_analysis",
        "byteguardx/plugins/network_security",
        "byteguardx/plugins/source_code",
        "byteguardx/plugins/infrastructure",
        "byteguardx/plugins/compliance"
    ]
    
    correct_import = """try:
    from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory"""
    
    cleaned_files = []
    
    for plugin_dir in plugin_dirs:
        if not os.path.exists(plugin_dir):
            continue
            
        for python_file in Path(plugin_dir).glob("*.py"):
            if python_file.name.startswith("__"):
                continue
                
            try:
                with open(python_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Remove all existing import blocks and replace with clean one
                lines = content.split('\n')
                new_lines = []
                in_import_block = False
                import_added = False
                
                for line in lines:
                    # Skip the problematic import section
                    if ('try:' in line or 'except ImportError:' in line or 'from ..plugin_framework' in line) and not import_added:
                        if not import_added:
                            new_lines.extend(correct_import.split('\n'))
                            import_added = True
                        in_import_block = True
                        continue
                    elif in_import_block and (line.strip() == '' or 'from ..' in line):
                        continue
                    else:
                        in_import_block = False
                        new_lines.append(line)
                
                # Write the cleaned content
                cleaned_content = '\n'.join(new_lines)
                
                with open(python_file, 'w', encoding='utf-8') as f:
                    f.write(cleaned_content)
                
                cleaned_files.append(str(python_file))
                print(f"✅ Cleaned: {python_file}")
                    
            except Exception as e:
                print(f"❌ Failed to clean {python_file}: {e}")
    
    print(f"\n🎉 Cleaned {len(cleaned_files)} plugin files")
    return cleaned_files

if __name__ == "__main__":
    clean_plugin_imports()
