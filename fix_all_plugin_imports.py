#!/usr/bin/env python3
"""
Script to fix all plugin imports to use mock framework first
"""

import os
import re
from pathlib import Path

def fix_all_plugin_imports():
    """Fix all plugin imports to use mock framework first"""
    
    plugin_dirs = [
        "byteguardx/plugins/cloud_security",
        "byteguardx/plugins/web_security", 
        "byteguardx/plugins/binary_analysis",
        "byteguardx/plugins/network_security",
        "byteguardx/plugins/source_code",
        "byteguardx/plugins/infrastructure",
        "byteguardx/plugins/compliance"
    ]
    
    old_pattern = r'try:\s*\n\s*from \.\.plugin_framework import BasePlugin, PluginManifest, PluginCategory\s*\nexcept ImportError:\s*\n\s*from \.\.plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory'
    
    new_import = """try:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory"""
    
    fixed_files = []
    
    for plugin_dir in plugin_dirs:
        if not os.path.exists(plugin_dir):
            continue
            
        for python_file in Path(plugin_dir).glob("*.py"):
            if python_file.name.startswith("__"):
                continue
                
            try:
                with open(python_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Replace the import pattern
                updated_content = re.sub(old_pattern, new_import, content, flags=re.MULTILINE | re.DOTALL)
                
                # Also handle simple cases
                if 'from ..plugin_framework import' in content and 'try:' in content:
                    lines = content.split('\n')
                    new_lines = []
                    skip_import_block = False
                    import_replaced = False
                    
                    for line in lines:
                        if 'try:' in line and not import_replaced and 'plugin_framework' in ''.join(lines[lines.index(line):lines.index(line)+5]):
                            new_lines.extend(new_import.split('\n'))
                            import_replaced = True
                            skip_import_block = True
                        elif skip_import_block and ('from ..' in line or 'except ImportError:' in line or line.strip() == ''):
                            continue
                        else:
                            skip_import_block = False
                            new_lines.append(line)
                    
                    updated_content = '\n'.join(new_lines)
                
                if updated_content != content:
                    with open(python_file, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
                    
                    fixed_files.append(str(python_file))
                    print(f"✅ Fixed: {python_file}")
                    
            except Exception as e:
                print(f"❌ Failed to fix {python_file}: {e}")
    
    print(f"\n🎉 Fixed {len(fixed_files)} plugin files")
    return fixed_files

if __name__ == "__main__":
    fix_all_plugin_imports()
