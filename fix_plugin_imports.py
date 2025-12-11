#!/usr/bin/env python3
"""
Script to fix plugin import issues
"""

import os
import re
from pathlib import Path

def fix_plugin_imports():
    """Fix all plugin import issues"""
    
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
                
                # Find and replace the import section
                lines = content.split('\n')
                new_lines = []
                skip_until_class = False
                
                for i, line in enumerate(lines):
                    if 'try:' in line and i < 20:  # Import section is usually at the top
                        # Look ahead to see if this is our import block
                        if i + 3 < len(lines) and 'plugin_framework' in lines[i+1]:
                            # Replace the entire import block
                            new_lines.extend(correct_import.split('\n'))
                            # Skip the old import block
                            j = i + 1
                            while j < len(lines) and (
                                'from ..' in lines[j] or 
                                'except ImportError:' in lines[j] or
                                lines[j].strip() == ''
                            ):
                                j += 1
                            i = j - 1  # Will be incremented by the loop
                            skip_until_class = False
                        else:
                            new_lines.append(line)
                    elif skip_until_class:
                        if 'class ' in line:
                            skip_until_class = False
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                
                # Write the fixed content
                fixed_content = '\n'.join(new_lines)
                
                with open(python_file, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                fixed_files.append(str(python_file))
                print(f"✅ Fixed: {python_file}")
                    
            except Exception as e:
                print(f"❌ Failed to fix {python_file}: {e}")
    
    print(f"\n🎉 Fixed {len(fixed_files)} plugin files")
    return fixed_files

if __name__ == "__main__":
    fix_plugin_imports()
