"""
Unsafe Function Usage Scanner Plugin
Detects usage of unsafe functions that can lead to security vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class UnsafeFunctionScanner(BasePlugin):
    """Scanner for unsafe function usage"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="unsafe_function_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects usage of unsafe functions like eval, exec, system calls",
            category=PluginCategory.SOURCE_CODE,
            supported_languages=["python", "javascript", "php", "java", "csharp"],
            supported_file_types=[".py", ".js", ".ts", ".php", ".java", ".cs"],
            requires_network=False,
            requires_filesystem=False,
            max_memory_mb=256,
            max_cpu_percent=30,
            timeout_seconds=60,
            trust_level="high",
            dependencies=[],
            api_version="1.0"
        )
        super().__init__(manifest)
        
        self.unsafe_functions = {
            "code_execution": {
                "patterns": [
                    r'\beval\s*\(',
                    r'\bexec\s*\(',
                    r'\bexecfile\s*\(',
                    r'\bcompile\s*\(',
                    r'Function\s*\(',
                    r'setTimeout\s*\(\s*["\'][^"\']*["\']',
                    r'setInterval\s*\(\s*["\'][^"\']*["\']'
                ],
                "description": "Unsafe code execution function detected",
                "severity": "critical"
            },
            "system_commands": {
                "patterns": [
                    r'\bos\.system\s*\(',
                    r'\bsubprocess\.call\s*\(',
                    r'\bsubprocess\.run\s*\(',
                    r'\bshell_exec\s*\(',
                    r'\bsystem\s*\(',
                    r'\bpassthru\s*\(',
                    r'Runtime\.getRuntime\(\)\.exec'
                ],
                "description": "System command execution detected",
                "severity": "high"
            },
            "deserialization": {
                "patterns": [
                    r'\bpickle\.loads\s*\(',
                    r'\bunserialize\s*\(',
                    r'\bJSON\.parse\s*\(',
                    r'ObjectInputStream\.readObject'
                ],
                "description": "Unsafe deserialization function detected",
                "severity": "high"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return any(func in content for func in ["eval", "exec", "system", "pickle", "unserialize"])
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.unsafe_functions.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Unsafe Function: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-94",
                            "remediation": "Replace with safer alternatives or add input validation",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
