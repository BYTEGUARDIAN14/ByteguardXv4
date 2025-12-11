"""
ReDoS (Regular Expression Denial of Service) Detector Plugin
Detects vulnerable regular expressions that can cause ReDoS attacks
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class ReDoSDetector(BasePlugin):
    """Scanner for ReDoS vulnerabilities in regular expressions"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="redos_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects regular expressions vulnerable to ReDoS (Regular Expression Denial of Service) attacks",
            category=PluginCategory.SOURCE_CODE,
            supported_languages=["python", "javascript", "java", "csharp", "php"],
            supported_file_types=[".py", ".js", ".ts", ".java", ".cs", ".php"],
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
        
        self.redos_patterns = {
            "nested_quantifiers": {
                "patterns": [
                    r'[\'"]/.*\([^)]*\+.*\)[*+].*[\'"]',
                    r'[\'"]/.*\([^)]*\*.*\)[*+].*[\'"]',
                    r'[\'"]/.*\([^)]*\{[^}]*,.*\}.*\)[*+].*[\'"]'
                ],
                "description": "Nested quantifiers in regex can cause ReDoS",
                "severity": "high"
            },
            "alternation_with_overlap": {
                "patterns": [
                    r'[\'"]/.*\([^)]*\|[^)]*\)[*+].*[\'"]',
                    r'[\'"]/.*\([^)]*\|[^)]*\)\{[^}]*,.*\}.*[\'"]'
                ],
                "description": "Alternation with overlapping patterns can cause ReDoS",
                "severity": "medium"
            },
            "exponential_backtracking": {
                "patterns": [
                    r'[\'"]/.*\([^)]*\.[*+].*\)[*+].*[\'"]',
                    r'[\'"]/.*\([^)]*\.\{[^}]*,.*\}.*\)[*+].*[\'"]'
                ],
                "description": "Pattern can cause exponential backtracking",
                "severity": "high"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return "re." in content or "regex" in content.lower() or "pattern" in content.lower()
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.redos_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line):
                        findings.append({
                            "title": f"ReDoS Vulnerability: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.7,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-1333",
                            "remediation": "Optimize regex to avoid catastrophic backtracking",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
