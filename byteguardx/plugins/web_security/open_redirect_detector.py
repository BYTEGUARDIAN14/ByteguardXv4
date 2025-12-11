"""
Open Redirect Detector Plugin
Detects open redirect vulnerabilities in web applications
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class OpenRedirectDetector(BasePlugin):
    """Scanner for open redirect vulnerabilities"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="open_redirect_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects open redirect vulnerabilities in web applications",
            category=PluginCategory.WEB_APPLICATION,
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
        
        self.redirect_patterns = {
            "redirect_with_user_input": {
                "patterns": [
                    r'redirect\s*\(\s*[^)]*(?:request\.|params\.|args\.)',
                    r'Response\.Redirect\s*\(\s*[^)]*Request\.',
                    r'header\s*\(\s*["\']Location["\'].*\$_(?:GET|POST)',
                    r'window\.location\s*=\s*[^;]*(?:params\.|query\.)'
                ],
                "description": "Redirect function uses unsanitized user input",
                "severity": "medium"
            },
            "javascript_redirect": {
                "patterns": [
                    r'window\.location\.href\s*=\s*[^;]*(?:params\.|query\.)',
                    r'document\.location\s*=\s*[^;]*(?:params\.|query\.)'
                ],
                "description": "JavaScript redirect with user input",
                "severity": "medium"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return "redirect" in content.lower() or "location" in content.lower()
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.redirect_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Open Redirect: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.7,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-601",
                            "remediation": "Validate redirect URLs against allowlist",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
