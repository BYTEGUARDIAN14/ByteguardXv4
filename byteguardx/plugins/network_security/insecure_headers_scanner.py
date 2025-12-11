"""
Insecure HTTP Headers Scanner Plugin
Detects missing or misconfigured security headers
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class InsecureHeadersScanner(BasePlugin):
    """Scanner for insecure HTTP headers"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="insecure_headers_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects missing or misconfigured HTTP security headers",
            category=PluginCategory.NETWORK_SECURITY,
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
        
        self.header_patterns = {
            "missing_csp": {
                "patterns": [
                    r'response\.headers(?!.*Content-Security-Policy)',
                    r'res\.set\((?!.*Content-Security-Policy)',
                    r'HttpServletResponse(?!.*Content-Security-Policy)'
                ],
                "description": "Missing Content-Security-Policy header",
                "severity": "medium"
            },
            "missing_hsts": {
                "patterns": [
                    r'response\.headers(?!.*Strict-Transport-Security)',
                    r'res\.set\((?!.*Strict-Transport-Security)'
                ],
                "description": "Missing Strict-Transport-Security header",
                "severity": "medium"
            },
            "unsafe_csp": {
                "patterns": [
                    r'Content-Security-Policy.*unsafe-inline',
                    r'Content-Security-Policy.*unsafe-eval',
                    r'CSP.*unsafe-inline'
                ],
                "description": "Unsafe Content-Security-Policy directive",
                "severity": "high"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        header_indicators = ["headers", "response", "Content-Security-Policy", "X-Frame-Options"]
        return any(indicator in content for indicator in header_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.header_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"HTTP Header Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.7,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-693",
                            "remediation": "Implement proper security headers",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
