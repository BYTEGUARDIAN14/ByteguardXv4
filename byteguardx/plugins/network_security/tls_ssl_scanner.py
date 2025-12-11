"""
TLS/SSL Misconfiguration Scanner Plugin
Detects TLS/SSL security misconfigurations
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class TLSSSLScanner(BasePlugin):
    """Scanner for TLS/SSL misconfigurations"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="tls_ssl_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects TLS/SSL security misconfigurations and weak cipher suites",
            category=PluginCategory.NETWORK_SECURITY,
            supported_languages=["python", "javascript", "java", "csharp", "nginx", "apache"],
            supported_file_types=[".py", ".js", ".ts", ".java", ".cs", ".conf", ".config"],
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
        
        self.tls_patterns = {
            "weak_protocols": {
                "patterns": [
                    r'ssl_protocols.*SSLv2',
                    r'ssl_protocols.*SSLv3',
                    r'ssl_protocols.*TLSv1\.0',
                    r'TLS_VERSION.*1\.0',
                    r'PROTOCOL_SSLv2',
                    r'PROTOCOL_SSLv3'
                ],
                "description": "Weak SSL/TLS protocol version enabled",
                "severity": "high"
            },
            "weak_ciphers": {
                "patterns": [
                    r'ssl_ciphers.*RC4',
                    r'ssl_ciphers.*DES',
                    r'ssl_ciphers.*MD5',
                    r'cipher.*RC4',
                    r'cipher.*DES'
                ],
                "description": "Weak cipher suite enabled",
                "severity": "medium"
            },
            "certificate_validation_disabled": {
                "patterns": [
                    r'verify_mode.*CERT_NONE',
                    r'verify.*false',
                    r'ssl_verify.*false',
                    r'rejectUnauthorized.*false'
                ],
                "description": "SSL certificate validation disabled",
                "severity": "high"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        tls_indicators = ["ssl", "tls", "https", "certificate", "cipher"]
        return any(indicator in content.lower() for indicator in tls_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.tls_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"TLS/SSL Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-326",
                            "remediation": "Use strong TLS protocols and cipher suites",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
