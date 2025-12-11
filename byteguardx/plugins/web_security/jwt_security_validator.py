"""
JWT Security Validator Plugin
Detects insecure JWT token implementations
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class JWTSecurityValidator(BasePlugin):
    """Scanner for JWT security issues"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="jwt_security_validator",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects insecure JWT token implementations and configurations",
            category=PluginCategory.WEB_APPLICATION,
            supported_languages=["python", "javascript", "java", "csharp"],
            supported_file_types=[".py", ".js", ".ts", ".java", ".cs"],
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
        
        self.jwt_patterns = {
            "weak_secret": {
                "patterns": [
                    r'jwt.*secret.*=.*["\'][^"\']{1,16}["\']',
                    r'JWT_SECRET.*=.*["\'][^"\']{1,16}["\']'
                ],
                "description": "JWT secret key is too weak",
                "severity": "high"
            },
            "no_signature_verification": {
                "patterns": [
                    r'verify.*=.*false',
                    r'verify_signature.*false',
                    r'algorithm.*none'
                ],
                "description": "JWT signature verification disabled",
                "severity": "critical"
            },
            "hardcoded_jwt_secret": {
                "patterns": [
                    r'jwt.*secret.*=.*["\'][A-Za-z0-9+/=]{20,}["\']',
                    r'JWT_SECRET.*=.*["\'][A-Za-z0-9+/=]{20,}["\']'
                ],
                "description": "Hardcoded JWT secret in source code",
                "severity": "high"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return "jwt" in content.lower() or "jsonwebtoken" in content.lower()
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.jwt_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"JWT Security Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-287",
                            "remediation": "Use strong JWT secrets and proper verification",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
