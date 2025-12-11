"""
Cryptographic Weakness Detector Plugin
Detects weak cryptographic implementations and algorithms
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class CryptoWeaknessDetector(BasePlugin):
    """Scanner for cryptographic weaknesses"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="crypto_weakness_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects weak cryptographic algorithms and implementations",
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
        
        self.crypto_patterns = {
            "weak_algorithms": {
                "patterns": [
                    r'\bMD5\s*\(',
                    r'\bSHA1\s*\(',
                    r'\bDES\s*\(',
                    r'\bRC4\s*\(',
                    r'hashlib\.md5',
                    r'hashlib\.sha1',
                    r'crypto\.MD5',
                    r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'
                ],
                "description": "Weak cryptographic algorithm detected",
                "severity": "medium"
            },
            "hardcoded_keys": {
                "patterns": [
                    r'key\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']',
                    r'secret\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']',
                    r'password\s*=\s*["\'][A-Za-z0-9+/=]{8,}["\']'
                ],
                "description": "Hardcoded cryptographic key or password",
                "severity": "high"
            },
            "weak_random": {
                "patterns": [
                    r'\brandom\.random\s*\(',
                    r'\bMath\.random\s*\(',
                    r'\brand\s*\(',
                    r'\bsrand\s*\('
                ],
                "description": "Weak random number generation",
                "severity": "medium"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        crypto_indicators = ["crypto", "hash", "encrypt", "decrypt", "cipher", "key", "random"]
        return any(indicator in content.lower() for indicator in crypto_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.crypto_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Crypto Weakness: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-327",
                            "remediation": "Use strong cryptographic algorithms and secure key management",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
