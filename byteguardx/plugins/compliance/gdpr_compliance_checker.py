"""
GDPR Compliance Checker Plugin
Detects GDPR compliance issues in code and configurations
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class GDPRComplianceChecker(BasePlugin):
    """Scanner for GDPR compliance issues"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="gdpr_compliance_checker",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects GDPR compliance issues and data protection violations",
            category=PluginCategory.COMPLIANCE,
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
        
        self.gdpr_patterns = {
            "personal_data_collection": {
                "patterns": [
                    r'email.*collect',
                    r'phone.*collect',
                    r'address.*collect',
                    r'personal.*data.*store',
                    r'user.*information.*save'
                ],
                "description": "Personal data collection without consent mechanism",
                "severity": "medium"
            },
            "missing_consent": {
                "patterns": [
                    r'cookie.*set(?!.*consent)',
                    r'tracking.*(?!.*consent)',
                    r'analytics.*(?!.*consent)'
                ],
                "description": "Data processing without explicit consent",
                "severity": "high"
            },
            "data_retention": {
                "patterns": [
                    r'delete.*user.*data',
                    r'retention.*policy',
                    r'data.*expiry',
                    r'purge.*personal'
                ],
                "description": "Data retention mechanism detected",
                "severity": "low"
            },
            "data_export": {
                "patterns": [
                    r'export.*user.*data',
                    r'download.*personal.*data',
                    r'data.*portability'
                ],
                "description": "Data portability mechanism detected",
                "severity": "low"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        gdpr_indicators = ["personal", "data", "privacy", "consent", "cookie", "tracking"]
        return any(indicator in content.lower() for indicator in gdpr_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.gdpr_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"GDPR Compliance: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.6,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-200",
                            "remediation": "Ensure GDPR compliance for data processing",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
