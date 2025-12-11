"""
Broken Access Control Detector Plugin
Detects broken access control vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class BrokenAccessControlDetector(BasePlugin):
    """Scanner for broken access control vulnerabilities"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="broken_access_control_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects broken access control and authorization bypass vulnerabilities",
            category=PluginCategory.WEB_APPLICATION,
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
        
        self.access_control_patterns = {
            "missing_authorization": {
                "patterns": [
                    r'@app\.route.*(?!.*@login_required)(?!.*@auth)',
                    r'@RequestMapping.*(?!.*@PreAuthorize)(?!.*@Secured)',
                    r'function.*admin.*\((?!.*auth)(?!.*login)'
                ],
                "description": "Endpoint missing authorization check",
                "severity": "high"
            },
            "role_based_bypass": {
                "patterns": [
                    r'if.*user\.role.*==.*admin.*:(?!.*else)',
                    r'user\.isAdmin\(\)(?!.*else)',
                    r'role.*==.*["\']admin["\'](?!.*else)'
                ],
                "description": "Role-based access control bypass possible",
                "severity": "medium"
            },
            "direct_object_reference": {
                "patterns": [
                    r'user_id.*=.*request\.',
                    r'file_id.*=.*params\.',
                    r'document_id.*=.*args\.'
                ],
                "description": "Potential insecure direct object reference",
                "severity": "medium"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        access_indicators = ["auth", "login", "role", "permission", "admin", "user"]
        return any(indicator in content.lower() for indicator in access_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.access_control_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Access Control Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.7,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-862",
                            "remediation": "Implement proper authorization checks",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
