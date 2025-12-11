"""
Terraform Security Scanner Plugin
Detects security misconfigurations in Terraform files
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class TerraformSecurityScanner(BasePlugin):
    """Scanner for Terraform security misconfigurations"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="terraform_security_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects security misconfigurations in Terraform infrastructure code",
            category=PluginCategory.INFRASTRUCTURE,
            supported_languages=["terraform", "hcl"],
            supported_file_types=[".tf", ".tfvars"],
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
        
        self.terraform_patterns = {
            "hardcoded_secrets": {
                "patterns": [
                    r'password\s*=\s*"[^"]{8,}"',
                    r'secret\s*=\s*"[^"]{8,}"',
                    r'api_key\s*=\s*"[^"]{8,}"'
                ],
                "description": "Hardcoded secrets in Terraform configuration",
                "severity": "critical"
            },
            "public_s3_bucket": {
                "patterns": [
                    r'acl\s*=\s*"public-read"',
                    r'acl\s*=\s*"public-read-write"'
                ],
                "description": "S3 bucket configured with public access",
                "severity": "high"
            },
            "unencrypted_storage": {
                "patterns": [
                    r'encrypted\s*=\s*false',
                    r'server_side_encryption_configuration\s*=\s*\[\]'
                ],
                "description": "Storage resource lacks encryption",
                "severity": "medium"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return file_path.endswith('.tf') or 'resource "' in content
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.terraform_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Terraform Security Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "remediation": "Fix Terraform security configuration",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
