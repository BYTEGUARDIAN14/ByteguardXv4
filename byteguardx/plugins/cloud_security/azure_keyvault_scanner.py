"""
Azure KeyVault Misconfiguration Scanner Plugin
Detects Azure KeyVault security misconfigurations
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class AzureKeyVaultScanner(BasePlugin):
    """Scanner for Azure KeyVault misconfigurations"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="azure_keyvault_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects Azure KeyVault security misconfigurations and access control issues",
            category=PluginCategory.CLOUD_SECURITY,
            supported_languages=["json", "yaml", "terraform", "arm"],
            supported_file_types=[".json", ".yaml", ".yml", ".tf", ".bicep"],
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
        
        self.keyvault_patterns = {
            "public_network_access": {
                "patterns": [r'"publicNetworkAccess"\s*:\s*"Enabled"', r'public_network_access_enabled\s*=\s*true'],
                "description": "KeyVault allows public network access",
                "severity": "high"
            },
            "missing_rbac": {
                "patterns": [r'"enableRbacAuthorization"\s*:\s*false', r'enable_rbac_authorization\s*=\s*false'],
                "description": "KeyVault RBAC authorization is disabled",
                "severity": "medium"
            },
            "soft_delete_disabled": {
                "patterns": [r'"enableSoftDelete"\s*:\s*false', r'soft_delete_enabled\s*=\s*false'],
                "description": "KeyVault soft delete is disabled",
                "severity": "medium"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return "keyvault" in content.lower() or "key vault" in content.lower()
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.keyvault_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Azure KeyVault Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "remediation": "Configure KeyVault with proper security settings",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
