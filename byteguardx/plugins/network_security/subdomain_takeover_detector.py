"""
Subdomain Takeover Risk Detector Plugin
Detects potential subdomain takeover vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class SubdomainTakeoverDetector(BasePlugin):
    """Scanner for subdomain takeover risks"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="subdomain_takeover_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects potential subdomain takeover vulnerabilities and misconfigurations",
            category=PluginCategory.NETWORK_SECURITY,
            supported_languages=["dns", "config", "yaml", "json"],
            supported_file_types=[".zone", ".conf", ".yaml", ".yml", ".json"],
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
        
        self.takeover_patterns = {
            "dangling_cname": {
                "patterns": [
                    r'CNAME.*\.amazonaws\.com',
                    r'CNAME.*\.azurewebsites\.net',
                    r'CNAME.*\.herokuapp\.com',
                    r'CNAME.*\.github\.io',
                    r'CNAME.*\.netlify\.com'
                ],
                "description": "Dangling CNAME record to cloud service",
                "severity": "high"
            },
            "orphaned_subdomain": {
                "patterns": [
                    r'subdomain.*\..*\.com.*CNAME.*404',
                    r'CNAME.*nonexistent',
                    r'CNAME.*deleted'
                ],
                "description": "Orphaned subdomain configuration",
                "severity": "medium"
            },
            "cloud_service_cname": {
                "patterns": [
                    r'CNAME.*\.s3\.amazonaws\.com',
                    r'CNAME.*\.cloudfront\.net',
                    r'CNAME.*\.trafficmanager\.net'
                ],
                "description": "CNAME pointing to cloud service",
                "severity": "low"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        dns_indicators = ["CNAME", "subdomain", "dns", "zone", "record"]
        return any(indicator in content for indicator in dns_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.takeover_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Subdomain Takeover Risk: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.7,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-346",
                            "remediation": "Verify CNAME targets and remove dangling records",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
