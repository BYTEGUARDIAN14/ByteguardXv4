"""
Dockerfile Security Analyzer Plugin
Detects security issues in Docker files
"""

import re
import logging
from typing import Dict, List, Any
try:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory
logger = logging.getLogger(__name__)

class DockerfileSecurityAnalyzer(BasePlugin):
    """Scanner for Dockerfile security issues"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="dockerfile_security_analyzer",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects security vulnerabilities and misconfigurations in Dockerfiles",
            category=PluginCategory.INFRASTRUCTURE,
            supported_languages=["dockerfile"],
            supported_file_types=["Dockerfile", ".dockerfile"],
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
        
        self.dockerfile_patterns = {
            "root_user": {
                "patterns": [r'^USER\s+root', r'^USER\s+0'],
                "description": "Container runs as root user",
                "severity": "high"
            },
            "sudo_usage": {
                "patterns": [r'RUN.*sudo', r'apt-get.*sudo'],
                "description": "Sudo usage in container build",
                "severity": "medium"
            },
            "hardcoded_secrets": {
                "patterns": [
                    r'ENV.*PASSWORD.*=',
                    r'ENV.*SECRET.*=',
                    r'ENV.*API_KEY.*='
                ],
                "description": "Hardcoded secrets in environment variables",
                "severity": "critical"
            },
            "latest_tag": {
                "patterns": [r'FROM.*:latest', r'FROM\s+[^:]+$'],
                "description": "Using latest tag for base image",
                "severity": "low"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        return 'FROM ' in content or file_path.lower().endswith('dockerfile')
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.dockerfile_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Dockerfile Security Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "remediation": "Fix Dockerfile security configuration",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
