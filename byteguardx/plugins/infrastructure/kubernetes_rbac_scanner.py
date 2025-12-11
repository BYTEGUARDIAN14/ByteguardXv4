"""
Kubernetes RBAC Misconfiguration Scanner Plugin
Detects Kubernetes RBAC security misconfigurations
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class KubernetesRBACScanner(BasePlugin):
    """Scanner for Kubernetes RBAC misconfigurations"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="kubernetes_rbac_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects Kubernetes RBAC security misconfigurations and privilege escalation risks",
            category=PluginCategory.INFRASTRUCTURE,
            supported_languages=["yaml", "json"],
            supported_file_types=[".yaml", ".yml", ".json"],
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
        
        self.k8s_patterns = {
            "cluster_admin_binding": {
                "patterns": [
                    r'roleRef:.*name:\s*cluster-admin',
                    r'clusterrole.*cluster-admin'
                ],
                "description": "Cluster admin role binding detected",
                "severity": "high"
            },
            "wildcard_permissions": {
                "patterns": [
                    r'resources:\s*-\s*"\*"',
                    r'verbs:\s*-\s*"\*"',
                    r'apiGroups:\s*-\s*"\*"'
                ],
                "description": "Wildcard permissions in RBAC",
                "severity": "medium"
            },
            "privileged_pod": {
                "patterns": [
                    r'privileged:\s*true',
                    r'runAsUser:\s*0',
                    r'hostNetwork:\s*true',
                    r'hostPID:\s*true'
                ],
                "description": "Privileged pod configuration",
                "severity": "high"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        k8s_indicators = ["apiVersion", "kind:", "ClusterRole", "RoleBinding", "ServiceAccount"]
        return any(indicator in content for indicator in k8s_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.k8s_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Kubernetes RBAC Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.8,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-269",
                            "remediation": "Apply principle of least privilege to Kubernetes RBAC",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
