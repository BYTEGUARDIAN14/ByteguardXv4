"""
GraphQL Introspection Disclosure Scanner Plugin
Detects GraphQL introspection vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class GraphQLIntrospectionScanner(BasePlugin):
    """Scanner for GraphQL introspection vulnerabilities"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="graphql_introspection_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects GraphQL introspection disclosure vulnerabilities",
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
        
        self.graphql_patterns = {
            "introspection_enabled": {
                "patterns": [
                    r'introspection.*true',
                    r'introspection.*enabled',
                    r'GraphQLSchema.*introspection.*true',
                    r'buildSchema.*introspection'
                ],
                "description": "GraphQL introspection is enabled",
                "severity": "medium"
            },
            "debug_mode": {
                "patterns": [
                    r'graphql.*debug.*true',
                    r'GraphQL.*debug.*enabled',
                    r'playground.*true'
                ],
                "description": "GraphQL debug mode enabled",
                "severity": "low"
            },
            "exposed_schema": {
                "patterns": [
                    r'__schema',
                    r'__type',
                    r'__typename',
                    r'introspectionQuery'
                ],
                "description": "GraphQL schema introspection queries detected",
                "severity": "low"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        graphql_indicators = ["graphql", "schema", "introspection", "playground"]
        return any(indicator in content.lower() for indicator in graphql_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.graphql_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"GraphQL Issue: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.7,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-200",
                            "remediation": "Disable GraphQL introspection in production",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
