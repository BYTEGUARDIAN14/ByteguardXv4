"""
Race Condition Pattern Analyzer Plugin
Detects potential race condition vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class RaceConditionAnalyzer(BasePlugin):
    """Scanner for race condition vulnerabilities"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="race_condition_analyzer",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects potential race condition vulnerabilities in concurrent code",
            category=PluginCategory.SOURCE_CODE,
            supported_languages=["python", "java", "csharp", "cpp"],
            supported_file_types=[".py", ".java", ".cs", ".cpp", ".c"],
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
        
        self.race_patterns = {
            "unsynchronized_access": {
                "patterns": [
                    r'global\s+\w+.*=',
                    r'static\s+\w+.*=',
                    r'shared_ptr.*=',
                    r'volatile\s+\w+.*='
                ],
                "description": "Unsynchronized access to shared variable",
                "severity": "medium"
            },
            "check_then_act": {
                "patterns": [
                    r'if.*exists.*:.*open',
                    r'if.*file.*:.*write',
                    r'if.*balance.*:.*withdraw'
                ],
                "description": "Check-then-act race condition pattern",
                "severity": "high"
            },
            "missing_locks": {
                "patterns": [
                    r'threading\.Thread.*(?!.*lock)',
                    r'new\s+Thread.*(?!.*synchronized)',
                    r'async\s+def.*(?!.*lock)'
                ],
                "description": "Thread creation without proper synchronization",
                "severity": "medium"
            }
        }
    
    def validate_input(self, content: str, file_path: str) -> bool:
        concurrency_indicators = ["thread", "async", "lock", "mutex", "synchronized", "volatile"]
        return any(indicator in content.lower() for indicator in concurrency_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.race_patterns.items():
                for pattern in pattern_data["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": f"Race Condition: {pattern_data['description']}",
                            "description": pattern_data["description"],
                            "severity": pattern_data["severity"],
                            "confidence": 0.6,
                            "file_path": file_path,
                            "line_number": line_num,
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": "CWE-362",
                            "remediation": "Use proper synchronization mechanisms",
                            "detection_metadata": {"pattern_type": pattern_name}
                        })
        
        return findings
