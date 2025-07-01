"""
AI Pattern Scanner - Detect unsafe AI-generated code patterns
"""

import re
import json
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class AIPatternMatch:
    """Data structure for AI pattern detection results"""
    pattern_type: str
    description: str
    line_number: int
    column_start: int
    column_end: int
    confidence: float
    file_path: str
    context: str
    severity: str
    suggestion: str

class AIPatternScanner:
    """
    Scanner for detecting unsafe patterns commonly found in AI-generated code
    """
    
    def __init__(self, patterns_file: str = None):
        self.patterns = self._load_patterns(patterns_file)
        self.compiled_patterns = self._compile_patterns()
        self.findings = []
        
    def _load_patterns(self, patterns_file: str = None) -> Dict:
        """Load AI pattern definitions from JSON file"""
        if patterns_file and Path(patterns_file).exists():
            try:
                with open(patterns_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load AI patterns file: {e}")
        
        # Default AI anti-patterns
        return {
            "input_validation": {
                "no_input_sanitization": {
                    "patterns": [
                        r"input\(\s*[\"'][^\"']*[\"']\s*\)",
                        r"raw_input\(\s*[\"'][^\"']*[\"']\s*\)",
                        r"request\.args\.get\([^)]+\)(?!\s*\|\s*safe)",
                        r"request\.form\.get\([^)]+\)(?!\s*\|\s*safe)"
                    ],
                    "description": "Direct use of user input without validation",
                    "severity": "high",
                    "suggestion": "Always validate and sanitize user input"
                },
                "sql_injection_risk": {
                    "patterns": [
                        r"execute\(\s*[\"'].*%s.*[\"']\s*%",
                        r"execute\(\s*[\"'].*\+.*[\"']\s*\)",
                        r"cursor\.execute\(\s*[\"'].*%.*[\"']\s*%",
                        r"query\s*=\s*[\"'].*\+.*[\"']"
                    ],
                    "description": "Potential SQL injection vulnerability",
                    "severity": "critical",
                    "suggestion": "Use parameterized queries or ORM methods"
                },
                "command_injection": {
                    "patterns": [
                        r"os\.system\(\s*[^)]*input\(",
                        r"subprocess\.call\(\s*[^)]*input\(",
                        r"eval\(\s*[^)]*input\(",
                        r"exec\(\s*[^)]*input\("
                    ],
                    "description": "Command injection vulnerability",
                    "severity": "critical",
                    "suggestion": "Avoid executing user input as commands"
                }
            },
            "authentication": {
                "weak_password_check": {
                    "patterns": [
                        r"password\s*==\s*[\"'][^\"']{1,7}[\"']",
                        r"if\s+password\s*==\s*[\"']password[\"']",
                        r"if\s+password\s*==\s*[\"']123456[\"']",
                        r"if\s+password\s*==\s*[\"']admin[\"']"
                    ],
                    "description": "Weak or hardcoded password check",
                    "severity": "high",
                    "suggestion": "Use proper password hashing and validation"
                },
                "no_auth_check": {
                    "patterns": [
                        r"@app\.route\([^)]+\)(?!\s*@.*auth)",
                        r"def\s+\w+\([^)]*\):\s*(?!.*auth|.*login|.*permission)"
                    ],
                    "description": "Endpoint without authentication check",
                    "severity": "medium",
                    "suggestion": "Add authentication decorators to protected endpoints"
                }
            },
            "crypto": {
                "weak_encryption": {
                    "patterns": [
                        r"DES\(",
                        r"MD5\(",
                        r"SHA1\(",
                        r"Random\(\)",
                        r"random\.random\(\)"
                    ],
                    "description": "Use of weak cryptographic algorithms",
                    "severity": "medium",
                    "suggestion": "Use strong cryptographic algorithms (AES, SHA-256, etc.)"
                },
                "hardcoded_crypto_key": {
                    "patterns": [
                        r"key\s*=\s*[\"'][A-Za-z0-9+/=]{16,}[\"']",
                        r"secret\s*=\s*[\"'][A-Za-z0-9+/=]{16,}[\"']",
                        r"AES\.new\(\s*[\"'][^\"']+[\"']"
                    ],
                    "description": "Hardcoded cryptographic key",
                    "severity": "high",
                    "suggestion": "Store cryptographic keys securely (environment variables, key management)"
                }
            },
            "error_handling": {
                "bare_except": {
                    "patterns": [
                        r"except\s*:",
                        r"except\s+Exception\s*:",
                        r"try:.*except.*pass"
                    ],
                    "description": "Overly broad exception handling",
                    "severity": "low",
                    "suggestion": "Catch specific exceptions and handle them appropriately"
                },
                "information_disclosure": {
                    "patterns": [
                        r"print\(\s*str\(e\)\s*\)",
                        r"return\s+str\(e\)",
                        r"traceback\.print_exc\(\)",
                        r"debug\s*=\s*True"
                    ],
                    "description": "Potential information disclosure in error messages",
                    "severity": "medium",
                    "suggestion": "Log errors securely and return generic error messages to users"
                }
            },
            "file_operations": {
                "path_traversal": {
                    "patterns": [
                        r"open\(\s*[^)]*\+[^)]*\)",
                        r"open\(\s*[^)]*input\([^)]*\)",
                        r"open\(\s*[^)]*request\.",
                        r"with\s+open\(\s*[^)]*\+[^)]*\)"
                    ],
                    "description": "Potential path traversal vulnerability",
                    "severity": "high",
                    "suggestion": "Validate and sanitize file paths"
                },
                "unsafe_file_permissions": {
                    "patterns": [
                        r"chmod\(\s*[^)]*777[^)]*\)",
                        r"os\.chmod\(\s*[^)]*0o777[^)]*\)",
                        r"stat\.S_IRWXU\s*\|\s*stat\.S_IRWXG\s*\|\s*stat\.S_IRWXO"
                    ],
                    "description": "Unsafe file permissions (world-writable)",
                    "severity": "medium",
                    "suggestion": "Use restrictive file permissions"
                }
            },
            "ai_specific": {
                "todo_comments": {
                    "patterns": [
                        r"#\s*TODO:.*security",
                        r"#\s*FIXME:.*auth",
                        r"#\s*HACK:.*validation",
                        r"//\s*TODO:.*security"
                    ],
                    "description": "Security-related TODO comments",
                    "severity": "low",
                    "suggestion": "Address security TODOs before production"
                },
                "placeholder_values": {
                    "patterns": [
                        r"password\s*=\s*[\"']changeme[\"']",
                        r"secret\s*=\s*[\"']your_secret_here[\"']",
                        r"api_key\s*=\s*[\"']your_api_key[\"']",
                        r"token\s*=\s*[\"']placeholder[\"']"
                    ],
                    "description": "Placeholder values in production code",
                    "severity": "medium",
                    "suggestion": "Replace placeholder values with proper configuration"
                }
            }
        }
    
    def _compile_patterns(self) -> Dict:
        """Compile regex patterns for better performance"""
        compiled = {}
        for category, patterns in self.patterns.items():
            compiled[category] = {}
            for name, config in patterns.items():
                compiled[category][name] = {
                    "regexes": [],
                    "config": config
                }
                for pattern in config["patterns"]:
                    try:
                        compiled[category][name]["regexes"].append(
                            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                        )
                    except re.error as e:
                        logger.error(f"Invalid regex pattern for {name}: {e}")
        return compiled
    
    def _calculate_confidence(self, pattern_type: str, context: str) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = 0.7
        
        # Increase confidence for certain contexts
        high_confidence_indicators = [
            "user", "input", "request", "form", "query", "param"
        ]
        
        low_confidence_indicators = [
            "test", "example", "demo", "mock", "sample"
        ]
        
        context_lower = context.lower()
        
        for indicator in high_confidence_indicators:
            if indicator in context_lower:
                base_confidence += 0.1
                break
        
        for indicator in low_confidence_indicators:
            if indicator in context_lower:
                base_confidence -= 0.3
                break
        
        return min(max(base_confidence, 0.1), 1.0)
    
    def scan_content(self, content: str, file_path: str) -> List[AIPatternMatch]:
        """Scan content for AI-generated anti-patterns"""
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments (except for TODO pattern detection)
            stripped_line = line.strip()
            if (stripped_line.startswith('#') and 'TODO' not in stripped_line and 
                'FIXME' not in stripped_line and 'HACK' not in stripped_line):
                continue
            
            # Scan with compiled patterns
            for category, patterns in self.compiled_patterns.items():
                for name, pattern_data in patterns.items():
                    regexes = pattern_data["regexes"]
                    config = pattern_data["config"]
                    
                    for regex in regexes:
                        for match in regex.finditer(line):
                            confidence = self._calculate_confidence(name, line)
                            
                            # Skip low-confidence matches in test files
                            if confidence < 0.5 and any(test_indicator in file_path.lower() 
                                                      for test_indicator in ['test', 'spec', 'mock']):
                                continue
                            
                            pattern_match = AIPatternMatch(
                                pattern_type=f"{category}.{name}",
                                description=config["description"],
                                line_number=line_num,
                                column_start=match.start(),
                                column_end=match.end(),
                                confidence=confidence,
                                file_path=file_path,
                                context=line.strip(),
                                severity=config["severity"],
                                suggestion=config["suggestion"]
                            )
                            
                            findings.append(pattern_match)

        return findings

    def scan_file(self, file_info: Dict) -> List[Dict]:
        """Scan a single file for AI anti-patterns"""
        if "error" in file_info:
            return []

        try:
            findings = self.scan_content(file_info["content"], file_info["file_path"])

            # Convert to dict format
            results = []
            for finding in findings:
                results.append({
                    "type": "ai_pattern",
                    "subtype": finding.pattern_type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "column_start": finding.column_start,
                    "column_end": finding.column_end,
                    "context": finding.context,
                    "description": finding.description,
                    "suggestion": finding.suggestion,
                    "recommendation": f"Fix: {finding.suggestion}"
                })

            self.findings.extend(results)
            return results

        except Exception as e:
            logger.error(f"Error scanning file {file_info.get('file_path', 'unknown')}: {e}")
            return []

    def get_summary(self) -> Dict:
        """Get scan summary"""
        if not self.findings:
            return {"total": 0, "by_severity": {}, "by_category": {}}

        by_severity = {}
        by_category = {}

        for finding in self.findings:
            severity = finding["severity"]
            category = finding["subtype"].split('.')[0]

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_category": by_category
        }

    def reset(self):
        """Reset scanner state"""
        self.findings.clear()
