"""
Intelligent Fallback System for ByteGuardX
Provides rule-based scanning when ML models fail or are unavailable
"""

import logging
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class FallbackReason(Enum):
    """Reasons for fallback activation"""
    ML_MODEL_UNAVAILABLE = "ml_model_unavailable"
    ML_MODEL_ERROR = "ml_model_error"
    ML_MODEL_TIMEOUT = "ml_model_timeout"
    ML_MODEL_LOW_CONFIDENCE = "ml_model_low_confidence"
    USER_PREFERENCE = "user_preference"
    PERFORMANCE_OPTIMIZATION = "performance_optimization"

@dataclass
class FallbackResult:
    """Result from fallback scanning"""
    findings: List[Dict[str, Any]]
    confidence: float
    method_used: str
    fallback_reason: FallbackReason
    processing_time: float
    rules_applied: List[str]

class RuleBasedSecretScanner:
    """Rule-based secret detection as fallback for AI scanner"""
    
    def __init__(self):
        self.patterns = self._load_secret_patterns()
        self.entropy_threshold = 4.5  # Minimum entropy for potential secrets
    
    def _load_secret_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load secret detection patterns"""
        return {
            "aws_access_key": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "confidence": 0.9,
                "description": "AWS Access Key ID"
            },
            "aws_secret_key": {
                "pattern": r"[A-Za-z0-9/+=]{40}",
                "confidence": 0.7,
                "description": "AWS Secret Access Key",
                "context_required": ["aws", "secret", "key"]
            },
            "github_token": {
                "pattern": r"ghp_[A-Za-z0-9]{36}",
                "confidence": 0.95,
                "description": "GitHub Personal Access Token"
            },
            "slack_token": {
                "pattern": r"xox[baprs]-[A-Za-z0-9-]+",
                "confidence": 0.9,
                "description": "Slack Token"
            },
            "jwt_token": {
                "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                "confidence": 0.8,
                "description": "JWT Token"
            },
            "api_key_generic": {
                "pattern": r"['\"]?[a-zA-Z0-9_-]*[aA][pP][iI][_-]?[kK][eE][yY]['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_-]{16,}['\"]?",
                "confidence": 0.6,
                "description": "Generic API Key"
            },
            "password_generic": {
                "pattern": r"['\"]?[pP][aA][sS][sS][wW][oO][rR][dD]['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+-=]{8,}['\"]?",
                "confidence": 0.5,
                "description": "Generic Password"
            },
            "private_key": {
                "pattern": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
                "confidence": 0.95,
                "description": "Private Key"
            },
            "database_url": {
                "pattern": r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+",
                "confidence": 0.7,
                "description": "Database Connection String",
                "context_required": ["database", "db", "connection", "url"]
            }
        }
    
    def scan_content(self, content: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Scan content for secrets using rule-based patterns"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and common false positives
            if self._should_skip_line(line):
                continue
            
            # Check each pattern
            for secret_type, pattern_info in self.patterns.items():
                matches = re.finditer(pattern_info["pattern"], line, re.IGNORECASE)
                
                for match in matches:
                    # Additional validation
                    if self._validate_match(match, line, pattern_info):
                        finding = {
                            "type": "secret",
                            "subtype": secret_type,
                            "description": pattern_info["description"],
                            "file_path": file_path,
                            "line_number": line_num,
                            "line_content": line.strip(),
                            "match": match.group(),
                            "start_pos": match.start(),
                            "end_pos": match.end(),
                            "confidence": pattern_info["confidence"],
                            "severity": self._get_severity(pattern_info["confidence"]),
                            "method": "rule_based_fallback"
                        }
                        findings.append(finding)
        
        # Additional entropy-based detection
        entropy_findings = self._detect_high_entropy_strings(content, file_path)
        findings.extend(entropy_findings)
        
        return findings
    
    def _should_skip_line(self, line: str) -> bool:
        """Check if line should be skipped"""
        line_stripped = line.strip()
        
        # Skip empty lines
        if not line_stripped:
            return True
        
        # Skip comments
        if line_stripped.startswith(('#', '//', '/*', '*', '--', '<!--')):
            return True
        
        # Skip common false positives
        false_positive_patterns = [
            r'^\s*import\s+',
            r'^\s*from\s+',
            r'^\s*console\.',
            r'^\s*print\s*\(',
            r'^\s*log\.',
            r'example',
            r'placeholder',
            r'dummy',
            r'test',
            r'fake'
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, line_stripped, re.IGNORECASE):
                return True
        
        return False
    
    def _validate_match(self, match, line: str, pattern_info: Dict[str, Any]) -> bool:
        """Validate if a pattern match is likely a real secret"""
        matched_text = match.group()
        
        # Check minimum length
        if len(matched_text) < 8:
            return False
        
        # Check for context requirements
        if "context_required" in pattern_info:
            context_found = any(
                keyword in line.lower() 
                for keyword in pattern_info["context_required"]
            )
            if not context_found:
                return False
        
        # Check for common false positives
        false_positives = [
            "example", "placeholder", "dummy", "test", "fake", "sample",
            "your_key_here", "insert_key_here", "replace_with", "todo"
        ]
        
        if any(fp in matched_text.lower() for fp in false_positives):
            return False
        
        return True
    
    def _detect_high_entropy_strings(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect high-entropy strings that might be secrets"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Find quoted strings
            quoted_strings = re.findall(r'["\']([A-Za-z0-9+/=]{16,})["\']', line)
            
            for string in quoted_strings:
                entropy = self._calculate_entropy(string)
                
                if entropy >= self.entropy_threshold and len(string) >= 16:
                    finding = {
                        "type": "secret",
                        "subtype": "high_entropy_string",
                        "description": f"High entropy string (entropy: {entropy:.2f})",
                        "file_path": file_path,
                        "line_number": line_num,
                        "line_content": line.strip(),
                        "match": string,
                        "confidence": min(0.8, entropy / 6.0),  # Scale entropy to confidence
                        "severity": "medium",
                        "method": "entropy_analysis",
                        "entropy": entropy
                    }
                    findings.append(finding)
        
        return findings
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        string_length = len(string)
        
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _get_severity(self, confidence: float) -> str:
        """Get severity level based on confidence"""
        if confidence >= 0.9:
            return "high"
        elif confidence >= 0.7:
            return "medium"
        else:
            return "low"

class RuleBasedVulnerabilityScanner:
    """Rule-based vulnerability detection as fallback"""
    
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability detection patterns"""
        return {
            "sql_injection": {
                "patterns": [
                    r"['\"]?\s*\+\s*['\"]?\s*SELECT\s+",
                    r"['\"]?\s*\+\s*['\"]?\s*INSERT\s+",
                    r"['\"]?\s*\+\s*['\"]?\s*UPDATE\s+",
                    r"['\"]?\s*\+\s*['\"]?\s*DELETE\s+",
                    r"['\"]?\s*\+\s*['\"]?\s*DROP\s+",
                    r"execute\s*\(\s*['\"]?[^'\"]*['\"]?\s*\+",
                    r"query\s*\(\s*['\"]?[^'\"]*['\"]?\s*\+"
                ],
                "confidence": 0.7,
                "description": "Potential SQL Injection vulnerability"
            },
            "xss": {
                "patterns": [
                    r"innerHTML\s*=\s*[^;]+\+",
                    r"document\.write\s*\(\s*[^)]*\+",
                    r"eval\s*\(\s*[^)]*\+",
                    r"setTimeout\s*\(\s*[^,]*\+",
                    r"setInterval\s*\(\s*[^,]*\+"
                ],
                "confidence": 0.6,
                "description": "Potential Cross-Site Scripting (XSS) vulnerability"
            },
            "command_injection": {
                "patterns": [
                    r"exec\s*\(\s*[^)]*\+",
                    r"system\s*\(\s*[^)]*\+",
                    r"shell_exec\s*\(\s*[^)]*\+",
                    r"os\.system\s*\(\s*[^)]*\+",
                    r"subprocess\.\w+\s*\(\s*[^)]*\+"
                ],
                "confidence": 0.8,
                "description": "Potential Command Injection vulnerability"
            },
            "path_traversal": {
                "patterns": [
                    r"\.\.\/",
                    r"\.\.\\\\",
                    r"file\s*=\s*[^;]+\+",
                    r"include\s*\(\s*[^)]*\+",
                    r"require\s*\(\s*[^)]*\+"
                ],
                "confidence": 0.6,
                "description": "Potential Path Traversal vulnerability"
            },
            "insecure_random": {
                "patterns": [
                    r"Math\.random\s*\(\s*\)",
                    r"random\.random\s*\(\s*\)",
                    r"rand\s*\(\s*\)",
                    r"srand\s*\("
                ],
                "confidence": 0.5,
                "description": "Use of insecure random number generator"
            }
        }
    
    def scan_content(self, content: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Scan content for vulnerabilities using rule-based patterns"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if self._should_skip_line(line):
                continue
            
            for vuln_type, vuln_info in self.vulnerability_patterns.items():
                for pattern in vuln_info["patterns"]:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        finding = {
                            "type": "vulnerability",
                            "subtype": vuln_type,
                            "description": vuln_info["description"],
                            "file_path": file_path,
                            "line_number": line_num,
                            "line_content": line.strip(),
                            "match": match.group(),
                            "confidence": vuln_info["confidence"],
                            "severity": self._get_severity(vuln_info["confidence"]),
                            "method": "rule_based_fallback"
                        }
                        findings.append(finding)
        
        return findings
    
    def _should_skip_line(self, line: str) -> bool:
        """Check if line should be skipped"""
        line_stripped = line.strip()
        
        if not line_stripped:
            return True
        
        if line_stripped.startswith(('#', '//', '/*', '*', '--', '<!--')):
            return True
        
        return False
    
    def _get_severity(self, confidence: float) -> str:
        """Get severity level based on confidence"""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"

class IntelligentFallbackSystem:
    """Main fallback system that coordinates rule-based scanners"""
    
    def __init__(self):
        self.secret_scanner = RuleBasedSecretScanner()
        self.vulnerability_scanner = RuleBasedVulnerabilityScanner()
        self.fallback_stats = {
            "total_fallbacks": 0,
            "fallback_reasons": {},
            "success_rate": 0.0
        }
    
    def scan_with_fallback(self, content: str, file_path: str = "", 
                          scan_type: str = "comprehensive",
                          fallback_reason: FallbackReason = FallbackReason.ML_MODEL_UNAVAILABLE) -> FallbackResult:
        """Perform scanning with rule-based fallback"""
        import time
        start_time = time.time()
        
        findings = []
        rules_applied = []
        
        try:
            # Secret scanning
            if scan_type in ["comprehensive", "secrets"]:
                secret_findings = self.secret_scanner.scan_content(content, file_path)
                findings.extend(secret_findings)
                rules_applied.append("secret_detection")
            
            # Vulnerability scanning
            if scan_type in ["comprehensive", "vulnerabilities"]:
                vuln_findings = self.vulnerability_scanner.scan_content(content, file_path)
                findings.extend(vuln_findings)
                rules_applied.append("vulnerability_detection")
            
            processing_time = time.time() - start_time
            
            # Calculate overall confidence
            if findings:
                avg_confidence = sum(f.get("confidence", 0) for f in findings) / len(findings)
            else:
                avg_confidence = 0.8  # High confidence when no issues found
            
            # Update statistics
            self._update_stats(fallback_reason, True)
            
            result = FallbackResult(
                findings=findings,
                confidence=avg_confidence,
                method_used="rule_based_fallback",
                fallback_reason=fallback_reason,
                processing_time=processing_time,
                rules_applied=rules_applied
            )
            
            logger.info(f"Fallback scan completed: {len(findings)} findings in {processing_time:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Fallback scanning failed: {e}")
            self._update_stats(fallback_reason, False)
            
            return FallbackResult(
                findings=[],
                confidence=0.0,
                method_used="fallback_error",
                fallback_reason=fallback_reason,
                processing_time=time.time() - start_time,
                rules_applied=[]
            )
    
    def _update_stats(self, reason: FallbackReason, success: bool):
        """Update fallback statistics"""
        self.fallback_stats["total_fallbacks"] += 1
        
        reason_key = reason.value
        if reason_key not in self.fallback_stats["fallback_reasons"]:
            self.fallback_stats["fallback_reasons"][reason_key] = {"count": 0, "successes": 0}
        
        self.fallback_stats["fallback_reasons"][reason_key]["count"] += 1
        if success:
            self.fallback_stats["fallback_reasons"][reason_key]["successes"] += 1
        
        # Recalculate success rate
        total_successes = sum(
            stats["successes"] for stats in self.fallback_stats["fallback_reasons"].values()
        )
        self.fallback_stats["success_rate"] = total_successes / self.fallback_stats["total_fallbacks"]
    
    def get_fallback_stats(self) -> Dict[str, Any]:
        """Get fallback system statistics"""
        return self.fallback_stats.copy()
    
    def is_fallback_recommended(self, ml_confidence: float = None, 
                               ml_processing_time: float = None) -> Tuple[bool, FallbackReason]:
        """Determine if fallback should be used"""
        # Use fallback if ML confidence is too low
        if ml_confidence is not None and ml_confidence < 0.5:
            return True, FallbackReason.ML_MODEL_LOW_CONFIDENCE
        
        # Use fallback if ML processing is too slow
        if ml_processing_time is not None and ml_processing_time > 30.0:
            return True, FallbackReason.ML_MODEL_TIMEOUT
        
        return False, FallbackReason.USER_PREFERENCE

# Global instance
intelligent_fallback = IntelligentFallbackSystem()
