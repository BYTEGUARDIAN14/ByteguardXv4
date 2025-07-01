"""
Secret Scanner - Detect hardcoded secrets using regex patterns and entropy analysis
"""

import re
import json
import math
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path
from dataclasses import dataclass
import signal
import threading
import time

logger = logging.getLogger(__name__)

class RegexTimeoutError(Exception):
    """Raised when regex operation times out"""
    pass

def safe_regex_search(pattern, text, timeout=5):
    """Perform regex search with timeout protection"""
    result = [None]
    exception = [None]

    def target():
        try:
            result[0] = pattern.finditer(text)
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        # Thread is still running, regex is taking too long
        logger.warning(f"Regex operation timed out after {timeout} seconds")
        raise RegexTimeoutError("Regex operation timed out")

    if exception[0]:
        raise exception[0]

    return result[0] or []

@dataclass
class SecretMatch:
    """Data structure for secret detection results"""
    type: str
    value: str
    line_number: int
    column_start: int
    column_end: int
    confidence: float
    entropy: float
    file_path: str
    context: str
    severity: str

class SecretScanner:
    """
    Advanced secret scanner with regex patterns and entropy analysis
    """
    
    def __init__(self, patterns_file: str = None):
        self.patterns = self._load_patterns(patterns_file)
        self.compiled_patterns = self._compile_patterns()
        self.findings = []
        
    def _load_patterns(self, patterns_file: str = None) -> Dict:
        """Load secret patterns from JSON file"""
        if patterns_file and Path(patterns_file).exists():
            try:
                with open(patterns_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load patterns file: {e}")
        
        # Default patterns
        return {
            "api_keys": {
                "aws_access_key": {
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "description": "AWS Access Key ID",
                    "severity": "critical"
                },
                "aws_secret_key": {
                    "pattern": r"[A-Za-z0-9/+=]{40}",
                    "description": "AWS Secret Access Key",
                    "severity": "critical",
                    "context_required": ["aws", "secret", "key"]
                },
                "github_token": {
                    "pattern": r"ghp_[A-Za-z0-9]{36}",
                    "description": "GitHub Personal Access Token",
                    "severity": "high"
                },
                "slack_token": {
                    "pattern": r"xox[baprs]-[A-Za-z0-9-]+",
                    "description": "Slack Token",
                    "severity": "high"
                },
                "stripe_key": {
                    "pattern": r"sk_live_[A-Za-z0-9]{24}",
                    "description": "Stripe Live Secret Key",
                    "severity": "critical"
                },
                "google_api": {
                    "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
                    "description": "Google API Key",
                    "severity": "high"
                }
            },
            "database": {
                "connection_string": {
                    "pattern": r"(mongodb|mysql|postgresql|redis)://[^\s]+",
                    "description": "Database Connection String",
                    "severity": "high"
                },
                "password_in_url": {
                    "pattern": r"://[^:]+:([^@]+)@",
                    "description": "Password in URL",
                    "severity": "medium"
                }
            },
            "generic": {
                "private_key": {
                    "pattern": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
                    "description": "Private Key",
                    "severity": "critical"
                },
                "jwt_token": {
                    "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                    "description": "JWT Token",
                    "severity": "medium"
                },
                "password_assignment": {
                    "pattern": r"(password|pwd|pass)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
                    "description": "Hardcoded Password",
                    "severity": "medium"
                }
            }
        }
    
    def _compile_patterns(self) -> Dict:
        """Compile regex patterns for better performance"""
        compiled = {}
        for category, patterns in self.patterns.items():
            compiled[category] = {}
            for name, config in patterns.items():
                try:
                    compiled[category][name] = {
                        "regex": re.compile(config["pattern"], re.IGNORECASE),
                        "config": config
                    }
                except re.error as e:
                    logger.error(f"Invalid regex pattern for {name}: {e}")
        return compiled
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_likely_secret(self, value: str, context: str = "") -> Tuple[bool, float]:
        """
        Determine if a value is likely a secret based on entropy and context
        """
        # Skip common false positives
        false_positives = {
            "example", "test", "demo", "sample", "placeholder", "dummy",
            "fake", "mock", "null", "none", "empty", "default", "todo",
            "changeme", "password", "secret", "key", "token"
        }
        
        if value.lower() in false_positives:
            return False, 0.0
        
        # Calculate entropy
        entropy = self.calculate_entropy(value)
        
        # Entropy thresholds
        min_entropy = 3.5  # Minimum entropy for secrets
        high_entropy = 4.5  # High confidence threshold
        
        # Length considerations
        if len(value) < 8:
            min_entropy = 3.0
        elif len(value) > 32:
            min_entropy = 4.0
        
        # Context analysis
        context_lower = context.lower()
        secret_indicators = ["key", "secret", "token", "password", "credential", "auth"]
        has_secret_context = any(indicator in context_lower for indicator in secret_indicators)
        
        if has_secret_context:
            min_entropy -= 0.5  # Lower threshold with context
        
        confidence = min(entropy / high_entropy, 1.0)
        is_secret = entropy >= min_entropy
        
        return is_secret, confidence
    
    def scan_content(self, content: str, file_path: str) -> List[SecretMatch]:
        """
        Scan content for secrets
        """
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and common false positives
            stripped_line = line.strip()
            if (stripped_line.startswith('#') or 
                stripped_line.startswith('//') or
                stripped_line.startswith('/*') or
                'example' in stripped_line.lower() or
                'test' in stripped_line.lower()):
                continue
            
            # Scan with compiled patterns
            for category, patterns in self.compiled_patterns.items():
                for name, pattern_data in patterns.items():
                    regex = pattern_data["regex"]
                    config = pattern_data["config"]
                    
                    try:
                        matches = safe_regex_search(regex, line, timeout=2)
                        for match in matches:
                            value = match.group(0)
                        
                        # Check context requirements
                        if "context_required" in config:
                            context_found = any(
                                ctx.lower() in line.lower() 
                                for ctx in config["context_required"]
                            )
                            if not context_found:
                                continue
                        
                        # Calculate entropy and confidence
                        entropy = self.calculate_entropy(value)
                        is_secret, confidence = self.is_likely_secret(value, line)
                        
                        # Skip low-confidence matches for generic patterns
                        if category == "generic" and confidence < 0.6:
                            continue
                        
                        secret_match = SecretMatch(
                            type=f"{category}.{name}",
                            value=value,
                            line_number=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            confidence=confidence,
                            entropy=entropy,
                            file_path=file_path,
                            context=line.strip(),
                            severity=config.get("severity", "medium")
                        )

                        findings.append(secret_match)

                    except RegexTimeoutError:
                        logger.warning(f"Regex timeout for pattern {name} in {file_path}:{line_num}")
                        continue
                    except Exception as e:
                        logger.error(f"Regex error for pattern {name}: {e}")
                        continue

        return findings
    
    def scan_file(self, file_info: Dict) -> List[Dict]:
        """
        Scan a single file for secrets
        """
        if "error" in file_info:
            return []
        
        try:
            findings = self.scan_content(file_info["content"], file_info["file_path"])
            
            # Convert to dict format
            results = []
            for finding in findings:
                results.append({
                    "type": "secret",
                    "subtype": finding.type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "column_start": finding.column_start,
                    "column_end": finding.column_end,
                    "value": finding.value[:50] + "..." if len(finding.value) > 50 else finding.value,
                    "context": finding.context,
                    "entropy": finding.entropy,
                    "description": self._get_description(finding.type),
                    "recommendation": self._get_recommendation(finding.type)
                })
            
            self.findings.extend(results)
            return results
            
        except Exception as e:
            logger.error(f"Error scanning file {file_info.get('file_path', 'unknown')}: {e}")
            return []
    
    def _get_description(self, secret_type: str) -> str:
        """Get description for secret type"""
        descriptions = {
            "api_keys.aws_access_key": "AWS Access Key ID detected",
            "api_keys.aws_secret_key": "AWS Secret Access Key detected",
            "api_keys.github_token": "GitHub Personal Access Token detected",
            "api_keys.slack_token": "Slack API Token detected",
            "api_keys.stripe_key": "Stripe Live Secret Key detected",
            "api_keys.google_api": "Google API Key detected",
            "database.connection_string": "Database connection string with credentials",
            "database.password_in_url": "Password embedded in URL",
            "generic.private_key": "Private key detected",
            "generic.jwt_token": "JWT token detected",
            "generic.password_assignment": "Hardcoded password assignment"
        }
        return descriptions.get(secret_type, "Potential secret detected")
    
    def _get_recommendation(self, secret_type: str) -> str:
        """Get recommendation for secret type"""
        return "Move secrets to environment variables or secure configuration management"
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        if not self.findings:
            return {"total": 0, "by_severity": {}, "by_type": {}}
        
        by_severity = {}
        by_type = {}
        
        for finding in self.findings:
            severity = finding["severity"]
            secret_type = finding["subtype"]
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[secret_type] = by_type.get(secret_type, 0) + 1
        
        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_type": by_type
        }
    
    def reset(self):
        """Reset scanner state"""
        self.findings.clear()
