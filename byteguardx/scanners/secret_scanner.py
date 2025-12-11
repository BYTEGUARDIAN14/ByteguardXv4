"""
Secret Scanner - Detect hardcoded secrets using regex patterns and entropy analysis
"""

import re
import json
import math
import logging
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
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
    """Enhanced data structure for secret detection results"""
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

    # Enhanced fields for better integration
    detection_timestamp: datetime = None
    pattern_name: str = ""
    validation_status: str = "pending"  # pending, verified, false_positive
    risk_score: float = 0.0
    remediation_suggestion: str = ""
    similar_findings: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.detection_timestamp is None:
            self.detection_timestamp = datetime.now()
        if self.similar_findings is None:
            self.similar_findings = []

        # Calculate risk score based on available data
        self.risk_score = self._calculate_risk_score()

        # Generate remediation suggestion
        self.remediation_suggestion = self._generate_remediation_suggestion()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        result = asdict(self)
        result['detection_timestamp'] = self.detection_timestamp.isoformat()
        return result

    def get_risk_assessment(self) -> Dict[str, Any]:
        """Get comprehensive risk assessment"""
        return {
            'risk_score': self.risk_score,
            'severity': self.severity,
            'confidence': self.confidence,
            'entropy': self.entropy,
            'validation_status': self.validation_status,
            'factors': self._get_risk_factors()
        }

    def _calculate_risk_score(self) -> float:
        """Calculate risk score based on multiple factors"""
        risk_score = 0.0

        # Base score from confidence
        risk_score += self.confidence * 0.4

        # Entropy contribution
        if self.entropy > 4.5:
            risk_score += 0.3
        elif self.entropy > 3.5:
            risk_score += 0.2

        # Severity contribution
        severity_weights = {'critical': 0.3, 'high': 0.2, 'medium': 0.1, 'low': 0.05}
        risk_score += severity_weights.get(self.severity.lower(), 0.1)

        # File path risk factors
        if any(term in self.file_path.lower() for term in ['prod', 'production', 'live']):
            risk_score += 0.1

        return min(risk_score, 1.0)

    def _generate_remediation_suggestion(self) -> str:
        """Generate remediation suggestion based on secret type"""
        suggestions = {
            'api_key': "Remove API key from code and use environment variables or secure key management",
            'password': "Remove hardcoded password and implement secure authentication",
            'token': "Remove token from code and use secure token storage with rotation",
            'private_key': "Remove private key and use secure key management system",
            'database_url': "Remove database URL and use environment variables with proper access controls"
        }

        secret_type = self.type.lower()
        for key, suggestion in suggestions.items():
            if key in secret_type:
                return suggestion

        return "Remove secret from code and use secure secret management practices"

    def _get_risk_factors(self) -> List[str]:
        """Get factors contributing to risk score"""
        factors = []

        if self.entropy > 4.5:
            factors.append("High entropy indicates likely secret")
        if self.confidence > 0.8:
            factors.append("High confidence detection")
        if any(term in self.file_path.lower() for term in ['prod', 'production', 'live']):
            factors.append("Found in production-related file")
        if len(self.value) > 32:
            factors.append("Long value suggests API key or token")
        if self.severity in ['critical', 'high']:
            factors.append(f"High severity classification: {self.severity}")

        return factors

class SecretScanner:
    """
    Advanced secret scanner with regex patterns and entropy analysis
    Enhanced with better integration capabilities
    """

    def __init__(self, patterns_file: str = None, config: Dict[str, Any] = None):
        self.patterns = self._load_patterns(patterns_file)
        self.compiled_patterns = self._compile_patterns()
        self.findings = []
        self.config = config or {}

        # Enhanced configuration
        self.entropy_threshold = self.config.get('entropy_threshold', 3.5)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.6)
        self.enable_cross_validation = self.config.get('enable_cross_validation', True)
        self.enable_context_analysis = self.config.get('enable_context_analysis', True)

        # Statistics tracking
        self.scan_stats = {
            'total_scans': 0,
            'secrets_found': 0,
            'false_positives_filtered': 0,
            'high_confidence_findings': 0,
            'processing_time_total': 0.0
        }

        # Cache for pattern matching optimization
        self.pattern_cache = {}
        self.context_cache = {}
        
    def _load_patterns(self, patterns_file: str = None) -> Dict:
        """Load secret patterns from JSON file"""
        if patterns_file and Path(patterns_file).exists():
            try:
                with open(patterns_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load patterns file: {e}")
        
        # Comprehensive patterns for real-world secret detection
        return {
            "cloud_providers": {
                # AWS
                "aws_access_key": {
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "description": "AWS Access Key ID",
                    "severity": "critical",
                    "entropy_threshold": 3.5
                },
                "aws_secret_key": {
                    "pattern": r"[A-Za-z0-9/+=]{40}",
                    "description": "AWS Secret Access Key",
                    "severity": "critical",
                    "context_required": ["aws", "secret", "key"],
                    "entropy_threshold": 5.0
                },
                "aws_session_token": {
                    "pattern": r"[A-Za-z0-9/+=]{100,}",
                    "description": "AWS Session Token",
                    "severity": "high",
                    "context_required": ["aws", "session", "token"],
                    "entropy_threshold": 5.5
                },
                # Azure
                "azure_client_secret": {
                    "pattern": r"[A-Za-z0-9~._-]{34}",
                    "description": "Azure Client Secret",
                    "severity": "critical",
                    "context_required": ["azure", "client", "secret"],
                    "entropy_threshold": 4.5
                },
                "azure_storage_key": {
                    "pattern": r"[A-Za-z0-9+/]{88}==",
                    "description": "Azure Storage Account Key",
                    "severity": "critical",
                    "entropy_threshold": 5.0
                },
                # Google Cloud
                "gcp_service_account": {
                    "pattern": r'"type":\s*"service_account"',
                    "description": "Google Cloud Service Account JSON",
                    "severity": "critical",
                    "multiline": True
                },
                "google_api": {
                    "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
                    "description": "Google API Key",
                    "severity": "high",
                    "entropy_threshold": 4.0
                },
                "google_oauth": {
                    "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                    "description": "Google OAuth Client ID",
                    "severity": "medium"
                }
            },
            "version_control": {
                # GitHub
                "github_token": {
                    "pattern": r"ghp_[A-Za-z0-9]{36}",
                    "description": "GitHub Personal Access Token",
                    "severity": "high"
                },
                "github_app_token": {
                    "pattern": r"ghs_[A-Za-z0-9]{36}",
                    "description": "GitHub App Token",
                    "severity": "high"
                },
                "github_refresh_token": {
                    "pattern": r"ghr_[A-Za-z0-9]{76}",
                    "description": "GitHub Refresh Token",
                    "severity": "high"
                },
                # GitLab
                "gitlab_token": {
                    "pattern": r"glpat-[A-Za-z0-9\-_]{20}",
                    "description": "GitLab Personal Access Token",
                    "severity": "high"
                },
                # Bitbucket
                "bitbucket_client_secret": {
                    "pattern": r"[A-Za-z0-9]{32}",
                    "description": "Bitbucket Client Secret",
                    "severity": "high",
                    "context_required": ["bitbucket", "client", "secret"]
                }
            },
            "payment_services": {
                # Stripe
                "stripe_live_key": {
                    "pattern": r"sk_live_[A-Za-z0-9]{24}",
                    "description": "Stripe Live Secret Key",
                    "severity": "critical"
                },
                "stripe_test_key": {
                    "pattern": r"sk_test_[A-Za-z0-9]{24}",
                    "description": "Stripe Test Secret Key",
                    "severity": "medium"
                },
                "stripe_publishable_key": {
                    "pattern": r"pk_(live|test)_[A-Za-z0-9]{24}",
                    "description": "Stripe Publishable Key",
                    "severity": "low"
                },
                # PayPal
                "paypal_client_secret": {
                    "pattern": r"[A-Za-z0-9\-_]{80}",
                    "description": "PayPal Client Secret",
                    "severity": "critical",
                    "context_required": ["paypal", "client", "secret"]
                }
            },
            "communication": {
                # Slack
                "slack_bot_token": {
                    "pattern": r"xoxb-[A-Za-z0-9-]+",
                    "description": "Slack Bot Token",
                    "severity": "high"
                },
                "slack_user_token": {
                    "pattern": r"xoxp-[A-Za-z0-9-]+",
                    "description": "Slack User Token",
                    "severity": "high"
                },
                "slack_webhook": {
                    "pattern": r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+",
                    "description": "Slack Webhook URL",
                    "severity": "medium"
                },
                # Discord
                "discord_bot_token": {
                    "pattern": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
                    "description": "Discord Bot Token",
                    "severity": "high"
                },
                "discord_webhook": {
                    "pattern": r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
                    "description": "Discord Webhook URL",
                    "severity": "medium"
                },
                # Telegram
                "telegram_bot_token": {
                    "pattern": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
                    "description": "Telegram Bot Token",
                    "severity": "high"
                }
            },
            "databases": {
                # Connection strings
                "mongodb_connection": {
                    "pattern": r"mongodb(\+srv)?://[^\s]+",
                    "description": "MongoDB Connection String",
                    "severity": "high"
                },
                "mysql_connection": {
                    "pattern": r"mysql://[^\s]+",
                    "description": "MySQL Connection String",
                    "severity": "high"
                },
                "postgresql_connection": {
                    "pattern": r"postgres(ql)?://[^\s]+",
                    "description": "PostgreSQL Connection String",
                    "severity": "high"
                },
                "redis_connection": {
                    "pattern": r"redis://[^\s]+",
                    "description": "Redis Connection String",
                    "severity": "medium"
                },
                "password_in_url": {
                    "pattern": r"://[^:]+:([^@\s]{3,})@",
                    "description": "Password in Database URL",
                    "severity": "high",
                    "entropy_threshold": 3.0
                }
            },
            "api_services": {
                # Twilio
                "twilio_account_sid": {
                    "pattern": r"AC[a-z0-9]{32}",
                    "description": "Twilio Account SID",
                    "severity": "medium"
                },
                "twilio_auth_token": {
                    "pattern": r"[a-z0-9]{32}",
                    "description": "Twilio Auth Token",
                    "severity": "high",
                    "context_required": ["twilio", "auth", "token"]
                },
                # SendGrid
                "sendgrid_api_key": {
                    "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
                    "description": "SendGrid API Key",
                    "severity": "high"
                },
                # Mailgun
                "mailgun_api_key": {
                    "pattern": r"key-[a-z0-9]{32}",
                    "description": "Mailgun API Key",
                    "severity": "high"
                },
                # Firebase
                "firebase_api_key": {
                    "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
                    "description": "Firebase API Key",
                    "severity": "medium",
                    "context_required": ["firebase"]
                }
            },
            "cryptographic": {
                # Private Keys
                "rsa_private_key": {
                    "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
                    "description": "RSA Private Key",
                    "severity": "critical",
                    "multiline": True
                },
                "openssh_private_key": {
                    "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
                    "description": "OpenSSH Private Key",
                    "severity": "critical",
                    "multiline": True
                },
                "ec_private_key": {
                    "pattern": r"-----BEGIN EC PRIVATE KEY-----",
                    "description": "EC Private Key",
                    "severity": "critical",
                    "multiline": True
                },
                "pgp_private_key": {
                    "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                    "description": "PGP Private Key",
                    "severity": "critical",
                    "multiline": True
                },
                # Certificates
                "certificate": {
                    "pattern": r"-----BEGIN CERTIFICATE-----",
                    "description": "X.509 Certificate",
                    "severity": "low",
                    "multiline": True
                }
            },
            "authentication": {
                # JWT Tokens
                "jwt_token": {
                    "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                    "description": "JWT Token",
                    "severity": "medium",
                    "entropy_threshold": 4.0
                },
                # API Keys (Generic)
                "generic_api_key": {
                    "pattern": r"['\"]?[Aa]pi[_-]?[Kk]ey['\"]?\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
                    "description": "Generic API Key",
                    "severity": "medium",
                    "entropy_threshold": 4.0
                },
                # Bearer Tokens
                "bearer_token": {
                    "pattern": r"[Bb]earer\s+([A-Za-z0-9\-_=+/]{20,})",
                    "description": "Bearer Token",
                    "severity": "medium",
                    "entropy_threshold": 4.0
                },
                # Basic Auth
                "basic_auth": {
                    "pattern": r"[Bb]asic\s+([A-Za-z0-9+/=]{20,})",
                    "description": "Basic Authentication Token",
                    "severity": "medium"
                }
            },
            "passwords": {
                # Hardcoded passwords
                "password_assignment": {
                    "pattern": r"(password|pwd|pass|secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
                    "description": "Hardcoded Password",
                    "severity": "high",
                    "entropy_threshold": 3.0
                },
                "password_field": {
                    "pattern": r"['\"]password['\"]:\s*['\"]([^'\"]{8,})['\"]",
                    "description": "Password in Configuration",
                    "severity": "high",
                    "entropy_threshold": 3.0
                },
                # Hash patterns
                "md5_hash": {
                    "pattern": r"\b[a-f0-9]{32}\b",
                    "description": "MD5 Hash",
                    "severity": "low",
                    "context_required": ["hash", "md5", "password"]
                },
                "sha1_hash": {
                    "pattern": r"\b[a-f0-9]{40}\b",
                    "description": "SHA1 Hash",
                    "severity": "low",
                    "context_required": ["hash", "sha1", "password"]
                },
                "sha256_hash": {
                    "pattern": r"\b[a-f0-9]{64}\b",
                    "description": "SHA256 Hash",
                    "severity": "low",
                    "context_required": ["hash", "sha256", "password"]
                }
            },
            "infrastructure": {
                # Docker
                "docker_registry_auth": {
                    "pattern": r'"auth":\s*"([A-Za-z0-9+/=]+)"',
                    "description": "Docker Registry Authentication",
                    "severity": "medium"
                },
                # Kubernetes
                "kubernetes_token": {
                    "pattern": r"[A-Za-z0-9\-_=+/]{100,}",
                    "description": "Kubernetes Service Account Token",
                    "severity": "high",
                    "context_required": ["kubernetes", "token", "service"]
                },
                # SSH
                "ssh_private_key_content": {
                    "pattern": r"[A-Za-z0-9+/]{64,}={0,2}",
                    "description": "SSH Private Key Content",
                    "severity": "critical",
                    "context_required": ["ssh", "private", "key"],
                    "entropy_threshold": 5.0
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
        Enhanced scan content for secrets with better integration
        """
        start_time = time.time()
        findings = []
        lines = content.splitlines()

        # Update statistics
        self.scan_stats['total_scans'] += 1
        
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

    def scan_content_enhanced(self, content: str, file_path: str, context: Dict[str, Any] = None) -> List[SecretMatch]:
        """
        Enhanced scan with additional context and validation
        """
        start_time = time.time()

        # Perform basic scan
        findings = self.scan_content(content, file_path)

        # Apply enhanced validation if enabled
        if self.enable_cross_validation and context:
            findings = self._apply_cross_validation(findings, context)

        if self.enable_context_analysis:
            findings = self._enhance_with_context_analysis(findings, content)

        # Filter based on confidence threshold
        filtered_findings = [
            f for f in findings
            if f.confidence >= self.confidence_threshold
        ]

        # Update statistics
        processing_time = time.time() - start_time
        self.scan_stats['processing_time_total'] += processing_time
        self.scan_stats['secrets_found'] += len(filtered_findings)
        self.scan_stats['false_positives_filtered'] += len(findings) - len(filtered_findings)
        self.scan_stats['high_confidence_findings'] += len([f for f in filtered_findings if f.confidence > 0.8])

        return filtered_findings

    def _apply_cross_validation(self, findings: List[SecretMatch], context: Dict[str, Any]) -> List[SecretMatch]:
        """
        Apply cross-validation with other scanner results
        """
        validated_findings = []

        for finding in findings:
            # Check if other scanners found similar issues
            cross_validation_score = self._calculate_cross_validation_score(finding, context)

            # Adjust confidence based on cross-validation
            if cross_validation_score > 0.7:
                finding.confidence = min(finding.confidence * 1.2, 1.0)
                finding.validation_status = "cross_validated"
            elif cross_validation_score < 0.3:
                finding.confidence = finding.confidence * 0.8

            validated_findings.append(finding)

        return validated_findings

    def _enhance_with_context_analysis(self, findings: List[SecretMatch], content: str) -> List[SecretMatch]:
        """
        Enhance findings with context analysis
        """
        enhanced_findings = []

        for finding in findings:
            # Analyze surrounding context
            context_analysis = self._analyze_surrounding_context(finding, content)

            # Update finding based on context
            if context_analysis['is_test_context']:
                finding.confidence *= 0.7
                finding.validation_status = "test_context"
            elif context_analysis['is_production_context']:
                finding.confidence = min(finding.confidence * 1.1, 1.0)
                finding.severity = self._escalate_severity(finding.severity)

            # Add similar findings from context analysis
            finding.similar_findings = context_analysis.get('similar_patterns', [])

            enhanced_findings.append(finding)

        return enhanced_findings

    def _calculate_cross_validation_score(self, finding: SecretMatch, context: Dict[str, Any]) -> float:
        """
        Calculate cross-validation score based on other scanner results
        """
        score = 0.0

        # Check if other scanners found issues at the same location
        other_findings = context.get('other_findings', [])

        for other_finding in other_findings:
            if (other_finding.get('file_path') == finding.file_path and
                abs(other_finding.get('line_number', 0) - finding.line_number) <= 2):

                # Same location, different scanner
                if other_finding.get('scanner_source') != 'SecretScanner':
                    score += 0.3

                # Similar type of finding
                if any(keyword in other_finding.get('description', '').lower()
                       for keyword in ['secret', 'key', 'token', 'password']):
                    score += 0.4

        return min(score, 1.0)

    def _analyze_surrounding_context(self, finding: SecretMatch, content: str) -> Dict[str, Any]:
        """
        Analyze the surrounding context of a finding
        """
        lines = content.splitlines()
        line_index = finding.line_number - 1

        # Get surrounding lines
        start_line = max(0, line_index - 3)
        end_line = min(len(lines), line_index + 4)
        surrounding_lines = lines[start_line:end_line]
        surrounding_text = '\n'.join(surrounding_lines).lower()

        analysis = {
            'is_test_context': False,
            'is_production_context': False,
            'is_example_context': False,
            'similar_patterns': []
        }

        # Check for test context
        test_indicators = ['test', 'example', 'demo', 'mock', 'fake', 'placeholder']
        analysis['is_test_context'] = any(indicator in surrounding_text for indicator in test_indicators)

        # Check for production context
        prod_indicators = ['prod', 'production', 'live', 'deploy']
        analysis['is_production_context'] = any(indicator in surrounding_text for indicator in prod_indicators)

        # Check for example context
        example_indicators = ['example', 'sample', 'demo', 'tutorial']
        analysis['is_example_context'] = any(indicator in surrounding_text for indicator in example_indicators)

        # Look for similar patterns in surrounding context
        for line in surrounding_lines:
            if finding.value not in line:  # Don't include the same finding
                entropy = self.calculate_entropy(line)
                if entropy > 3.0:  # Potential secret-like content
                    analysis['similar_patterns'].append({
                        'line': line.strip(),
                        'entropy': entropy
                    })

        return analysis

    def _escalate_severity(self, current_severity: str) -> str:
        """
        Escalate severity level
        """
        severity_levels = ['low', 'medium', 'high', 'critical']

        try:
            current_index = severity_levels.index(current_severity.lower())
            if current_index < len(severity_levels) - 1:
                return severity_levels[current_index + 1]
        except ValueError:
            pass

        return current_severity

    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive scan statistics
        """
        stats = self.scan_stats.copy()

        if stats['total_scans'] > 0:
            stats['avg_secrets_per_scan'] = stats['secrets_found'] / stats['total_scans']
            stats['false_positive_rate'] = stats['false_positives_filtered'] / (stats['secrets_found'] + stats['false_positives_filtered']) if (stats['secrets_found'] + stats['false_positives_filtered']) > 0 else 0
            stats['avg_processing_time'] = stats['processing_time_total'] / stats['total_scans']
            stats['high_confidence_rate'] = stats['high_confidence_findings'] / stats['secrets_found'] if stats['secrets_found'] > 0 else 0
        else:
            stats['avg_secrets_per_scan'] = 0
            stats['false_positive_rate'] = 0
            stats['avg_processing_time'] = 0
            stats['high_confidence_rate'] = 0

        return stats

    def reset_statistics(self):
        """
        Reset scan statistics
        """
        self.scan_stats = {
            'total_scans': 0,
            'secrets_found': 0,
            'false_positives_filtered': 0,
            'high_confidence_findings': 0,
            'processing_time_total': 0.0
        }

    def validate_finding(self, finding: SecretMatch, validation_result: str, user_feedback: Dict[str, Any] = None):
        """
        Update finding validation status based on user feedback
        """
        finding.validation_status = validation_result

        if user_feedback:
            # Update confidence based on feedback
            if validation_result == "false_positive":
                finding.confidence *= 0.5
            elif validation_result == "verified":
                finding.confidence = min(finding.confidence * 1.1, 1.0)

            # Store feedback for future improvements
            feedback_key = f"{finding.type}:{finding.pattern_name}"
            if feedback_key not in self.context_cache:
                self.context_cache[feedback_key] = []

            self.context_cache[feedback_key].append({
                'validation': validation_result,
                'feedback': user_feedback,
                'timestamp': datetime.now().isoformat()
            })
