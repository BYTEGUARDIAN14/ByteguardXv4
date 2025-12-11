"""
AWS S3 Bucket Exposure Scanner Plugin
Detects S3 bucket misconfigurations and exposure risks
"""

import re
import json
import logging
from typing import Dict, List, Any
try:
    from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class AWSS3ExposureScanner(BasePlugin):
    """Scanner for AWS S3 bucket exposure and misconfiguration risks"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="aws_s3_exposure_scanner",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects AWS S3 bucket misconfigurations, public access, and exposure risks",
            category=PluginCategory.CLOUD_SECURITY,
            supported_languages=["json", "yaml", "terraform", "cloudformation", "python", "javascript"],
            supported_file_types=[".json", ".yaml", ".yml", ".tf", ".py", ".js", ".ts"],
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
        
        self.s3_patterns = self._load_s3_patterns()
        self.compiled_patterns = self._compile_patterns()
    
    def _load_s3_patterns(self) -> Dict[str, Any]:
        """Load S3 security patterns"""
        return {
            "public_bucket_policies": {
                "patterns": [
                    r'"Principal"\s*:\s*"\*"',
                    r'"Effect"\s*:\s*"Allow".*"Principal"\s*:\s*"\*"',
                    r'aws:PrincipalOrgID.*\*',
                    r'"Action"\s*:\s*"s3:\*".*"Principal"\s*:\s*"\*"'
                ],
                "description": "S3 bucket policy allows public access",
                "severity": "critical",
                "cwe_id": "CWE-732",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "public_read_access": {
                "patterns": [
                    r'"PublicRead"\s*:\s*true',
                    r'"PublicReadWrite"\s*:\s*true',
                    r'public-read',
                    r'public-read-write',
                    r'AllUsers.*READ',
                    r'AuthenticatedUsers.*READ'
                ],
                "description": "S3 bucket configured with public read access",
                "severity": "high",
                "cwe_id": "CWE-200",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "public_write_access": {
                "patterns": [
                    r'"PublicWrite"\s*:\s*true',
                    r'"PublicReadWrite"\s*:\s*true',
                    r'public-read-write',
                    r'AllUsers.*WRITE',
                    r'AllUsers.*FULL_CONTROL'
                ],
                "description": "S3 bucket configured with public write access",
                "severity": "critical",
                "cwe_id": "CWE-732",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "missing_encryption": {
                "patterns": [
                    r'"ServerSideEncryptionConfiguration"\s*:\s*\[\s*\]',
                    r'"BucketEncryption"\s*:\s*null',
                    r'encryption\s*=\s*false',
                    r'server_side_encryption_configuration\s*=\s*\[\s*\]'
                ],
                "description": "S3 bucket lacks server-side encryption",
                "severity": "medium",
                "cwe_id": "CWE-311",
                "owasp_category": "A02:2021 – Cryptographic Failures"
            },
            "missing_versioning": {
                "patterns": [
                    r'"Versioning"\s*:\s*"Suspended"',
                    r'"Status"\s*:\s*"Suspended"',
                    r'versioning\s*=\s*false',
                    r'versioning.*enabled\s*=\s*false'
                ],
                "description": "S3 bucket versioning is disabled",
                "severity": "medium",
                "cwe_id": "CWE-404",
                "owasp_category": "A04:2021 – Insecure Design"
            },
            "missing_mfa_delete": {
                "patterns": [
                    r'"MfaDelete"\s*:\s*"Disabled"',
                    r'mfa_delete\s*=\s*false',
                    r'mfa_delete.*"Disabled"'
                ],
                "description": "S3 bucket MFA delete protection is disabled",
                "severity": "medium",
                "cwe_id": "CWE-287",
                "owasp_category": "A07:2021 – Identification and Authentication Failures"
            },
            "logging_disabled": {
                "patterns": [
                    r'"LoggingEnabled"\s*:\s*false',
                    r'"AccessLogging"\s*:\s*null',
                    r'logging\s*=\s*\[\s*\]',
                    r'access_logging.*enabled\s*=\s*false'
                ],
                "description": "S3 bucket access logging is disabled",
                "severity": "low",
                "cwe_id": "CWE-778",
                "owasp_category": "A09:2021 – Security Logging and Monitoring Failures"
            },
            "cors_misconfiguration": {
                "patterns": [
                    r'"AllowedOrigins"\s*:\s*\[\s*"\*"\s*\]',
                    r'"AllowedMethods"\s*:\s*\[\s*"\*"\s*\]',
                    r'allowed_origins.*\*',
                    r'cors_rule.*allowed_origins.*\*'
                ],
                "description": "S3 bucket CORS configuration allows all origins",
                "severity": "medium",
                "cwe_id": "CWE-346",
                "owasp_category": "A05:2021 – Security Misconfiguration"
            },
            "lifecycle_missing": {
                "patterns": [
                    r'"LifecycleConfiguration"\s*:\s*null',
                    r'"Rules"\s*:\s*\[\s*\]',
                    r'lifecycle_rule\s*=\s*\[\s*\]'
                ],
                "description": "S3 bucket lacks lifecycle management configuration",
                "severity": "low",
                "cwe_id": "CWE-404",
                "owasp_category": "A04:2021 – Insecure Design"
            },
            "hardcoded_credentials": {
                "patterns": [
                    r'aws_access_key_id\s*=\s*["\'][^"\']+["\']',
                    r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']',
                    r'AWS_ACCESS_KEY_ID.*["\'][^"\']+["\']',
                    r'AWS_SECRET_ACCESS_KEY.*["\'][^"\']+["\']'
                ],
                "description": "Hardcoded AWS credentials detected",
                "severity": "critical",
                "cwe_id": "CWE-798",
                "owasp_category": "A07:2021 – Identification and Authentication Failures"
            },
            "insecure_transport": {
                "patterns": [
                    r'"aws:SecureTransport"\s*:\s*"false"',
                    r'SecureTransport.*false',
                    r'ssl_requests_only\s*=\s*false'
                ],
                "description": "S3 bucket allows insecure transport (HTTP)",
                "severity": "medium",
                "cwe_id": "CWE-319",
                "owasp_category": "A02:2021 – Cryptographic Failures"
            }
        }
    
    def _compile_patterns(self) -> Dict[str, Any]:
        """Compile regex patterns for performance"""
        compiled = {}
        for name, config in self.s3_patterns.items():
            compiled[name] = {
                "regexes": [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                           for pattern in config["patterns"]],
                "config": config
            }
        return compiled
    
    def validate_input(self, content: str, file_path: str) -> bool:
        """Validate input for S3 scanning"""
        if not content or not content.strip():
            return False
        
        # Check if content is relevant to AWS/S3
        s3_indicators = [
            "s3", "bucket", "aws", "amazon", "cloudformation", 
            "terraform", "resource", "policy", "principal"
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in s3_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan content for S3 security issues"""
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.compiled_patterns.items():
                regexes = pattern_data["regexes"]
                config = pattern_data["config"]
                
                for regex in regexes:
                    for match in regex.finditer(line):
                        # Calculate confidence based on context
                        confidence = self._calculate_confidence(pattern_name, line, file_path)
                        
                        # Skip low-confidence matches
                        if confidence < 0.5:
                            continue
                        
                        # Generate remediation advice
                        remediation = self._generate_remediation(pattern_name, match.group())
                        
                        finding = {
                            "title": f"AWS S3 Security Issue: {config['description']}",
                            "description": config["description"],
                            "severity": config["severity"],
                            "confidence": confidence,
                            "file_path": file_path,
                            "line_number": line_num,
                            "column_start": match.start(),
                            "column_end": match.end(),
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": config.get("cwe_id", ""),
                            "owasp_category": config.get("owasp_category", ""),
                            "remediation": remediation,
                            "risk_factors": self._assess_risk_factors(pattern_name, line, context),
                            "compliance_impact": self._assess_compliance_impact(pattern_name),
                            "exploit_scenario": self._generate_exploit_scenario(pattern_name),
                            "detection_metadata": {
                                "pattern_type": pattern_name,
                                "matched_text": match.group(),
                                "aws_service": "s3",
                                "resource_type": self._identify_resource_type(line),
                                "configuration_type": self._identify_config_type(file_path)
                            }
                        }
                        
                        findings.append(finding)
        
        return findings
    
    def _calculate_confidence(self, pattern_name: str, line: str, file_path: str) -> float:
        """Calculate confidence score for S3 findings"""
        base_confidence = 0.7
        
        # File type adjustments
        if file_path.endswith(('.tf', '.yaml', '.yml', '.json')):
            base_confidence += 0.2
        
        # Context adjustments
        line_lower = line.lower()
        
        # High confidence indicators
        if any(indicator in line_lower for indicator in ['bucket', 's3', 'aws']):
            base_confidence += 0.1
        
        # Pattern-specific adjustments
        if pattern_name == "public_bucket_policies" and '"Principal"' in line:
            base_confidence += 0.15
        elif pattern_name == "hardcoded_credentials" and any(key in line_lower for key in ['access_key', 'secret']):
            base_confidence += 0.2
        
        # Reduce confidence for comments or examples
        if any(indicator in line_lower for indicator in ['example', 'test', 'demo', '#', '//']):
            base_confidence -= 0.3
        
        return max(0.1, min(1.0, base_confidence))
    
    def _generate_remediation(self, pattern_name: str, matched_text: str) -> str:
        """Generate specific remediation advice"""
        remediation_map = {
            "public_bucket_policies": "Restrict bucket policy to specific principals and implement least privilege access",
            "public_read_access": "Disable public read access and use signed URLs or CloudFront for public content",
            "public_write_access": "Immediately disable public write access and implement proper authentication",
            "missing_encryption": "Enable server-side encryption with AWS KMS or S3-managed keys",
            "missing_versioning": "Enable versioning to protect against accidental deletion and modification",
            "missing_mfa_delete": "Enable MFA delete protection for critical buckets",
            "logging_disabled": "Enable access logging to monitor bucket access patterns",
            "cors_misconfiguration": "Restrict CORS to specific origins and methods required by your application",
            "lifecycle_missing": "Implement lifecycle policies to manage storage costs and data retention",
            "hardcoded_credentials": "Remove hardcoded credentials and use IAM roles or environment variables",
            "insecure_transport": "Enforce HTTPS-only access using bucket policies"
        }
        
        return remediation_map.get(pattern_name, "Review and fix the identified S3 security configuration")
    
    def _assess_risk_factors(self, pattern_name: str, line: str, context: Dict[str, Any]) -> List[str]:
        """Assess risk factors for the finding"""
        risk_factors = []
        
        if pattern_name in ["public_bucket_policies", "public_read_access", "public_write_access"]:
            risk_factors.extend([
                "Data exposure to unauthorized users",
                "Potential for data exfiltration",
                "Compliance violations (GDPR, HIPAA, SOX)"
            ])
        
        if pattern_name == "hardcoded_credentials":
            risk_factors.extend([
                "Credential exposure in version control",
                "Unauthorized AWS account access",
                "Potential for privilege escalation"
            ])
        
        if pattern_name == "missing_encryption":
            risk_factors.extend([
                "Data at rest not protected",
                "Compliance requirement violations",
                "Increased impact of data breaches"
            ])
        
        return risk_factors
    
    def _assess_compliance_impact(self, pattern_name: str) -> Dict[str, str]:
        """Assess compliance framework impact"""
        compliance_map = {
            "public_bucket_policies": {
                "GDPR": "High - Personal data exposure risk",
                "HIPAA": "Critical - PHI exposure risk",
                "SOX": "Medium - Financial data controls",
                "PCI-DSS": "High - Cardholder data protection"
            },
            "missing_encryption": {
                "GDPR": "Medium - Data protection requirements",
                "HIPAA": "High - PHI encryption required",
                "SOX": "Medium - Financial data protection",
                "PCI-DSS": "High - Encryption requirements"
            },
            "hardcoded_credentials": {
                "SOX": "High - Access control violations",
                "PCI-DSS": "Critical - Authentication requirements",
                "NIST": "High - Identity management controls"
            }
        }
        
        return compliance_map.get(pattern_name, {})
    
    def _generate_exploit_scenario(self, pattern_name: str) -> str:
        """Generate realistic exploit scenario"""
        scenarios = {
            "public_bucket_policies": "Attacker discovers public bucket through automated scanning, downloads sensitive data, and uses it for identity theft or corporate espionage",
            "public_write_access": "Malicious actor uploads malware or illegal content to your bucket, potentially causing legal liability and service disruption",
            "hardcoded_credentials": "Credentials leaked in public repository are used to access AWS account, leading to resource hijacking and data theft",
            "missing_encryption": "Physical access to AWS infrastructure or insider threat results in unencrypted data exposure",
            "cors_misconfiguration": "Cross-origin attacks allow malicious websites to access bucket contents from user browsers"
        }
        
        return scenarios.get(pattern_name, "Security misconfiguration could be exploited by attackers")
    
    def _identify_resource_type(self, line: str) -> str:
        """Identify AWS resource type from line content"""
        if "bucket" in line.lower():
            return "S3Bucket"
        elif "policy" in line.lower():
            return "BucketPolicy"
        elif "cors" in line.lower():
            return "CORSConfiguration"
        elif "lifecycle" in line.lower():
            return "LifecycleConfiguration"
        else:
            return "Unknown"
    
    def _identify_config_type(self, file_path: str) -> str:
        """Identify configuration file type"""
        if file_path.endswith('.tf'):
            return "Terraform"
        elif file_path.endswith(('.yaml', '.yml')):
            return "CloudFormation"
        elif file_path.endswith('.json'):
            return "JSON Configuration"
        elif file_path.endswith(('.py', '.js', '.ts')):
            return "Application Code"
        else:
            return "Unknown"
