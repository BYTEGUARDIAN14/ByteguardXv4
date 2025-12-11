"""
GCP IAM Role Weakness Detector Plugin
Detects Google Cloud Platform IAM misconfigurations and privilege escalation risks
"""

import re
import json
import logging
from typing import Dict, List, Any
try:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory
except ImportError:
    from ..plugin_framework_mock import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class GCPIAMWeaknessDetector(BasePlugin):
    """Scanner for GCP IAM role weaknesses and privilege escalation risks"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="gcp_iam_weakness_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects GCP IAM role misconfigurations, excessive permissions, and privilege escalation risks",
            category=PluginCategory.CLOUD_SECURITY,
            supported_languages=["json", "yaml", "terraform", "python", "javascript"],
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
        
        self.iam_patterns = self._load_iam_patterns()
        self.compiled_patterns = self._compile_patterns()
        self.dangerous_permissions = self._load_dangerous_permissions()
    
    def _load_iam_patterns(self) -> Dict[str, Any]:
        """Load GCP IAM security patterns"""
        return {
            "overprivileged_roles": {
                "patterns": [
                    r'"roles/owner"',
                    r'"roles/editor"',
                    r'"roles/.*admin"',
                    r'roles/iam\.serviceAccountAdmin',
                    r'roles/iam\.serviceAccountKeyAdmin',
                    r'roles/resourcemanager\.projectIamAdmin'
                ],
                "description": "Overprivileged IAM role assignment detected",
                "severity": "high",
                "cwe_id": "CWE-269",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "wildcard_permissions": {
                "patterns": [
                    r'"[^"]*\*[^"]*".*permissions',
                    r'permissions.*\*',
                    r'"[^"]*\.\*"',
                    r'actions.*\*'
                ],
                "description": "Wildcard permissions grant excessive access",
                "severity": "high",
                "cwe_id": "CWE-732",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "public_iam_bindings": {
                "patterns": [
                    r'"allUsers"',
                    r'"allAuthenticatedUsers"',
                    r'members.*allUsers',
                    r'members.*allAuthenticatedUsers'
                ],
                "description": "IAM binding grants access to all users",
                "severity": "critical",
                "cwe_id": "CWE-284",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "service_account_impersonation": {
                "patterns": [
                    r'roles/iam\.serviceAccountTokenCreator',
                    r'iam\.serviceAccounts\.actAs',
                    r'iam\.serviceAccounts\.implicitDelegation',
                    r'serviceAccountImpersonationChain'
                ],
                "description": "Service account impersonation permissions detected",
                "severity": "medium",
                "cwe_id": "CWE-269",
                "owasp_category": "A07:2021 – Identification and Authentication Failures"
            },
            "compute_admin_access": {
                "patterns": [
                    r'roles/compute\.admin',
                    r'roles/compute\.instanceAdmin',
                    r'compute\.instances\.create',
                    r'compute\.instances\.setServiceAccount'
                ],
                "description": "Compute admin access can lead to privilege escalation",
                "severity": "medium",
                "cwe_id": "CWE-269",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "storage_admin_access": {
                "patterns": [
                    r'roles/storage\.admin',
                    r'roles/storage\.objectAdmin',
                    r'storage\.objects\.create',
                    r'storage\.objects\.delete'
                ],
                "description": "Storage admin access grants broad data permissions",
                "severity": "medium",
                "cwe_id": "CWE-732",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "project_level_bindings": {
                "patterns": [
                    r'"projects/[^"]*".*bindings',
                    r'project.*bindings',
                    r'resource.*projects/.*policy'
                ],
                "description": "Project-level IAM bindings should be minimized",
                "severity": "low",
                "cwe_id": "CWE-732",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "missing_conditions": {
                "patterns": [
                    r'"bindings".*\[.*\](?!.*condition)',
                    r'members.*:.*(?!.*condition)',
                    r'role.*members(?!.*condition)'
                ],
                "description": "IAM binding lacks conditional access controls",
                "severity": "low",
                "cwe_id": "CWE-284",
                "owasp_category": "A01:2021 – Broken Access Control"
            },
            "hardcoded_service_keys": {
                "patterns": [
                    r'"type"\s*:\s*"service_account"',
                    r'"private_key_id"\s*:\s*"[^"]*"',
                    r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----',
                    r'service_account_key.*json'
                ],
                "description": "Hardcoded GCP service account key detected",
                "severity": "critical",
                "cwe_id": "CWE-798",
                "owasp_category": "A07:2021 – Identification and Authentication Failures"
            },
            "cross_project_access": {
                "patterns": [
                    r'serviceAccount:[^@]*@[^.]*\.iam\.gserviceaccount\.com',
                    r'projects/[^/]*/serviceAccounts/',
                    r'cross.*project.*access'
                ],
                "description": "Cross-project service account access detected",
                "severity": "medium",
                "cwe_id": "CWE-284",
                "owasp_category": "A01:2021 – Broken Access Control"
            }
        }
    
    def _load_dangerous_permissions(self) -> Dict[str, List[str]]:
        """Load dangerous GCP permissions that can lead to privilege escalation"""
        return {
            "iam_admin": [
                "iam.roles.create",
                "iam.roles.update",
                "iam.serviceAccounts.create",
                "iam.serviceAccountKeys.create",
                "resourcemanager.projects.setIamPolicy"
            ],
            "compute_escalation": [
                "compute.instances.create",
                "compute.instances.setServiceAccount",
                "compute.instances.setMetadata",
                "compute.disks.create"
            ],
            "storage_access": [
                "storage.objects.create",
                "storage.objects.delete",
                "storage.buckets.setIamPolicy",
                "storage.hmacKeys.create"
            ],
            "deployment_manager": [
                "deploymentmanager.deployments.create",
                "deploymentmanager.deployments.update",
                "deploymentmanager.manifests.create"
            ],
            "cloud_functions": [
                "cloudfunctions.functions.create",
                "cloudfunctions.functions.update",
                "cloudfunctions.functions.setIamPolicy"
            ]
        }
    
    def _compile_patterns(self) -> Dict[str, Any]:
        """Compile regex patterns for performance"""
        compiled = {}
        for name, config in self.iam_patterns.items():
            compiled[name] = {
                "regexes": [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                           for pattern in config["patterns"]],
                "config": config
            }
        return compiled
    
    def validate_input(self, content: str, file_path: str) -> bool:
        """Validate input for GCP IAM scanning"""
        if not content or not content.strip():
            return False
        
        # Check if content is relevant to GCP IAM
        gcp_indicators = [
            "gcp", "google", "cloud", "iam", "roles", "permissions",
            "serviceaccount", "bindings", "policy", "gserviceaccount"
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in gcp_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan content for GCP IAM security issues"""
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
                            "title": f"GCP IAM Security Issue: {config['description']}",
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
                            "privilege_escalation_paths": self._analyze_escalation_paths(pattern_name, match.group()),
                            "compliance_impact": self._assess_compliance_impact(pattern_name),
                            "detection_metadata": {
                                "pattern_type": pattern_name,
                                "matched_text": match.group(),
                                "cloud_provider": "gcp",
                                "service": "iam",
                                "resource_type": self._identify_resource_type(line),
                                "permission_level": self._assess_permission_level(pattern_name, match.group())
                            }
                        }
                        
                        findings.append(finding)
        
        return findings
    
    def _calculate_confidence(self, pattern_name: str, line: str, file_path: str) -> float:
        """Calculate confidence score for GCP IAM findings"""
        base_confidence = 0.7
        
        # File type adjustments
        if file_path.endswith(('.tf', '.yaml', '.yml', '.json')):
            base_confidence += 0.2
        
        # Context adjustments
        line_lower = line.lower()
        
        # High confidence indicators
        if any(indicator in line_lower for indicator in ['iam', 'roles', 'permissions', 'bindings']):
            base_confidence += 0.1
        
        # Pattern-specific adjustments
        if pattern_name == "public_iam_bindings" and 'allUsers' in line:
            base_confidence += 0.2
        elif pattern_name == "hardcoded_service_keys" and 'service_account' in line_lower:
            base_confidence += 0.15
        elif pattern_name == "overprivileged_roles" and any(role in line_lower for role in ['owner', 'editor', 'admin']):
            base_confidence += 0.1
        
        # Reduce confidence for comments or examples
        if any(indicator in line_lower for indicator in ['example', 'test', 'demo', '#', '//']):
            base_confidence -= 0.3
        
        return max(0.1, min(1.0, base_confidence))
    
    def _generate_remediation(self, pattern_name: str, matched_text: str) -> str:
        """Generate specific remediation advice"""
        remediation_map = {
            "overprivileged_roles": "Replace with least-privilege custom roles or predefined roles with minimal permissions",
            "wildcard_permissions": "Replace wildcard permissions with specific, required permissions only",
            "public_iam_bindings": "Remove public access and grant permissions to specific users or service accounts",
            "service_account_impersonation": "Restrict service account impersonation to necessary use cases only",
            "compute_admin_access": "Use specific compute roles instead of admin access",
            "storage_admin_access": "Grant specific storage permissions instead of admin access",
            "project_level_bindings": "Move to resource-level bindings where possible",
            "missing_conditions": "Add conditional access controls (IP restrictions, time-based access)",
            "hardcoded_service_keys": "Use Workload Identity or store keys securely in Secret Manager",
            "cross_project_access": "Review and minimize cross-project service account access"
        }
        
        return remediation_map.get(pattern_name, "Review and apply principle of least privilege")
    
    def _assess_risk_factors(self, pattern_name: str, line: str, context: Dict[str, Any]) -> List[str]:
        """Assess risk factors for the finding"""
        risk_factors = []
        
        if pattern_name in ["overprivileged_roles", "wildcard_permissions"]:
            risk_factors.extend([
                "Excessive permissions enable privilege escalation",
                "Increased blast radius of compromised accounts",
                "Compliance violations for access controls"
            ])
        
        if pattern_name == "public_iam_bindings":
            risk_factors.extend([
                "Unrestricted public access to resources",
                "Data exposure and unauthorized operations",
                "Potential for resource abuse and billing fraud"
            ])
        
        if pattern_name == "hardcoded_service_keys":
            risk_factors.extend([
                "Service account key exposure in code repositories",
                "Long-lived credentials without rotation",
                "Potential for unauthorized GCP access"
            ])
        
        return risk_factors
    
    def _analyze_escalation_paths(self, pattern_name: str, matched_text: str) -> List[Dict[str, str]]:
        """Analyze potential privilege escalation paths"""
        escalation_paths = []
        
        if pattern_name == "overprivileged_roles":
            if "owner" in matched_text.lower():
                escalation_paths.append({
                    "path": "Project Owner → Full GCP Access",
                    "description": "Owner role grants full access to all project resources",
                    "impact": "Complete project compromise"
                })
            elif "editor" in matched_text.lower():
                escalation_paths.append({
                    "path": "Editor → Resource Modification",
                    "description": "Editor role allows modification of most resources",
                    "impact": "Data manipulation and service disruption"
                })
        
        if pattern_name == "service_account_impersonation":
            escalation_paths.append({
                "path": "Service Account Impersonation → Privilege Escalation",
                "description": "Impersonate higher-privileged service accounts",
                "impact": "Access to resources beyond original permissions"
            })
        
        if pattern_name == "compute_admin_access":
            escalation_paths.append({
                "path": "Compute Admin → Metadata Service → Service Account Keys",
                "description": "Create instances with high-privilege service accounts",
                "impact": "Access to service account credentials via metadata"
            })
        
        return escalation_paths
    
    def _assess_compliance_impact(self, pattern_name: str) -> Dict[str, str]:
        """Assess compliance framework impact"""
        compliance_map = {
            "overprivileged_roles": {
                "SOC2": "High - Access control requirements",
                "ISO27001": "Medium - Privilege management controls",
                "NIST": "High - Least privilege principle violations"
            },
            "public_iam_bindings": {
                "GDPR": "Critical - Personal data access controls",
                "HIPAA": "Critical - PHI access restrictions",
                "SOX": "High - Financial data access controls"
            },
            "hardcoded_service_keys": {
                "SOC2": "Critical - Credential management failures",
                "PCI-DSS": "High - Authentication requirements",
                "NIST": "High - Identity management controls"
            }
        }
        
        return compliance_map.get(pattern_name, {})
    
    def _identify_resource_type(self, line: str) -> str:
        """Identify GCP resource type from line content"""
        if "bindings" in line.lower():
            return "IAMBinding"
        elif "role" in line.lower():
            return "IAMRole"
        elif "serviceaccount" in line.lower():
            return "ServiceAccount"
        elif "policy" in line.lower():
            return "IAMPolicy"
        else:
            return "Unknown"
    
    def _assess_permission_level(self, pattern_name: str, matched_text: str) -> str:
        """Assess the permission level of the finding"""
        if pattern_name in ["overprivileged_roles", "public_iam_bindings"]:
            if any(role in matched_text.lower() for role in ["owner", "admin"]):
                return "Administrative"
            elif "editor" in matched_text.lower():
                return "Elevated"
            else:
                return "Standard"
        
        if pattern_name == "wildcard_permissions":
            return "Excessive"
        
        return "Unknown"
