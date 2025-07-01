"""
Fix Engine - Generate fix suggestions from offline templates
"""

import json
import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class FixSuggestion:
    """Data structure for fix suggestions"""
    vulnerability_type: str
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float
    file_path: str
    line_number: int

class FixEngine:
    """
    Engine for generating fix suggestions from offline templates
    """
    
    def __init__(self, templates_file: str = None):
        self.fix_templates = self._load_fix_templates(templates_file)
        self.suggestions = []
        
    def _load_fix_templates(self, templates_file: str = None) -> Dict:
        """Load fix templates from JSON file"""
        if templates_file and Path(templates_file).exists():
            try:
                with open(templates_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load fix templates: {e}")
        
        # Default fix templates
        return {
            "secrets": {
                "api_keys.aws_access_key": {
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "replacement": "os.environ.get('AWS_ACCESS_KEY_ID')",
                    "explanation": "Move AWS access key to environment variable",
                    "imports": ["import os"],
                    "example": {
                        "before": "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'",
                        "after": "aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')"
                    }
                },
                "api_keys.github_token": {
                    "pattern": r"ghp_[A-Za-z0-9]{36}",
                    "replacement": "os.environ.get('GITHUB_TOKEN')",
                    "explanation": "Move GitHub token to environment variable",
                    "imports": ["import os"],
                    "example": {
                        "before": "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
                        "after": "token = os.environ.get('GITHUB_TOKEN')"
                    }
                },
                "generic.password_assignment": {
                    "pattern": r"(password|pwd|pass)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
                    "replacement": "\\1 = os.environ.get('PASSWORD')",
                    "explanation": "Move password to environment variable",
                    "imports": ["import os"],
                    "example": {
                        "before": "password = 'mySecretPassword123'",
                        "after": "password = os.environ.get('PASSWORD')"
                    }
                }
            },
            "ai_patterns": {
                "input_validation.no_input_sanitization": {
                    "pattern": r"input\(\s*[\"'][^\"']*[\"']\s*\)",
                    "replacement": "validate_input(input(\\1))",
                    "explanation": "Add input validation function",
                    "imports": ["from validators import validate_input"],
                    "helper_functions": [
                        "def validate_input(user_input):",
                        "    # Add your validation logic here",
                        "    if not user_input or len(user_input) > 1000:",
                        "        raise ValueError('Invalid input')",
                        "    return user_input.strip()"
                    ],
                    "example": {
                        "before": "name = input('Enter your name: ')",
                        "after": "name = validate_input(input('Enter your name: '))"
                    }
                },
                "input_validation.sql_injection_risk": {
                    "pattern": r"execute\(\s*[\"'].*%s.*[\"']\s*%",
                    "replacement": "execute(query, params)",
                    "explanation": "Use parameterized queries to prevent SQL injection",
                    "example": {
                        "before": "cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
                        "after": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                    }
                },
                "authentication.weak_password_check": {
                    "pattern": r"password\s*==\s*[\"'][^\"']{1,7}[\"']",
                    "replacement": "bcrypt.checkpw(password.encode('utf-8'), stored_hash)",
                    "explanation": "Use proper password hashing instead of plain text comparison",
                    "imports": ["import bcrypt"],
                    "example": {
                        "before": "if password == 'admin':",
                        "after": "if bcrypt.checkpw(password.encode('utf-8'), stored_hash):"
                    }
                },
                "crypto.weak_encryption": {
                    "pattern": r"MD5\(",
                    "replacement": "hashlib.sha256(",
                    "explanation": "Use SHA-256 instead of MD5 for better security",
                    "imports": ["import hashlib"],
                    "example": {
                        "before": "hash_value = hashlib.md5(data).hexdigest()",
                        "after": "hash_value = hashlib.sha256(data).hexdigest()"
                    }
                },
                "error_handling.bare_except": {
                    "pattern": r"except\s*:",
                    "replacement": "except SpecificException as e:",
                    "explanation": "Catch specific exceptions instead of using bare except",
                    "example": {
                        "before": "try:\n    risky_operation()\nexcept:\n    pass",
                        "after": "try:\n    risky_operation()\nexcept ValueError as e:\n    logger.error(f'Value error: {e}')"
                    }
                },
                "file_operations.path_traversal": {
                    "pattern": r"open\(\s*[^)]*\+[^)]*\)",
                    "replacement": "open(os.path.join(safe_directory, sanitized_filename), mode)",
                    "explanation": "Validate file paths to prevent directory traversal",
                    "imports": ["import os"],
                    "helper_functions": [
                        "def sanitize_filename(filename):",
                        "    # Remove path separators and dangerous characters",
                        "    return re.sub(r'[^a-zA-Z0-9._-]', '', filename)",
                        "",
                        "def validate_path(filepath, base_dir):",
                        "    # Ensure path is within base directory",
                        "    abs_path = os.path.abspath(filepath)",
                        "    abs_base = os.path.abspath(base_dir)",
                        "    return abs_path.startswith(abs_base)"
                    ],
                    "example": {
                        "before": "with open(user_filename, 'r') as f:",
                        "after": "safe_filename = sanitize_filename(user_filename)\nwith open(os.path.join(safe_directory, safe_filename), 'r') as f:"
                    }
                }
            },
            "dependencies": {
                "update_package": {
                    "explanation": "Update package to the latest secure version",
                    "commands": {
                        "python": "pip install {package}=={version}",
                        "javascript": "npm install {package}@{version}",
                        "rust": "cargo update {package}",
                        "go": "go get {package}@{version}"
                    }
                }
            }
        }
    
    def generate_fix_for_secret(self, finding: Dict) -> Optional[FixSuggestion]:
        """Generate fix suggestion for secret finding"""
        subtype = finding.get("subtype", "")
        
        if subtype in self.fix_templates["secrets"]:
            template = self.fix_templates["secrets"][subtype]
            
            # Extract the original code context
            original_line = finding.get("context", "")
            
            # Apply template replacement
            pattern = template["pattern"]
            replacement = template["replacement"]
            
            try:
                fixed_line = re.sub(pattern, replacement, original_line, flags=re.IGNORECASE)
                
                return FixSuggestion(
                    vulnerability_type=subtype,
                    original_code=original_line,
                    fixed_code=fixed_line,
                    explanation=template["explanation"],
                    confidence=0.8,
                    file_path=finding["file_path"],
                    line_number=finding["line_number"]
                )
            except re.error as e:
                logger.error(f"Regex error in fix generation: {e}")
                return None
        
        return None
    
    def generate_fix_for_ai_pattern(self, finding: Dict) -> Optional[FixSuggestion]:
        """Generate fix suggestion for AI pattern finding"""
        subtype = finding.get("subtype", "")
        
        if subtype in self.fix_templates["ai_patterns"]:
            template = self.fix_templates["ai_patterns"][subtype]
            
            original_line = finding.get("context", "")
            
            # For AI patterns, we often need more context-aware fixes
            if "example" in template:
                # Use the example as a guide for the fix
                fixed_line = self._apply_example_fix(original_line, template["example"])
            else:
                # Apply pattern replacement
                pattern = template.get("pattern", "")
                replacement = template.get("replacement", "")
                
                try:
                    fixed_line = re.sub(pattern, replacement, original_line, flags=re.IGNORECASE)
                except re.error:
                    fixed_line = template["example"]["after"] if "example" in template else original_line
            
            return FixSuggestion(
                vulnerability_type=subtype,
                original_code=original_line,
                fixed_code=fixed_line,
                explanation=template["explanation"],
                confidence=0.7,
                file_path=finding["file_path"],
                line_number=finding["line_number"]
            )
        
        return None
    
    def generate_fix_for_dependency(self, finding: Dict) -> Optional[FixSuggestion]:
        """Generate fix suggestion for dependency vulnerability"""
        package_name = finding.get("package_name", "")
        fixed_version = finding.get("fixed_version", "")
        ecosystem = finding.get("ecosystem", "")
        
        if not package_name or not fixed_version:
            return None
        
        template = self.fix_templates["dependencies"]["update_package"]
        commands = template.get("commands", {})
        
        if ecosystem in commands:
            command = commands[ecosystem].format(package=package_name, version=fixed_version)
            
            return FixSuggestion(
                vulnerability_type="dependency_update",
                original_code=f"{package_name} (vulnerable version)",
                fixed_code=f"Run: {command}",
                explanation=f"Update {package_name} to version {fixed_version} or later",
                confidence=0.9,
                file_path=finding["file_path"],
                line_number=finding.get("line_number", 0)
            )
        
        return None
    
    def _apply_example_fix(self, original_line: str, example: Dict) -> str:
        """Apply fix based on example template"""
        before_pattern = example.get("before", "")
        after_template = example.get("after", "")
        
        # Try to extract variable names and values from the original line
        # This is a simplified approach - in practice, you'd want more sophisticated parsing
        
        # For now, return the after template as-is
        return after_template
    
    def generate_fixes(self, findings: List[Dict]) -> List[FixSuggestion]:
        """Generate fix suggestions for a list of findings - optimized version"""
        suggestions = []

        # Group findings by type for batch processing
        findings_by_type = {}
        for finding in findings:
            finding_type = finding.get("type", "")
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)

        # Process each type in batch
        for finding_type, type_findings in findings_by_type.items():
            if finding_type == "secret":
                for finding in type_findings:
                    fix = self.generate_fix_for_secret(finding)
                    if fix:
                        suggestions.append(fix)
            elif finding_type == "ai_pattern":
                for finding in type_findings:
                    fix = self.generate_fix_for_ai_pattern(finding)
                    if fix:
                        suggestions.append(fix)
            elif finding_type == "vulnerability":
                for finding in type_findings:
                    fix = self.generate_fix_for_dependency(finding)
                    if fix:
                        suggestions.append(fix)

        self.suggestions.extend(suggestions)
        return suggestions
    
    def get_fix_summary(self) -> Dict:
        """Get summary of generated fixes"""
        if not self.suggestions:
            return {"total": 0, "by_type": {}}
        
        by_type = {}
        for suggestion in self.suggestions:
            vuln_type = suggestion.vulnerability_type
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
        
        return {
            "total": len(self.suggestions),
            "by_type": by_type
        }
    
    def export_fixes_to_dict(self) -> List[Dict]:
        """Export fix suggestions to dictionary format"""
        return [
            {
                "vulnerability_type": fix.vulnerability_type,
                "original_code": fix.original_code,
                "fixed_code": fix.fixed_code,
                "explanation": fix.explanation,
                "confidence": fix.confidence,
                "file_path": fix.file_path,
                "line_number": fix.line_number
            }
            for fix in self.suggestions
        ]
    
    def reset(self):
        """Reset fix engine state"""
        self.suggestions.clear()
