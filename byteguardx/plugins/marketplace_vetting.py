"""
Plugin Marketplace Vetting System
Comprehensive security validation for uploaded and marketplace plugins
"""

import ast
import re
import hashlib
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import tempfile
import shutil

logger = logging.getLogger(__name__)

class VettingResult(Enum):
    """Plugin vetting results"""
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"
    QUARANTINED = "quarantined"

@dataclass
class SecurityViolation:
    """Security violation found during vetting"""
    type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None

@dataclass
class VettingReport:
    """Comprehensive vetting report"""
    plugin_name: str
    plugin_version: str
    result: VettingResult
    score: int  # 0-100 security score
    violations: List[SecurityViolation] = field(default_factory=list)
    static_analysis: Dict[str, Any] = field(default_factory=dict)
    dynamic_analysis: Dict[str, Any] = field(default_factory=dict)
    hash_verification: Dict[str, str] = field(default_factory=dict)
    metadata_validation: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

class PluginVettingSystem:
    """Comprehensive plugin vetting and validation system"""
    
    # Dangerous patterns that automatically reject plugins
    CRITICAL_PATTERNS = [
        (r'eval\s*\(', 'Use of eval() function'),
        (r'exec\s*\(', 'Use of exec() function'),
        (r'__import__\s*\(', 'Dynamic import usage'),
        (r'compile\s*\(', 'Code compilation'),
        (r'subprocess\.(call|run|Popen)', 'Subprocess execution'),
        (r'os\.system\s*\(', 'OS system call'),
        (r'os\.popen\s*\(', 'OS popen call'),
        (r'socket\.(socket|create_connection)', 'Network socket usage'),
        (r'urllib\.(request|urlopen)', 'HTTP request'),
        (r'requests\.(get|post|put|delete)', 'HTTP request library'),
        (r'pickle\.(loads|load)', 'Pickle deserialization'),
        (r'marshal\.(loads|load)', 'Marshal deserialization'),
        (r'ctypes\.(CDLL|windll)', 'Native library loading'),
        (r'multiprocessing\.Process', 'Process creation'),
        (r'threading\.Thread', 'Thread creation'),
        (r'open\s*\([^)]*["\']w["\']', 'File write operations'),
        (r'shutil\.(rmtree|move|copy)', 'File system operations'),
        (r'tempfile\.(mktemp|mkdtemp)', 'Temporary file creation'),
    ]
    
    # Suspicious patterns that require review
    SUSPICIOUS_PATTERNS = [
        (r'import\s+(os|sys|subprocess)', 'System module import'),
        (r'from\s+(os|sys|subprocess)', 'System module import'),
        (r'getattr\s*\(', 'Dynamic attribute access'),
        (r'setattr\s*\(', 'Dynamic attribute setting'),
        (r'hasattr\s*\(', 'Attribute checking'),
        (r'globals\s*\(\)', 'Global namespace access'),
        (r'locals\s*\(\)', 'Local namespace access'),
        (r'vars\s*\(', 'Variable inspection'),
        (r'dir\s*\(', 'Object inspection'),
        (r'__.*__', 'Dunder method usage'),
        (r'base64\.(decode|b64decode)', 'Base64 decoding'),
        (r'zlib\.(decompress|inflate)', 'Data decompression'),
        (r'gzip\.(decompress|open)', 'Gzip operations'),
    ]
    
    # Required metadata fields
    REQUIRED_METADATA = [
        'name', 'version', 'description', 'author', 'license'
    ]
    
    def __init__(self):
        self.temp_dir = Path(tempfile.gettempdir()) / "byteguardx_vetting"
        self.temp_dir.mkdir(exist_ok=True)
    
    def vet_plugin(self, plugin_path: Path, metadata: Dict[str, Any]) -> VettingReport:
        """Comprehensive plugin vetting"""
        report = VettingReport(
            plugin_name=metadata.get('name', 'unknown'),
            plugin_version=metadata.get('version', '0.0.0'),
            result=VettingResult.NEEDS_REVIEW,
            score=100  # Start with perfect score, deduct for violations
        )
        
        try:
            # 1. Metadata validation
            self._validate_metadata(metadata, report)
            
            # 2. Hash verification
            self._verify_plugin_hash(plugin_path, report)
            
            # 3. Static code analysis
            self._static_analysis(plugin_path, report)
            
            # 4. Dynamic analysis (if safe enough)
            if report.score >= 70:  # Only if reasonably safe
                self._dynamic_analysis(plugin_path, report)
            
            # 5. Determine final result
            self._determine_final_result(report)
            
        except Exception as e:
            logger.error(f"Vetting failed for {plugin_path}: {e}")
            report.result = VettingResult.REJECTED
            report.violations.append(SecurityViolation(
                type="vetting_error",
                severity="CRITICAL",
                description=f"Vetting process failed: {str(e)}"
            ))
            report.score = 0
        
        return report
    
    def _validate_metadata(self, metadata: Dict[str, Any], report: VettingReport):
        """Validate plugin metadata"""
        validation_results = {}
        
        # Check required fields
        missing_fields = []
        for field in self.REQUIRED_METADATA:
            if field not in metadata or not metadata[field]:
                missing_fields.append(field)
        
        if missing_fields:
            report.violations.append(SecurityViolation(
                type="missing_metadata",
                severity="MEDIUM",
                description=f"Missing required metadata fields: {', '.join(missing_fields)}"
            ))
            report.score -= 10
        
        # Validate version format
        version = metadata.get('version', '')
        if not re.match(r'^\d+\.\d+\.\d+', version):
            report.violations.append(SecurityViolation(
                type="invalid_version",
                severity="LOW",
                description="Version should follow semantic versioning (x.y.z)"
            ))
            report.score -= 5
        
        # Check for suspicious metadata
        suspicious_keywords = ['hack', 'crack', 'exploit', 'backdoor', 'malware']
        for field in ['name', 'description']:
            value = metadata.get(field, '').lower()
            for keyword in suspicious_keywords:
                if keyword in value:
                    report.violations.append(SecurityViolation(
                        type="suspicious_metadata",
                        severity="HIGH",
                        description=f"Suspicious keyword '{keyword}' in {field}"
                    ))
                    report.score -= 20
        
        report.metadata_validation = validation_results
    
    def _verify_plugin_hash(self, plugin_path: Path, report: VettingReport):
        """Verify plugin file integrity"""
        try:
            with open(plugin_path, 'rb') as f:
                content = f.read()
            
            # Calculate various hashes
            hashes = {
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest()
            }
            
            report.hash_verification = hashes
            
            # Check against known malicious hashes (would be from a database)
            # This is a placeholder for actual malware hash checking
            known_malicious = set()  # Would load from security database
            
            for hash_type, hash_value in hashes.items():
                if hash_value in known_malicious:
                    report.violations.append(SecurityViolation(
                        type="malicious_hash",
                        severity="CRITICAL",
                        description=f"Plugin matches known malicious {hash_type} hash"
                    ))
                    report.score = 0
                    
        except Exception as e:
            report.violations.append(SecurityViolation(
                type="hash_verification_failed",
                severity="MEDIUM",
                description=f"Could not verify plugin hash: {str(e)}"
            ))
            report.score -= 10
    
    def _static_analysis(self, plugin_path: Path, report: VettingReport):
        """Static code analysis"""
        try:
            with open(plugin_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            lines = code.split('\n')
            
            # Check for critical patterns
            for line_num, line in enumerate(lines, 1):
                for pattern, description in self.CRITICAL_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        report.violations.append(SecurityViolation(
                            type="critical_pattern",
                            severity="CRITICAL",
                            description=description,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            recommendation="Remove or replace with safe alternative"
                        ))
                        report.score -= 30
            
            # Check for suspicious patterns
            for line_num, line in enumerate(lines, 1):
                for pattern, description in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        report.violations.append(SecurityViolation(
                            type="suspicious_pattern",
                            severity="MEDIUM",
                            description=description,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            recommendation="Review usage and ensure it's necessary"
                        ))
                        report.score -= 10
            
            # AST analysis
            try:
                tree = ast.parse(code)
                ast_analysis = self._analyze_ast(tree)
                report.static_analysis['ast'] = ast_analysis
                
                # Deduct points for risky AST patterns
                if ast_analysis.get('has_exec_calls', False):
                    report.score -= 40
                if ast_analysis.get('has_eval_calls', False):
                    report.score -= 40
                if ast_analysis.get('has_import_calls', False):
                    report.score -= 20
                    
            except SyntaxError as e:
                report.violations.append(SecurityViolation(
                    type="syntax_error",
                    severity="HIGH",
                    description=f"Python syntax error: {str(e)}"
                ))
                report.score -= 25
            
            # Run external static analysis tools
            self._run_external_analysis(plugin_path, report)
            
        except Exception as e:
            report.violations.append(SecurityViolation(
                type="static_analysis_failed",
                severity="MEDIUM",
                description=f"Static analysis failed: {str(e)}"
            ))
            report.score -= 15
    
    def _analyze_ast(self, tree: ast.AST) -> Dict[str, Any]:
        """Analyze AST for dangerous patterns"""
        analysis = {
            'has_exec_calls': False,
            'has_eval_calls': False,
            'has_import_calls': False,
            'function_count': 0,
            'class_count': 0,
            'import_count': 0
        }
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['exec', 'eval']:
                        analysis['has_exec_calls'] = True
                    elif node.func.id == '__import__':
                        analysis['has_import_calls'] = True
            
            elif isinstance(node, ast.FunctionDef):
                analysis['function_count'] += 1
            
            elif isinstance(node, ast.ClassDef):
                analysis['class_count'] += 1
            
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                analysis['import_count'] += 1
        
        return analysis
    
    def _run_external_analysis(self, plugin_path: Path, report: VettingReport):
        """Run external static analysis tools"""
        try:
            # Run bandit for security analysis
            result = subprocess.run([
                'bandit', '-f', 'json', str(plugin_path)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                try:
                    bandit_results = json.loads(result.stdout)
                    report.static_analysis['bandit'] = bandit_results
                    
                    # Process bandit results
                    for issue in bandit_results.get('results', []):
                        severity_map = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH'}
                        severity = severity_map.get(issue.get('issue_severity', 'MEDIUM'), 'MEDIUM')
                        
                        report.violations.append(SecurityViolation(
                            type="bandit_issue",
                            severity=severity,
                            description=issue.get('issue_text', 'Security issue detected'),
                            line_number=issue.get('line_number'),
                            recommendation="Review and fix security issue"
                        ))
                        
                        # Deduct points based on severity
                        if severity == 'HIGH':
                            report.score -= 20
                        elif severity == 'MEDIUM':
                            report.score -= 10
                        else:
                            report.score -= 5
                            
                except json.JSONDecodeError:
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Bandit not available or timed out
            pass
    
    def _dynamic_analysis(self, plugin_path: Path, report: VettingReport):
        """Safe dynamic analysis in sandbox"""
        # This would use the Docker sandbox to safely execute and analyze
        # the plugin's behavior
        report.dynamic_analysis = {
            'executed': False,
            'reason': 'Dynamic analysis not implemented yet'
        }
    
    def _determine_final_result(self, report: VettingReport):
        """Determine final vetting result based on analysis"""
        critical_violations = [v for v in report.violations if v.severity == 'CRITICAL']
        high_violations = [v for v in report.violations if v.severity == 'HIGH']
        
        if critical_violations or report.score < 30:
            report.result = VettingResult.REJECTED
            report.recommendations.append("Plugin contains critical security issues and cannot be approved")
        
        elif high_violations or report.score < 60:
            report.result = VettingResult.NEEDS_REVIEW
            report.recommendations.append("Plugin requires manual security review before approval")
        
        elif report.score < 80:
            report.result = VettingResult.NEEDS_REVIEW
            report.recommendations.append("Plugin has minor security concerns that should be reviewed")
        
        else:
            report.result = VettingResult.APPROVED
            report.recommendations.append("Plugin passed automated security checks")
        
        # Add specific recommendations based on violations
        for violation in report.violations:
            if violation.recommendation:
                report.recommendations.append(violation.recommendation)

# Global vetting system instance
plugin_vetting_system = PluginVettingSystem()
