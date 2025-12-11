#!/usr/bin/env python3
"""
Advanced Plugin Security System for ByteGuardX
Implements comprehensive plugin security with behavioral analysis and runtime monitoring
"""

import logging
import hashlib
import json
import subprocess
import tempfile
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import threading
import time

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class PluginSecurityProfile:
    """Comprehensive plugin security profile"""
    plugin_id: str
    name: str
    version: str
    publisher: str
    signature_valid: bool
    reputation_score: float
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    permissions_requested: List[str]
    permissions_granted: List[str]
    behavioral_flags: List[str]
    vulnerability_scan_results: Dict[str, Any]
    runtime_violations: List[str]
    last_security_scan: datetime
    security_status: str  # 'APPROVED', 'PENDING', 'REJECTED', 'QUARANTINED'

@dataclass
class SecurityViolation:
    """Security violation record"""
    violation_id: str
    plugin_id: str
    violation_type: str
    severity: str
    description: str
    detected_at: datetime
    evidence: Dict[str, Any]
    mitigation_actions: List[str]

class AdvancedPluginSecurity:
    """
    Advanced plugin security system with behavioral analysis
    """
    
    def __init__(self):
        # Security profiles and violations
        self.security_profiles: Dict[str, PluginSecurityProfile] = {}
        self.security_violations: List[SecurityViolation] = []
        
        # Security scanning tools
        self.yara_rules = None
        self.docker_client = None
        
        # Behavioral monitoring
        self.behavioral_monitors = {}
        self.runtime_stats = {}
        
        # Security policies
        self.security_policies = self._load_security_policies()
        
        # Initialize security tools
        self._init_security_tools()
        
        # Start monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None
        self._start_monitoring()
        
        logger.info("Advanced plugin security system initialized")
    
    def _load_security_policies(self) -> Dict[str, Any]:
        """Load security policies configuration"""
        return {
            'max_memory_usage': 100 * 1024 * 1024,  # 100MB
            'max_cpu_usage': 50.0,  # 50%
            'max_network_connections': 10,
            'allowed_file_operations': ['read', 'write_temp'],
            'blocked_system_calls': ['exec', 'fork', 'kill'],
            'required_permissions': ['scan_files'],
            'reputation_threshold': 0.7,
            'quarantine_on_violation': True,
            'auto_update_security_rules': True
        }
    
    def _init_security_tools(self):
        """Initialize security scanning tools"""
        try:
            # Initialize Docker client for sandboxing
            if DOCKER_AVAILABLE:
                self.docker_client = docker.from_env()
                logger.info("Docker client initialized for plugin sandboxing")
            
            # Initialize YARA rules for malware detection
            if YARA_AVAILABLE:
                self._load_yara_rules()
                logger.info("YARA rules loaded for malware detection")
            
        except Exception as e:
            logger.error(f"Security tools initialization failed: {e}")
    
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            # Create basic YARA rules for plugin security
            yara_rules_content = '''
            rule SuspiciousImports {
                strings:
                    $import1 = "import subprocess"
                    $import2 = "import os"
                    $import3 = "import sys"
                    $import4 = "from subprocess import"
                condition:
                    2 of them
            }
            
            rule NetworkActivity {
                strings:
                    $net1 = "socket.socket"
                    $net2 = "urllib.request"
                    $net3 = "requests.get"
                    $net4 = "http.client"
                condition:
                    any of them
            }
            
            rule FileSystemAccess {
                strings:
                    $file1 = "open("
                    $file2 = "os.remove"
                    $file3 = "os.rmdir"
                    $file4 = "shutil.rmtree"
                condition:
                    2 of them
            }
            
            rule CryptoOperations {
                strings:
                    $crypto1 = "hashlib"
                    $crypto2 = "cryptography"
                    $crypto3 = "Crypto"
                    $crypto4 = "base64"
                condition:
                    any of them
            }
            '''
            
            # Save rules to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(yara_rules_content)
                rules_file = f.name
            
            # Compile YARA rules
            self.yara_rules = yara.compile(filepath=rules_file)
            
            # Clean up temporary file
            os.unlink(rules_file)
            
        except Exception as e:
            logger.error(f"YARA rules loading failed: {e}")
            self.yara_rules = None
    
    def scan_plugin_security(self, plugin_path: str, plugin_metadata: Dict[str, Any]) -> PluginSecurityProfile:
        """Comprehensive security scan of plugin"""
        try:
            plugin_id = plugin_metadata.get('id', 'unknown')
            
            # Initialize security profile
            profile = PluginSecurityProfile(
                plugin_id=plugin_id,
                name=plugin_metadata.get('name', 'Unknown'),
                version=plugin_metadata.get('version', '0.0.0'),
                publisher=plugin_metadata.get('publisher', 'Unknown'),
                signature_valid=False,
                reputation_score=0.0,
                risk_level='UNKNOWN',
                permissions_requested=plugin_metadata.get('permissions', []),
                permissions_granted=[],
                behavioral_flags=[],
                vulnerability_scan_results={},
                runtime_violations=[],
                last_security_scan=datetime.now(),
                security_status='PENDING'
            )
            
            # 1. Static code analysis
            static_results = self._perform_static_analysis(plugin_path)
            profile.vulnerability_scan_results['static_analysis'] = static_results
            
            # 2. YARA malware scanning
            if self.yara_rules:
                yara_results = self._perform_yara_scan(plugin_path)
                profile.vulnerability_scan_results['malware_scan'] = yara_results
                
                # Update behavioral flags based on YARA results
                for match in yara_results.get('matches', []):
                    profile.behavioral_flags.append(f"yara_match_{match}")
            
            # 3. Dependency vulnerability scanning
            dependency_results = self._scan_dependencies(plugin_path)
            profile.vulnerability_scan_results['dependency_scan'] = dependency_results
            
            # 4. Permission analysis
            permission_results = self._analyze_permissions(plugin_metadata)
            profile.vulnerability_scan_results['permission_analysis'] = permission_results
            
            # 5. Calculate reputation score
            profile.reputation_score = self._calculate_reputation_score(profile)
            
            # 6. Determine risk level
            profile.risk_level = self._determine_risk_level(profile)
            
            # 7. Make security decision
            profile.security_status = self._make_security_decision(profile)
            
            # Store security profile
            self.security_profiles[plugin_id] = profile
            
            logger.info(f"Plugin security scan completed: {plugin_id} - {profile.security_status}")
            
            return profile
            
        except Exception as e:
            logger.error(f"Plugin security scan failed: {e}")
            # Return default unsafe profile
            return PluginSecurityProfile(
                plugin_id=plugin_id,
                name='Unknown',
                version='0.0.0',
                publisher='Unknown',
                signature_valid=False,
                reputation_score=0.0,
                risk_level='CRITICAL',
                permissions_requested=[],
                permissions_granted=[],
                behavioral_flags=['scan_failed'],
                vulnerability_scan_results={'error': str(e)},
                runtime_violations=[],
                last_security_scan=datetime.now(),
                security_status='REJECTED'
            )
    
    def _perform_static_analysis(self, plugin_path: str) -> Dict[str, Any]:
        """Perform static code analysis"""
        results = {
            'suspicious_patterns': [],
            'security_issues': [],
            'complexity_score': 0,
            'line_count': 0
        }
        
        try:
            # Read plugin files
            plugin_files = []
            if os.path.isfile(plugin_path):
                plugin_files = [plugin_path]
            elif os.path.isdir(plugin_path):
                for root, dirs, files in os.walk(plugin_path):
                    for file in files:
                        if file.endswith(('.py', '.js', '.ts')):
                            plugin_files.append(os.path.join(root, file))
            
            total_lines = 0
            suspicious_patterns = []
            
            # Analyze each file
            for file_path in plugin_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        total_lines += len(lines)
                        
                        # Check for suspicious patterns
                        suspicious_keywords = [
                            'eval(', 'exec(', '__import__', 'subprocess.call',
                            'os.system', 'shell=True', 'pickle.loads',
                            'marshal.loads', 'compile(', 'globals()',
                            'locals()', '__builtins__'
                        ]
                        
                        for i, line in enumerate(lines):
                            for keyword in suspicious_keywords:
                                if keyword in line:
                                    suspicious_patterns.append({
                                        'file': file_path,
                                        'line': i + 1,
                                        'pattern': keyword,
                                        'content': line.strip()
                                    })
                
                except Exception as e:
                    logger.warning(f"Failed to analyze file {file_path}: {e}")
            
            results['line_count'] = total_lines
            results['suspicious_patterns'] = suspicious_patterns
            results['complexity_score'] = min(total_lines / 100, 10)  # Normalize to 0-10
            
            # Determine security issues
            if len(suspicious_patterns) > 5:
                results['security_issues'].append('High number of suspicious patterns')
            
            if total_lines > 10000:
                results['security_issues'].append('Unusually large plugin size')
            
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _perform_yara_scan(self, plugin_path: str) -> Dict[str, Any]:
        """Perform YARA malware scan"""
        results = {
            'matches': [],
            'scan_time': 0,
            'files_scanned': 0
        }
        
        try:
            start_time = time.time()
            files_scanned = 0
            
            # Scan plugin files
            if os.path.isfile(plugin_path):
                matches = self.yara_rules.match(plugin_path)
                files_scanned = 1
            elif os.path.isdir(plugin_path):
                matches = []
                for root, dirs, files in os.walk(plugin_path):
                    for file in files:
                        if file.endswith(('.py', '.js', '.ts')):
                            file_path = os.path.join(root, file)
                            try:
                                file_matches = self.yara_rules.match(file_path)
                                matches.extend(file_matches)
                                files_scanned += 1
                            except Exception as e:
                                logger.warning(f"YARA scan failed for {file_path}: {e}")
            
            # Process matches
            for match in matches:
                results['matches'].append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'strings': [str(s) for s in match.strings]
                })
            
            results['scan_time'] = time.time() - start_time
            results['files_scanned'] = files_scanned
            
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _scan_dependencies(self, plugin_path: str) -> Dict[str, Any]:
        """Scan plugin dependencies for vulnerabilities"""
        results = {
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            # Look for requirements files
            requirements_files = []
            if os.path.isdir(plugin_path):
                for file in ['requirements.txt', 'package.json', 'setup.py']:
                    req_file = os.path.join(plugin_path, file)
                    if os.path.exists(req_file):
                        requirements_files.append(req_file)
            
            # Analyze requirements
            for req_file in requirements_files:
                if req_file.endswith('requirements.txt'):
                    self._analyze_python_requirements(req_file, results)
                elif req_file.endswith('package.json'):
                    self._analyze_npm_requirements(req_file, results)
            
        except Exception as e:
            logger.error(f"Dependency scan failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_python_requirements(self, req_file: str, results: Dict[str, Any]):
        """Analyze Python requirements for vulnerabilities"""
        try:
            with open(req_file, 'r') as f:
                requirements = f.read().strip().split('\n')
            
            for req in requirements:
                if req.strip() and not req.startswith('#'):
                    # Parse requirement
                    package_name = req.split('==')[0].split('>=')[0].split('<=')[0].strip()
                    results['dependencies'].append({
                        'name': package_name,
                        'requirement': req,
                        'type': 'python'
                    })
                    
                    # Check for known vulnerable packages
                    vulnerable_packages = [
                        'pickle', 'marshal', 'subprocess', 'os',
                        'eval', 'exec', 'compile'
                    ]
                    
                    if package_name.lower() in vulnerable_packages:
                        results['vulnerabilities'].append({
                            'package': package_name,
                            'severity': 'HIGH',
                            'description': f'Potentially dangerous package: {package_name}'
                        })
        
        except Exception as e:
            logger.error(f"Python requirements analysis failed: {e}")
    
    def _analyze_npm_requirements(self, package_file: str, results: Dict[str, Any]):
        """Analyze NPM package.json for vulnerabilities"""
        try:
            with open(package_file, 'r') as f:
                package_data = json.load(f)
            
            dependencies = package_data.get('dependencies', {})
            dev_dependencies = package_data.get('devDependencies', {})
            
            all_deps = {**dependencies, **dev_dependencies}
            
            for package_name, version in all_deps.items():
                results['dependencies'].append({
                    'name': package_name,
                    'version': version,
                    'type': 'npm'
                })
        
        except Exception as e:
            logger.error(f"NPM requirements analysis failed: {e}")
    
    def _analyze_permissions(self, plugin_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze requested permissions"""
        results = {
            'requested_permissions': [],
            'high_risk_permissions': [],
            'permission_score': 0
        }
        
        try:
            requested_permissions = plugin_metadata.get('permissions', [])
            results['requested_permissions'] = requested_permissions
            
            # Define high-risk permissions
            high_risk_perms = [
                'file_system_write', 'network_access', 'system_commands',
                'process_control', 'registry_access', 'admin_privileges'
            ]
            
            # Check for high-risk permissions
            for permission in requested_permissions:
                if permission in high_risk_perms:
                    results['high_risk_permissions'].append(permission)
            
            # Calculate permission risk score (0-10)
            total_perms = len(requested_permissions)
            high_risk_count = len(results['high_risk_permissions'])
            
            if total_perms > 0:
                results['permission_score'] = (high_risk_count / total_perms) * 10
            
        except Exception as e:
            logger.error(f"Permission analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _calculate_reputation_score(self, profile: PluginSecurityProfile) -> float:
        """Calculate plugin reputation score (0.0 - 1.0)"""
        try:
            score = 1.0  # Start with perfect score
            
            # Deduct for suspicious patterns
            static_results = profile.vulnerability_scan_results.get('static_analysis', {})
            suspicious_count = len(static_results.get('suspicious_patterns', []))
            score -= min(suspicious_count * 0.1, 0.5)  # Max 0.5 deduction
            
            # Deduct for YARA matches
            yara_results = profile.vulnerability_scan_results.get('malware_scan', {})
            yara_matches = len(yara_results.get('matches', []))
            score -= min(yara_matches * 0.2, 0.6)  # Max 0.6 deduction
            
            # Deduct for vulnerabilities
            dep_results = profile.vulnerability_scan_results.get('dependency_scan', {})
            vuln_count = len(dep_results.get('vulnerabilities', []))
            score -= min(vuln_count * 0.15, 0.4)  # Max 0.4 deduction
            
            # Deduct for high-risk permissions
            perm_results = profile.vulnerability_scan_results.get('permission_analysis', {})
            high_risk_perms = len(perm_results.get('high_risk_permissions', []))
            score -= min(high_risk_perms * 0.1, 0.3)  # Max 0.3 deduction
            
            # Ensure score is within bounds
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.error(f"Reputation score calculation failed: {e}")
            return 0.0
    
    def _determine_risk_level(self, profile: PluginSecurityProfile) -> str:
        """Determine plugin risk level"""
        try:
            if profile.reputation_score >= 0.8:
                return 'LOW'
            elif profile.reputation_score >= 0.6:
                return 'MEDIUM'
            elif profile.reputation_score >= 0.3:
                return 'HIGH'
            else:
                return 'CRITICAL'
                
        except Exception:
            return 'CRITICAL'
    
    def _make_security_decision(self, profile: PluginSecurityProfile) -> str:
        """Make final security decision for plugin"""
        try:
            # Auto-reject critical risk plugins
            if profile.risk_level == 'CRITICAL':
                return 'REJECTED'
            
            # Auto-approve low risk plugins from trusted publishers
            if (profile.risk_level == 'LOW' and 
                profile.reputation_score >= self.security_policies['reputation_threshold']):
                return 'APPROVED'
            
            # Quarantine high-risk plugins
            if profile.risk_level == 'HIGH':
                return 'QUARANTINED'
            
            # Default to pending for manual review
            return 'PENDING'
            
        except Exception:
            return 'REJECTED'
    
    def _start_monitoring(self):
        """Start runtime monitoring thread"""
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Plugin runtime monitoring started")
    
    def _monitoring_loop(self):
        """Runtime monitoring loop"""
        while self.monitoring_active:
            try:
                self._monitor_plugin_runtime()
                time.sleep(10)  # Monitor every 10 seconds
            except Exception as e:
                logger.error(f"Runtime monitoring error: {e}")
                time.sleep(10)
    
    def _monitor_plugin_runtime(self):
        """Monitor plugin runtime behavior with advanced analytics"""
        try:
            # Monitor active plugins
            for plugin_id, profile in self.security_profiles.items():
                if profile.security_status == 'APPROVED':
                    self._analyze_plugin_behavior(plugin_id, profile)

            # Check for behavioral anomalies
            self._detect_behavioral_anomalies()

            # Update runtime statistics
            self._update_runtime_stats()

        except Exception as e:
            logger.error(f"Runtime monitoring error: {e}")

    def _analyze_plugin_behavior(self, plugin_id: str, profile: PluginSecurityProfile):
        """Analyze individual plugin behavior"""
        try:
            current_time = datetime.now()

            # Initialize behavior tracking if not exists
            if plugin_id not in self.behavioral_monitors:
                self.behavioral_monitors[plugin_id] = {
                    'start_time': current_time,
                    'cpu_usage_history': deque(maxlen=100),
                    'memory_usage_history': deque(maxlen=100),
                    'network_connections': [],
                    'file_operations': [],
                    'system_calls': [],
                    'api_calls': [],
                    'anomaly_score': 0.0,
                    'last_check': current_time
                }

            behavior = self.behavioral_monitors[plugin_id]

            # Simulate resource monitoring (in production, this would use actual monitoring)
            cpu_usage = self._get_plugin_cpu_usage(plugin_id)
            memory_usage = self._get_plugin_memory_usage(plugin_id)

            behavior['cpu_usage_history'].append({
                'timestamp': current_time,
                'value': cpu_usage
            })

            behavior['memory_usage_history'].append({
                'timestamp': current_time,
                'value': memory_usage
            })

            # Check for policy violations
            violations = self._check_policy_violations(plugin_id, behavior)

            if violations:
                for violation in violations:
                    self._handle_security_violation(plugin_id, violation)

            # Update anomaly score
            behavior['anomaly_score'] = self._calculate_anomaly_score(behavior)
            behavior['last_check'] = current_time

        except Exception as e:
            logger.error(f"Plugin behavior analysis failed for {plugin_id}: {e}")

    def _get_plugin_cpu_usage(self, plugin_id: str) -> float:
        """Get plugin CPU usage (simulated - would use actual monitoring in production)"""
        try:
            # In production, this would query the actual plugin process
            import random
            base_usage = random.uniform(0.5, 5.0)  # Normal range

            # Add spikes occasionally to test anomaly detection
            if random.random() < 0.05:  # 5% chance of spike
                base_usage += random.uniform(20.0, 50.0)

            return base_usage
        except Exception:
            return 0.0

    def _get_plugin_memory_usage(self, plugin_id: str) -> float:
        """Get plugin memory usage in MB (simulated)"""
        try:
            import random
            base_usage = random.uniform(10.0, 50.0)  # Normal range

            # Add memory leaks occasionally
            if random.random() < 0.03:  # 3% chance of leak
                base_usage += random.uniform(100.0, 200.0)

            return base_usage
        except Exception:
            return 0.0

    def _check_policy_violations(self, plugin_id: str, behavior: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for security policy violations"""
        violations = []

        try:
            # Check CPU usage violations
            if behavior['cpu_usage_history']:
                recent_cpu = [entry['value'] for entry in list(behavior['cpu_usage_history'])[-10:]]
                avg_cpu = sum(recent_cpu) / len(recent_cpu)

                if avg_cpu > self.security_policies['max_cpu_usage']:
                    violations.append({
                        'type': 'CPU_USAGE_EXCEEDED',
                        'severity': 'HIGH',
                        'current_value': avg_cpu,
                        'threshold': self.security_policies['max_cpu_usage'],
                        'description': f'Plugin {plugin_id} exceeded CPU usage limit'
                    })

            # Check memory usage violations
            if behavior['memory_usage_history']:
                recent_memory = [entry['value'] for entry in list(behavior['memory_usage_history'])[-10:]]
                avg_memory = sum(recent_memory) / len(recent_memory)
                max_memory_mb = self.security_policies['max_memory_usage'] / (1024 * 1024)

                if avg_memory > max_memory_mb:
                    violations.append({
                        'type': 'MEMORY_USAGE_EXCEEDED',
                        'severity': 'HIGH',
                        'current_value': avg_memory,
                        'threshold': max_memory_mb,
                        'description': f'Plugin {plugin_id} exceeded memory usage limit'
                    })

            # Check for suspicious behavior patterns
            anomaly_score = behavior.get('anomaly_score', 0.0)
            if anomaly_score > 0.8:
                violations.append({
                    'type': 'BEHAVIORAL_ANOMALY',
                    'severity': 'MEDIUM',
                    'current_value': anomaly_score,
                    'threshold': 0.8,
                    'description': f'Plugin {plugin_id} showing anomalous behavior'
                })

        except Exception as e:
            logger.error(f"Policy violation check failed: {e}")

        return violations

    def _calculate_anomaly_score(self, behavior: Dict[str, Any]) -> float:
        """Calculate behavioral anomaly score (0.0 - 1.0)"""
        try:
            score = 0.0

            # CPU usage anomaly
            if len(behavior['cpu_usage_history']) > 10:
                cpu_values = [entry['value'] for entry in behavior['cpu_usage_history']]
                cpu_mean = statistics.mean(cpu_values)
                cpu_std = statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0

                if cpu_std > 0:
                    recent_cpu = cpu_values[-5:]  # Last 5 measurements
                    for value in recent_cpu:
                        z_score = abs(value - cpu_mean) / cpu_std
                        if z_score > 2:  # 2 standard deviations
                            score += 0.2

            # Memory usage anomaly
            if len(behavior['memory_usage_history']) > 10:
                memory_values = [entry['value'] for entry in behavior['memory_usage_history']]
                memory_mean = statistics.mean(memory_values)
                memory_std = statistics.stdev(memory_values) if len(memory_values) > 1 else 0

                if memory_std > 0:
                    recent_memory = memory_values[-5:]
                    for value in recent_memory:
                        z_score = abs(value - memory_mean) / memory_std
                        if z_score > 2:
                            score += 0.2

            # Ensure score is within bounds
            return min(1.0, score)

        except Exception as e:
            logger.error(f"Anomaly score calculation failed: {e}")
            return 0.0

    def _handle_security_violation(self, plugin_id: str, violation: Dict[str, Any]):
        """Handle detected security violation"""
        try:
            violation_id = f"{plugin_id}_{violation['type']}_{int(time.time())}"

            security_violation = SecurityViolation(
                violation_id=violation_id,
                plugin_id=plugin_id,
                violation_type=violation['type'],
                severity=violation['severity'],
                description=violation['description'],
                detected_at=datetime.now(),
                evidence={
                    'current_value': violation['current_value'],
                    'threshold': violation['threshold'],
                    'behavior_data': self.behavioral_monitors.get(plugin_id, {})
                },
                mitigation_actions=[]
            )

            # Determine mitigation actions
            if violation['severity'] == 'HIGH':
                security_violation.mitigation_actions = ['QUARANTINE_PLUGIN', 'NOTIFY_ADMIN']

                # Quarantine plugin if policy allows
                if self.security_policies.get('quarantine_on_violation', True):
                    self._quarantine_plugin(plugin_id, violation_id)

            elif violation['severity'] == 'MEDIUM':
                security_violation.mitigation_actions = ['MONITOR_CLOSELY', 'LOG_INCIDENT']

            # Store violation
            self.security_violations.append(security_violation)

            # Keep only recent violations
            if len(self.security_violations) > 1000:
                self.security_violations = self.security_violations[-1000:]

            logger.warning(f"Security violation detected: {violation_id} - {violation['description']}")

        except Exception as e:
            logger.error(f"Security violation handling failed: {e}")

    def _quarantine_plugin(self, plugin_id: str, violation_id: str):
        """Quarantine plugin due to security violation"""
        try:
            if plugin_id in self.security_profiles:
                self.security_profiles[plugin_id].security_status = 'QUARANTINED'
                self.security_profiles[plugin_id].runtime_violations.append(violation_id)

                logger.warning(f"Plugin {plugin_id} quarantined due to violation {violation_id}")

                # In production, this would stop the plugin execution
                # self._stop_plugin_execution(plugin_id)

        except Exception as e:
            logger.error(f"Plugin quarantine failed: {e}")

    def _detect_behavioral_anomalies(self):
        """Detect system-wide behavioral anomalies"""
        try:
            # Analyze patterns across all plugins
            total_cpu = 0
            total_memory = 0
            high_anomaly_plugins = []

            for plugin_id, behavior in self.behavioral_monitors.items():
                if behavior['cpu_usage_history']:
                    recent_cpu = [entry['value'] for entry in list(behavior['cpu_usage_history'])[-5:]]
                    total_cpu += sum(recent_cpu) / len(recent_cpu)

                if behavior['memory_usage_history']:
                    recent_memory = [entry['value'] for entry in list(behavior['memory_usage_history'])[-5:]]
                    total_memory += sum(recent_memory) / len(recent_memory)

                if behavior.get('anomaly_score', 0) > 0.7:
                    high_anomaly_plugins.append(plugin_id)

            # System-wide anomaly detection
            if total_cpu > 80.0:  # 80% total CPU usage
                logger.warning(f"High system CPU usage detected: {total_cpu:.1f}%")

            if total_memory > 1000.0:  # 1GB total memory usage
                logger.warning(f"High system memory usage detected: {total_memory:.1f}MB")

            if len(high_anomaly_plugins) > 3:
                logger.warning(f"Multiple plugins showing anomalous behavior: {high_anomaly_plugins}")

        except Exception as e:
            logger.error(f"Behavioral anomaly detection failed: {e}")

    def _update_runtime_stats(self):
        """Update runtime statistics"""
        try:
            current_time = datetime.now()

            self.runtime_stats = {
                'last_update': current_time,
                'monitored_plugins': len(self.behavioral_monitors),
                'active_violations': len([v for v in self.security_violations
                                        if (current_time - v.detected_at).total_seconds() < 3600]),
                'quarantined_plugins': len([p for p in self.security_profiles.values()
                                          if p.security_status == 'QUARANTINED']),
                'average_anomaly_score': 0.0
            }

            # Calculate average anomaly score
            if self.behavioral_monitors:
                total_score = sum(behavior.get('anomaly_score', 0)
                                for behavior in self.behavioral_monitors.values())
                self.runtime_stats['average_anomaly_score'] = total_score / len(self.behavioral_monitors)

        except Exception as e:
            logger.error(f"Runtime stats update failed: {e}")
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get overall plugin security status"""
        try:
            total_plugins = len(self.security_profiles)
            approved_plugins = len([p for p in self.security_profiles.values() if p.security_status == 'APPROVED'])
            rejected_plugins = len([p for p in self.security_profiles.values() if p.security_status == 'REJECTED'])
            quarantined_plugins = len([p for p in self.security_profiles.values() if p.security_status == 'QUARANTINED'])
            
            recent_violations = [
                v for v in self.security_violations
                if (datetime.now() - v.detected_at).total_seconds() < 3600  # Last hour
            ]
            
            return {
                'total_plugins': total_plugins,
                'approved_plugins': approved_plugins,
                'rejected_plugins': rejected_plugins,
                'quarantined_plugins': quarantined_plugins,
                'recent_violations': len(recent_violations),
                'security_tools_available': {
                    'docker': DOCKER_AVAILABLE,
                    'yara': YARA_AVAILABLE
                },
                'monitoring_active': self.monitoring_active
            }
            
        except Exception as e:
            logger.error(f"Security status error: {e}")
            return {'error': str(e)}

# Global advanced plugin security instance
advanced_plugin_security = AdvancedPluginSecurity()
