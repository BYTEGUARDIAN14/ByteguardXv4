"""
Enhanced Plugin Marketplace Manager
Handles plugin dependency resolution, verification badges, and update notifications
"""

import logging
import json
import hashlib
import semver
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import requests
import zipfile
import tempfile
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class PluginStatus(Enum):
    """Plugin status in marketplace"""
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    DEPRECATED = "deprecated"
    SUSPENDED = "suspended"

class VerificationLevel(Enum):
    """Plugin verification levels"""
    BASIC = "basic"           # Basic security scan
    STANDARD = "standard"     # Security + functionality tests
    PREMIUM = "premium"       # Full audit + performance tests
    BYTEGUARDX_VERIFIED = "byteguardx_verified"  # Official ByteGuardX verification

class DependencyType(Enum):
    """Types of plugin dependencies"""
    REQUIRED = "required"
    OPTIONAL = "optional"
    CONFLICTING = "conflicting"

@dataclass
class PluginDependency:
    """Plugin dependency specification"""
    name: str
    version_constraint: str  # e.g., ">=1.0.0,<2.0.0"
    dependency_type: DependencyType
    description: str = ""

@dataclass
class PluginMetadata:
    """Enhanced plugin metadata"""
    plugin_id: str
    name: str
    version: str
    author: str
    description: str
    category: str
    tags: List[str]
    
    # Dependencies
    dependencies: List[PluginDependency] = field(default_factory=list)
    conflicts_with: List[str] = field(default_factory=list)
    
    # Verification
    verification_level: VerificationLevel = VerificationLevel.BASIC
    verification_date: Optional[datetime] = None
    verification_details: Dict[str, Any] = field(default_factory=dict)
    
    # Marketplace info
    status: PluginStatus = PluginStatus.PENDING
    downloads: int = 0
    rating: float = 0.0
    reviews_count: int = 0
    
    # Technical details
    min_byteguardx_version: str = "1.0.0"
    max_byteguardx_version: Optional[str] = None
    supported_platforms: List[str] = field(default_factory=lambda: ["linux", "windows", "macos"])
    
    # Security
    checksum: str = ""
    signature: str = ""
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_verified: Optional[datetime] = None

@dataclass
class PluginUpdate:
    """Plugin update information"""
    plugin_id: str
    current_version: str
    latest_version: str
    update_type: str  # "major", "minor", "patch"
    changelog: str
    security_fixes: bool
    breaking_changes: bool
    release_date: datetime

@dataclass
class DependencyConflict:
    """Dependency conflict information"""
    plugin_a: str
    plugin_b: str
    conflict_type: str
    description: str
    resolution_suggestions: List[str]

class EnhancedPluginMarketplace:
    """
    Enhanced plugin marketplace with dependency resolution and verification
    """
    
    def __init__(self, marketplace_url: str = "https://marketplace.byteguardx.com"):
        self.marketplace_url = marketplace_url
        self.installed_plugins: Dict[str, PluginMetadata] = {}
        self.available_plugins: Dict[str, PluginMetadata] = {}
        self.verification_cache: Dict[str, Dict[str, Any]] = {}
        
        # Load installed plugins
        self._load_installed_plugins()
        
        # Refresh available plugins
        self._refresh_marketplace()
    
    def _load_installed_plugins(self):
        """Load metadata for installed plugins"""
        # In production, this would scan the plugins directory
        # For now, we'll use mock data
        pass
    
    def _refresh_marketplace(self):
        """Refresh available plugins from marketplace"""
        try:
            response = requests.get(f"{self.marketplace_url}/api/plugins", timeout=10)
            if response.status_code == 200:
                plugins_data = response.json()
                for plugin_data in plugins_data:
                    metadata = self._parse_plugin_metadata(plugin_data)
                    self.available_plugins[metadata.plugin_id] = metadata
                logger.info(f"Refreshed {len(plugins_data)} plugins from marketplace")
        except Exception as e:
            logger.error(f"Failed to refresh marketplace: {e}")
    
    def _parse_plugin_metadata(self, plugin_data: Dict[str, Any]) -> PluginMetadata:
        """Parse plugin metadata from marketplace data"""
        dependencies = []
        for dep_data in plugin_data.get('dependencies', []):
            dependencies.append(PluginDependency(
                name=dep_data['name'],
                version_constraint=dep_data['version_constraint'],
                dependency_type=DependencyType(dep_data.get('type', 'required')),
                description=dep_data.get('description', '')
            ))
        
        return PluginMetadata(
            plugin_id=plugin_data['id'],
            name=plugin_data['name'],
            version=plugin_data['version'],
            author=plugin_data['author'],
            description=plugin_data['description'],
            category=plugin_data.get('category', 'general'),
            tags=plugin_data.get('tags', []),
            dependencies=dependencies,
            conflicts_with=plugin_data.get('conflicts_with', []),
            verification_level=VerificationLevel(plugin_data.get('verification_level', 'basic')),
            verification_date=datetime.fromisoformat(plugin_data['verification_date']) if plugin_data.get('verification_date') else None,
            status=PluginStatus(plugin_data.get('status', 'pending')),
            downloads=plugin_data.get('downloads', 0),
            rating=plugin_data.get('rating', 0.0),
            reviews_count=plugin_data.get('reviews_count', 0),
            min_byteguardx_version=plugin_data.get('min_byteguardx_version', '1.0.0'),
            checksum=plugin_data.get('checksum', ''),
            created_at=datetime.fromisoformat(plugin_data['created_at']) if plugin_data.get('created_at') else datetime.now()
        )
    
    def resolve_dependencies(self, plugin_id: str, 
                           target_version: str = None) -> Tuple[List[str], List[DependencyConflict]]:
        """Resolve plugin dependencies and detect conflicts"""
        if plugin_id not in self.available_plugins:
            raise ValueError(f"Plugin {plugin_id} not found in marketplace")
        
        plugin = self.available_plugins[plugin_id]
        if target_version:
            # In a real implementation, we'd fetch the specific version
            pass
        
        install_order = []
        conflicts = []
        visited = set()
        
        def resolve_recursive(current_plugin_id: str, path: List[str]):
            if current_plugin_id in visited:
                return
            
            if current_plugin_id in path:
                # Circular dependency detected
                logger.warning(f"Circular dependency detected: {' -> '.join(path + [current_plugin_id])}")
                return
            
            if current_plugin_id not in self.available_plugins:
                logger.warning(f"Dependency {current_plugin_id} not found in marketplace")
                return
            
            current_plugin = self.available_plugins[current_plugin_id]
            new_path = path + [current_plugin_id]
            
            # Check for conflicts with already resolved plugins
            for resolved_plugin_id in install_order:
                conflict = self._check_plugin_conflict(current_plugin_id, resolved_plugin_id)
                if conflict:
                    conflicts.append(conflict)
            
            # Resolve dependencies first
            for dependency in current_plugin.dependencies:
                if dependency.dependency_type == DependencyType.REQUIRED:
                    resolve_recursive(dependency.name, new_path)
            
            # Add current plugin to install order
            if current_plugin_id not in install_order:
                install_order.append(current_plugin_id)
            
            visited.add(current_plugin_id)
        
        resolve_recursive(plugin_id, [])
        
        return install_order, conflicts
    
    def _check_plugin_conflict(self, plugin_a_id: str, plugin_b_id: str) -> Optional[DependencyConflict]:
        """Check if two plugins conflict with each other"""
        plugin_a = self.available_plugins.get(plugin_a_id)
        plugin_b = self.available_plugins.get(plugin_b_id)
        
        if not plugin_a or not plugin_b:
            return None
        
        # Check explicit conflicts
        if plugin_b_id in plugin_a.conflicts_with or plugin_a_id in plugin_b.conflicts_with:
            return DependencyConflict(
                plugin_a=plugin_a_id,
                plugin_b=plugin_b_id,
                conflict_type="explicit",
                description=f"{plugin_a.name} and {plugin_b.name} are explicitly incompatible",
                resolution_suggestions=[
                    "Choose one plugin over the other",
                    "Look for alternative plugins with similar functionality"
                ]
            )
        
        # Check for dependency version conflicts
        for dep_a in plugin_a.dependencies:
            for dep_b in plugin_b.dependencies:
                if dep_a.name == dep_b.name:
                    if not self._version_constraints_compatible(dep_a.version_constraint, dep_b.version_constraint):
                        return DependencyConflict(
                            plugin_a=plugin_a_id,
                            plugin_b=plugin_b_id,
                            conflict_type="dependency_version",
                            description=f"Incompatible version requirements for {dep_a.name}",
                            resolution_suggestions=[
                                "Update one of the plugins to a compatible version",
                                "Use plugin version pinning to resolve conflicts"
                            ]
                        )
        
        return None
    
    def _version_constraints_compatible(self, constraint_a: str, constraint_b: str) -> bool:
        """Check if two version constraints are compatible"""
        # Simplified version compatibility check
        # In production, this would use a proper semver library
        try:
            # Parse constraints (simplified)
            if constraint_a == constraint_b:
                return True
            
            # For now, assume they're compatible if they don't explicitly conflict
            return True
        except Exception:
            return False
    
    def verify_plugin(self, plugin_id: str, verification_level: VerificationLevel) -> Dict[str, Any]:
        """Verify plugin security and functionality"""
        if plugin_id not in self.available_plugins:
            raise ValueError(f"Plugin {plugin_id} not found")
        
        plugin = self.available_plugins[plugin_id]
        verification_results = {
            'plugin_id': plugin_id,
            'verification_level': verification_level.value,
            'timestamp': datetime.now().isoformat(),
            'passed': False,
            'issues': [],
            'recommendations': []
        }
        
        # Basic security scan
        if verification_level in [VerificationLevel.BASIC, VerificationLevel.STANDARD, 
                                VerificationLevel.PREMIUM, VerificationLevel.BYTEGUARDX_VERIFIED]:
            security_issues = self._perform_security_scan(plugin)
            verification_results['security_scan'] = security_issues
            if security_issues['critical_issues'] > 0:
                verification_results['issues'].append("Critical security vulnerabilities found")
        
        # Functionality tests
        if verification_level in [VerificationLevel.STANDARD, VerificationLevel.PREMIUM, 
                                VerificationLevel.BYTEGUARDX_VERIFIED]:
            functionality_results = self._perform_functionality_tests(plugin)
            verification_results['functionality_tests'] = functionality_results
            if not functionality_results['all_tests_passed']:
                verification_results['issues'].append("Some functionality tests failed")
        
        # Performance tests
        if verification_level in [VerificationLevel.PREMIUM, VerificationLevel.BYTEGUARDX_VERIFIED]:
            performance_results = self._perform_performance_tests(plugin)
            verification_results['performance_tests'] = performance_results
            if performance_results['memory_usage'] > 100:  # MB
                verification_results['recommendations'].append("Consider optimizing memory usage")
        
        # Full audit (ByteGuardX verified only)
        if verification_level == VerificationLevel.BYTEGUARDX_VERIFIED:
            audit_results = self._perform_full_audit(plugin)
            verification_results['full_audit'] = audit_results
            if not audit_results['code_quality_passed']:
                verification_results['issues'].append("Code quality standards not met")
        
        # Determine overall pass/fail
        verification_results['passed'] = len(verification_results['issues']) == 0
        
        # Cache results
        self.verification_cache[plugin_id] = verification_results
        
        # Update plugin metadata
        plugin.verification_level = verification_level
        plugin.verification_date = datetime.now()
        plugin.verification_details = verification_results
        plugin.last_verified = datetime.now()
        
        if verification_results['passed']:
            plugin.status = PluginStatus.VERIFIED
        
        logger.info(f"Plugin {plugin_id} verification completed: {'PASSED' if verification_results['passed'] else 'FAILED'}")
        
        return verification_results
    
    def _perform_security_scan(self, plugin: PluginMetadata) -> Dict[str, Any]:
        """Perform security scan on plugin"""
        # Mock security scan results
        return {
            'critical_issues': 0,
            'high_issues': 1,
            'medium_issues': 2,
            'low_issues': 3,
            'scan_duration': 45.2,
            'issues_details': [
                {'severity': 'high', 'type': 'hardcoded_secret', 'description': 'Potential API key found'},
                {'severity': 'medium', 'type': 'unsafe_function', 'description': 'Use of eval() function'},
                {'severity': 'medium', 'type': 'weak_crypto', 'description': 'Weak cryptographic algorithm'}
            ]
        }
    
    def _perform_functionality_tests(self, plugin: PluginMetadata) -> Dict[str, Any]:
        """Perform functionality tests on plugin"""
        # Mock functionality test results
        return {
            'all_tests_passed': True,
            'tests_run': 15,
            'tests_passed': 14,
            'tests_failed': 1,
            'test_duration': 120.5,
            'failed_tests': [
                {'name': 'test_edge_case_handling', 'error': 'IndexError: list index out of range'}
            ]
        }
    
    def _perform_performance_tests(self, plugin: PluginMetadata) -> Dict[str, Any]:
        """Perform performance tests on plugin"""
        # Mock performance test results
        return {
            'memory_usage': 85.2,  # MB
            'cpu_usage': 12.5,     # %
            'execution_time': 2.3,  # seconds
            'throughput': 450,      # operations/second
            'performance_grade': 'B+'
        }
    
    def _perform_full_audit(self, plugin: PluginMetadata) -> Dict[str, Any]:
        """Perform full code audit"""
        # Mock full audit results
        return {
            'code_quality_passed': True,
            'documentation_score': 85,
            'test_coverage': 78,
            'maintainability_index': 82,
            'complexity_score': 'Medium',
            'license_compliance': True,
            'audit_duration': 3600  # seconds
        }
    
    def check_for_updates(self) -> List[PluginUpdate]:
        """Check for plugin updates"""
        updates = []
        
        for plugin_id, installed_plugin in self.installed_plugins.items():
            if plugin_id in self.available_plugins:
                available_plugin = self.available_plugins[plugin_id]
                
                if semver.compare(available_plugin.version, installed_plugin.version) > 0:
                    update_type = self._determine_update_type(
                        installed_plugin.version, 
                        available_plugin.version
                    )
                    
                    updates.append(PluginUpdate(
                        plugin_id=plugin_id,
                        current_version=installed_plugin.version,
                        latest_version=available_plugin.version,
                        update_type=update_type,
                        changelog=f"Update from {installed_plugin.version} to {available_plugin.version}",
                        security_fixes=self._has_security_fixes(plugin_id, available_plugin.version),
                        breaking_changes=update_type == "major",
                        release_date=available_plugin.updated_at
                    ))
        
        return updates
    
    def _determine_update_type(self, current_version: str, new_version: str) -> str:
        """Determine if update is major, minor, or patch"""
        try:
            current = semver.VersionInfo.parse(current_version)
            new = semver.VersionInfo.parse(new_version)
            
            if new.major > current.major:
                return "major"
            elif new.minor > current.minor:
                return "minor"
            else:
                return "patch"
        except Exception:
            return "unknown"
    
    def _has_security_fixes(self, plugin_id: str, version: str) -> bool:
        """Check if version contains security fixes"""
        # In production, this would check changelog or security advisories
        return False

# Global instance
plugin_marketplace = EnhancedPluginMarketplace()
