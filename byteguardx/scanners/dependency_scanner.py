"""
Dependency Scanner - Detect vulnerable dependencies and CVE matching
"""

import json
import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
import pkg_resources
from packaging import version

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityMatch:
    """Data structure for vulnerability detection results"""
    package_name: str
    current_version: str
    vulnerable_versions: List[str]
    cve_id: str
    severity: str
    description: str
    fixed_version: str
    file_path: str
    line_number: int

class DependencyScanner:
    """
    Scanner for vulnerable dependencies in various package managers
    """
    
    def __init__(self, vuln_db_file: str = None):
        self.vulnerability_db = self._load_vulnerability_db(vuln_db_file)
        self.findings = []
        self.supported_files = {
            'requirements.txt': self._parse_requirements_txt,
            'package.json': self._parse_package_json,
            'Pipfile': self._parse_pipfile,
            'poetry.lock': self._parse_poetry_lock,
            'Cargo.toml': self._parse_cargo_toml,
            'go.mod': self._parse_go_mod,
            'pom.xml': self._parse_pom_xml,
            'build.gradle': self._parse_gradle,
            'composer.json': self._parse_composer_json
        }
    
    def _load_vulnerability_db(self, vuln_db_file: str = None) -> Dict:
        """Load vulnerability database from JSON file"""
        if vuln_db_file and Path(vuln_db_file).exists():
            try:
                with open(vuln_db_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load vulnerability database: {e}")
        
        # Default vulnerability database (sample data)
        return {
            "python": {
                "django": [
                    {
                        "cve_id": "CVE-2023-31047",
                        "vulnerable_versions": ["<4.2.2", "<4.1.9", "<3.2.19"],
                        "severity": "high",
                        "description": "Django SQL injection vulnerability",
                        "fixed_version": "4.2.2"
                    }
                ],
                "requests": [
                    {
                        "cve_id": "CVE-2023-32681",
                        "vulnerable_versions": ["<2.31.0"],
                        "severity": "medium",
                        "description": "Requests proxy-authorization header leak",
                        "fixed_version": "2.31.0"
                    }
                ],
                "pillow": [
                    {
                        "cve_id": "CVE-2023-44271",
                        "vulnerable_versions": ["<10.0.1"],
                        "severity": "high",
                        "description": "Pillow arbitrary code execution",
                        "fixed_version": "10.0.1"
                    }
                ]
            },
            "javascript": {
                "lodash": [
                    {
                        "cve_id": "CVE-2021-23337",
                        "vulnerable_versions": ["<4.17.21"],
                        "severity": "high",
                        "description": "Lodash command injection vulnerability",
                        "fixed_version": "4.17.21"
                    }
                ],
                "axios": [
                    {
                        "cve_id": "CVE-2023-45857",
                        "vulnerable_versions": ["<1.6.0"],
                        "severity": "medium",
                        "description": "Axios CSRF vulnerability",
                        "fixed_version": "1.6.0"
                    }
                ]
            }
        }
    
    def _parse_requirements_txt(self, content: str, file_path: str) -> List[Dict]:
        """Parse Python requirements.txt file"""
        dependencies = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Parse package==version or package>=version
            match = re.match(r'^([a-zA-Z0-9_-]+)([><=!]+)([0-9.]+)', line)
            if match:
                package_name = match.group(1).lower()
                operator = match.group(2)
                package_version = match.group(3)
                
                dependencies.append({
                    'name': package_name,
                    'version': package_version,
                    'operator': operator,
                    'line_number': line_num,
                    'ecosystem': 'python'
                })
        
        return dependencies
    
    def _parse_package_json(self, content: str, file_path: str) -> List[Dict]:
        """Parse Node.js package.json file"""
        dependencies = []
        
        try:
            data = json.loads(content)
            
            # Parse dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for package_name, version_spec in data[dep_type].items():
                        # Clean version specification
                        version_clean = re.sub(r'[^0-9.]', '', version_spec)
                        if version_clean:
                            dependencies.append({
                                'name': package_name.lower(),
                                'version': version_clean,
                                'operator': '==',
                                'line_number': 0,  # JSON doesn't have line numbers easily
                                'ecosystem': 'javascript',
                                'dep_type': dep_type
                            })
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse package.json: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, content: str, file_path: str) -> List[Dict]:
        """Parse Python Pipfile"""
        # Simplified TOML parsing for Pipfile
        dependencies = []
        lines = content.splitlines()
        in_packages = False
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if line == '[packages]':
                in_packages = True
                continue
            elif line.startswith('[') and line != '[packages]':
                in_packages = False
                continue
            
            if in_packages and '=' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    package_name = parts[0].strip().strip('"\'')
                    version_spec = parts[1].strip().strip('"\'')
                    
                    # Extract version number
                    version_match = re.search(r'([0-9.]+)', version_spec)
                    if version_match:
                        dependencies.append({
                            'name': package_name.lower(),
                            'version': version_match.group(1),
                            'operator': '==',
                            'line_number': line_num,
                            'ecosystem': 'python'
                        })
        
        return dependencies
    
    def _parse_poetry_lock(self, content: str, file_path: str) -> List[Dict]:
        """Parse Python poetry.lock file"""
        # Simplified parsing for poetry.lock
        dependencies = []
        lines = content.splitlines()
        current_package = None
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if line.startswith('name = '):
                current_package = line.split('=')[1].strip().strip('"\'').lower()
            elif line.startswith('version = ') and current_package:
                version = line.split('=')[1].strip().strip('"\'')
                dependencies.append({
                    'name': current_package,
                    'version': version,
                    'operator': '==',
                    'line_number': line_num,
                    'ecosystem': 'python'
                })
                current_package = None
        
        return dependencies
    
    def _parse_cargo_toml(self, content: str, file_path: str) -> List[Dict]:
        """Parse Rust Cargo.toml file"""
        # Simplified TOML parsing for Cargo.toml
        dependencies = []
        lines = content.splitlines()
        in_dependencies = False
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if line == '[dependencies]':
                in_dependencies = True
                continue
            elif line.startswith('[') and line != '[dependencies]':
                in_dependencies = False
                continue
            
            if in_dependencies and '=' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    package_name = parts[0].strip()
                    version_spec = parts[1].strip().strip('"\'')
                    
                    version_match = re.search(r'([0-9.]+)', version_spec)
                    if version_match:
                        dependencies.append({
                            'name': package_name.lower(),
                            'version': version_match.group(1),
                            'operator': '==',
                            'line_number': line_num,
                            'ecosystem': 'rust'
                        })
        
        return dependencies
    
    def _parse_go_mod(self, content: str, file_path: str) -> List[Dict]:
        """Parse Go go.mod file"""
        dependencies = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Parse require statements
            if line.startswith('require '):
                parts = line.replace('require ', '').split()
                if len(parts) >= 2:
                    package_name = parts[0]
                    version = parts[1].lstrip('v')
                    
                    dependencies.append({
                        'name': package_name.lower(),
                        'version': version,
                        'operator': '==',
                        'line_number': line_num,
                        'ecosystem': 'go'
                    })
        
        return dependencies
    
    def _parse_pom_xml(self, content: str, file_path: str) -> List[Dict]:
        """Parse Java Maven pom.xml file"""
        # Simplified XML parsing for Maven dependencies
        dependencies = []
        
        # Use regex to find dependency blocks
        dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
        matches = re.findall(dependency_pattern, content, re.DOTALL)
        
        for match in matches:
            group_id, artifact_id, version = match
            package_name = f"{group_id}:{artifact_id}".lower()
            
            dependencies.append({
                'name': package_name,
                'version': version.strip(),
                'operator': '==',
                'line_number': 0,
                'ecosystem': 'java'
            })
        
        return dependencies
    
    def _parse_gradle(self, content: str, file_path: str) -> List[Dict]:
        """Parse Java Gradle build.gradle file"""
        dependencies = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Parse implementation/compile statements
            if ('implementation' in line or 'compile' in line) and ':' in line:
                # Extract dependency string
                dep_match = re.search(r'["\']([^"\']+:[^"\']+:[^"\']+)["\']', line)
                if dep_match:
                    dep_parts = dep_match.group(1).split(':')
                    if len(dep_parts) >= 3:
                        group_id, artifact_id, version = dep_parts[:3]
                        package_name = f"{group_id}:{artifact_id}".lower()
                        
                        dependencies.append({
                            'name': package_name,
                            'version': version,
                            'operator': '==',
                            'line_number': line_num,
                            'ecosystem': 'java'
                        })
        
        return dependencies
    
    def _parse_composer_json(self, content: str, file_path: str) -> List[Dict]:
        """Parse PHP composer.json file"""
        dependencies = []
        
        try:
            data = json.loads(content)
            
            for dep_type in ['require', 'require-dev']:
                if dep_type in data:
                    for package_name, version_spec in data[dep_type].items():
                        # Skip PHP version requirement
                        if package_name == 'php':
                            continue
                        
                        version_clean = re.sub(r'[^0-9.]', '', version_spec)
                        if version_clean:
                            dependencies.append({
                                'name': package_name.lower(),
                                'version': version_clean,
                                'operator': '==',
                                'line_number': 0,
                                'ecosystem': 'php'
                            })
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse composer.json: {e}")

        return dependencies

    def _is_version_vulnerable(self, current_version: str, vulnerable_versions: List[str]) -> bool:
        """Check if current version matches vulnerable version patterns"""
        try:
            current_ver = version.parse(current_version)

            for vuln_pattern in vulnerable_versions:
                # Handle version range patterns like "<4.2.2", ">=1.0,<2.0"
                if vuln_pattern.startswith('<'):
                    max_ver = version.parse(vuln_pattern[1:])
                    if current_ver < max_ver:
                        return True
                elif vuln_pattern.startswith('<='):
                    max_ver = version.parse(vuln_pattern[2:])
                    if current_ver <= max_ver:
                        return True
                elif vuln_pattern.startswith('>='):
                    min_ver = version.parse(vuln_pattern[2:])
                    if current_ver >= min_ver:
                        return True
                elif vuln_pattern.startswith('>'):
                    min_ver = version.parse(vuln_pattern[1:])
                    if current_ver > min_ver:
                        return True
                elif vuln_pattern == current_version:
                    return True

        except Exception as e:
            logger.error(f"Version comparison error: {e}")
            return False

        return False

    def check_vulnerabilities(self, dependencies: List[Dict], file_path: str) -> List[Dict]:
        """Check dependencies against vulnerability database"""
        vulnerabilities = []

        for dep in dependencies:
            ecosystem = dep.get('ecosystem', 'unknown')
            package_name = dep['name']
            current_version = dep['version']

            # Check if package exists in vulnerability database
            if ecosystem in self.vulnerability_db:
                if package_name in self.vulnerability_db[ecosystem]:
                    vulns = self.vulnerability_db[ecosystem][package_name]

                    for vuln in vulns:
                        if self._is_version_vulnerable(current_version, vuln['vulnerable_versions']):
                            vulnerability = {
                                'type': 'vulnerability',
                                'subtype': 'dependency',
                                'package_name': package_name,
                                'current_version': current_version,
                                'cve_id': vuln['cve_id'],
                                'severity': vuln['severity'],
                                'description': vuln['description'],
                                'fixed_version': vuln['fixed_version'],
                                'file_path': file_path,
                                'line_number': dep['line_number'],
                                'ecosystem': ecosystem,
                                'recommendation': f"Update {package_name} to version {vuln['fixed_version']} or later"
                            }
                            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def scan_file(self, file_info: Dict) -> List[Dict]:
        """Scan a dependency file for vulnerabilities"""
        if "error" in file_info:
            return []

        file_path = file_info["file_path"]
        file_name = Path(file_path).name

        # Check if this is a supported dependency file
        if file_name not in self.supported_files:
            return []

        try:
            # Parse dependencies using appropriate parser
            parser = self.supported_files[file_name]
            dependencies = parser(file_info["content"], file_path)

            # Check for vulnerabilities
            vulnerabilities = self.check_vulnerabilities(dependencies, file_path)

            self.findings.extend(vulnerabilities)
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error scanning dependency file {file_path}: {e}")
            return []

    def get_summary(self) -> Dict:
        """Get scan summary"""
        if not self.findings:
            return {"total": 0, "by_severity": {}, "by_ecosystem": {}}

        by_severity = {}
        by_ecosystem = {}

        for finding in self.findings:
            severity = finding["severity"]
            ecosystem = finding["ecosystem"]

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_ecosystem[ecosystem] = by_ecosystem.get(ecosystem, 0) + 1

        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_ecosystem": by_ecosystem
        }

    def reset(self):
        """Reset scanner state"""
        self.findings.clear()
