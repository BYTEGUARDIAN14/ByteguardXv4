"""
Container Supply Chain Security for ByteGuardX
Implements Trivy scanning, package freezing, and secure container practices
"""

import os
import json
import logging
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class ContainerVulnerability:
    """Container vulnerability information"""
    cve_id: str
    severity: VulnerabilitySeverity
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    description: str
    references: List[str]

@dataclass
class ContainerScanResult:
    """Container security scan result"""
    image_name: str
    scan_timestamp: datetime
    vulnerabilities: List[ContainerVulnerability]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration: float
    passed_security_check: bool

class ContainerSecurityScanner:
    """Container security scanner using Trivy and security best practices"""
    
    def __init__(self):
        self.trivy_path = self._find_trivy_binary()
        self.max_critical_vulnerabilities = 0
        self.max_high_vulnerabilities = 5
        self.scan_timeout = 300  # 5 minutes
        
    def _find_trivy_binary(self) -> Optional[str]:
        """Find Trivy binary in system PATH"""
        try:
            result = subprocess.run(['which', 'trivy'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        # Try common installation paths
        common_paths = [
            '/usr/local/bin/trivy',
            '/usr/bin/trivy',
            '/opt/trivy/bin/trivy'
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        logger.warning("Trivy binary not found - container scanning disabled")
        return None
    
    def install_trivy(self) -> bool:
        """Install Trivy scanner"""
        try:
            # Download and install Trivy
            install_script = """
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
            """
            
            result = subprocess.run(install_script, shell=True, 
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.trivy_path = '/usr/local/bin/trivy'
                logger.info("Trivy installed successfully")
                return True
            else:
                logger.error(f"Trivy installation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to install Trivy: {e}")
            return False
    
    def scan_image(self, image_name: str) -> ContainerScanResult:
        """
        Scan container image for vulnerabilities
        
        Args:
            image_name: Docker image name to scan
            
        Returns:
            ContainerScanResult with vulnerability information
        """
        start_time = datetime.now()
        
        if not self.trivy_path:
            logger.error("Trivy not available - attempting installation")
            if not self.install_trivy():
                return ContainerScanResult(
                    image_name=image_name,
                    scan_timestamp=start_time,
                    vulnerabilities=[],
                    total_vulnerabilities=0,
                    critical_count=0,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    scan_duration=0.0,
                    passed_security_check=False
                )
        
        try:
            # Run Trivy scan
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
                output_file = f.name
            
            cmd = [
                self.trivy_path,
                'image',
                '--format', 'json',
                '--output', output_file,
                '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--no-progress',
                image_name
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self.scan_timeout)
            
            if result.returncode != 0:
                logger.error(f"Trivy scan failed: {result.stderr}")
                return self._create_failed_result(image_name, start_time)
            
            # Parse results
            with open(output_file, 'r') as f:
                scan_data = json.load(f)
            
            # Clean up temp file
            os.unlink(output_file)
            
            # Process vulnerabilities
            vulnerabilities = self._process_trivy_results(scan_data)
            
            # Count by severity
            severity_counts = self._count_vulnerabilities_by_severity(vulnerabilities)
            
            # Determine if scan passed security check
            passed_check = (
                severity_counts['critical'] <= self.max_critical_vulnerabilities and
                severity_counts['high'] <= self.max_high_vulnerabilities
            )
            
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            result = ContainerScanResult(
                image_name=image_name,
                scan_timestamp=start_time,
                vulnerabilities=vulnerabilities,
                total_vulnerabilities=len(vulnerabilities),
                critical_count=severity_counts['critical'],
                high_count=severity_counts['high'],
                medium_count=severity_counts['medium'],
                low_count=severity_counts['low'],
                scan_duration=scan_duration,
                passed_security_check=passed_check
            )
            
            logger.info(f"Container scan completed for {image_name}: "
                       f"{len(vulnerabilities)} vulnerabilities found")
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy scan timeout for image {image_name}")
            return self._create_failed_result(image_name, start_time)
            
        except Exception as e:
            logger.error(f"Container scan failed: {e}")
            return self._create_failed_result(image_name, start_time)
    
    def scan_dockerfile(self, dockerfile_path: str) -> Dict[str, Any]:
        """
        Scan Dockerfile for security best practices
        
        Args:
            dockerfile_path: Path to Dockerfile
            
        Returns:
            Dict containing security analysis results
        """
        try:
            with open(dockerfile_path, 'r') as f:
                dockerfile_content = f.read()
            
            issues = []
            recommendations = []
            
            lines = dockerfile_content.split('\n')
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Check for security issues
                if line.upper().startswith('USER ROOT'):
                    issues.append({
                        'line': i,
                        'severity': 'HIGH',
                        'issue': 'Running as root user',
                        'recommendation': 'Create and use a non-root user'
                    })
                
                if 'curl' in line.lower() and '|' in line and 'sh' in line.lower():
                    issues.append({
                        'line': i,
                        'severity': 'CRITICAL',
                        'issue': 'Piping curl to shell',
                        'recommendation': 'Download and verify files before execution'
                    })
                
                if 'apt-get install' in line.lower() and '-y' in line.lower():
                    if '--no-install-recommends' not in line.lower():
                        issues.append({
                            'line': i,
                            'severity': 'MEDIUM',
                            'issue': 'Installing recommended packages',
                            'recommendation': 'Use --no-install-recommends flag'
                        })
                
                if 'ADD' in line.upper() and ('http://' in line or 'https://' in line):
                    issues.append({
                        'line': i,
                        'severity': 'MEDIUM',
                        'issue': 'Using ADD with URL',
                        'recommendation': 'Use COPY instead of ADD for URLs'
                    })
                
                if 'COPY --from=' not in line.upper() and 'COPY' in line.upper():
                    if '*' in line or '.' in line:
                        issues.append({
                            'line': i,
                            'severity': 'LOW',
                            'issue': 'Copying unnecessary files',
                            'recommendation': 'Be specific about files to copy'
                        })
            
            # Check for missing security practices
            has_user_directive = any('USER' in line.upper() for line in lines)
            if not has_user_directive:
                recommendations.append({
                    'severity': 'HIGH',
                    'recommendation': 'Add USER directive to run as non-root'
                })
            
            has_healthcheck = any('HEALTHCHECK' in line.upper() for line in lines)
            if not has_healthcheck:
                recommendations.append({
                    'severity': 'MEDIUM',
                    'recommendation': 'Add HEALTHCHECK directive for container monitoring'
                })
            
            return {
                'dockerfile_path': dockerfile_path,
                'issues': issues,
                'recommendations': recommendations,
                'total_issues': len(issues),
                'critical_issues': len([i for i in issues if i['severity'] == 'CRITICAL']),
                'high_issues': len([i for i in issues if i['severity'] == 'HIGH']),
                'passed_check': len([i for i in issues if i['severity'] in ['CRITICAL', 'HIGH']]) == 0
            }
            
        except Exception as e:
            logger.error(f"Dockerfile scan failed: {e}")
            return {
                'dockerfile_path': dockerfile_path,
                'error': str(e),
                'passed_check': False
            }
    
    def create_secure_dockerfile(self, base_image: str, packages: List[str] = None) -> str:
        """
        Create a secure Dockerfile template
        
        Args:
            base_image: Base Docker image
            packages: List of packages to install
            
        Returns:
            Secure Dockerfile content
        """
        packages = packages or []
        
        dockerfile_template = f"""# Secure Dockerfile for ByteGuardX
FROM {base_image}

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install packages securely
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    {' '.join(packages)} && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* && \\
    apt-mark hold {' '.join(packages)}

# Create app directory
RUN mkdir -p /app && chown appuser:appuser /app

# Set working directory
WORKDIR /app

# Copy application files
COPY --chown=appuser:appuser . /app/

# Switch to non-root user
USER appuser

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Run application
CMD ["python", "app.py"]
"""
        
        return dockerfile_template
    
    def _process_trivy_results(self, scan_data: Dict[str, Any]) -> List[ContainerVulnerability]:
        """Process Trivy scan results into vulnerability objects"""
        vulnerabilities = []
        
        results = scan_data.get('Results', [])
        for result in results:
            vulns = result.get('Vulnerabilities', [])
            for vuln in vulns:
                vulnerability = ContainerVulnerability(
                    cve_id=vuln.get('VulnerabilityID', 'N/A'),
                    severity=VulnerabilitySeverity(vuln.get('Severity', 'UNKNOWN')),
                    package_name=vuln.get('PkgName', 'N/A'),
                    installed_version=vuln.get('InstalledVersion', 'N/A'),
                    fixed_version=vuln.get('FixedVersion'),
                    description=vuln.get('Description', 'N/A'),
                    references=vuln.get('References', [])
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[ContainerVulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        
        for vuln in vulnerabilities:
            severity_key = vuln.severity.value.lower()
            if severity_key in counts:
                counts[severity_key] += 1
        
        return counts
    
    def _create_failed_result(self, image_name: str, start_time: datetime) -> ContainerScanResult:
        """Create a failed scan result"""
        return ContainerScanResult(
            image_name=image_name,
            scan_timestamp=start_time,
            vulnerabilities=[],
            total_vulnerabilities=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            scan_duration=(datetime.now() - start_time).total_seconds(),
            passed_security_check=False
        )

# Global instance
container_security_scanner = ContainerSecurityScanner()
