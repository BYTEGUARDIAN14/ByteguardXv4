"""
Dynamic Application Security Testing (DAST) Integration for ByteGuardX
Provides integration stubs for OWASP ZAP, Burp Suite, and internal spider/fuzzer
"""

import os
import json
import logging
import subprocess
import requests
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
import threading
import uuid

logger = logging.getLogger(__name__)

class DASTTool(Enum):
    """Supported DAST tools"""
    OWASP_ZAP = "owasp_zap"
    BURP_SUITE = "burp_suite"
    INTERNAL_SPIDER = "internal_spider"
    CUSTOM = "custom"

class ScanStatus(Enum):
    """DAST scan status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class DASTFinding:
    """DAST vulnerability finding"""
    finding_id: str
    vulnerability_type: str
    severity: str
    confidence: str
    url: str
    method: str
    parameter: Optional[str]
    description: str
    evidence: str
    solution: str
    reference: Optional[str] = None
    cwe_id: Optional[int] = None
    owasp_category: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class DASTScanResult:
    """DAST scan result"""
    scan_id: str
    tool: DASTTool
    target_url: str
    status: ScanStatus
    started_at: str
    completed_at: Optional[str]
    findings: List[DASTFinding]
    scan_config: Dict[str, Any]
    statistics: Dict[str, Any]
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['tool'] = self.tool.value
        result['status'] = self.status.value
        result['findings'] = [f.to_dict() for f in self.findings]
        return result

class OWASPZAPIntegration:
    """OWASP ZAP integration"""
    
    def __init__(self, zap_proxy_url: str = "http://localhost:8080"):
        self.zap_proxy_url = zap_proxy_url
        self.api_key = os.environ.get('ZAP_API_KEY', '')
    
    def start_scan(self, target_url: str, scan_config: Dict[str, Any]) -> str:
        """Start OWASP ZAP scan"""
        try:
            # This is a stub implementation
            # In production, you would use the ZAP API
            scan_id = str(uuid.uuid4())
            
            # Simulate ZAP API call
            logger.info(f"Starting OWASP ZAP scan for {target_url}")
            
            # Example ZAP API calls (commented out for stub)
            # requests.get(f"{self.zap_proxy_url}/JSON/spider/action/scan/", 
            #             params={'url': target_url, 'apikey': self.api_key})
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start ZAP scan: {e}")
            raise
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Get ZAP scan status"""
        # Stub implementation - in production would query ZAP API
        return ScanStatus.COMPLETED
    
    def get_scan_results(self, scan_id: str) -> List[DASTFinding]:
        """Get ZAP scan results"""
        # Stub implementation - would parse ZAP results
        return [
            DASTFinding(
                finding_id=f"zap_{uuid.uuid4()}",
                vulnerability_type="Cross Site Scripting (Reflected)",
                severity="high",
                confidence="medium",
                url="http://example.com/search",
                method="GET",
                parameter="q",
                description="Reflected XSS vulnerability found in search parameter",
                evidence="<script>alert('XSS')</script>",
                solution="Sanitize user input and encode output",
                cwe_id=79,
                owasp_category="A03:2021 – Injection"
            )
        ]

class BurpSuiteIntegration:
    """Burp Suite integration"""
    
    def __init__(self, burp_api_url: str = "http://localhost:1337"):
        self.burp_api_url = burp_api_url
        self.api_key = os.environ.get('BURP_API_KEY', '')
    
    def start_scan(self, target_url: str, scan_config: Dict[str, Any]) -> str:
        """Start Burp Suite scan"""
        try:
            scan_id = str(uuid.uuid4())
            logger.info(f"Starting Burp Suite scan for {target_url}")
            
            # Stub implementation - would use Burp REST API
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start Burp scan: {e}")
            raise
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Get Burp scan status"""
        return ScanStatus.COMPLETED
    
    def get_scan_results(self, scan_id: str) -> List[DASTFinding]:
        """Get Burp scan results"""
        return [
            DASTFinding(
                finding_id=f"burp_{uuid.uuid4()}",
                vulnerability_type="SQL Injection",
                severity="critical",
                confidence="high",
                url="http://example.com/login",
                method="POST",
                parameter="username",
                description="SQL injection vulnerability in login form",
                evidence="' OR '1'='1",
                solution="Use parameterized queries",
                cwe_id=89,
                owasp_category="A03:2021 – Injection"
            )
        ]

class InternalSpiderFuzzer:
    """Internal spider and fuzzer implementation"""
    
    def __init__(self):
        self.common_payloads = {
            'xss': ['<script>alert(1)</script>', '"><script>alert(1)</script>', "javascript:alert(1)"],
            'sqli': ["' OR '1'='1", "'; DROP TABLE users; --", "1' UNION SELECT NULL--"],
            'lfi': ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'],
            'command_injection': ['; ls -la', '| whoami', '`id`']
        }
    
    def start_scan(self, target_url: str, scan_config: Dict[str, Any]) -> str:
        """Start internal spider/fuzzer scan"""
        try:
            scan_id = str(uuid.uuid4())
            logger.info(f"Starting internal spider scan for {target_url}")
            
            # Simulate crawling and fuzzing
            threading.Thread(
                target=self._run_spider_scan,
                args=(scan_id, target_url, scan_config),
                daemon=True
            ).start()
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start internal scan: {e}")
            raise
    
    def _run_spider_scan(self, scan_id: str, target_url: str, config: Dict[str, Any]):
        """Run spider scan in background"""
        try:
            # Simulate crawling delay
            time.sleep(2)
            
            # Simulate finding vulnerabilities
            findings = []
            
            # Simulate XSS finding
            if config.get('test_xss', True):
                findings.append(DASTFinding(
                    finding_id=f"spider_{uuid.uuid4()}",
                    vulnerability_type="Cross Site Scripting (Reflected)",
                    severity="medium",
                    confidence="low",
                    url=f"{target_url}/search",
                    method="GET",
                    parameter="query",
                    description="Potential XSS vulnerability detected",
                    evidence="Payload: <script>alert(1)</script>",
                    solution="Implement proper input validation and output encoding"
                ))
            
            # Store results (in production, would use database)
            self._store_scan_results(scan_id, findings)
            
        except Exception as e:
            logger.error(f"Internal spider scan failed: {e}")
    
    def _store_scan_results(self, scan_id: str, findings: List[DASTFinding]):
        """Store scan results"""
        # Stub implementation - would store in database
        logger.info(f"Stored {len(findings)} findings for scan {scan_id}")
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Get internal scan status"""
        return ScanStatus.COMPLETED
    
    def get_scan_results(self, scan_id: str) -> List[DASTFinding]:
        """Get internal scan results"""
        # Stub implementation - would retrieve from database
        return []

class DASTManager:
    """Main DAST manager that coordinates different tools"""
    
    def __init__(self, dast_logs_dir: str = "data/dast_logs"):
        self.dast_logs_dir = Path(dast_logs_dir)
        self.dast_logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize integrations
        self.zap_integration = OWASPZAPIntegration()
        self.burp_integration = BurpSuiteIntegration()
        self.internal_spider = InternalSpiderFuzzer()
        
        # Active scans
        self.active_scans: Dict[str, DASTScanResult] = {}
        self._lock = threading.Lock()
    
    def start_dast_scan(self, target_url: str, tool: DASTTool, 
                       scan_config: Dict[str, Any] = None) -> str:
        """Start DAST scan with specified tool"""
        try:
            scan_config = scan_config or {}
            scan_id = str(uuid.uuid4())
            
            # Create scan result object
            scan_result = DASTScanResult(
                scan_id=scan_id,
                tool=tool,
                target_url=target_url,
                status=ScanStatus.PENDING,
                started_at=datetime.now().isoformat(),
                completed_at=None,
                findings=[],
                scan_config=scan_config,
                statistics={}
            )
            
            with self._lock:
                self.active_scans[scan_id] = scan_result
            
            # Start scan with appropriate tool
            if tool == DASTTool.OWASP_ZAP:
                tool_scan_id = self.zap_integration.start_scan(target_url, scan_config)
            elif tool == DASTTool.BURP_SUITE:
                tool_scan_id = self.burp_integration.start_scan(target_url, scan_config)
            elif tool == DASTTool.INTERNAL_SPIDER:
                tool_scan_id = self.internal_spider.start_scan(target_url, scan_config)
            else:
                raise ValueError(f"Unsupported DAST tool: {tool}")
            
            # Update status
            scan_result.status = ScanStatus.RUNNING
            
            # Start monitoring thread
            threading.Thread(
                target=self._monitor_scan,
                args=(scan_id, tool, tool_scan_id),
                daemon=True
            ).start()
            
            logger.info(f"Started DAST scan {scan_id} with {tool.value}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start DAST scan: {e}")
            if scan_id in self.active_scans:
                self.active_scans[scan_id].status = ScanStatus.FAILED
                self.active_scans[scan_id].error_message = str(e)
            raise
    
    def _monitor_scan(self, scan_id: str, tool: DASTTool, tool_scan_id: str):
        """Monitor scan progress"""
        try:
            while True:
                # Check scan status
                if tool == DASTTool.OWASP_ZAP:
                    status = self.zap_integration.get_scan_status(tool_scan_id)
                elif tool == DASTTool.BURP_SUITE:
                    status = self.burp_integration.get_scan_status(tool_scan_id)
                elif tool == DASTTool.INTERNAL_SPIDER:
                    status = self.internal_spider.get_scan_status(tool_scan_id)
                else:
                    status = ScanStatus.FAILED
                
                if status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                    # Get results
                    if status == ScanStatus.COMPLETED:
                        if tool == DASTTool.OWASP_ZAP:
                            findings = self.zap_integration.get_scan_results(tool_scan_id)
                        elif tool == DASTTool.BURP_SUITE:
                            findings = self.burp_integration.get_scan_results(tool_scan_id)
                        elif tool == DASTTool.INTERNAL_SPIDER:
                            findings = self.internal_spider.get_scan_results(tool_scan_id)
                        else:
                            findings = []
                        
                        with self._lock:
                            if scan_id in self.active_scans:
                                self.active_scans[scan_id].findings = findings
                                self.active_scans[scan_id].status = status
                                self.active_scans[scan_id].completed_at = datetime.now().isoformat()
                                self.active_scans[scan_id].statistics = {
                                    'total_findings': len(findings),
                                    'critical_findings': len([f for f in findings if f.severity == 'critical']),
                                    'high_findings': len([f for f in findings if f.severity == 'high']),
                                    'medium_findings': len([f for f in findings if f.severity == 'medium']),
                                    'low_findings': len([f for f in findings if f.severity == 'low'])
                                }
                        
                        # Save results to log file
                        self._save_scan_log(scan_id)
                    
                    break
                
                time.sleep(5)  # Check every 5 seconds
                
        except Exception as e:
            logger.error(f"Scan monitoring failed: {e}")
            with self._lock:
                if scan_id in self.active_scans:
                    self.active_scans[scan_id].status = ScanStatus.FAILED
                    self.active_scans[scan_id].error_message = str(e)
    
    def get_scan_result(self, scan_id: str) -> Optional[DASTScanResult]:
        """Get scan result by ID"""
        with self._lock:
            return self.active_scans.get(scan_id)
    
    def list_scans(self) -> List[DASTScanResult]:
        """List all scans"""
        with self._lock:
            return list(self.active_scans.values())
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel running scan"""
        try:
            with self._lock:
                if scan_id in self.active_scans:
                    self.active_scans[scan_id].status = ScanStatus.CANCELLED
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to cancel scan: {e}")
            return False
    
    def _save_scan_log(self, scan_id: str):
        """Save scan results to log file"""
        try:
            scan_result = self.active_scans.get(scan_id)
            if scan_result:
                log_file = self.dast_logs_dir / f"dast_scan_{scan_id}.json"
                with open(log_file, 'w') as f:
                    json.dump(scan_result.to_dict(), f, indent=2)
                logger.info(f"Saved DAST scan log: {log_file}")
        except Exception as e:
            logger.error(f"Failed to save scan log: {e}")

# Global instance
dast_manager = DASTManager()
