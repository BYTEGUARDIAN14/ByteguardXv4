"""
ByteGuardX API Client

Main client class for interacting with the ByteGuardX API.
"""

import os
import json
import time
from typing import Dict, List, Optional, Union, Any
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import ScanConfig, ScanResult, ScanStatus, Vulnerability
from .exceptions import (
    ByteGuardXError,
    AuthenticationError,
    ScanError,
    ConfigurationError,
    APIError
)


class ByteGuardXClient:
    """
    Main client for interacting with ByteGuardX API.
    
    This client provides methods for scanning code, managing scans,
    and retrieving security reports.
    """
    
    def __init__(
        self,
        api_key: str = None,
        api_url: str = "https://api.byteguardx.com",
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True
    ):
        """
        Initialize the ByteGuardX client.
        
        Args:
            api_key: Your ByteGuardX API key (or set BYTEGUARDX_API_KEY env var)
            api_url: ByteGuardX API base URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates
        """
        self.api_key = api_key or os.getenv('BYTEGUARDX_API_KEY')
        if not self.api_key:
            raise ConfigurationError(
                "API key is required. Set BYTEGUARDX_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Configure session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': f'ByteGuardX-Python-SDK/1.0.0'
        })
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        files: Dict = None,
        params: Dict = None
    ) -> Dict:
        """Make an HTTP request to the API."""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        
        try:
            if files:
                # Remove Content-Type header for file uploads
                headers = {k: v for k, v in self.session.headers.items() 
                          if k.lower() != 'content-type'}
                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    files=files,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    headers=headers
                )
            else:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            # Handle different response status codes
            if response.status_code == 401:
                raise AuthenticationError("Invalid API key or authentication failed")
            elif response.status_code == 403:
                raise AuthenticationError("Access forbidden - check your permissions")
            elif response.status_code == 429:
                raise APIError("Rate limit exceeded - please try again later")
            elif response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', f'HTTP {response.status_code}')
                except:
                    error_message = f'HTTP {response.status_code}: {response.text}'
                raise APIError(error_message)
            
            return response.json() if response.content else {}
            
        except requests.exceptions.Timeout:
            raise APIError(f"Request timeout after {self.timeout} seconds")
        except requests.exceptions.ConnectionError:
            raise APIError(f"Failed to connect to {self.api_url}")
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}")
    
    def scan_directory(
        self,
        directory_path: str,
        config: ScanConfig = None,
        wait_for_completion: bool = True
    ) -> ScanResult:
        """
        Scan a directory for security vulnerabilities.
        
        Args:
            directory_path: Path to the directory to scan
            config: Scan configuration options
            wait_for_completion: Whether to wait for scan completion
            
        Returns:
            ScanResult with the security findings
        """
        path = Path(directory_path)
        if not path.exists():
            raise ScanError(f"Directory does not exist: {directory_path}")
        if not path.is_dir():
            raise ScanError(f"Path is not a directory: {directory_path}")
        
        # Create scan configuration
        if config is None:
            config = ScanConfig()
        
        scan_data = {
            'scan_type': 'directory',
            'target_path': str(path.absolute()),
            'config': config.to_dict()
        }
        
        # Start the scan
        response = self._make_request('POST', '/api/scans', data=scan_data)
        scan_id = response['scan_id']
        
        if wait_for_completion:
            return self._wait_for_scan_completion(scan_id)
        else:
            return ScanResult(scan_id=scan_id, status=ScanStatus.RUNNING)
    
    def scan_file(
        self,
        file_path: str,
        config: ScanConfig = None,
        wait_for_completion: bool = True
    ) -> ScanResult:
        """
        Scan a single file for security vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            config: Scan configuration options
            wait_for_completion: Whether to wait for scan completion
            
        Returns:
            ScanResult with the security findings
        """
        path = Path(file_path)
        if not path.exists():
            raise ScanError(f"File does not exist: {file_path}")
        if not path.is_file():
            raise ScanError(f"Path is not a file: {file_path}")
        
        # Upload and scan file
        with open(path, 'rb') as f:
            files = {'file': (path.name, f, 'application/octet-stream')}
            
            scan_data = {
                'scan_type': 'file',
                'config': json.dumps(config.to_dict() if config else {})
            }
            
            response = self._make_request(
                'POST', '/api/scans/upload', 
                data=scan_data, 
                files=files
            )
        
        scan_id = response['scan_id']
        
        if wait_for_completion:
            return self._wait_for_scan_completion(scan_id)
        else:
            return ScanResult(scan_id=scan_id, status=ScanStatus.RUNNING)
    
    def quick_scan(self, path: str, **kwargs) -> ScanResult:
        """
        Perform a quick security scan with default settings.
        
        Args:
            path: Path to file or directory to scan
            **kwargs: Additional scan options
            
        Returns:
            ScanResult with the security findings
        """
        config = ScanConfig(
            scan_secrets=True,
            scan_vulnerabilities=True,
            scan_dependencies=False,
            max_file_size_mb=10
        )
        
        path_obj = Path(path)
        if path_obj.is_dir():
            return self.scan_directory(path, config, **kwargs)
        else:
            return self.scan_file(path, config, **kwargs)
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Get the current status of a scan."""
        response = self._make_request('GET', f'/api/scans/{scan_id}/status')
        return ScanStatus(response['status'])
    
    def get_scan_result(self, scan_id: str) -> ScanResult:
        """Get the complete results of a scan."""
        response = self._make_request('GET', f'/api/scans/{scan_id}')
        return ScanResult.from_dict(response)
    
    def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        status: ScanStatus = None
    ) -> List[Dict]:
        """List recent scans."""
        params = {'limit': limit, 'offset': offset}
        if status:
            params['status'] = status.value
        
        response = self._make_request('GET', '/api/scans', params=params)
        return response['scans']
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its results."""
        self._make_request('DELETE', f'/api/scans/{scan_id}')
        return True
    
    def get_vulnerability_details(self, vulnerability_id: str) -> Vulnerability:
        """Get detailed information about a specific vulnerability."""
        response = self._make_request('GET', f'/api/vulnerabilities/{vulnerability_id}')
        return Vulnerability.from_dict(response)
    
    def export_report(
        self,
        scan_id: str,
        format: str = 'json',
        include_details: bool = True
    ) -> bytes:
        """
        Export a scan report in the specified format.
        
        Args:
            scan_id: ID of the scan to export
            format: Report format ('json', 'pdf', 'html', 'csv')
            include_details: Whether to include detailed vulnerability information
            
        Returns:
            Report data as bytes
        """
        params = {
            'format': format,
            'include_details': include_details
        }
        
        response = self.session.get(
            f"{self.api_url}/api/scans/{scan_id}/export",
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        
        if response.status_code != 200:
            raise APIError(f"Failed to export report: HTTP {response.status_code}")
        
        return response.content
    
    def _wait_for_scan_completion(
        self,
        scan_id: str,
        poll_interval: int = 5,
        max_wait_time: int = 3600
    ) -> ScanResult:
        """Wait for a scan to complete and return the results."""
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            status = self.get_scan_status(scan_id)
            
            if status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                return self.get_scan_result(scan_id)
            
            time.sleep(poll_interval)
        
        raise ScanError(f"Scan {scan_id} did not complete within {max_wait_time} seconds")
    
    def health_check(self) -> Dict:
        """Check the health of the ByteGuardX API."""
        return self._make_request('GET', '/health')
    
    def get_account_info(self) -> Dict:
        """Get information about your ByteGuardX account."""
        return self._make_request('GET', '/api/account')
    
    def close(self):
        """Close the HTTP session."""
        if self.session:
            self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
