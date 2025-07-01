"""
API validation and testing for ByteGuardX
Provides automated API endpoint validation and testing
"""

import logging
import json
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import jsonschema
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """API validation result"""
    endpoint: str
    method: str
    status: str  # "pass", "fail", "error"
    response_code: int
    response_time_ms: float
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    response_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EndpointTest:
    """API endpoint test definition"""
    path: str
    method: str
    description: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    request_body: Dict[str, Any] = field(default_factory=dict)
    expected_status: int = 200
    expected_schema: Dict[str, Any] = field(default_factory=dict)
    auth_required: bool = False

class APIValidator:
    """
    API validation and testing framework
    Validates API endpoints against OpenAPI specification
    """
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.auth_token = None
        
        # Test definitions
        self.endpoint_tests = self._define_endpoint_tests()
    
    def set_auth_token(self, token: str):
        """Set authentication token"""
        self.auth_token = token
        self.session.headers.update({"Authorization": f"Bearer {token}"})
    
    def validate_all_endpoints(self) -> List[ValidationResult]:
        """Validate all defined endpoints"""
        results = []
        
        for test in self.endpoint_tests:
            try:
                result = self.validate_endpoint(test)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to validate {test.method} {test.path}: {e}")
                results.append(ValidationResult(
                    endpoint=test.path,
                    method=test.method,
                    status="error",
                    response_code=0,
                    response_time_ms=0.0,
                    errors=[str(e)]
                ))
        
        return results
    
    def validate_endpoint(self, test: EndpointTest) -> ValidationResult:
        """Validate single endpoint"""
        try:
            start_time = datetime.now()
            
            # Prepare request
            url = f"{self.base_url}{test.path}"
            headers = {**test.headers}
            
            # Add auth if required
            if test.auth_required and self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Make request
            response = self.session.request(
                method=test.method,
                url=url,
                headers=headers,
                params=test.query_params,
                json=test.request_body if test.request_body else None,
                timeout=30
            )
            
            end_time = datetime.now()
            response_time_ms = (end_time - start_time).total_seconds() * 1000
            
            # Parse response
            try:
                response_data = response.json() if response.content else {}
            except json.JSONDecodeError:
                response_data = {"raw_content": response.text}
            
            # Validate response
            result = ValidationResult(
                endpoint=test.path,
                method=test.method,
                status="pass",
                response_code=response.status_code,
                response_time_ms=response_time_ms,
                response_data=response_data
            )
            
            # Check status code
            if response.status_code != test.expected_status:
                result.status = "fail"
                result.errors.append(
                    f"Expected status {test.expected_status}, got {response.status_code}"
                )
            
            # Validate response schema
            if test.expected_schema and response_data:
                try:
                    jsonschema.validate(response_data, test.expected_schema)
                except jsonschema.ValidationError as e:
                    result.status = "fail"
                    result.errors.append(f"Schema validation failed: {e.message}")
            
            # Check response time
            if response_time_ms > 5000:  # 5 seconds
                result.warnings.append(f"Slow response time: {response_time_ms:.0f}ms")
            
            return result
            
        except requests.RequestException as e:
            return ValidationResult(
                endpoint=test.path,
                method=test.method,
                status="error",
                response_code=0,
                response_time_ms=0.0,
                errors=[f"Request failed: {str(e)}"]
            )
    
    def generate_test_report(self, results: List[ValidationResult]) -> str:
        """Generate validation test report"""
        try:
            total_tests = len(results)
            passed_tests = sum(1 for r in results if r.status == "pass")
            failed_tests = sum(1 for r in results if r.status == "fail")
            error_tests = sum(1 for r in results if r.status == "error")
            
            avg_response_time = sum(r.response_time_ms for r in results) / total_tests if total_tests > 0 else 0
            
            report = f"""# ByteGuardX API Validation Report

Generated: {datetime.now().isoformat()}

## Summary

- **Total Tests**: {total_tests}
- **Passed**: {passed_tests}
- **Failed**: {failed_tests}
- **Errors**: {error_tests}
- **Success Rate**: {(passed_tests / total_tests * 100):.1f}%
- **Average Response Time**: {avg_response_time:.0f}ms

## Test Results

"""
            
            for result in results:
                status_emoji = "✅" if result.status == "pass" else "❌" if result.status == "fail" else "⚠️"
                
                report += f"""### {status_emoji} {result.method} {result.endpoint}

- **Status**: {result.status.upper()}
- **Response Code**: {result.response_code}
- **Response Time**: {result.response_time_ms:.0f}ms

"""
                
                if result.errors:
                    report += "**Errors:**\n"
                    for error in result.errors:
                        report += f"- {error}\n"
                    report += "\n"
                
                if result.warnings:
                    report += "**Warnings:**\n"
                    for warning in result.warnings:
                        report += f"- {warning}\n"
                    report += "\n"
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate test report: {e}")
            return f"Error generating report: {e}"
    
    def _define_endpoint_tests(self) -> List[EndpointTest]:
        """Define API endpoint tests"""
        return [
            # Health check
            EndpointTest(
                path="/health",
                method="GET",
                description="Health check endpoint",
                expected_status=200,
                expected_schema={
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "timestamp": {"type": "string"}
                    },
                    "required": ["status", "timestamp"]
                }
            ),
            
            # Authentication
            EndpointTest(
                path="/auth/login",
                method="POST",
                description="User login",
                request_body={
                    "email": "test@example.com",
                    "password": "testpassword"
                },
                expected_status=200,
                expected_schema={
                    "type": "object",
                    "properties": {
                        "access_token": {"type": "string"},
                        "refresh_token": {"type": "string"},
                        "user": {"type": "object"}
                    }
                }
            ),
            
            # Scanning endpoints
            EndpointTest(
                path="/scan/directory",
                method="POST",
                description="Directory scan",
                request_body={
                    "directory_path": "/tmp/test",
                    "recursive": True
                },
                auth_required=True,
                expected_status=200
            ),
            
            EndpointTest(
                path="/scan/file",
                method="POST",
                description="File scan",
                request_body={
                    "file_path": "/tmp/test.py",
                    "content": "print('hello world')"
                },
                auth_required=True,
                expected_status=200
            ),
            
            EndpointTest(
                path="/scan/list",
                method="GET",
                description="List scans",
                query_params={"page": 1, "limit": 10},
                auth_required=True,
                expected_status=200,
                expected_schema={
                    "type": "object",
                    "properties": {
                        "scans": {"type": "array"},
                        "total": {"type": "integer"},
                        "page": {"type": "integer"},
                        "limit": {"type": "integer"}
                    }
                }
            ),
            
            # Report endpoints
            EndpointTest(
                path="/report/generate",
                method="POST",
                description="Generate report",
                request_body={
                    "scan_id": "test-scan-id",
                    "format": "json"
                },
                auth_required=True,
                expected_status=200
            ),
            
            # AI suggestions
            EndpointTest(
                path="/fix/suggestions/test-finding-id",
                method="GET",
                description="Get fix suggestions",
                auth_required=True,
                expected_status=200
            ),
            
            # Analytics (if enabled)
            EndpointTest(
                path="/analytics/trends",
                method="GET",
                description="Security trends",
                auth_required=True,
                expected_status=200
            ),
            
            # Enterprise features
            EndpointTest(
                path="/enterprise/features",
                method="GET",
                description="Enterprise features status",
                auth_required=True,
                expected_status=200
            ),
        ]

class EndpointValidator:
    """Individual endpoint validator"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def validate_endpoint_schema(self, endpoint: str, method: str, 
                                response_data: Dict[str, Any], 
                                expected_schema: Dict[str, Any]) -> List[str]:
        """Validate endpoint response against schema"""
        errors = []
        
        try:
            jsonschema.validate(response_data, expected_schema)
        except jsonschema.ValidationError as e:
            errors.append(f"Schema validation failed: {e.message}")
        except Exception as e:
            errors.append(f"Schema validation error: {str(e)}")
        
        return errors
    
    def validate_response_time(self, response_time_ms: float, 
                              max_time_ms: float = 5000) -> List[str]:
        """Validate response time"""
        warnings = []
        
        if response_time_ms > max_time_ms:
            warnings.append(f"Response time {response_time_ms:.0f}ms exceeds {max_time_ms:.0f}ms")
        
        return warnings
    
    def validate_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """Validate security headers"""
        warnings = []
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        for header in required_headers:
            if header not in headers:
                warnings.append(f"Missing security header: {header}")
        
        return warnings

# Global API validator
api_validator = APIValidator()
