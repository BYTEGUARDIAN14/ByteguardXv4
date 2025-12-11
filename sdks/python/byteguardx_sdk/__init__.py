"""
ByteGuardX Python SDK

A comprehensive Python SDK for integrating ByteGuardX security scanning
capabilities into your applications and CI/CD pipelines.
"""

__version__ = "1.0.0"
__author__ = "ByteGuardX Team"
__email__ = "support@byteguardx.com"

from .client import ByteGuardXClient
from .scanner import SecurityScanner
from .models import (
    ScanConfig,
    ScanResult,
    Vulnerability,
    SecurityIssue,
    ScanStatus,
    SeverityLevel
)
from .exceptions import (
    ByteGuardXError,
    AuthenticationError,
    ScanError,
    ConfigurationError,
    APIError
)

# Convenience imports
from .client import ByteGuardXClient as Client
from .scanner import SecurityScanner as Scanner

__all__ = [
    # Main classes
    'ByteGuardXClient',
    'SecurityScanner',
    'Client',
    'Scanner',
    
    # Models
    'ScanConfig',
    'ScanResult',
    'Vulnerability',
    'SecurityIssue',
    'ScanStatus',
    'SeverityLevel',
    
    # Exceptions
    'ByteGuardXError',
    'AuthenticationError',
    'ScanError',
    'ConfigurationError',
    'APIError',
    
    # Metadata
    '__version__',
    '__author__',
    '__email__',
]

# Default configuration
DEFAULT_API_URL = "https://api.byteguardx.com"
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3

def create_client(api_key: str, api_url: str = None, **kwargs) -> ByteGuardXClient:
    """
    Create a ByteGuardX client with the given API key.
    
    Args:
        api_key: Your ByteGuardX API key
        api_url: Optional custom API URL (defaults to production)
        **kwargs: Additional client configuration options
        
    Returns:
        Configured ByteGuardXClient instance
        
    Example:
        >>> import byteguardx_sdk
        >>> client = byteguardx_sdk.create_client("your-api-key")
        >>> result = client.scan_directory("/path/to/code")
    """
    return ByteGuardXClient(
        api_key=api_key,
        api_url=api_url or DEFAULT_API_URL,
        **kwargs
    )

def quick_scan(path: str, api_key: str = None, **kwargs) -> ScanResult:
    """
    Perform a quick security scan on the specified path.
    
    Args:
        path: Path to file or directory to scan
        api_key: ByteGuardX API key (can also be set via environment variable)
        **kwargs: Additional scan configuration options
        
    Returns:
        ScanResult containing the security findings
        
    Example:
        >>> import byteguardx_sdk
        >>> result = byteguardx_sdk.quick_scan("/path/to/code", api_key="your-key")
        >>> print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    """
    client = create_client(api_key)
    return client.quick_scan(path, **kwargs)

# Version check utility
def check_version() -> dict:
    """
    Check the current SDK version and compare with latest available.
    
    Returns:
        Dictionary with version information
    """
    import requests
    try:
        response = requests.get(
            "https://pypi.org/pypi/byteguardx-sdk/json",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            latest_version = data["info"]["version"]
            return {
                "current": __version__,
                "latest": latest_version,
                "update_available": __version__ != latest_version
            }
    except Exception:
        pass
    
    return {
        "current": __version__,
        "latest": "unknown",
        "update_available": False
    }
