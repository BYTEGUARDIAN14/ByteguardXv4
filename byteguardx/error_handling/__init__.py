"""
Error handling and resilience module for ByteGuardX
Provides centralized exception handling, graceful degradation, and retry logic
"""

from .exception_handler import (
    ByteGuardXException, ScannerException, DatabaseException,
    AuthenticationException, ValidationException, ExceptionHandler
)
from .graceful_degradation import GracefulDegradation, FallbackMode
from .retry_logic import RetryManager, RetryPolicy, exponential_backoff

__all__ = [
    'ByteGuardXException', 'ScannerException', 'DatabaseException',
    'AuthenticationException', 'ValidationException', 'ExceptionHandler',
    'GracefulDegradation', 'FallbackMode', 'RetryManager', 
    'RetryPolicy', 'exponential_backoff'
]
