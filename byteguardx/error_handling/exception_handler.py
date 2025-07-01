"""
Centralized exception handling for ByteGuardX
Provides custom exceptions and comprehensive error handling
"""

import logging
import traceback
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from enum import Enum
import sys
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ErrorContext:
    """Context information for errors"""
    component: str
    operation: str
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    additional_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_data is None:
            self.additional_data = {}

class ByteGuardXException(Exception):
    """Base exception for ByteGuardX"""
    
    def __init__(self, message: str, error_code: str = None, 
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 context: ErrorContext = None, cause: Exception = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.severity = severity
        self.context = context
        self.cause = cause
        self.timestamp = datetime.now()
        self.traceback_str = traceback.format_exc()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/API responses"""
        return {
            'error_type': self.__class__.__name__,
            'error_code': self.error_code,
            'message': self.message,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'context': {
                'component': self.context.component if self.context else None,
                'operation': self.context.operation if self.context else None,
                'user_id': self.context.user_id if self.context else None,
                'request_id': self.context.request_id if self.context else None,
                'additional_data': self.context.additional_data if self.context else {}
            },
            'cause': str(self.cause) if self.cause else None,
            'traceback': self.traceback_str
        }

class ScannerException(ByteGuardXException):
    """Exception for scanner-related errors"""
    
    def __init__(self, message: str, scanner_type: str = None, 
                 file_path: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.scanner_type = scanner_type
        self.file_path = file_path

class DatabaseException(ByteGuardXException):
    """Exception for database-related errors"""
    
    def __init__(self, message: str, operation: str = None, 
                 table: str = None, **kwargs):
        super().__init__(message, severity=ErrorSeverity.HIGH, **kwargs)
        self.operation = operation
        self.table = table

class AuthenticationException(ByteGuardXException):
    """Exception for authentication/authorization errors"""
    
    def __init__(self, message: str, user_id: str = None, 
                 ip_address: str = None, **kwargs):
        super().__init__(message, severity=ErrorSeverity.HIGH, **kwargs)
        self.user_id = user_id
        self.ip_address = ip_address

class ValidationException(ByteGuardXException):
    """Exception for input validation errors"""
    
    def __init__(self, message: str, field: str = None, 
                 value: Any = None, **kwargs):
        super().__init__(message, severity=ErrorSeverity.LOW, **kwargs)
        self.field = field
        self.value = value

class RateLimitException(ByteGuardXException):
    """Exception for rate limiting"""
    
    def __init__(self, message: str, limit: int = None, 
                 reset_time: datetime = None, **kwargs):
        super().__init__(message, severity=ErrorSeverity.MEDIUM, **kwargs)
        self.limit = limit
        self.reset_time = reset_time

class ExceptionHandler:
    """Centralized exception handler with logging and notification"""
    
    def __init__(self):
        self.error_handlers: Dict[type, Callable] = {}
        self.error_stats: Dict[str, int] = {}
        self.notification_callbacks: List[Callable] = []
        
        # Register default handlers
        self._register_default_handlers()
    
    def register_handler(self, exception_type: type, handler: Callable):
        """Register custom exception handler"""
        self.error_handlers[exception_type] = handler
        logger.info(f"Registered handler for {exception_type.__name__}")
    
    def add_notification_callback(self, callback: Callable):
        """Add callback for error notifications"""
        self.notification_callbacks.append(callback)
    
    def handle_exception(self, exception: Exception, context: ErrorContext = None) -> Dict[str, Any]:
        """Handle exception with appropriate logging and response"""
        try:
            # Convert to ByteGuardX exception if needed
            if not isinstance(exception, ByteGuardXException):
                exception = self._wrap_exception(exception, context)
            
            # Update error statistics
            self._update_error_stats(exception)
            
            # Log the exception
            self._log_exception(exception)
            
            # Call registered handler
            handler = self.error_handlers.get(type(exception))
            if handler:
                try:
                    handler(exception)
                except Exception as handler_error:
                    logger.error(f"Error in exception handler: {handler_error}")
            
            # Send notifications for critical errors
            if exception.severity == ErrorSeverity.CRITICAL:
                self._send_notifications(exception)
            
            # Return error response
            return self._create_error_response(exception)
            
        except Exception as handling_error:
            logger.critical(f"Error in exception handling: {handling_error}")
            return {
                'error': 'Internal error handling failure',
                'error_code': 'HANDLER_FAILURE',
                'message': 'An unexpected error occurred while processing the request'
            }
    
    def _wrap_exception(self, exception: Exception, context: ErrorContext = None) -> ByteGuardXException:
        """Wrap generic exception in ByteGuardX exception"""
        # Determine severity based on exception type
        severity = ErrorSeverity.MEDIUM
        
        if isinstance(exception, (ConnectionError, TimeoutError)):
            severity = ErrorSeverity.HIGH
        elif isinstance(exception, (MemoryError, SystemError)):
            severity = ErrorSeverity.CRITICAL
        elif isinstance(exception, (ValueError, TypeError)):
            severity = ErrorSeverity.LOW
        
        return ByteGuardXException(
            message=str(exception),
            severity=severity,
            context=context,
            cause=exception
        )
    
    def _update_error_stats(self, exception: ByteGuardXException):
        """Update error statistics"""
        error_key = f"{exception.__class__.__name__}:{exception.error_code}"
        self.error_stats[error_key] = self.error_stats.get(error_key, 0) + 1
    
    def _log_exception(self, exception: ByteGuardXException):
        """Log exception with appropriate level"""
        error_dict = exception.to_dict()
        
        if exception.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"Critical error: {exception.message}", extra=error_dict)
        elif exception.severity == ErrorSeverity.HIGH:
            logger.error(f"High severity error: {exception.message}", extra=error_dict)
        elif exception.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"Medium severity error: {exception.message}", extra=error_dict)
        else:
            logger.info(f"Low severity error: {exception.message}", extra=error_dict)
    
    def _send_notifications(self, exception: ByteGuardXException):
        """Send notifications for critical errors"""
        for callback in self.notification_callbacks:
            try:
                callback(exception)
            except Exception as e:
                logger.error(f"Error in notification callback: {e}")
    
    def _create_error_response(self, exception: ByteGuardXException) -> Dict[str, Any]:
        """Create standardized error response"""
        # Don't expose sensitive information in API responses
        response = {
            'error': True,
            'error_code': exception.error_code,
            'message': exception.message,
            'timestamp': exception.timestamp.isoformat()
        }
        
        # Add context for debugging (only in development)
        if logger.isEnabledFor(logging.DEBUG):
            response['debug_info'] = {
                'error_type': exception.__class__.__name__,
                'severity': exception.severity.value,
                'context': exception.context.to_dict() if exception.context else None
            }
        
        return response
    
    def _register_default_handlers(self):
        """Register default exception handlers"""
        
        def handle_database_exception(exception: DatabaseException):
            """Handle database exceptions"""
            # TODO: Implement database connection recovery
            logger.error(f"Database error in {exception.operation}: {exception.message}")
        
        def handle_scanner_exception(exception: ScannerException):
            """Handle scanner exceptions"""
            logger.error(f"Scanner error ({exception.scanner_type}): {exception.message}")
            # TODO: Implement scanner fallback mechanisms
        
        def handle_auth_exception(exception: AuthenticationException):
            """Handle authentication exceptions"""
            logger.warning(f"Auth error for user {exception.user_id}: {exception.message}")
            # TODO: Implement security monitoring
        
        self.register_handler(DatabaseException, handle_database_exception)
        self.register_handler(ScannerException, handle_scanner_exception)
        self.register_handler(AuthenticationException, handle_auth_exception)
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        total_errors = sum(self.error_stats.values())
        
        return {
            'total_errors': total_errors,
            'error_breakdown': dict(self.error_stats),
            'most_common_errors': sorted(
                self.error_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
    
    def reset_error_stats(self):
        """Reset error statistics"""
        self.error_stats.clear()
        logger.info("Error statistics reset")

# Global exception handler instance
exception_handler = ExceptionHandler()

def handle_exceptions(context: ErrorContext = None):
    """Decorator for automatic exception handling"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_response = exception_handler.handle_exception(e, context)
                # Re-raise for Flask error handlers to catch
                raise ByteGuardXException(
                    message=error_response.get('message', 'Unknown error'),
                    error_code=error_response.get('error_code', 'UNKNOWN')
                )
        return wrapper
    return decorator
