#!/usr/bin/env python3
"""
Advanced Error Recovery System for ByteGuardX
Implements circuit breakers, retry mechanisms, and graceful degradation
"""

import logging
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import threading
import traceback

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    CLOSED = "CLOSED"      # Normal operation
    OPEN = "OPEN"          # Circuit breaker tripped
    HALF_OPEN = "HALF_OPEN"  # Testing if service recovered

@dataclass
class ErrorMetrics:
    """Error tracking metrics"""
    total_requests: int = 0
    failed_requests: int = 0
    success_requests: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    error_types: Dict[str, int] = field(default_factory=dict)

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    success_threshold: int = 3  # for half-open state
    timeout: int = 30  # request timeout
    monitor_window: int = 300  # 5 minutes

class CircuitBreaker:
    """
    Circuit breaker implementation for fault tolerance
    """
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.metrics = ErrorMetrics()
        self.lock = threading.RLock()
        self.last_state_change = datetime.now()
        
        logger.info(f"Circuit breaker '{name}' initialized")
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for circuit breaker"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        with self.lock:
            # Check circuit state
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                else:
                    raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is OPEN")
            
            # Execute function
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                # Record success
                self._record_success(execution_time)
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                # Record failure
                self._record_failure(e, execution_time)
                
                # Check if circuit should open
                if self._should_trip():
                    self._transition_to_open()
                
                raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt reset"""
        time_since_open = (datetime.now() - self.last_state_change).total_seconds()
        return time_since_open >= self.config.recovery_timeout
    
    def _should_trip(self) -> bool:
        """Check if circuit breaker should trip"""
        if self.state == CircuitState.OPEN:
            return False
        
        # Trip on consecutive failures
        if self.metrics.consecutive_failures >= self.config.failure_threshold:
            return True
        
        # Trip on failure rate within window
        if self.metrics.total_requests >= 10:  # Minimum requests
            failure_rate = self.metrics.failed_requests / self.metrics.total_requests
            if failure_rate >= 0.5:  # 50% failure rate
                return True
        
        return False
    
    def _transition_to_open(self):
        """Transition circuit to OPEN state"""
        self.state = CircuitState.OPEN
        self.last_state_change = datetime.now()
        logger.warning(f"Circuit breaker '{self.name}' transitioned to OPEN")
    
    def _transition_to_half_open(self):
        """Transition circuit to HALF_OPEN state"""
        self.state = CircuitState.HALF_OPEN
        self.last_state_change = datetime.now()
        self.metrics.consecutive_successes = 0
        logger.info(f"Circuit breaker '{self.name}' transitioned to HALF_OPEN")
    
    def _transition_to_closed(self):
        """Transition circuit to CLOSED state"""
        self.state = CircuitState.CLOSED
        self.last_state_change = datetime.now()
        self.metrics.consecutive_failures = 0
        logger.info(f"Circuit breaker '{self.name}' transitioned to CLOSED")
    
    def _record_success(self, execution_time: float):
        """Record successful execution"""
        self.metrics.total_requests += 1
        self.metrics.success_requests += 1
        self.metrics.consecutive_successes += 1
        self.metrics.consecutive_failures = 0
        self.metrics.last_success_time = datetime.now()
        
        # Transition from HALF_OPEN to CLOSED if enough successes
        if (self.state == CircuitState.HALF_OPEN and 
            self.metrics.consecutive_successes >= self.config.success_threshold):
            self._transition_to_closed()
    
    def _record_failure(self, error: Exception, execution_time: float):
        """Record failed execution"""
        self.metrics.total_requests += 1
        self.metrics.failed_requests += 1
        self.metrics.consecutive_failures += 1
        self.metrics.consecutive_successes = 0
        self.metrics.last_failure_time = datetime.now()
        
        # Track error types
        error_type = type(error).__name__
        self.metrics.error_types[error_type] = self.metrics.error_types.get(error_type, 0) + 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics"""
        with self.lock:
            return {
                'name': self.name,
                'state': self.state.value,
                'total_requests': self.metrics.total_requests,
                'failed_requests': self.metrics.failed_requests,
                'success_requests': self.metrics.success_requests,
                'failure_rate': (self.metrics.failed_requests / max(self.metrics.total_requests, 1)),
                'consecutive_failures': self.metrics.consecutive_failures,
                'consecutive_successes': self.metrics.consecutive_successes,
                'last_failure_time': self.metrics.last_failure_time.isoformat() if self.metrics.last_failure_time else None,
                'last_success_time': self.metrics.last_success_time.isoformat() if self.metrics.last_success_time else None,
                'last_state_change': self.last_state_change.isoformat(),
                'error_types': self.metrics.error_types.copy()
            }
    
    def reset(self):
        """Manually reset circuit breaker"""
        with self.lock:
            self.state = CircuitState.CLOSED
            self.metrics = ErrorMetrics()
            self.last_state_change = datetime.now()
            logger.info(f"Circuit breaker '{self.name}' manually reset")

class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open"""
    pass

class RetryConfig:
    """Retry mechanism configuration"""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, 
                 max_delay: float = 60.0, exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

def retry_with_backoff(config: RetryConfig = None, 
                      exceptions: tuple = (Exception,)):
    """
    Retry decorator with exponential backoff
    """
    config = config or RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                    
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == config.max_attempts - 1:
                        # Last attempt failed
                        logger.error(f"Function {func.__name__} failed after {config.max_attempts} attempts: {e}")
                        raise
                    
                    # Calculate delay
                    delay = min(
                        config.base_delay * (config.exponential_base ** attempt),
                        config.max_delay
                    )
                    
                    # Add jitter
                    if config.jitter:
                        import random
                        delay *= (0.5 + random.random() * 0.5)
                    
                    logger.warning(f"Function {func.__name__} failed (attempt {attempt + 1}/{config.max_attempts}), "
                                 f"retrying in {delay:.2f}s: {e}")
                    
                    time.sleep(delay)
                
                except Exception as e:
                    # Non-retryable exception
                    logger.error(f"Function {func.__name__} failed with non-retryable exception: {e}")
                    raise
            
            # Should never reach here
            raise last_exception
        
        return wrapper
    return decorator

class ErrorRecoveryManager:
    """
    Centralized error recovery management
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_handlers: Dict[str, Callable] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
        self.lock = threading.RLock()
        
        # Global error statistics
        self.global_errors = ErrorMetrics()
        
        logger.info("Error recovery manager initialized")
    
    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create circuit breaker"""
        with self.lock:
            if name not in self.circuit_breakers:
                self.circuit_breakers[name] = CircuitBreaker(name, config)
            return self.circuit_breakers[name]
    
    def register_error_handler(self, error_type: str, handler: Callable):
        """Register error handler for specific error type"""
        self.error_handlers[error_type] = handler
        logger.info(f"Registered error handler for {error_type}")
    
    def register_fallback_handler(self, service_name: str, handler: Callable):
        """Register fallback handler for service"""
        self.fallback_handlers[service_name] = handler
        logger.info(f"Registered fallback handler for {service_name}")
    
    def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> Any:
        """Handle error with registered handlers"""
        error_type = type(error).__name__
        
        # Update global error metrics
        self.global_errors.total_requests += 1
        self.global_errors.failed_requests += 1
        self.global_errors.error_types[error_type] = self.global_errors.error_types.get(error_type, 0) + 1
        
        # Try specific error handler
        if error_type in self.error_handlers:
            try:
                return self.error_handlers[error_type](error, context)
            except Exception as handler_error:
                logger.error(f"Error handler for {error_type} failed: {handler_error}")
        
        # Try fallback handler
        service_name = context.get('service_name') if context else None
        if service_name and service_name in self.fallback_handlers:
            try:
                return self.fallback_handlers[service_name](error, context)
            except Exception as fallback_error:
                logger.error(f"Fallback handler for {service_name} failed: {fallback_error}")
        
        # No handler available, re-raise
        raise error
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health metrics"""
        with self.lock:
            circuit_health = {}
            for name, cb in self.circuit_breakers.items():
                metrics = cb.get_metrics()
                circuit_health[name] = {
                    'state': metrics['state'],
                    'failure_rate': metrics['failure_rate'],
                    'healthy': metrics['state'] == 'CLOSED' and metrics['failure_rate'] < 0.1
                }
            
            overall_healthy = all(cb['healthy'] for cb in circuit_health.values())
            
            return {
                'overall_healthy': overall_healthy,
                'circuit_breakers': circuit_health,
                'global_error_rate': (self.global_errors.failed_requests / 
                                    max(self.global_errors.total_requests, 1)),
                'total_errors': self.global_errors.failed_requests,
                'error_types': self.global_errors.error_types.copy()
            }

# Global error recovery manager
error_recovery = ErrorRecoveryManager()

# Convenience decorators
def circuit_breaker(name: str, config: CircuitBreakerConfig = None):
    """Circuit breaker decorator"""
    cb = error_recovery.get_circuit_breaker(name, config)
    return cb

def retry(max_attempts: int = 3, base_delay: float = 1.0, exceptions: tuple = (Exception,)):
    """Retry decorator with default configuration"""
    config = RetryConfig(max_attempts=max_attempts, base_delay=base_delay)
    return retry_with_backoff(config, exceptions)
