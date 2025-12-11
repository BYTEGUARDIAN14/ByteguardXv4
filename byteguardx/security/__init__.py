"""
Enhanced security module for ByteGuardX
Provides production-ready authentication, authorization, and security features
"""

# Import only existing modules to avoid import errors
try:
    from .auth_middleware import AuthMiddleware, TokenValidator
except ImportError:
    pass

try:
    from .rbac import RoleBasedAccessControl, Permission, Role
except ImportError:
    pass

try:
    from .jwt_utils import JWTManager, TokenBlacklist
except ImportError:
    pass

try:
    from .two_factor_auth import TwoFactorAuth, TOTPManager
except ImportError:
    pass

try:
    from .password_policy import PasswordPolicy, PasswordValidator
except ImportError:
    pass

try:
    from .rate_limiter import RateLimiter, BruteForceProtection
except ImportError:
    pass

try:
    from .encryption import DataEncryption, SecureStorage
except ImportError:
    pass

try:
    from .audit_logger import AuditLogger, SecurityEvent
except ImportError:
    pass

__all__ = [
    'AuthMiddleware', 'TokenValidator', 'RoleBasedAccessControl',
    'Permission', 'Role', 'JWTManager', 'TokenBlacklist',
    # 'SessionManager',  # TODO: Implement session handler
    'InputValidator', 'ValidationError',
    'TwoFactorAuth', 'TOTPManager', 'PasswordPolicy', 'PasswordValidator',
    'RateLimiter', 'BruteForceProtection', 'DataEncryption', 'SecureStorage',
    'AuditLogger', 'SecurityEvent'
]
