"""
User and subscription models for ByteGuardX
"""

import uuid
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import bcrypt
import json
from pathlib import Path

class UserRole(Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    MANAGER = "manager"
    DEVELOPER = "developer"
    VIEWER = "viewer"

class SubscriptionTier(Enum):
    """Subscription tiers"""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class PermissionType(Enum):
    """Permission types"""
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_DELETE = "scan:delete"
    REPORT_GENERATE = "report:generate"
    REPORT_DOWNLOAD = "report:download"
    USER_MANAGE = "user:manage"
    SETTINGS_MANAGE = "settings:manage"
    ANALYTICS_VIEW = "analytics:view"

@dataclass
class User:
    """User model"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    email: str = ""
    username: str = ""
    password_hash: str = ""
    role: UserRole = UserRole.DEVELOPER
    subscription_tier: SubscriptionTier = SubscriptionTier.FREE
    organization_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = True
    email_verified: bool = False
    
    # Usage tracking
    scans_this_month: int = 0
    total_scans: int = 0
    
    # Settings
    preferences: Dict = field(default_factory=dict)
    
    def set_password(self, password: str):
        """Hash and set password"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Verify password"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def has_permission(self, permission: PermissionType) -> bool:
        """Check if user has specific permission"""
        role_permissions = {
            UserRole.ADMIN: list(PermissionType),
            UserRole.MANAGER: [
                PermissionType.SCAN_CREATE, PermissionType.SCAN_READ, PermissionType.SCAN_DELETE,
                PermissionType.REPORT_GENERATE, PermissionType.REPORT_DOWNLOAD,
                PermissionType.ANALYTICS_VIEW
            ],
            UserRole.DEVELOPER: [
                PermissionType.SCAN_CREATE, PermissionType.SCAN_READ,
                PermissionType.REPORT_GENERATE, PermissionType.REPORT_DOWNLOAD
            ],
            UserRole.VIEWER: [
                PermissionType.SCAN_READ, PermissionType.REPORT_DOWNLOAD
            ]
        }
        return permission in role_permissions.get(self.role, [])
    
    def can_scan(self) -> bool:
        """Check if user can create new scans based on subscription limits"""
        limits = {
            SubscriptionTier.FREE: 5,
            SubscriptionTier.PRO: float('inf'),
            SubscriptionTier.ENTERPRISE: float('inf')
        }
        return self.scans_this_month < limits.get(self.subscription_tier, 0)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'role': self.role.value,
            'subscription_tier': self.subscription_tier.value,
            'organization_id': self.organization_id,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'scans_this_month': self.scans_this_month,
            'total_scans': self.total_scans,
            'preferences': self.preferences
        }

@dataclass
class Organization:
    """Organization model for multi-tenancy"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    domain: str = ""
    subscription_tier: SubscriptionTier = SubscriptionTier.FREE
    max_users: int = 5
    created_at: datetime = field(default_factory=datetime.now)
    
    # Usage tracking
    total_scans: int = 0
    scans_this_month: int = 0
    
    # Settings
    settings: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'domain': self.domain,
            'subscription_tier': self.subscription_tier.value,
            'max_users': self.max_users,
            'created_at': self.created_at.isoformat(),
            'total_scans': self.total_scans,
            'scans_this_month': self.scans_this_month,
            'settings': self.settings
        }

@dataclass
class AuditLog:
    """Audit log entry"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    organization_id: Optional[str] = None
    action: str = ""
    resource_type: str = ""
    resource_id: str = ""
    details: Dict = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'organization_id': self.organization_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat()
        }

class UserManager:
    """User management with file-based storage"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.users_file = self.data_dir / "users.json"
        self.orgs_file = self.data_dir / "organizations.json"
        self.audit_file = self.data_dir / "audit_logs.json"
        
        # Initialize files if they don't exist
        for file_path in [self.users_file, self.orgs_file, self.audit_file]:
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    json.dump([], f)
    
    def create_user(self, email: str, username: str, password: str, 
                   role: UserRole = UserRole.DEVELOPER) -> User:
        """Create new user"""
        user = User(email=email, username=username, role=role)
        user.set_password(password)
        
        users = self._load_users()
        users.append(user.to_dict())
        self._save_users(users)
        
        return user
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        users = self._load_users()
        for user_data in users:
            if user_data['email'] == email:
                return self._dict_to_user(user_data)
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        users = self._load_users()
        for user_data in users:
            if user_data['id'] == user_id:
                return self._dict_to_user(user_data)
        return None
    
    def update_user(self, user: User):
        """Update user"""
        users = self._load_users()
        for i, user_data in enumerate(users):
            if user_data['id'] == user.id:
                users[i] = user.to_dict()
                break
        self._save_users(users)
    
    def log_audit(self, user_id: str, action: str, resource_type: str, 
                  resource_id: str, details: Dict = None, ip_address: str = "",
                  user_agent: str = ""):
        """Log audit event"""
        audit_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        logs = self._load_audit_logs()
        logs.append(audit_entry.to_dict())
        self._save_audit_logs(logs)
    
    def _load_users(self) -> List[Dict]:
        """Load users from file"""
        with open(self.users_file, 'r') as f:
            return json.load(f)
    
    def _save_users(self, users: List[Dict]):
        """Save users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=2)
    
    def _load_audit_logs(self) -> List[Dict]:
        """Load audit logs from file"""
        with open(self.audit_file, 'r') as f:
            return json.load(f)
    
    def _save_audit_logs(self, logs: List[Dict]):
        """Save audit logs to file"""
        with open(self.audit_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def _dict_to_user(self, user_data: Dict) -> User:
        """Convert dictionary to User object"""
        user = User(
            id=user_data['id'],
            email=user_data['email'],
            username=user_data['username'],
            password_hash=user_data.get('password_hash', ''),
            role=UserRole(user_data.get('role', 'developer')),
            subscription_tier=SubscriptionTier(user_data.get('subscription_tier', 'free')),
            organization_id=user_data.get('organization_id'),
            is_active=user_data.get('is_active', True),
            email_verified=user_data.get('email_verified', False),
            scans_this_month=user_data.get('scans_this_month', 0),
            total_scans=user_data.get('total_scans', 0),
            preferences=user_data.get('preferences', {})
        )
        
        if user_data.get('created_at'):
            user.created_at = datetime.fromisoformat(user_data['created_at'])
        if user_data.get('last_login'):
            user.last_login = datetime.fromisoformat(user_data['last_login'])
            
        return user
