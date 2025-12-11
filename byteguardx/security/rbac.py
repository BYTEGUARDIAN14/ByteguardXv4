"""
Enhanced Role-Based Access Control (RBAC) for ByteGuardX
Provides fine-grained permissions and enterprise-grade access control
"""

import logging
from enum import Enum
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class Permission(Enum):
    """Fine-grained permissions for ByteGuardX"""
    # Scan permissions
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_DELETE = "scan:delete"
    SCAN_SHARE = "scan:share"
    
    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_IMPERSONATE = "user:impersonate"
    
    # Organization management
    ORG_CREATE = "org:create"
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    ORG_MANAGE_USERS = "org:manage_users"
    
    # Pattern and ML management
    PATTERN_CREATE = "pattern:create"
    PATTERN_UPDATE = "pattern:update"
    PATTERN_DELETE = "pattern:delete"
    PATTERN_TRAIN = "pattern:train"
    
    # System administration
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_MONITOR = "system:monitor"
    SYSTEM_CONFIG = "system:config"
    
    # API access
    API_READ = "api:read"
    API_WRITE = "api:write"
    API_ADMIN = "api:admin"
    
    # Reports and analytics
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_SHARE = "report:share"
    ANALYTICS_READ = "analytics:read"
    
    # Compliance and audit
    AUDIT_READ = "audit:read"
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_EXPORT = "compliance:export"

class Role(Enum):
    """Predefined roles with permission sets"""
    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"
    API_USER = "api_user"

@dataclass
class RoleDefinition:
    """Role definition with permissions and constraints"""
    name: str
    display_name: str
    description: str
    permissions: Set[Permission]
    inherits_from: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    is_system_role: bool = True
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class AccessContext:
    """Context for access control decisions"""
    user_id: str
    organization_id: Optional[str] = None
    resource_type: str = ""
    resource_id: str = ""
    action: str = ""
    ip_address: str = ""
    user_agent: str = ""
    additional_context: Dict[str, Any] = field(default_factory=dict)

class RoleBasedAccessControl:
    """
    Enterprise-grade RBAC system with hierarchical roles,
    fine-grained permissions, and context-aware access control
    """
    
    def __init__(self, config_dir: str = "data/rbac"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Role definitions
        self.roles: Dict[str, RoleDefinition] = {}
        self.custom_roles: Dict[str, RoleDefinition] = {}
        
        # User role assignments
        self.user_roles: Dict[str, Set[str]] = {}
        self.user_permissions: Dict[str, Set[Permission]] = {}
        
        # Organization-specific roles
        self.org_roles: Dict[str, Dict[str, Set[str]]] = {}
        
        # Access policies
        self.access_policies: List[Dict[str, Any]] = []
        
        # Initialize system roles
        self._initialize_system_roles()
        self._load_configuration()
    
    def _initialize_system_roles(self):
        """Initialize predefined system roles"""
        
        # Super Admin - Full system access
        self.roles[Role.SUPER_ADMIN.value] = RoleDefinition(
            name=Role.SUPER_ADMIN.value,
            display_name="Super Administrator",
            description="Full system access with all permissions",
            permissions=set(Permission),  # All permissions
            is_system_role=True
        )
        
        # Organization Admin - Manage organization and users
        self.roles[Role.ORG_ADMIN.value] = RoleDefinition(
            name=Role.ORG_ADMIN.value,
            display_name="Organization Administrator",
            description="Manage organization, users, and scans within organization",
            permissions={
                Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_DELETE, Permission.SCAN_SHARE,
                Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE, Permission.USER_DELETE,
                Permission.ORG_READ, Permission.ORG_UPDATE, Permission.ORG_MANAGE_USERS,
                Permission.PATTERN_CREATE, Permission.PATTERN_UPDATE, Permission.PATTERN_DELETE,
                Permission.API_READ, Permission.API_WRITE,
                Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_SHARE,
                Permission.ANALYTICS_READ, Permission.AUDIT_READ
            },
            constraints={
                "scope": "organization",  # Limited to own organization
                "max_users": 100,
                "max_scans_per_month": 1000
            },
            is_system_role=True
        )
        
        # Security Analyst - Advanced scanning and analysis
        self.roles[Role.SECURITY_ANALYST.value] = RoleDefinition(
            name=Role.SECURITY_ANALYST.value,
            display_name="Security Analyst",
            description="Advanced scanning, pattern training, and security analysis",
            permissions={
                Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_SHARE,
                Permission.USER_READ,
                Permission.PATTERN_CREATE, Permission.PATTERN_UPDATE, Permission.PATTERN_TRAIN,
                Permission.API_READ, Permission.API_WRITE,
                Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_SHARE,
                Permission.ANALYTICS_READ, Permission.AUDIT_READ
            },
            constraints={
                "scope": "organization",
                "max_scans_per_month": 500
            },
            is_system_role=True
        )
        
        # Developer - Basic scanning and development features
        self.roles[Role.DEVELOPER.value] = RoleDefinition(
            name=Role.DEVELOPER.value,
            display_name="Developer",
            description="Basic scanning and development-focused features",
            permissions={
                Permission.SCAN_CREATE, Permission.SCAN_READ,
                Permission.USER_READ,
                Permission.API_READ,
                Permission.REPORT_CREATE, Permission.REPORT_READ
            },
            constraints={
                "scope": "user",  # Limited to own resources
                "max_scans_per_month": 100
            },
            is_system_role=True
        )
        
        # Viewer - Read-only access
        self.roles[Role.VIEWER.value] = RoleDefinition(
            name=Role.VIEWER.value,
            display_name="Viewer",
            description="Read-only access to scans and reports",
            permissions={
                Permission.SCAN_READ,
                Permission.USER_READ,
                Permission.API_READ,
                Permission.REPORT_READ
            },
            constraints={
                "scope": "organization",
                "read_only": True
            },
            is_system_role=True
        )
        
        # API User - Programmatic access
        self.roles[Role.API_USER.value] = RoleDefinition(
            name=Role.API_USER.value,
            display_name="API User",
            description="Programmatic API access for integrations",
            permissions={
                Permission.SCAN_CREATE, Permission.SCAN_READ,
                Permission.API_READ, Permission.API_WRITE,
                Permission.REPORT_CREATE, Permission.REPORT_READ
            },
            constraints={
                "scope": "organization",
                "api_only": True,
                "rate_limit": "1000/hour"
            },
            is_system_role=True
        )
    
    def assign_role(self, user_id: str, role_name: str, organization_id: Optional[str] = None) -> bool:
        """Assign role to user"""
        try:
            # Validate role exists
            if role_name not in self.roles and role_name not in self.custom_roles:
                raise ValueError(f"Role {role_name} does not exist")
            
            # Initialize user roles if needed
            if user_id not in self.user_roles:
                self.user_roles[user_id] = set()
            
            # Add role
            if organization_id:
                # Organization-specific role
                if organization_id not in self.org_roles:
                    self.org_roles[organization_id] = {}
                if user_id not in self.org_roles[organization_id]:
                    self.org_roles[organization_id][user_id] = set()
                self.org_roles[organization_id][user_id].add(role_name)
            else:
                # Global role
                self.user_roles[user_id].add(role_name)
            
            # Update user permissions cache
            self._update_user_permissions(user_id)
            
            # Save configuration
            self._save_configuration()
            
            logger.info(f"Assigned role {role_name} to user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to assign role: {e}")
            return False
    
    def revoke_role(self, user_id: str, role_name: str, organization_id: Optional[str] = None) -> bool:
        """Revoke role from user"""
        try:
            if organization_id:
                # Remove organization-specific role
                if (organization_id in self.org_roles and 
                    user_id in self.org_roles[organization_id]):
                    self.org_roles[organization_id][user_id].discard(role_name)
            else:
                # Remove global role
                if user_id in self.user_roles:
                    self.user_roles[user_id].discard(role_name)
            
            # Update user permissions cache
            self._update_user_permissions(user_id)
            
            # Save configuration
            self._save_configuration()
            
            logger.info(f"Revoked role {role_name} from user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke role: {e}")
            return False
    
    def check_permission(self, user_id: str, permission: Permission, 
                        context: Optional[AccessContext] = None) -> bool:
        """Check if user has specific permission"""
        try:
            # Get user permissions
            user_permissions = self._get_user_permissions(user_id, context)
            
            # Check permission
            has_permission = permission in user_permissions
            
            # Apply context-specific policies
            if has_permission and context:
                has_permission = self._apply_access_policies(user_id, permission, context)
            
            return has_permission
            
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return False
    
    def _get_user_permissions(self, user_id: str, context: Optional[AccessContext] = None) -> Set[Permission]:
        """Get all permissions for user"""
        permissions = set()
        
        # Get global roles
        user_roles = self.user_roles.get(user_id, set())
        
        # Get organization-specific roles
        if context and context.organization_id:
            org_roles = self.org_roles.get(context.organization_id, {})
            user_org_roles = org_roles.get(user_id, set())
            user_roles.update(user_org_roles)
        
        # Collect permissions from all roles
        for role_name in user_roles:
            role_def = self.roles.get(role_name) or self.custom_roles.get(role_name)
            if role_def:
                permissions.update(role_def.permissions)
        
        return permissions
    
    def _update_user_permissions(self, user_id: str):
        """Update cached user permissions"""
        permissions = self._get_user_permissions(user_id)
        self.user_permissions[user_id] = permissions
    
    def _apply_access_policies(self, user_id: str, permission: Permission, 
                             context: AccessContext) -> bool:
        """Apply context-specific access policies"""
        # Check role constraints
        user_roles = self.user_roles.get(user_id, set())
        
        for role_name in user_roles:
            role_def = self.roles.get(role_name) or self.custom_roles.get(role_name)
            if not role_def:
                continue
            
            constraints = role_def.constraints
            
            # Check scope constraints
            if constraints.get("scope") == "user":
                # User can only access their own resources
                if context.resource_type in ["scan", "report"] and context.user_id != user_id:
                    return False
            
            elif constraints.get("scope") == "organization":
                # User can only access resources in their organization
                if context.organization_id and context.organization_id != context.organization_id:
                    return False
            
            # Check read-only constraints
            if constraints.get("read_only") and permission.value.endswith(":write"):
                return False
            
            # Check API-only constraints
            if constraints.get("api_only") and context.user_agent and "browser" in context.user_agent.lower():
                return False
        
        return True
    
    def create_custom_role(self, role_name: str, display_name: str, description: str,
                          permissions: List[Permission], constraints: Dict[str, Any] = None) -> bool:
        """Create custom role"""
        try:
            if role_name in self.roles or role_name in self.custom_roles:
                raise ValueError(f"Role {role_name} already exists")
            
            custom_role = RoleDefinition(
                name=role_name,
                display_name=display_name,
                description=description,
                permissions=set(permissions),
                constraints=constraints or {},
                is_system_role=False
            )
            
            self.custom_roles[role_name] = custom_role
            self._save_configuration()
            
            logger.info(f"Created custom role: {role_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create custom role: {e}")
            return False
    
    def get_user_roles(self, user_id: str, organization_id: Optional[str] = None) -> List[str]:
        """Get all roles assigned to user"""
        roles = list(self.user_roles.get(user_id, set()))
        
        if organization_id and organization_id in self.org_roles:
            org_roles = self.org_roles[organization_id].get(user_id, set())
            roles.extend(list(org_roles))
        
        return list(set(roles))  # Remove duplicates
    
    def _load_configuration(self):
        """Load RBAC configuration from files"""
        try:
            # Load custom roles
            custom_roles_file = self.config_dir / "custom_roles.json"
            if custom_roles_file.exists():
                with open(custom_roles_file, 'r') as f:
                    data = json.load(f)
                    for role_data in data:
                        role_def = RoleDefinition(
                            name=role_data['name'],
                            display_name=role_data['display_name'],
                            description=role_data['description'],
                            permissions={Permission(p) for p in role_data['permissions']},
                            constraints=role_data.get('constraints', {}),
                            is_system_role=False
                        )
                        self.custom_roles[role_data['name']] = role_def
            
            # Load user role assignments
            user_roles_file = self.config_dir / "user_roles.json"
            if user_roles_file.exists():
                with open(user_roles_file, 'r') as f:
                    self.user_roles = {k: set(v) for k, v in json.load(f).items()}
            
            # Load organization roles
            org_roles_file = self.config_dir / "org_roles.json"
            if org_roles_file.exists():
                with open(org_roles_file, 'r') as f:
                    data = json.load(f)
                    self.org_roles = {
                        org_id: {user_id: set(roles) for user_id, roles in users.items()}
                        for org_id, users in data.items()
                    }
            
        except Exception as e:
            logger.error(f"Failed to load RBAC configuration: {e}")
    
    def _save_configuration(self):
        """Save RBAC configuration to files"""
        try:
            # Save custom roles
            custom_roles_file = self.config_dir / "custom_roles.json"
            with open(custom_roles_file, 'w') as f:
                roles_data = []
                for role_def in self.custom_roles.values():
                    roles_data.append({
                        'name': role_def.name,
                        'display_name': role_def.display_name,
                        'description': role_def.description,
                        'permissions': [p.value for p in role_def.permissions],
                        'constraints': role_def.constraints
                    })
                json.dump(roles_data, f, indent=2)
            
            # Save user role assignments
            user_roles_file = self.config_dir / "user_roles.json"
            with open(user_roles_file, 'w') as f:
                json.dump({k: list(v) for k, v in self.user_roles.items()}, f, indent=2)
            
            # Save organization roles
            org_roles_file = self.config_dir / "org_roles.json"
            with open(org_roles_file, 'w') as f:
                data = {
                    org_id: {user_id: list(roles) for user_id, roles in users.items()}
                    for org_id, users in self.org_roles.items()
                }
                json.dump(data, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to save RBAC configuration: {e}")

# Global RBAC instance
rbac = RoleBasedAccessControl()
