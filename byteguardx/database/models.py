"""
SQLAlchemy database models for ByteGuardX
Replaces JSON file storage with proper database persistence
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import uuid
import json
from enum import Enum

from sqlalchemy import (
    create_engine, Column, String, Integer, DateTime, Boolean, 
    Text, JSON, Float, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
import bcrypt

Base = declarative_base()

# Enums for consistent data types
class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class UserRole(Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"

class SubscriptionTier(Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class User(Base):
    """User model with enhanced security and tracking"""
    __tablename__ = 'users'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile information
    first_name = Column(String(100))
    last_name = Column(String(100))
    role = Column(String(50), nullable=False, default=UserRole.DEVELOPER.value)
    subscription_tier = Column(String(50), nullable=False, default=SubscriptionTier.FREE.value)
    
    # Organization
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'))
    organization = relationship("Organization", back_populates="users")
    
    # Status and timestamps
    is_active = Column(Boolean, default=True, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)
    last_login = Column(DateTime(timezone=True))
    
    # Usage tracking
    scans_this_month = Column(Integer, default=0, nullable=False)
    total_scans = Column(Integer, default=0, nullable=False)
    
    # Settings and preferences
    preferences = Column(JSON, default=dict)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="user")
    user_feedback = relationship("UserFeedback", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def set_password(self, password: str):
        """Hash and set password using bcrypt"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'subscription_tier': self.subscription_tier,
            'organization_id': str(self.organization_id) if self.organization_id else None,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'scans_this_month': self.scans_this_month,
            'total_scans': self.total_scans,
            'preferences': self.preferences
        }

class Organization(Base):
    """Organization model for enterprise features"""
    __tablename__ = 'organizations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True, index=True)
    
    # Settings
    settings = Column(JSON, default=dict)
    subscription_tier = Column(String(50), nullable=False, default=SubscriptionTier.FREE.value)
    
    # Status and timestamps
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    users = relationship("User", back_populates="organization")
    scan_results = relationship("ScanResult", back_populates="organization")

class ScanResult(Base):
    """Scan result model to replace JSON storage"""
    __tablename__ = 'scan_results'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(100), unique=True, nullable=False, index=True)
    
    # Scan metadata
    directory_path = Column(Text, nullable=False)
    total_files = Column(Integer, default=0, nullable=False)
    status = Column(String(50), nullable=False, default=ScanStatus.PENDING.value)
    
    # User and organization
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="scan_results")
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'))
    organization = relationship("Organization", back_populates="scan_results")
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Scan configuration
    scan_config = Column(JSON, default=dict)
    
    # Summary statistics
    total_findings = Column(Integer, default=0, nullable=False)
    critical_findings = Column(Integer, default=0, nullable=False)
    high_findings = Column(Integer, default=0, nullable=False)
    medium_findings = Column(Integer, default=0, nullable=False)
    low_findings = Column(Integer, default=0, nullable=False)
    
    # Performance metrics
    scan_duration_seconds = Column(Float)
    files_per_second = Column(Float)
    
    # Relationships
    findings = relationship("Finding", back_populates="scan_result", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_scan_user_created', 'user_id', 'created_at'),
        Index('idx_scan_org_created', 'organization_id', 'created_at'),
        Index('idx_scan_status', 'status'),
    )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'directory_path': self.directory_path,
            'total_files': self.total_files,
            'status': self.status,
            'user_id': str(self.user_id),
            'organization_id': str(self.organization_id) if self.organization_id else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'scan_config': self.scan_config,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'scan_duration_seconds': self.scan_duration_seconds,
            'files_per_second': self.files_per_second
        }

class Finding(Base):
    """Individual vulnerability finding"""
    __tablename__ = 'findings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Scan relationship
    scan_result_id = Column(UUID(as_uuid=True), ForeignKey('scan_results.id'), nullable=False)
    scan_result = relationship("ScanResult", back_populates="findings")
    
    # Finding details
    vulnerability_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Location information
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer)
    column_number = Column(Integer)
    
    # Code context
    code_snippet = Column(Text)
    matched_pattern = Column(Text)
    
    # Risk assessment
    confidence_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    
    # Fix information
    fix_suggestion = Column(Text)
    fix_applied = Column(Boolean, default=False)
    
    # Metadata
    scanner_type = Column(String(50), nullable=False)  # secret, dependency, ai_pattern
    metadata = Column(JSON, default=dict)
    
    # Status
    is_false_positive = Column(Boolean, default=False)
    is_suppressed = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    user_feedback = relationship("UserFeedback", back_populates="finding")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_finding_scan_severity', 'scan_result_id', 'severity'),
        Index('idx_finding_type_severity', 'vulnerability_type', 'severity'),
        Index('idx_finding_file_path', 'file_path'),
    )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'scan_result_id': str(self.scan_result_id),
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'column_number': self.column_number,
            'code_snippet': self.code_snippet,
            'matched_pattern': self.matched_pattern,
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'fix_suggestion': self.fix_suggestion,
            'fix_applied': self.fix_applied,
            'scanner_type': self.scanner_type,
            'metadata': self.metadata,
            'is_false_positive': self.is_false_positive,
            'is_suppressed': self.is_suppressed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class UserFeedback(Base):
    """User feedback on findings for ML learning"""
    __tablename__ = 'user_feedback'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="user_feedback")
    finding_id = Column(UUID(as_uuid=True), ForeignKey('findings.id'), nullable=False)
    finding = relationship("Finding", back_populates="user_feedback")

    # Feedback details
    is_false_positive = Column(Boolean, nullable=False)
    feedback_type = Column(String(50), nullable=False)  # false_positive, severity_change, etc.
    comments = Column(Text)
    suggested_severity = Column(String(20))

    # Metadata
    confidence = Column(Float, default=1.0)
    metadata = Column(JSON, default=dict)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)

    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'finding_id', name='unique_user_finding_feedback'),
        Index('idx_feedback_type', 'feedback_type'),
    )

class Pattern(Base):
    """Learned patterns from ML training"""
    __tablename__ = 'patterns'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Pattern details
    pattern_type = Column(String(50), nullable=False, index=True)
    pattern_regex = Column(Text, nullable=False)
    description = Column(Text)

    # Classification
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence_threshold = Column(Float, default=0.5)

    # Performance metrics
    true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    precision = Column(Float, default=0.0)
    recall = Column(Float, default=0.0)

    # Status
    is_active = Column(Boolean, default=True)
    is_learned = Column(Boolean, default=False)  # True if ML-generated

    # Metadata
    metadata = Column(JSON, default=dict)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Indexes
    __table_args__ = (
        Index('idx_pattern_type_active', 'pattern_type', 'is_active'),
        Index('idx_pattern_vuln_type', 'vulnerability_type'),
    )

class AuditLog(Base):
    """Audit trail for security and compliance"""
    __tablename__ = 'audit_logs'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # User and action
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    user = relationship("User", back_populates="audit_logs")
    action = Column(String(100), nullable=False, index=True)

    # Resource information
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100))

    # Request details
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    endpoint = Column(String(255))
    method = Column(String(10))

    # Result
    status_code = Column(Integer)
    success = Column(Boolean, default=True)
    error_message = Column(Text)

    # Additional context
    metadata = Column(JSON, default=dict)

    # Timestamp
    created_at = Column(DateTime(timezone=True), default=datetime.now, nullable=False)

    # Indexes for performance
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_created', 'created_at'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )

# Database session management
from sqlalchemy.orm import scoped_session

class DatabaseSession:
    """Database session factory"""

    def __init__(self, database_url: str):
        self.engine = create_engine(
            database_url,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False  # Set to True for SQL debugging
        )
        self.SessionLocal = scoped_session(sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        ))

    def create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(bind=self.engine)

    def get_session(self):
        """Get database session"""
        return self.SessionLocal()

    def close_session(self):
        """Close session"""
        self.SessionLocal.remove()

# Global database instance
db = None

def init_database(database_url: str = "sqlite:///byteguardx.db"):
    """Initialize database connection"""
    global db
    db = DatabaseSession(database_url)
    db.create_tables()
    return db
