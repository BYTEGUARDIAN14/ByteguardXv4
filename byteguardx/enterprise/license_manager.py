"""
License management and usage tracking for ByteGuardX
Provides enterprise license validation and feature enforcement
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import threading
from pathlib import Path
import hashlib
import hmac

logger = logging.getLogger(__name__)

class LicenseType(Enum):
    """License types"""
    COMMUNITY = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    TRIAL = "trial"

class FeatureFlag(Enum):
    """Feature flags controlled by license"""
    UNLIMITED_SCANS = "unlimited_scans"
    ADVANCED_ANALYTICS = "advanced_analytics"
    SSO_INTEGRATION = "sso_integration"
    API_ACCESS = "api_access"
    CUSTOM_RULES = "custom_rules"
    PRIORITY_SUPPORT = "priority_support"
    AUDIT_LOGS = "audit_logs"
    COMPLIANCE_REPORTS = "compliance_reports"
    MULTI_TENANT = "multi_tenant"
    CICD_INTEGRATION = "cicd_integration"

@dataclass
class LicenseInfo:
    """License information"""
    license_key: str
    license_type: LicenseType
    organization: str
    issued_date: datetime
    expiry_date: datetime
    max_users: int
    max_scans_per_month: int
    enabled_features: List[FeatureFlag] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_valid(self) -> bool:
        """Check if license is currently valid"""
        return datetime.now() < self.expiry_date
    
    @property
    def days_until_expiry(self) -> int:
        """Days until license expires"""
        if not self.is_valid:
            return 0
        return (self.expiry_date - datetime.now()).days

@dataclass
class UsageMetrics:
    """Usage tracking metrics"""
    period_start: datetime
    period_end: datetime
    total_scans: int = 0
    active_users: int = 0
    api_calls: int = 0
    storage_used_mb: float = 0.0
    features_used: Dict[str, int] = field(default_factory=dict)

class LicenseManager:
    """
    Enterprise license manager with usage tracking and feature enforcement
    """
    
    def __init__(self, license_dir: str = "data/license"):
        self.license_dir = Path(license_dir)
        self.license_dir.mkdir(parents=True, exist_ok=True)
        
        # Current license
        self.current_license: Optional[LicenseInfo] = None
        
        # Usage tracking
        self.usage_metrics: Dict[str, UsageMetrics] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Load license
        self._load_license()
        
        # Initialize usage tracking
        self._init_usage_tracking()
    
    def install_license(self, license_key: str, signature: str = None) -> bool:
        """Install and validate license"""
        try:
            # Validate license format
            if not self._validate_license_format(license_key):
                logger.error("Invalid license format")
                return False
            
            # Decode license
            license_info = self._decode_license(license_key)
            if not license_info:
                logger.error("Failed to decode license")
                return False
            
            # Validate signature if provided
            if signature and not self._validate_signature(license_key, signature):
                logger.error("Invalid license signature")
                return False
            
            # Check expiry
            if not license_info.is_valid:
                logger.error("License has expired")
                return False
            
            with self._lock:
                self.current_license = license_info
                self._save_license()
            
            logger.info(f"License installed successfully: {license_info.license_type.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install license: {e}")
            return False
    
    def check_feature_access(self, feature: FeatureFlag) -> bool:
        """Check if feature is enabled by current license"""
        with self._lock:
            if not self.current_license:
                # Community features only
                community_features = {
                    FeatureFlag.API_ACCESS,
                }
                return feature in community_features
            
            if not self.current_license.is_valid:
                logger.warning("License has expired")
                return False
            
            return feature in self.current_license.enabled_features
    
    def check_usage_limits(self, metric_type: str, current_value: int) -> bool:
        """Check if usage is within license limits"""
        with self._lock:
            if not self.current_license:
                # Community limits
                limits = {
                    "users": 1,
                    "scans_per_month": 100,
                    "api_calls_per_day": 1000
                }
                return current_value <= limits.get(metric_type, 0)
            
            if not self.current_license.is_valid:
                return False
            
            # Check license-specific limits
            if metric_type == "users":
                return current_value <= self.current_license.max_users
            elif metric_type == "scans_per_month":
                return current_value <= self.current_license.max_scans_per_month
            
            return True
    
    def track_usage(self, metric_type: str, value: int = 1, metadata: Dict[str, Any] = None):
        """Track usage metrics"""
        try:
            current_month = datetime.now().strftime("%Y-%m")
            
            with self._lock:
                if current_month not in self.usage_metrics:
                    month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
                    
                    self.usage_metrics[current_month] = UsageMetrics(
                        period_start=month_start,
                        period_end=month_end
                    )
                
                metrics = self.usage_metrics[current_month]
                
                if metric_type == "scan":
                    metrics.total_scans += value
                elif metric_type == "api_call":
                    metrics.api_calls += value
                elif metric_type == "storage":
                    metrics.storage_used_mb += value
                elif metric_type == "feature_usage":
                    feature_name = metadata.get("feature") if metadata else "unknown"
                    metrics.features_used[feature_name] = metrics.features_used.get(feature_name, 0) + value
                
                # Save usage data
                self._save_usage_metrics()
            
        except Exception as e:
            logger.error(f"Failed to track usage: {e}")
    
    def get_license_status(self) -> Dict[str, Any]:
        """Get current license status"""
        with self._lock:
            if not self.current_license:
                return {
                    "license_type": "community",
                    "status": "active",
                    "features": ["basic_scanning", "api_access"],
                    "limits": {
                        "max_users": 1,
                        "max_scans_per_month": 100
                    }
                }
            
            return {
                "license_type": self.current_license.license_type.value,
                "organization": self.current_license.organization,
                "status": "active" if self.current_license.is_valid else "expired",
                "expiry_date": self.current_license.expiry_date.isoformat(),
                "days_until_expiry": self.current_license.days_until_expiry,
                "features": [f.value for f in self.current_license.enabled_features],
                "limits": {
                    "max_users": self.current_license.max_users,
                    "max_scans_per_month": self.current_license.max_scans_per_month
                }
            }
    
    def get_usage_report(self, period: str = None) -> Dict[str, Any]:
        """Get usage report for specified period"""
        period = period or datetime.now().strftime("%Y-%m")
        
        with self._lock:
            if period not in self.usage_metrics:
                return {"error": "No usage data for specified period"}
            
            metrics = self.usage_metrics[period]
            license_status = self.get_license_status()
            
            return {
                "period": period,
                "period_start": metrics.period_start.isoformat(),
                "period_end": metrics.period_end.isoformat(),
                "usage": {
                    "total_scans": metrics.total_scans,
                    "active_users": metrics.active_users,
                    "api_calls": metrics.api_calls,
                    "storage_used_mb": metrics.storage_used_mb,
                    "features_used": metrics.features_used
                },
                "limits": license_status.get("limits", {}),
                "compliance": {
                    "scans_within_limit": metrics.total_scans <= license_status.get("limits", {}).get("max_scans_per_month", 0),
                    "users_within_limit": metrics.active_users <= license_status.get("limits", {}).get("max_users", 0)
                }
            }
    
    def _validate_license_format(self, license_key: str) -> bool:
        """Validate license key format"""
        # Simple format validation
        return len(license_key) >= 32 and license_key.replace("-", "").isalnum()
    
    def _decode_license(self, license_key: str) -> Optional[LicenseInfo]:
        """Decode license key to extract information"""
        try:
            # This is a simplified decoder - in production would use proper cryptography
            import base64
            
            # Remove dashes and decode
            clean_key = license_key.replace("-", "")
            
            # For demo purposes, create a license based on key pattern
            if clean_key.startswith("COMM"):
                license_type = LicenseType.COMMUNITY
                max_users = 1
                max_scans = 100
                features = [FeatureFlag.API_ACCESS]
            elif clean_key.startswith("PROF"):
                license_type = LicenseType.PROFESSIONAL
                max_users = 10
                max_scans = 1000
                features = [
                    FeatureFlag.API_ACCESS,
                    FeatureFlag.ADVANCED_ANALYTICS,
                    FeatureFlag.CUSTOM_RULES,
                    FeatureFlag.CICD_INTEGRATION
                ]
            elif clean_key.startswith("ENT"):
                license_type = LicenseType.ENTERPRISE
                max_users = 100
                max_scans = 10000
                features = list(FeatureFlag)  # All features
            else:
                license_type = LicenseType.TRIAL
                max_users = 5
                max_scans = 500
                features = [
                    FeatureFlag.API_ACCESS,
                    FeatureFlag.ADVANCED_ANALYTICS,
                    FeatureFlag.SSO_INTEGRATION
                ]
            
            return LicenseInfo(
                license_key=license_key,
                license_type=license_type,
                organization="Demo Organization",
                issued_date=datetime.now(),
                expiry_date=datetime.now() + timedelta(days=365),
                max_users=max_users,
                max_scans_per_month=max_scans,
                enabled_features=features
            )
            
        except Exception as e:
            logger.error(f"Failed to decode license: {e}")
            return None
    
    def _validate_signature(self, license_key: str, signature: str) -> bool:
        """Validate license signature"""
        try:
            # In production, this would validate against a public key
            secret_key = "byteguardx-license-validation-key"
            expected_signature = hmac.new(
                secret_key.encode(),
                license_key.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            logger.error(f"Failed to validate signature: {e}")
            return False
    
    def _load_license(self):
        """Load license from storage"""
        try:
            license_file = self.license_dir / "license.json"
            if license_file.exists():
                with open(license_file, 'r') as f:
                    data = json.load(f)
                
                self.current_license = LicenseInfo(
                    license_key=data['license_key'],
                    license_type=LicenseType(data['license_type']),
                    organization=data['organization'],
                    issued_date=datetime.fromisoformat(data['issued_date']),
                    expiry_date=datetime.fromisoformat(data['expiry_date']),
                    max_users=data['max_users'],
                    max_scans_per_month=data['max_scans_per_month'],
                    enabled_features=[FeatureFlag(f) for f in data['enabled_features']],
                    metadata=data.get('metadata', {})
                )
                
                logger.info("License loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load license: {e}")
    
    def _save_license(self):
        """Save license to storage"""
        try:
            if not self.current_license:
                return
            
            license_file = self.license_dir / "license.json"
            data = {
                'license_key': self.current_license.license_key,
                'license_type': self.current_license.license_type.value,
                'organization': self.current_license.organization,
                'issued_date': self.current_license.issued_date.isoformat(),
                'expiry_date': self.current_license.expiry_date.isoformat(),
                'max_users': self.current_license.max_users,
                'max_scans_per_month': self.current_license.max_scans_per_month,
                'enabled_features': [f.value for f in self.current_license.enabled_features],
                'metadata': self.current_license.metadata
            }
            
            with open(license_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to save license: {e}")
    
    def _init_usage_tracking(self):
        """Initialize usage tracking"""
        try:
            usage_file = self.license_dir / "usage.json"
            if usage_file.exists():
                with open(usage_file, 'r') as f:
                    data = json.load(f)
                
                for period, metrics_data in data.items():
                    self.usage_metrics[period] = UsageMetrics(
                        period_start=datetime.fromisoformat(metrics_data['period_start']),
                        period_end=datetime.fromisoformat(metrics_data['period_end']),
                        total_scans=metrics_data.get('total_scans', 0),
                        active_users=metrics_data.get('active_users', 0),
                        api_calls=metrics_data.get('api_calls', 0),
                        storage_used_mb=metrics_data.get('storage_used_mb', 0.0),
                        features_used=metrics_data.get('features_used', {})
                    )
            
        except Exception as e:
            logger.error(f"Failed to load usage metrics: {e}")
    
    def _save_usage_metrics(self):
        """Save usage metrics to storage"""
        try:
            usage_file = self.license_dir / "usage.json"
            data = {}
            
            for period, metrics in self.usage_metrics.items():
                data[period] = {
                    'period_start': metrics.period_start.isoformat(),
                    'period_end': metrics.period_end.isoformat(),
                    'total_scans': metrics.total_scans,
                    'active_users': metrics.active_users,
                    'api_calls': metrics.api_calls,
                    'storage_used_mb': metrics.storage_used_mb,
                    'features_used': metrics.features_used
                }
            
            with open(usage_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to save usage metrics: {e}")

# Global license manager
license_manager = LicenseManager()
