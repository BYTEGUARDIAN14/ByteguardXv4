#!/usr/bin/env python3
"""
Certificate Pinning for ByteGuardX
Implements SSL certificate pinning for external API calls and plugin marketplace
"""

import logging
import hashlib
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import requests
from urllib.parse import urlparse
import base64

try:
    import certifi
    CERTIFI_AVAILABLE = True
except ImportError:
    CERTIFI_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class PinnedCertificate:
    """Represents a pinned certificate"""
    hostname: str
    pin_type: str  # 'sha256', 'sha1'
    pin_value: str
    backup_pins: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

@dataclass
class CertificateValidationResult:
    """Certificate validation result"""
    hostname: str
    is_valid: bool
    pin_matched: bool
    certificate_info: Dict[str, Any]
    validation_errors: List[str]
    validated_at: datetime

class CertificatePinning:
    """
    SSL Certificate pinning manager
    """
    
    def __init__(self):
        # Pinned certificates for critical services
        self.pinned_certificates = self._load_default_pins()
        
        # Validation cache
        self.validation_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Certificate validation results
        self.validation_results = []
        
        logger.info("Certificate pinning initialized")
    
    def _load_default_pins(self) -> Dict[str, PinnedCertificate]:
        """Load default certificate pins for critical services"""
        pins = {}
        
        # GitHub API (for plugin marketplace)
        pins['api.github.com'] = PinnedCertificate(
            hostname='api.github.com',
            pin_type='sha256',
            pin_value='jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=',  # Example pin
            backup_pins=[
                'k2v657xBsOVe1PQRwOsHsw3bsGT2VzIqz5K+59sNQws=',  # Backup pin
                'WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18='   # Another backup
            ],
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=365),
            is_active=True
        )
        
        # Plugin marketplace (if external)
        pins['plugins.byteguardx.com'] = PinnedCertificate(
            hostname='plugins.byteguardx.com',
            pin_type='sha256',
            pin_value='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',  # Placeholder
            backup_pins=[
                'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
                'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC='
            ],
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=365),
            is_active=True
        )
        
        # Threat intelligence feeds
        pins['feeds.byteguardx.com'] = PinnedCertificate(
            hostname='feeds.byteguardx.com',
            pin_type='sha256',
            pin_value='DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=',  # Placeholder
            backup_pins=[
                'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=',
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF='
            ],
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=365),
            is_active=True
        )
        
        return pins
    
    def add_pin(self, hostname: str, pin_value: str, pin_type: str = 'sha256', 
                backup_pins: List[str] = None) -> bool:
        """Add a new certificate pin"""
        try:
            pin = PinnedCertificate(
                hostname=hostname,
                pin_type=pin_type,
                pin_value=pin_value,
                backup_pins=backup_pins or [],
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=365),
                is_active=True
            )
            
            self.pinned_certificates[hostname] = pin
            
            # Clear cache for this hostname
            self.validation_cache.pop(hostname, None)
            
            logger.info(f"Added certificate pin for {hostname}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add certificate pin for {hostname}: {e}")
            return False
    
    def remove_pin(self, hostname: str) -> bool:
        """Remove a certificate pin"""
        try:
            if hostname in self.pinned_certificates:
                del self.pinned_certificates[hostname]
                self.validation_cache.pop(hostname, None)
                logger.info(f"Removed certificate pin for {hostname}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to remove certificate pin for {hostname}: {e}")
            return False
    
    def get_certificate_info(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Get certificate information for a hostname"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
            
            # Calculate certificate pins
            sha256_pin = self._calculate_pin(cert, 'sha256')
            sha1_pin = self._calculate_pin(cert, 'sha1')
            
            return {
                'hostname': hostname,
                'subject': dict(x[0] for x in cert_info['subject']),
                'issuer': dict(x[0] for x in cert_info['issuer']),
                'version': cert_info['version'],
                'serial_number': cert_info['serialNumber'],
                'not_before': cert_info['notBefore'],
                'not_after': cert_info['notAfter'],
                'sha256_pin': sha256_pin,
                'sha1_pin': sha1_pin,
                'subject_alt_names': cert_info.get('subjectAltName', [])
            }
            
        except Exception as e:
            logger.error(f"Failed to get certificate info for {hostname}: {e}")
            return None
    
    def _calculate_pin(self, cert_der: bytes, hash_type: str = 'sha256') -> str:
        """Calculate certificate pin"""
        try:
            if hash_type == 'sha256':
                digest = hashlib.sha256(cert_der).digest()
            elif hash_type == 'sha1':
                digest = hashlib.sha1(cert_der).digest()
            else:
                raise ValueError(f"Unsupported hash type: {hash_type}")
            
            return base64.b64encode(digest).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to calculate certificate pin: {e}")
            return ''
    
    def validate_certificate(self, hostname: str, port: int = 443) -> CertificateValidationResult:
        """Validate certificate against pinned values"""
        validation_errors = []
        pin_matched = False
        
        try:
            # Check cache first
            cache_key = f"{hostname}:{port}"
            if cache_key in self.validation_cache:
                cached_result = self.validation_cache[cache_key]
                if (datetime.now() - cached_result['timestamp']).total_seconds() < self.cache_ttl:
                    return cached_result['result']
            
            # Get certificate info
            cert_info = self.get_certificate_info(hostname, port)
            
            if not cert_info:
                validation_errors.append("Failed to retrieve certificate")
                result = CertificateValidationResult(
                    hostname=hostname,
                    is_valid=False,
                    pin_matched=False,
                    certificate_info={},
                    validation_errors=validation_errors,
                    validated_at=datetime.now()
                )
                return result
            
            # Check if hostname has pinned certificate
            if hostname not in self.pinned_certificates:
                # No pin configured - allow but log
                logger.info(f"No certificate pin configured for {hostname}")
                result = CertificateValidationResult(
                    hostname=hostname,
                    is_valid=True,
                    pin_matched=True,  # No pin to match
                    certificate_info=cert_info,
                    validation_errors=[],
                    validated_at=datetime.now()
                )
                
                # Cache result
                self.validation_cache[cache_key] = {
                    'result': result,
                    'timestamp': datetime.now()
                }
                
                return result
            
            # Validate against pinned certificate
            pinned_cert = self.pinned_certificates[hostname]
            
            if not pinned_cert.is_active:
                validation_errors.append("Certificate pin is disabled")
            
            # Check expiration
            if pinned_cert.expires_at and datetime.now() > pinned_cert.expires_at:
                validation_errors.append("Certificate pin has expired")
            
            # Get current certificate pin
            if pinned_cert.pin_type == 'sha256':
                current_pin = cert_info['sha256_pin']
            elif pinned_cert.pin_type == 'sha1':
                current_pin = cert_info['sha1_pin']
            else:
                validation_errors.append(f"Unsupported pin type: {pinned_cert.pin_type}")
                current_pin = ''
            
            # Check pin match
            all_pins = [pinned_cert.pin_value] + pinned_cert.backup_pins
            pin_matched = current_pin in all_pins
            
            if not pin_matched:
                validation_errors.append(f"Certificate pin mismatch for {hostname}")
                logger.warning(f"Certificate pin mismatch for {hostname}: expected one of {all_pins}, got {current_pin}")
            
            # Create result
            result = CertificateValidationResult(
                hostname=hostname,
                is_valid=len(validation_errors) == 0,
                pin_matched=pin_matched,
                certificate_info=cert_info,
                validation_errors=validation_errors,
                validated_at=datetime.now()
            )
            
            # Cache result
            self.validation_cache[cache_key] = {
                'result': result,
                'timestamp': datetime.now()
            }
            
            # Store validation result
            self.validation_results.append(result)
            
            # Keep only recent results
            if len(self.validation_results) > 1000:
                self.validation_results = self.validation_results[-1000:]
            
            return result
            
        except Exception as e:
            logger.error(f"Certificate validation failed for {hostname}: {e}")
            validation_errors.append(f"Validation error: {str(e)}")
            
            return CertificateValidationResult(
                hostname=hostname,
                is_valid=False,
                pin_matched=False,
                certificate_info={},
                validation_errors=validation_errors,
                validated_at=datetime.now()
            )
    
    def create_pinned_session(self) -> requests.Session:
        """Create requests session with certificate pinning"""
        session = requests.Session()
        
        # Custom adapter with certificate pinning
        adapter = PinnedHTTPSAdapter(self)
        session.mount('https://', adapter)
        
        return session
    
    def get_pinning_status(self) -> Dict[str, Any]:
        """Get certificate pinning status"""
        active_pins = sum(1 for pin in self.pinned_certificates.values() if pin.is_active)
        expired_pins = sum(1 for pin in self.pinned_certificates.values() 
                          if pin.expires_at and datetime.now() > pin.expires_at)
        
        recent_validations = [
            result for result in self.validation_results
            if (datetime.now() - result.validated_at).total_seconds() < 3600
        ]
        
        failed_validations = [result for result in recent_validations if not result.is_valid]
        
        return {
            'total_pins': len(self.pinned_certificates),
            'active_pins': active_pins,
            'expired_pins': expired_pins,
            'recent_validations': len(recent_validations),
            'failed_validations': len(failed_validations),
            'cache_size': len(self.validation_cache),
            'pinned_hostnames': list(self.pinned_certificates.keys())
        }
    
    def update_pins_from_live_certificates(self) -> Dict[str, bool]:
        """Update certificate pins from live certificates (admin function)"""
        results = {}
        
        for hostname in self.pinned_certificates.keys():
            try:
                cert_info = self.get_certificate_info(hostname)
                if cert_info:
                    # Update pin with current certificate
                    current_pin = cert_info['sha256_pin']
                    
                    # Keep old pin as backup
                    old_pin = self.pinned_certificates[hostname]
                    backup_pins = [old_pin.pin_value] + old_pin.backup_pins
                    
                    # Update pin
                    self.pinned_certificates[hostname].pin_value = current_pin
                    self.pinned_certificates[hostname].backup_pins = backup_pins[:2]  # Keep 2 backups
                    
                    # Clear cache
                    self.validation_cache.pop(hostname, None)
                    
                    results[hostname] = True
                    logger.info(f"Updated certificate pin for {hostname}")
                else:
                    results[hostname] = False
                    logger.error(f"Failed to get certificate for {hostname}")
                    
            except Exception as e:
                results[hostname] = False
                logger.error(f"Failed to update pin for {hostname}: {e}")
        
        return results

class PinnedHTTPSAdapter(requests.adapters.HTTPSAdapter):
    """Custom HTTPS adapter with certificate pinning"""
    
    def __init__(self, cert_pinning: CertificatePinning):
        self.cert_pinning = cert_pinning
        super().__init__()
    
    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with custom SSL context"""
        context = ssl.create_default_context()
        
        # Custom certificate verification
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)
    
    def send(self, request, **kwargs):
        """Send request with certificate pinning validation"""
        # Extract hostname from URL
        hostname = urlparse(request.url).hostname
        
        # Validate certificate pin before sending request
        if hostname:
            validation_result = self.cert_pinning.validate_certificate(hostname)
            
            if not validation_result.is_valid or not validation_result.pin_matched:
                raise requests.exceptions.SSLError(
                    f"Certificate pinning validation failed for {hostname}: "
                    f"{', '.join(validation_result.validation_errors)}"
                )
        
        # Send request if validation passed
        return super().send(request, **kwargs)

# Global certificate pinning instance
cert_pinning = CertificatePinning()
