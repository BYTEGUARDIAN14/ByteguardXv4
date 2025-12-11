"""
WebAuthn Biometric 2FA Implementation
Provides passwordless authentication using biometrics, security keys, and platform authenticators
"""

import logging
import json
import base64
import secrets
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticationCredential,
    RegistrationCredential
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from ..database.connection_pool import db_manager
from ..database.models import User
from .audit_logger import audit_logger

logger = logging.getLogger(__name__)

class AuthenticatorType(Enum):
    """Types of WebAuthn authenticators"""
    PLATFORM = "platform"  # Built-in biometrics (TouchID, FaceID, Windows Hello)
    CROSS_PLATFORM = "cross-platform"  # External security keys (YubiKey, etc.)
    HYBRID = "hybrid"  # Both platform and cross-platform

class BiometricType(Enum):
    """Types of biometric authentication"""
    FINGERPRINT = "fingerprint"
    FACE_RECOGNITION = "face_recognition"
    VOICE_RECOGNITION = "voice_recognition"
    IRIS_SCAN = "iris_scan"
    PALM_PRINT = "palm_print"

@dataclass
class WebAuthnCredential:
    """WebAuthn credential information"""
    credential_id: str
    public_key: str
    sign_count: int
    user_id: str
    authenticator_type: AuthenticatorType
    biometric_type: Optional[BiometricType] = None
    device_name: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None
    is_active: bool = True
    backup_eligible: bool = False
    backup_state: bool = False

@dataclass
class WebAuthnChallenge:
    """WebAuthn challenge for registration/authentication"""
    challenge: str
    user_id: str
    challenge_type: str  # 'registration' or 'authentication'
    created_at: datetime
    expires_at: datetime
    options: Dict[str, Any]

class WebAuthnManager:
    """
    Comprehensive WebAuthn biometric 2FA manager
    """
    
    def __init__(self, rp_id: str = "byteguardx.com", rp_name: str = "ByteGuardX"):
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = f"https://{rp_id}"
        
        # Challenge storage (in production, use Redis or database)
        self.active_challenges: Dict[str, WebAuthnChallenge] = {}
        
        # Credential storage
        self.user_credentials: Dict[str, List[WebAuthnCredential]] = {}
        
        # Supported algorithms (in order of preference)
        self.supported_algorithms = [
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.ECDSA_SHA_384,
            COSEAlgorithmIdentifier.ECDSA_SHA_512,
            COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
            COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
        ]
    
    def start_registration(self, user_id: str, username: str, display_name: str,
                          authenticator_type: AuthenticatorType = AuthenticatorType.PLATFORM,
                          require_resident_key: bool = True) -> Dict[str, Any]:
        """Start WebAuthn credential registration process"""
        try:
            # Get existing credentials to exclude
            existing_credentials = self._get_user_credentials(user_id)
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=cred.credential_id.encode())
                for cred in existing_credentials
            ]
            
            # Configure authenticator selection
            authenticator_selection = AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM if authenticator_type == AuthenticatorType.PLATFORM else None,
                resident_key=ResidentKeyRequirement.REQUIRED if require_resident_key else ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED
            )
            
            # Generate registration options
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id.encode(),
                user_name=username,
                user_display_name=display_name,
                attestation=AttestationConveyancePreference.DIRECT,
                authenticator_selection=authenticator_selection,
                supported_pub_key_algs=self.supported_algorithms,
                exclude_credentials=exclude_credentials,
                timeout=300000  # 5 minutes
            )
            
            # Store challenge
            challenge_id = secrets.token_urlsafe(32)
            challenge = WebAuthnChallenge(
                challenge=options.challenge,
                user_id=user_id,
                challenge_type='registration',
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(minutes=5),
                options=options.__dict__
            )
            self.active_challenges[challenge_id] = challenge
            
            # Convert options to JSON-serializable format
            options_dict = {
                'challenge': base64.urlsafe_b64encode(options.challenge).decode().rstrip('='),
                'rp': {'id': options.rp.id, 'name': options.rp.name},
                'user': {
                    'id': base64.urlsafe_b64encode(options.user.id).decode().rstrip('='),
                    'name': options.user.name,
                    'displayName': options.user.display_name
                },
                'pubKeyCredParams': [
                    {'type': 'public-key', 'alg': alg.value}
                    for alg in options.supported_pub_key_algs
                ],
                'timeout': options.timeout,
                'attestation': options.attestation.value,
                'authenticatorSelection': {
                    'authenticatorAttachment': options.authenticator_selection.authenticator_attachment.value if options.authenticator_selection.authenticator_attachment else None,
                    'residentKey': options.authenticator_selection.resident_key.value,
                    'userVerification': options.authenticator_selection.user_verification.value
                },
                'excludeCredentials': [
                    {
                        'type': 'public-key',
                        'id': base64.urlsafe_b64encode(cred.id).decode().rstrip('=')
                    }
                    for cred in exclude_credentials
                ]
            }
            
            logger.info(f"Started WebAuthn registration for user {user_id}")
            
            return {
                'success': True,
                'challenge_id': challenge_id,
                'options': options_dict
            }
            
        except Exception as e:
            logger.error(f"Failed to start WebAuthn registration: {e}")
            return {'success': False, 'error': str(e)}
    
    def complete_registration(self, challenge_id: str, credential_response: Dict[str, Any],
                            device_name: str = "", biometric_type: BiometricType = None) -> Dict[str, Any]:
        """Complete WebAuthn credential registration"""
        try:
            # Get challenge
            challenge = self.active_challenges.get(challenge_id)
            if not challenge:
                return {'success': False, 'error': 'Invalid or expired challenge'}
            
            if challenge.expires_at < datetime.now():
                del self.active_challenges[challenge_id]
                return {'success': False, 'error': 'Challenge expired'}
            
            # Parse credential response
            credential = RegistrationCredential.parse_raw(json.dumps(credential_response))
            
            # Verify registration response
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge.challenge,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id
            )
            
            if not verification.verified:
                logger.warning(f"WebAuthn registration verification failed for user {challenge.user_id}")
                return {'success': False, 'error': 'Registration verification failed'}
            
            # Store credential
            webauthn_credential = WebAuthnCredential(
                credential_id=base64.urlsafe_b64encode(verification.credential_id).decode().rstrip('='),
                public_key=base64.urlsafe_b64encode(verification.credential_public_key).decode().rstrip('='),
                sign_count=verification.sign_count,
                user_id=challenge.user_id,
                authenticator_type=AuthenticatorType.PLATFORM,  # Detect from response
                biometric_type=biometric_type,
                device_name=device_name or "Unknown Device",
                backup_eligible=verification.credential_backup_eligible,
                backup_state=verification.credential_backup_state
            )
            
            self._store_credential(webauthn_credential)
            
            # Clean up challenge
            del self.active_challenges[challenge_id]
            
            # Log successful registration
            audit_logger.log_security_event(
                event_type="webauthn_registration_success",
                user_id=challenge.user_id,
                details={
                    'credential_id': webauthn_credential.credential_id,
                    'device_name': device_name,
                    'biometric_type': biometric_type.value if biometric_type else None,
                    'authenticator_type': webauthn_credential.authenticator_type.value
                }
            )
            
            logger.info(f"WebAuthn registration completed for user {challenge.user_id}")
            
            return {
                'success': True,
                'credential_id': webauthn_credential.credential_id,
                'device_name': webauthn_credential.device_name
            }
            
        except Exception as e:
            logger.error(f"Failed to complete WebAuthn registration: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_authentication(self, user_id: str = None) -> Dict[str, Any]:
        """Start WebAuthn authentication process"""
        try:
            # Get user credentials if user_id provided
            allow_credentials = []
            if user_id:
                user_credentials = self._get_user_credentials(user_id)
                allow_credentials = [
                    PublicKeyCredentialDescriptor(id=cred.credential_id.encode())
                    for cred in user_credentials if cred.is_active
                ]
            
            # Generate authentication options
            options = generate_authentication_options(
                rp_id=self.rp_id,
                timeout=300000,  # 5 minutes
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.REQUIRED
            )
            
            # Store challenge
            challenge_id = secrets.token_urlsafe(32)
            challenge = WebAuthnChallenge(
                challenge=options.challenge,
                user_id=user_id or "",
                challenge_type='authentication',
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(minutes=5),
                options=options.__dict__
            )
            self.active_challenges[challenge_id] = challenge
            
            # Convert options to JSON-serializable format
            options_dict = {
                'challenge': base64.urlsafe_b64encode(options.challenge).decode().rstrip('='),
                'timeout': options.timeout,
                'rpId': options.rp_id,
                'userVerification': options.user_verification.value,
                'allowCredentials': [
                    {
                        'type': 'public-key',
                        'id': base64.urlsafe_b64encode(cred.id).decode().rstrip('=')
                    }
                    for cred in allow_credentials
                ]
            }
            
            logger.info(f"Started WebAuthn authentication for user {user_id or 'unknown'}")
            
            return {
                'success': True,
                'challenge_id': challenge_id,
                'options': options_dict
            }
            
        except Exception as e:
            logger.error(f"Failed to start WebAuthn authentication: {e}")
            return {'success': False, 'error': str(e)}

    def complete_authentication(self, challenge_id: str, credential_response: Dict[str, Any]) -> Dict[str, Any]:
        """Complete WebAuthn authentication"""
        try:
            # Get challenge
            challenge = self.active_challenges.get(challenge_id)
            if not challenge:
                return {'success': False, 'error': 'Invalid or expired challenge'}

            if challenge.expires_at < datetime.now():
                del self.active_challenges[challenge_id]
                return {'success': False, 'error': 'Challenge expired'}

            # Parse credential response
            credential = AuthenticationCredential.parse_raw(json.dumps(credential_response))

            # Find the credential
            credential_id = base64.urlsafe_b64encode(credential.raw_id).decode().rstrip('=')
            stored_credential = self._find_credential(credential_id)

            if not stored_credential:
                return {'success': False, 'error': 'Credential not found'}

            if not stored_credential.is_active:
                return {'success': False, 'error': 'Credential is disabled'}

            # Verify authentication response
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge.challenge,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=base64.urlsafe_b64decode(stored_credential.public_key + '=='),
                credential_current_sign_count=stored_credential.sign_count
            )

            if not verification.verified:
                logger.warning(f"WebAuthn authentication verification failed for credential {credential_id}")
                audit_logger.log_security_event(
                    event_type="webauthn_authentication_failed",
                    user_id=stored_credential.user_id,
                    details={'credential_id': credential_id, 'reason': 'verification_failed'}
                )
                return {'success': False, 'error': 'Authentication verification failed'}

            # Update credential sign count and last used
            stored_credential.sign_count = verification.new_sign_count
            stored_credential.last_used = datetime.now()
            self._update_credential(stored_credential)

            # Clean up challenge
            del self.active_challenges[challenge_id]

            # Log successful authentication
            audit_logger.log_security_event(
                event_type="webauthn_authentication_success",
                user_id=stored_credential.user_id,
                details={
                    'credential_id': credential_id,
                    'device_name': stored_credential.device_name,
                    'biometric_type': stored_credential.biometric_type.value if stored_credential.biometric_type else None
                }
            )

            logger.info(f"WebAuthn authentication completed for user {stored_credential.user_id}")

            return {
                'success': True,
                'user_id': stored_credential.user_id,
                'credential_id': credential_id,
                'device_name': stored_credential.device_name
            }

        except Exception as e:
            logger.error(f"Failed to complete WebAuthn authentication: {e}")
            return {'success': False, 'error': str(e)}

    def _get_user_credentials(self, user_id: str) -> List[WebAuthnCredential]:
        """Get all credentials for a user"""
        return self.user_credentials.get(user_id, [])

    def _store_credential(self, credential: WebAuthnCredential):
        """Store a WebAuthn credential"""
        if credential.user_id not in self.user_credentials:
            self.user_credentials[credential.user_id] = []
        self.user_credentials[credential.user_id].append(credential)

        # In production, store in database
        # self._save_credential_to_db(credential)

    def _update_credential(self, credential: WebAuthnCredential):
        """Update a WebAuthn credential"""
        # In production, update in database
        # self._update_credential_in_db(credential)
        pass

    def _find_credential(self, credential_id: str) -> Optional[WebAuthnCredential]:
        """Find a credential by ID"""
        for user_credentials in self.user_credentials.values():
            for credential in user_credentials:
                if credential.credential_id == credential_id:
                    return credential
        return None

    def get_user_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user's WebAuthn credentials (safe for API response)"""
        credentials = self._get_user_credentials(user_id)
        return [
            {
                'credential_id': cred.credential_id,
                'device_name': cred.device_name,
                'authenticator_type': cred.authenticator_type.value,
                'biometric_type': cred.biometric_type.value if cred.biometric_type else None,
                'created_at': cred.created_at.isoformat(),
                'last_used': cred.last_used.isoformat() if cred.last_used else None,
                'is_active': cred.is_active,
                'backup_eligible': cred.backup_eligible
            }
            for cred in credentials
        ]

    def disable_credential(self, user_id: str, credential_id: str) -> bool:
        """Disable a WebAuthn credential"""
        try:
            credentials = self._get_user_credentials(user_id)
            for credential in credentials:
                if credential.credential_id == credential_id:
                    credential.is_active = False
                    self._update_credential(credential)

                    audit_logger.log_security_event(
                        event_type="webauthn_credential_disabled",
                        user_id=user_id,
                        details={'credential_id': credential_id, 'device_name': credential.device_name}
                    )

                    logger.info(f"Disabled WebAuthn credential {credential_id} for user {user_id}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to disable WebAuthn credential: {e}")
            return False

    def delete_credential(self, user_id: str, credential_id: str) -> bool:
        """Delete a WebAuthn credential"""
        try:
            if user_id in self.user_credentials:
                credentials = self.user_credentials[user_id]
                for i, credential in enumerate(credentials):
                    if credential.credential_id == credential_id:
                        deleted_credential = credentials.pop(i)

                        audit_logger.log_security_event(
                            event_type="webauthn_credential_deleted",
                            user_id=user_id,
                            details={'credential_id': credential_id, 'device_name': deleted_credential.device_name}
                        )

                        logger.info(f"Deleted WebAuthn credential {credential_id} for user {user_id}")
                        return True

            return False

        except Exception as e:
            logger.error(f"Failed to delete WebAuthn credential: {e}")
            return False

    def cleanup_expired_challenges(self):
        """Clean up expired challenges"""
        now = datetime.now()
        expired_challenges = [
            challenge_id for challenge_id, challenge in self.active_challenges.items()
            if challenge.expires_at < now
        ]

        for challenge_id in expired_challenges:
            del self.active_challenges[challenge_id]

        if expired_challenges:
            logger.info(f"Cleaned up {len(expired_challenges)} expired WebAuthn challenges")

    def get_statistics(self) -> Dict[str, Any]:
        """Get WebAuthn usage statistics"""
        total_credentials = sum(len(creds) for creds in self.user_credentials.values())
        active_credentials = sum(
            len([c for c in creds if c.is_active])
            for creds in self.user_credentials.values()
        )

        authenticator_types = {}
        biometric_types = {}

        for credentials in self.user_credentials.values():
            for credential in credentials:
                if credential.is_active:
                    auth_type = credential.authenticator_type.value
                    authenticator_types[auth_type] = authenticator_types.get(auth_type, 0) + 1

                    if credential.biometric_type:
                        bio_type = credential.biometric_type.value
                        biometric_types[bio_type] = biometric_types.get(bio_type, 0) + 1

        return {
            'total_users': len(self.user_credentials),
            'total_credentials': total_credentials,
            'active_credentials': active_credentials,
            'active_challenges': len(self.active_challenges),
            'authenticator_types': authenticator_types,
            'biometric_types': biometric_types
        }

# Global instance
webauthn_manager = WebAuthnManager()
