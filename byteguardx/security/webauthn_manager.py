#!/usr/bin/env python3
"""
WebAuthn (FIDO2) Authentication Manager for ByteGuardX
Implements passwordless authentication with hardware security keys
"""

import logging
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import base64

try:
    from webauthn import generate_registration_options, verify_registration_response
    from webauthn import generate_authentication_options, verify_authentication_response
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        AttestationConveyancePreference,
        PublicKeyCredentialDescriptor,
        AuthenticatorAttachment,
        ResidentKeyRequirement
    )
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class WebAuthnCredential:
    """Represents a WebAuthn credential"""
    credential_id: str
    public_key: str
    sign_count: int
    user_id: str
    created_at: datetime
    last_used: datetime
    device_name: str
    aaguid: str
    is_backup_eligible: bool
    is_backup_state: bool

@dataclass
class WebAuthnChallenge:
    """Represents a WebAuthn challenge"""
    challenge: str
    user_id: str
    expires_at: datetime
    challenge_type: str  # 'registration' or 'authentication'

class WebAuthnManager:
    """
    Advanced WebAuthn manager for passwordless authentication
    """
    
    def __init__(self, rp_id: str = "localhost", rp_name: str = "ByteGuardX"):
        if not WEBAUTHN_AVAILABLE:
            logger.warning("WebAuthn not available - install webauthn package")
            return
            
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = f"https://{rp_id}" if rp_id != "localhost" else "http://localhost:3002"
        
        # Storage for credentials and challenges (use database in production)
        self.credentials: Dict[str, List[WebAuthnCredential]] = {}
        self.challenges: Dict[str, WebAuthnChallenge] = {}
        
        # Supported algorithms (in order of preference)
        self.supported_algorithms = [
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
        ]
    
    def generate_registration_options(self, user_id: str, username: str, display_name: str) -> Dict[str, Any]:
        """
        Generate WebAuthn registration options for a user
        """
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("WebAuthn not available")
        
        try:
            # Get existing credentials for this user
            existing_credentials = self.credentials.get(user_id, [])
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=base64.b64decode(cred.credential_id))
                for cred in existing_credentials
            ]
            
            # Generate registration options
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id.encode('utf-8'),
                user_name=username,
                user_display_name=display_name,
                attestation=AttestationConveyancePreference.DIRECT,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                    resident_key=ResidentKeyRequirement.PREFERRED,
                    user_verification=UserVerificationRequirement.PREFERRED,
                ),
                challenge=secrets.token_bytes(64),
                exclude_credentials=exclude_credentials,
                supported_pub_key_algs=self.supported_algorithms,
            )
            
            # Store challenge
            challenge_id = secrets.token_urlsafe(32)
            self.challenges[challenge_id] = WebAuthnChallenge(
                challenge=base64.b64encode(options.challenge).decode('utf-8'),
                user_id=user_id,
                expires_at=datetime.now() + timedelta(minutes=5),
                challenge_type='registration'
            )
            
            # Convert to JSON-serializable format
            options_dict = {
                'rp': {'id': options.rp.id, 'name': options.rp.name},
                'user': {
                    'id': base64.b64encode(options.user.id).decode('utf-8'),
                    'name': options.user.name,
                    'displayName': options.user.display_name
                },
                'challenge': base64.b64encode(options.challenge).decode('utf-8'),
                'pubKeyCredParams': [
                    {'type': 'public-key', 'alg': alg.value}
                    for alg in options.pub_key_cred_params
                ],
                'timeout': options.timeout,
                'excludeCredentials': [
                    {
                        'type': 'public-key',
                        'id': base64.b64encode(cred.id).decode('utf-8')
                    }
                    for cred in options.exclude_credentials
                ],
                'authenticatorSelection': {
                    'authenticatorAttachment': options.authenticator_selection.authenticator_attachment.value if options.authenticator_selection.authenticator_attachment else None,
                    'residentKey': options.authenticator_selection.resident_key.value if options.authenticator_selection.resident_key else None,
                    'userVerification': options.authenticator_selection.user_verification.value
                },
                'attestation': options.attestation.value,
                'challengeId': challenge_id
            }
            
            logger.info(f"Generated WebAuthn registration options for user {user_id}")
            return options_dict
            
        except Exception as e:
            logger.error(f"Failed to generate registration options: {e}")
            raise
    
    def verify_registration_response(self, challenge_id: str, credential_response: Dict[str, Any]) -> bool:
        """
        Verify WebAuthn registration response
        """
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("WebAuthn not available")
        
        try:
            # Get and validate challenge
            if challenge_id not in self.challenges:
                logger.warning(f"Invalid challenge ID: {challenge_id}")
                return False
            
            challenge = self.challenges[challenge_id]
            if datetime.now() > challenge.expires_at:
                logger.warning(f"Expired challenge: {challenge_id}")
                del self.challenges[challenge_id]
                return False
            
            if challenge.challenge_type != 'registration':
                logger.warning(f"Invalid challenge type for registration: {challenge.challenge_type}")
                return False
            
            # Verify the registration response
            verification = verify_registration_response(
                credential=credential_response,
                expected_challenge=base64.b64decode(challenge.challenge),
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
            )
            
            if verification.verified:
                # Store the credential
                credential = WebAuthnCredential(
                    credential_id=base64.b64encode(verification.credential_id).decode('utf-8'),
                    public_key=base64.b64encode(verification.credential_public_key).decode('utf-8'),
                    sign_count=verification.sign_count,
                    user_id=challenge.user_id,
                    created_at=datetime.now(),
                    last_used=datetime.now(),
                    device_name=credential_response.get('deviceName', 'Unknown Device'),
                    aaguid=verification.aaguid.hex() if verification.aaguid else '',
                    is_backup_eligible=verification.credential_backup_eligible,
                    is_backup_state=verification.credential_backup_state
                )
                
                if challenge.user_id not in self.credentials:
                    self.credentials[challenge.user_id] = []
                
                self.credentials[challenge.user_id].append(credential)
                
                # Clean up challenge
                del self.challenges[challenge_id]
                
                logger.info(f"Successfully registered WebAuthn credential for user {challenge.user_id}")
                return True
            else:
                logger.warning(f"WebAuthn registration verification failed for user {challenge.user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify registration response: {e}")
            return False
    
    def generate_authentication_options(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate WebAuthn authentication options
        """
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("WebAuthn not available")
        
        try:
            # Get user credentials if user_id provided
            allow_credentials = []
            if user_id and user_id in self.credentials:
                allow_credentials = [
                    PublicKeyCredentialDescriptor(id=base64.b64decode(cred.credential_id))
                    for cred in self.credentials[user_id]
                ]
            
            # Generate authentication options
            options = generate_authentication_options(
                rp_id=self.rp_id,
                challenge=secrets.token_bytes(64),
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.PREFERRED,
            )
            
            # Store challenge
            challenge_id = secrets.token_urlsafe(32)
            self.challenges[challenge_id] = WebAuthnChallenge(
                challenge=base64.b64encode(options.challenge).decode('utf-8'),
                user_id=user_id or 'unknown',
                expires_at=datetime.now() + timedelta(minutes=5),
                challenge_type='authentication'
            )
            
            # Convert to JSON-serializable format
            options_dict = {
                'challenge': base64.b64encode(options.challenge).decode('utf-8'),
                'timeout': options.timeout,
                'rpId': options.rp_id,
                'allowCredentials': [
                    {
                        'type': 'public-key',
                        'id': base64.b64encode(cred.id).decode('utf-8')
                    }
                    for cred in options.allow_credentials
                ],
                'userVerification': options.user_verification.value,
                'challengeId': challenge_id
            }
            
            logger.info(f"Generated WebAuthn authentication options for user {user_id}")
            return options_dict
            
        except Exception as e:
            logger.error(f"Failed to generate authentication options: {e}")
            raise
    
    def verify_authentication_response(self, challenge_id: str, credential_response: Dict[str, Any]) -> Optional[str]:
        """
        Verify WebAuthn authentication response
        Returns user_id if successful, None if failed
        """
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("WebAuthn not available")
        
        try:
            # Get and validate challenge
            if challenge_id not in self.challenges:
                logger.warning(f"Invalid challenge ID: {challenge_id}")
                return None
            
            challenge = self.challenges[challenge_id]
            if datetime.now() > challenge.expires_at:
                logger.warning(f"Expired challenge: {challenge_id}")
                del self.challenges[challenge_id]
                return None
            
            if challenge.challenge_type != 'authentication':
                logger.warning(f"Invalid challenge type for authentication: {challenge.challenge_type}")
                return None
            
            # Find the credential
            credential_id = credential_response.get('id')
            if not credential_id:
                logger.warning("No credential ID in authentication response")
                return None
            
            user_credential = None
            user_id = None
            
            # Search for credential across all users
            for uid, user_creds in self.credentials.items():
                for cred in user_creds:
                    if cred.credential_id == credential_id:
                        user_credential = cred
                        user_id = uid
                        break
                if user_credential:
                    break
            
            if not user_credential:
                logger.warning(f"Credential not found: {credential_id}")
                return None
            
            # Verify the authentication response
            verification = verify_authentication_response(
                credential=credential_response,
                expected_challenge=base64.b64decode(challenge.challenge),
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=base64.b64decode(user_credential.public_key),
                credential_current_sign_count=user_credential.sign_count,
            )
            
            if verification.verified:
                # Update credential sign count and last used
                user_credential.sign_count = verification.new_sign_count
                user_credential.last_used = datetime.now()
                
                # Clean up challenge
                del self.challenges[challenge_id]
                
                logger.info(f"Successfully authenticated user {user_id} with WebAuthn")
                return user_id
            else:
                logger.warning(f"WebAuthn authentication verification failed")
                return None
                
        except Exception as e:
            logger.error(f"Failed to verify authentication response: {e}")
            return None
    
    def get_user_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all WebAuthn credentials for a user"""
        if user_id not in self.credentials:
            return []
        
        return [
            {
                'id': cred.credential_id,
                'device_name': cred.device_name,
                'created_at': cred.created_at.isoformat(),
                'last_used': cred.last_used.isoformat(),
                'is_backup_eligible': cred.is_backup_eligible,
                'sign_count': cred.sign_count
            }
            for cred in self.credentials[user_id]
        ]
    
    def revoke_credential(self, user_id: str, credential_id: str) -> bool:
        """Revoke a WebAuthn credential"""
        if user_id not in self.credentials:
            return False
        
        original_count = len(self.credentials[user_id])
        self.credentials[user_id] = [
            cred for cred in self.credentials[user_id]
            if cred.credential_id != credential_id
        ]
        
        revoked = len(self.credentials[user_id]) < original_count
        if revoked:
            logger.info(f"Revoked WebAuthn credential {credential_id} for user {user_id}")
        
        return revoked
    
    def cleanup_expired_challenges(self):
        """Clean up expired challenges"""
        current_time = datetime.now()
        expired_challenges = [
            challenge_id for challenge_id, challenge in self.challenges.items()
            if current_time > challenge.expires_at
        ]
        
        for challenge_id in expired_challenges:
            del self.challenges[challenge_id]
        
        if expired_challenges:
            logger.info(f"Cleaned up {len(expired_challenges)} expired WebAuthn challenges")

# Global WebAuthn manager instance
webauthn_manager = WebAuthnManager()
