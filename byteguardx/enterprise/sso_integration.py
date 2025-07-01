"""
Single Sign-On (SSO) integration for ByteGuardX
Supports SAML 2.0 and OpenID Connect (OIDC) providers
"""

import logging
import json
import time
import base64
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import xml.etree.ElementTree as ET
from urllib.parse import urlencode, parse_qs
import jwt
import requests

from ..database.connection_pool import db_manager
from ..database.models import User, Organization
from ..security.jwt_utils import jwt_manager

logger = logging.getLogger(__name__)

class SSOProvider(Enum):
    """SSO provider types"""
    SAML = "saml"
    OIDC = "oidc"
    AZURE_AD = "azure_ad"
    GOOGLE = "google"
    OKTA = "okta"
    AUTH0 = "auth0"

@dataclass
class SSOConfig:
    """SSO configuration"""
    provider_type: SSOProvider
    provider_name: str
    enabled: bool = True
    
    # Common settings
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    
    # SAML specific
    saml_metadata_url: str = ""
    saml_entity_id: str = ""
    saml_sso_url: str = ""
    saml_certificate: str = ""
    
    # OIDC specific
    oidc_discovery_url: str = ""
    oidc_authorization_endpoint: str = ""
    oidc_token_endpoint: str = ""
    oidc_userinfo_endpoint: str = ""
    oidc_jwks_uri: str = ""
    
    # Attribute mapping
    attribute_mapping: Dict[str, str] = field(default_factory=lambda: {
        'email': 'email',
        'first_name': 'given_name',
        'last_name': 'family_name',
        'username': 'preferred_username',
        'groups': 'groups'
    })
    
    # Auto-provisioning
    auto_provision_users: bool = True
    default_role: str = "developer"
    
    # Additional settings
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SSOUser:
    """SSO user information"""
    provider: str
    external_id: str
    email: str
    username: str
    first_name: str = ""
    last_name: str = ""
    groups: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

class SAMLProvider:
    """SAML 2.0 SSO provider implementation"""
    
    def __init__(self, config: SSOConfig):
        self.config = config
        self.metadata = None
        self._load_metadata()
    
    def _load_metadata(self):
        """Load SAML metadata from provider"""
        try:
            if self.config.saml_metadata_url:
                response = requests.get(self.config.saml_metadata_url, timeout=30)
                response.raise_for_status()
                self.metadata = ET.fromstring(response.content)
                logger.info(f"Loaded SAML metadata for {self.config.provider_name}")
        except Exception as e:
            logger.error(f"Failed to load SAML metadata: {e}")
    
    def generate_auth_request(self, relay_state: str = None) -> str:
        """Generate SAML authentication request"""
        try:
            request_id = f"_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            issue_instant = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            saml_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{request_id}"
                    Version="2.0"
                    IssueInstant="{issue_instant}"
                    Destination="{self.config.saml_sso_url}"
                    AssertionConsumerServiceURL="{self.config.redirect_uri}">
    <saml:Issuer>{self.config.saml_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" 
                        AllowCreate="true"/>
</samlp:AuthnRequest>'''
            
            # Base64 encode the request
            encoded_request = base64.b64encode(saml_request.encode()).decode()
            
            # Build SSO URL
            params = {
                'SAMLRequest': encoded_request
            }
            if relay_state:
                params['RelayState'] = relay_state
            
            sso_url = f"{self.config.saml_sso_url}?{urlencode(params)}"
            return sso_url
            
        except Exception as e:
            logger.error(f"Failed to generate SAML auth request: {e}")
            raise
    
    def process_response(self, saml_response: str, relay_state: str = None) -> SSOUser:
        """Process SAML response and extract user information"""
        try:
            # Decode SAML response
            decoded_response = base64.b64decode(saml_response)
            response_xml = ET.fromstring(decoded_response)
            
            # Extract assertion
            assertion = response_xml.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            if assertion is None:
                raise ValueError("No assertion found in SAML response")
            
            # Extract user attributes
            attributes = {}
            attr_statements = assertion.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
            
            for attr_statement in attr_statements:
                for attr in attr_statement.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
                    attr_name = attr.get('Name')
                    attr_values = [val.text for val in attr.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')]
                    attributes[attr_name] = attr_values[0] if len(attr_values) == 1 else attr_values
            
            # Extract NameID
            name_id = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
            external_id = name_id.text if name_id is not None else ""
            
            # Map attributes to user fields
            mapping = self.config.attribute_mapping
            
            sso_user = SSOUser(
                provider=self.config.provider_name,
                external_id=external_id,
                email=attributes.get(mapping.get('email', 'email'), ''),
                username=attributes.get(mapping.get('username', 'username'), ''),
                first_name=attributes.get(mapping.get('first_name', 'first_name'), ''),
                last_name=attributes.get(mapping.get('last_name', 'last_name'), ''),
                groups=attributes.get(mapping.get('groups', 'groups'), []),
                attributes=attributes
            )
            
            return sso_user
            
        except Exception as e:
            logger.error(f"Failed to process SAML response: {e}")
            raise

class OIDCProvider:
    """OpenID Connect SSO provider implementation"""
    
    def __init__(self, config: SSOConfig):
        self.config = config
        self.discovery_doc = None
        self._load_discovery_document()
    
    def _load_discovery_document(self):
        """Load OIDC discovery document"""
        try:
            if self.config.oidc_discovery_url:
                response = requests.get(self.config.oidc_discovery_url, timeout=30)
                response.raise_for_status()
                self.discovery_doc = response.json()
                
                # Update endpoints from discovery document
                self.config.oidc_authorization_endpoint = self.discovery_doc.get('authorization_endpoint')
                self.config.oidc_token_endpoint = self.discovery_doc.get('token_endpoint')
                self.config.oidc_userinfo_endpoint = self.discovery_doc.get('userinfo_endpoint')
                self.config.oidc_jwks_uri = self.discovery_doc.get('jwks_uri')
                
                logger.info(f"Loaded OIDC discovery document for {self.config.provider_name}")
        except Exception as e:
            logger.error(f"Failed to load OIDC discovery document: {e}")
    
    def generate_auth_url(self, state: str = None, nonce: str = None) -> str:
        """Generate OIDC authorization URL"""
        try:
            params = {
                'response_type': 'code',
                'client_id': self.config.client_id,
                'redirect_uri': self.config.redirect_uri,
                'scope': 'openid profile email',
            }
            
            if state:
                params['state'] = state
            if nonce:
                params['nonce'] = nonce
            
            auth_url = f"{self.config.oidc_authorization_endpoint}?{urlencode(params)}"
            return auth_url
            
        except Exception as e:
            logger.error(f"Failed to generate OIDC auth URL: {e}")
            raise
    
    def exchange_code(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange authorization code for tokens"""
        try:
            token_data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.config.redirect_uri,
                'client_id': self.config.client_id,
                'client_secret': self.config.client_secret
            }
            
            response = requests.post(
                self.config.oidc_token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to exchange OIDC code: {e}")
            raise
    
    def get_user_info(self, access_token: str) -> SSOUser:
        """Get user information using access token"""
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            response = requests.get(
                self.config.oidc_userinfo_endpoint,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            user_info = response.json()
            mapping = self.config.attribute_mapping
            
            sso_user = SSOUser(
                provider=self.config.provider_name,
                external_id=user_info.get('sub', ''),
                email=user_info.get(mapping.get('email', 'email'), ''),
                username=user_info.get(mapping.get('username', 'preferred_username'), ''),
                first_name=user_info.get(mapping.get('first_name', 'given_name'), ''),
                last_name=user_info.get(mapping.get('last_name', 'family_name'), ''),
                groups=user_info.get(mapping.get('groups', 'groups'), []),
                attributes=user_info
            )
            
            return sso_user
            
        except Exception as e:
            logger.error(f"Failed to get OIDC user info: {e}")
            raise

class SSOManager:
    """
    SSO manager for handling multiple SSO providers
    Supports SAML 2.0 and OpenID Connect
    """
    
    def __init__(self, config_dir: str = "data/sso"):
        self.config_dir = config_dir
        self.providers: Dict[str, SSOConfig] = {}
        self.saml_providers: Dict[str, SAMLProvider] = {}
        self.oidc_providers: Dict[str, OIDCProvider] = {}
        
        self._load_configurations()
    
    def add_provider(self, config: SSOConfig) -> bool:
        """Add SSO provider configuration"""
        try:
            self.providers[config.provider_name] = config
            
            if config.provider_type == SSOProvider.SAML:
                self.saml_providers[config.provider_name] = SAMLProvider(config)
            elif config.provider_type in [SSOProvider.OIDC, SSOProvider.AZURE_AD, 
                                         SSOProvider.GOOGLE, SSOProvider.OKTA, SSOProvider.AUTH0]:
                self.oidc_providers[config.provider_name] = OIDCProvider(config)
            
            self._save_configuration(config)
            logger.info(f"Added SSO provider: {config.provider_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add SSO provider: {e}")
            return False
    
    def get_auth_url(self, provider_name: str, state: str = None) -> str:
        """Get authentication URL for provider"""
        if provider_name not in self.providers:
            raise ValueError(f"Provider {provider_name} not found")
        
        config = self.providers[provider_name]
        
        if config.provider_type == SSOProvider.SAML:
            provider = self.saml_providers[provider_name]
            return provider.generate_auth_request(state)
        else:
            provider = self.oidc_providers[provider_name]
            return provider.generate_auth_url(state)
    
    def process_callback(self, provider_name: str, **kwargs) -> SSOUser:
        """Process SSO callback and return user information"""
        if provider_name not in self.providers:
            raise ValueError(f"Provider {provider_name} not found")
        
        config = self.providers[provider_name]
        
        if config.provider_type == SSOProvider.SAML:
            provider = self.saml_providers[provider_name]
            saml_response = kwargs.get('SAMLResponse')
            relay_state = kwargs.get('RelayState')
            return provider.process_response(saml_response, relay_state)
        else:
            provider = self.oidc_providers[provider_name]
            code = kwargs.get('code')
            state = kwargs.get('state')
            
            # Exchange code for tokens
            tokens = provider.exchange_code(code, state)
            access_token = tokens.get('access_token')
            
            # Get user information
            return provider.get_user_info(access_token)
    
    def provision_user(self, sso_user: SSOUser, organization_id: str = None) -> User:
        """Provision or update user from SSO information"""
        try:
            with db_manager.get_session() as session:
                # Check if user already exists
                user = session.query(User).filter(User.email == sso_user.email).first()
                
                if user:
                    # Update existing user
                    user.first_name = sso_user.first_name or user.first_name
                    user.last_name = sso_user.last_name or user.last_name
                    user.last_login = datetime.now()
                    
                    # Update SSO attributes
                    if not user.preferences:
                        user.preferences = {}
                    user.preferences['sso_provider'] = sso_user.provider
                    user.preferences['sso_external_id'] = sso_user.external_id
                    user.preferences['sso_groups'] = sso_user.groups
                    
                else:
                    # Create new user
                    config = self.providers[sso_user.provider]
                    
                    if not config.auto_provision_users:
                        raise ValueError("User auto-provisioning is disabled")
                    
                    user = User(
                        email=sso_user.email,
                        username=sso_user.username or sso_user.email.split('@')[0],
                        first_name=sso_user.first_name,
                        last_name=sso_user.last_name,
                        role=config.default_role,
                        organization_id=organization_id,
                        is_active=True,
                        email_verified=True,  # SSO users are pre-verified
                        preferences={
                            'sso_provider': sso_user.provider,
                            'sso_external_id': sso_user.external_id,
                            'sso_groups': sso_user.groups
                        }
                    )
                    
                    # Set a random password (won't be used for SSO users)
                    import secrets
                    user.set_password(secrets.token_urlsafe(32))
                    
                    session.add(user)
                
                session.commit()
                
                logger.info(f"Provisioned SSO user: {sso_user.email}")
                return user
                
        except Exception as e:
            logger.error(f"Failed to provision SSO user: {e}")
            raise
    
    def generate_jwt_token(self, user: User) -> Dict[str, str]:
        """Generate JWT token for SSO user"""
        user_data = {
            'email': user.email,
            'username': user.username,
            'role': user.role,
            'subscription_tier': user.subscription_tier,
            'sso_login': True
        }
        
        return jwt_manager.generate_tokens(str(user.id), user_data)
    
    def list_providers(self) -> List[Dict[str, Any]]:
        """List configured SSO providers"""
        providers = []
        for name, config in self.providers.items():
            if config.enabled:
                providers.append({
                    'name': name,
                    'type': config.provider_type.value,
                    'display_name': config.provider_name,
                    'auth_url': f'/auth/sso/{name}'
                })
        return providers
    
    def _load_configurations(self):
        """Load SSO configurations from storage"""
        # Implementation would load from database or config files
        pass
    
    def _save_configuration(self, config: SSOConfig):
        """Save SSO configuration to storage"""
        # Implementation would save to database or config files
        pass

# Global SSO manager instance
sso_manager = SSOManager()
