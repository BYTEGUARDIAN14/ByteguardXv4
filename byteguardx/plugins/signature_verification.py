"""
Plugin Signature Verification System for ByteGuardX
Provides cryptographic verification of plugin integrity and authenticity
"""

import os
import json
import hashlib
import logging
from typing import Dict, Optional, Tuple, List
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import hmac
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

@dataclass
class PluginSignature:
    """Plugin signature metadata"""
    plugin_id: str
    plugin_version: str
    file_hash: str
    signature: str
    signer_id: str
    signed_at: str
    expires_at: Optional[str] = None
    algorithm: str = "RSA-SHA256"
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PluginSignature':
        return cls(**data)

@dataclass
class TrustedSigner:
    """Trusted plugin signer information"""
    signer_id: str
    name: str
    public_key: str
    trusted_since: str
    expires_at: Optional[str] = None
    revoked: bool = False
    permissions: List[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = ["plugin:sign"]

class PluginSignatureVerifier:
    """
    Handles plugin signature verification and trust management
    """
    
    def __init__(self, trust_store_dir: str = "data/plugin_trust"):
        self.trust_store_dir = Path(trust_store_dir)
        self.trust_store_dir.mkdir(parents=True, exist_ok=True)
        
        # Trust store files
        self.trusted_signers_file = self.trust_store_dir / "trusted_signers.json"
        self.revoked_signatures_file = self.trust_store_dir / "revoked_signatures.json"
        
        # In-memory caches
        self.trusted_signers: Dict[str, TrustedSigner] = {}
        self.revoked_signatures: List[str] = []
        
        # Load trust store
        self._load_trust_store()
        self._initialize_default_signers()
    
    def _load_trust_store(self):
        """Load trusted signers and revoked signatures"""
        try:
            # Load trusted signers
            if self.trusted_signers_file.exists():
                with open(self.trusted_signers_file, 'r') as f:
                    signers_data = json.load(f)
                    for signer_id, signer_data in signers_data.items():
                        self.trusted_signers[signer_id] = TrustedSigner(**signer_data)
            
            # Load revoked signatures
            if self.revoked_signatures_file.exists():
                with open(self.revoked_signatures_file, 'r') as f:
                    self.revoked_signatures = json.load(f)
                    
        except Exception as e:
            logger.error(f"Failed to load trust store: {e}")
    
    def _save_trust_store(self):
        """Save trust store to disk"""
        try:
            # Save trusted signers
            signers_data = {}
            for signer_id, signer in self.trusted_signers.items():
                signers_data[signer_id] = asdict(signer)
            
            with open(self.trusted_signers_file, 'w') as f:
                json.dump(signers_data, f, indent=2)
            
            # Save revoked signatures
            with open(self.revoked_signatures_file, 'w') as f:
                json.dump(self.revoked_signatures, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save trust store: {e}")
    
    def _initialize_default_signers(self):
        """Initialize default trusted signers"""
        # ByteGuardX official signer (self-signed for development)
        if "byteguardx-official" not in self.trusted_signers:
            # Generate or load official signing key
            official_key_path = self.trust_store_dir / "byteguardx_official.pem"
            if not official_key_path.exists():
                self._generate_official_signing_key(official_key_path)
            
            with open(official_key_path, 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None)
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            
            self.trusted_signers["byteguardx-official"] = TrustedSigner(
                signer_id="byteguardx-official",
                name="ByteGuardX Official",
                public_key=public_pem,
                trusted_since=datetime.now().isoformat(),
                permissions=["plugin:sign", "plugin:distribute"]
            )
            self._save_trust_store()
    
    def _generate_official_signing_key(self, key_path: Path):
        """Generate official signing key for development"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            with open(key_path, 'wb') as f:
                f.write(pem)
            
            logger.info("Generated official signing key for development")
            
        except Exception as e:
            logger.error(f"Failed to generate signing key: {e}")
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of plugin file"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate file hash: {e}")
            return ""
    
    def sign_plugin(self, plugin_path: str, signer_id: str, private_key_path: str,
                   plugin_id: str, plugin_version: str) -> Optional[PluginSignature]:
        """Sign a plugin file"""
        try:
            # Calculate file hash
            file_hash = self.calculate_file_hash(plugin_path)
            if not file_hash:
                return None
            
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None)
            
            # Create signature payload
            payload = f"{plugin_id}:{plugin_version}:{file_hash}".encode('utf-8')
            
            # Sign the payload
            signature_bytes = private_key.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signature = base64.b64encode(signature_bytes).decode('utf-8')
            
            # Create signature object
            plugin_signature = PluginSignature(
                plugin_id=plugin_id,
                plugin_version=plugin_version,
                file_hash=file_hash,
                signature=signature,
                signer_id=signer_id,
                signed_at=datetime.now().isoformat(),
                expires_at=(datetime.now() + timedelta(days=365)).isoformat()
            )
            
            logger.info(f"Successfully signed plugin {plugin_id}:{plugin_version}")
            return plugin_signature
            
        except Exception as e:
            logger.error(f"Failed to sign plugin: {e}")
            return None
    
    def verify_plugin_signature(self, plugin_path: str, signature: PluginSignature) -> Tuple[bool, str]:
        """Verify plugin signature"""
        try:
            # Check if signature is revoked
            signature_id = f"{signature.plugin_id}:{signature.plugin_version}:{signature.signature[:16]}"
            if signature_id in self.revoked_signatures:
                return False, "Signature has been revoked"
            
            # Check if signer is trusted
            if signature.signer_id not in self.trusted_signers:
                return False, f"Unknown signer: {signature.signer_id}"
            
            signer = self.trusted_signers[signature.signer_id]
            if signer.revoked:
                return False, f"Signer {signature.signer_id} has been revoked"
            
            # Check signature expiration
            if signature.expires_at:
                expires_at = datetime.fromisoformat(signature.expires_at)
                if datetime.now() > expires_at:
                    return False, "Signature has expired"
            
            # Check signer expiration
            if signer.expires_at:
                signer_expires_at = datetime.fromisoformat(signer.expires_at)
                if datetime.now() > signer_expires_at:
                    return False, "Signer certificate has expired"
            
            # Verify file hash
            current_hash = self.calculate_file_hash(plugin_path)
            if current_hash != signature.file_hash:
                return False, "File hash mismatch - plugin may have been modified"
            
            # Verify cryptographic signature
            try:
                public_key = load_pem_public_key(signer.public_key.encode('utf-8'))
                payload = f"{signature.plugin_id}:{signature.plugin_version}:{signature.file_hash}".encode('utf-8')
                signature_bytes = base64.b64decode(signature.signature)
                
                public_key.verify(
                    signature_bytes,
                    payload,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                logger.info(f"Successfully verified signature for plugin {signature.plugin_id}:{signature.plugin_version}")
                return True, "Signature verification successful"
                
            except InvalidSignature:
                return False, "Invalid cryptographic signature"
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False, f"Verification error: {str(e)}"
    
    def add_trusted_signer(self, signer: TrustedSigner) -> bool:
        """Add a trusted signer"""
        try:
            self.trusted_signers[signer.signer_id] = signer
            self._save_trust_store()
            logger.info(f"Added trusted signer: {signer.signer_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add trusted signer: {e}")
            return False
    
    def revoke_signer(self, signer_id: str) -> bool:
        """Revoke a trusted signer"""
        try:
            if signer_id in self.trusted_signers:
                self.trusted_signers[signer_id].revoked = True
                self._save_trust_store()
                logger.warning(f"Revoked signer: {signer_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to revoke signer: {e}")
            return False
    
    def revoke_signature(self, signature: PluginSignature) -> bool:
        """Revoke a specific signature"""
        try:
            signature_id = f"{signature.plugin_id}:{signature.plugin_version}:{signature.signature[:16]}"
            if signature_id not in self.revoked_signatures:
                self.revoked_signatures.append(signature_id)
                self._save_trust_store()
                logger.warning(f"Revoked signature: {signature_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke signature: {e}")
            return False
    
    def get_trusted_signers(self) -> List[TrustedSigner]:
        """Get list of trusted signers"""
        return [signer for signer in self.trusted_signers.values() if not signer.revoked]
    
    def is_plugin_trusted(self, plugin_path: str, signature: PluginSignature) -> bool:
        """Check if plugin is from a trusted source"""
        is_valid, _ = self.verify_plugin_signature(plugin_path, signature)
        return is_valid

# Global instance
plugin_signature_verifier = PluginSignatureVerifier()
