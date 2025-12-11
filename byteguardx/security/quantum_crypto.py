#!/usr/bin/env python3
"""
Quantum-Resistant Cryptography for ByteGuardX
Implements post-quantum cryptographic algorithms for future-proof security
"""

import logging
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json

try:
    import pqcrypto.kem.kyber512 as kyber512
    import pqcrypto.kem.kyber768 as kyber768
    import pqcrypto.kem.kyber1024 as kyber1024
    import pqcrypto.sign.dilithium2 as dilithium2
    import pqcrypto.sign.dilithium3 as dilithium3
    import pqcrypto.sign.dilithium5 as dilithium5
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class QuantumKeyPair:
    """Quantum-resistant key pair"""
    key_id: str
    algorithm: str
    public_key: bytes
    private_key: bytes
    created_at: datetime
    expires_at: Optional[datetime]
    usage_count: int
    max_usage: Optional[int]
    is_active: bool

@dataclass
class QuantumSignature:
    """Quantum-resistant digital signature"""
    signature_id: str
    algorithm: str
    signature_data: bytes
    message_hash: str
    signer_key_id: str
    created_at: datetime
    is_valid: bool

@dataclass
class QuantumEncapsulation:
    """Quantum key encapsulation result"""
    encapsulation_id: str
    algorithm: str
    ciphertext: bytes
    shared_secret: bytes
    public_key_id: str
    created_at: datetime

class QuantumCryptoManager:
    """
    Quantum-resistant cryptography manager
    Provides post-quantum security algorithms
    """
    
    def __init__(self):
        if not PQCRYPTO_AVAILABLE:
            logger.warning("Post-quantum cryptography not available - install pqcrypto package")
            return
        
        # Key storage
        self.quantum_keypairs: Dict[str, QuantumKeyPair] = {}
        self.quantum_signatures: Dict[str, QuantumSignature] = {}
        self.quantum_encapsulations: Dict[str, QuantumEncapsulation] = {}
        
        # Supported algorithms
        self.kem_algorithms = {
            'kyber512': kyber512,
            'kyber768': kyber768,
            'kyber1024': kyber1024
        }
        
        self.signature_algorithms = {
            'dilithium2': dilithium2,
            'dilithium3': dilithium3,
            'dilithium5': dilithium5
        }
        
        # Security levels
        self.security_levels = {
            'kyber512': 128,    # bits
            'kyber768': 192,
            'kyber1024': 256,
            'dilithium2': 128,
            'dilithium3': 192,
            'dilithium5': 256
        }
        
        # Default algorithms by security level
        self.default_kem = 'kyber768'      # 192-bit security
        self.default_signature = 'dilithium3'  # 192-bit security
        
        logger.info("Quantum-resistant cryptography manager initialized")
    
    def generate_kem_keypair(self, key_id: str, algorithm: str = None) -> str:
        """
        Generate quantum-resistant KEM (Key Encapsulation Mechanism) keypair
        """
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError("Post-quantum cryptography not available")
        
        try:
            algorithm = algorithm or self.default_kem
            
            if algorithm not in self.kem_algorithms:
                raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
            
            kem_module = self.kem_algorithms[algorithm]
            
            # Generate keypair
            public_key, private_key = kem_module.keypair()
            
            # Create keypair object
            keypair = QuantumKeyPair(
                key_id=key_id,
                algorithm=algorithm,
                public_key=public_key,
                private_key=private_key,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=365),  # 1 year
                usage_count=0,
                max_usage=1000000,  # 1M operations
                is_active=True
            )
            
            # Store keypair
            self.quantum_keypairs[key_id] = keypair
            
            logger.info(f"Generated quantum KEM keypair: {key_id} ({algorithm})")
            
            # Return base64-encoded public key
            return base64.b64encode(public_key).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to generate KEM keypair: {e}")
            raise
    
    def generate_signature_keypair(self, key_id: str, algorithm: str = None) -> str:
        """
        Generate quantum-resistant signature keypair
        """
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError("Post-quantum cryptography not available")
        
        try:
            algorithm = algorithm or self.default_signature
            
            if algorithm not in self.signature_algorithms:
                raise ValueError(f"Unsupported signature algorithm: {algorithm}")
            
            sig_module = self.signature_algorithms[algorithm]
            
            # Generate keypair
            public_key, private_key = sig_module.keypair()
            
            # Create keypair object
            keypair = QuantumKeyPair(
                key_id=key_id,
                algorithm=algorithm,
                public_key=public_key,
                private_key=private_key,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=365),  # 1 year
                usage_count=0,
                max_usage=100000,  # 100K signatures
                is_active=True
            )
            
            # Store keypair
            self.quantum_keypairs[key_id] = keypair
            
            logger.info(f"Generated quantum signature keypair: {key_id} ({algorithm})")
            
            # Return base64-encoded public key
            return base64.b64encode(public_key).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to generate signature keypair: {e}")
            raise
    
    def quantum_encapsulate(self, public_key_id: str) -> Tuple[str, str]:
        """
        Perform quantum key encapsulation
        Returns: (ciphertext, shared_secret)
        """
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError("Post-quantum cryptography not available")
        
        try:
            if public_key_id not in self.quantum_keypairs:
                raise ValueError(f"Public key not found: {public_key_id}")
            
            keypair = self.quantum_keypairs[public_key_id]
            
            if keypair.algorithm not in self.kem_algorithms:
                raise ValueError(f"Not a KEM algorithm: {keypair.algorithm}")
            
            kem_module = self.kem_algorithms[keypair.algorithm]
            
            # Perform encapsulation
            ciphertext, shared_secret = kem_module.enc(keypair.public_key)
            
            # Create encapsulation record
            encapsulation_id = secrets.token_hex(16)
            encapsulation = QuantumEncapsulation(
                encapsulation_id=encapsulation_id,
                algorithm=keypair.algorithm,
                ciphertext=ciphertext,
                shared_secret=shared_secret,
                public_key_id=public_key_id,
                created_at=datetime.now()
            )
            
            # Store encapsulation
            self.quantum_encapsulations[encapsulation_id] = encapsulation
            
            # Update usage count
            keypair.usage_count += 1
            
            logger.info(f"Quantum encapsulation performed: {public_key_id}")
            
            return (
                base64.b64encode(ciphertext).decode('utf-8'),
                base64.b64encode(shared_secret).decode('utf-8')
            )
            
        except Exception as e:
            logger.error(f"Quantum encapsulation failed: {e}")
            raise
    
    def quantum_decapsulate(self, private_key_id: str, ciphertext: str) -> str:
        """
        Perform quantum key decapsulation
        Returns: shared_secret
        """
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError("Post-quantum cryptography not available")
        
        try:
            if private_key_id not in self.quantum_keypairs:
                raise ValueError(f"Private key not found: {private_key_id}")
            
            keypair = self.quantum_keypairs[private_key_id]
            
            if keypair.algorithm not in self.kem_algorithms:
                raise ValueError(f"Not a KEM algorithm: {keypair.algorithm}")
            
            kem_module = self.kem_algorithms[keypair.algorithm]
            
            # Decode ciphertext
            ciphertext_bytes = base64.b64decode(ciphertext)
            
            # Perform decapsulation
            shared_secret = kem_module.dec(ciphertext_bytes, keypair.private_key)
            
            # Update usage count
            keypair.usage_count += 1
            
            logger.info(f"Quantum decapsulation performed: {private_key_id}")
            
            return base64.b64encode(shared_secret).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Quantum decapsulation failed: {e}")
            raise
    
    def quantum_sign(self, private_key_id: str, message: Union[str, bytes]) -> str:
        """
        Create quantum-resistant digital signature
        """
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError("Post-quantum cryptography not available")
        
        try:
            if private_key_id not in self.quantum_keypairs:
                raise ValueError(f"Private key not found: {private_key_id}")
            
            keypair = self.quantum_keypairs[private_key_id]
            
            if keypair.algorithm not in self.signature_algorithms:
                raise ValueError(f"Not a signature algorithm: {keypair.algorithm}")
            
            sig_module = self.signature_algorithms[keypair.algorithm]
            
            # Convert message to bytes
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # Create message hash
            message_hash = hashlib.sha256(message_bytes).hexdigest()
            
            # Create signature
            signature_data = sig_module.sign(message_bytes, keypair.private_key)
            
            # Create signature record
            signature_id = secrets.token_hex(16)
            signature = QuantumSignature(
                signature_id=signature_id,
                algorithm=keypair.algorithm,
                signature_data=signature_data,
                message_hash=message_hash,
                signer_key_id=private_key_id,
                created_at=datetime.now(),
                is_valid=True
            )
            
            # Store signature
            self.quantum_signatures[signature_id] = signature
            
            # Update usage count
            keypair.usage_count += 1
            
            logger.info(f"Quantum signature created: {private_key_id}")
            
            return base64.b64encode(signature_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Quantum signing failed: {e}")
            raise
    
    def quantum_verify(self, public_key_id: str, message: Union[str, bytes], signature: str) -> bool:
        """
        Verify quantum-resistant digital signature
        """
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError("Post-quantum cryptography not available")
        
        try:
            if public_key_id not in self.quantum_keypairs:
                raise ValueError(f"Public key not found: {public_key_id}")
            
            keypair = self.quantum_keypairs[public_key_id]
            
            if keypair.algorithm not in self.signature_algorithms:
                raise ValueError(f"Not a signature algorithm: {keypair.algorithm}")
            
            sig_module = self.signature_algorithms[keypair.algorithm]
            
            # Convert message to bytes
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Verify signature
            try:
                sig_module.open(signature_bytes, keypair.public_key)
                is_valid = True
            except Exception:
                is_valid = False
            
            # Update usage count
            keypair.usage_count += 1
            
            logger.info(f"Quantum signature verification: {public_key_id} -> {is_valid}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Quantum verification failed: {e}")
            return False
    
    def hybrid_encrypt(self, data: Union[str, bytes], public_key_id: str) -> Dict[str, str]:
        """
        Hybrid encryption using quantum-resistant KEM + symmetric encryption
        """
        try:
            # Convert data to bytes
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Generate symmetric key using quantum KEM
            ciphertext, shared_secret_b64 = self.quantum_encapsulate(public_key_id)
            shared_secret = base64.b64decode(shared_secret_b64)
            
            # Use first 32 bytes as AES key
            aes_key = shared_secret[:32]
            
            # Encrypt data with AES (using existing crypto manager)
            from .crypto_manager import crypto_manager
            if crypto_manager:
                # Create temporary symmetric key
                temp_key_id = f"temp_{secrets.token_hex(8)}"
                crypto_manager.keys[temp_key_id] = type('Key', (), {
                    'key_data': aes_key,
                    'algorithm': 'AES-256',
                    'key_type': 'symmetric',
                    'is_active': True,
                    'expires_at': None,
                    'usage_count': 0
                })()
                
                # Encrypt data
                encrypted_data = crypto_manager.encrypt_data(data_bytes, temp_key_id)
                
                # Clean up temporary key
                del crypto_manager.keys[temp_key_id]
            else:
                # Fallback: simple XOR encryption (not recommended for production)
                encrypted_data = base64.b64encode(
                    bytes(a ^ b for a, b in zip(data_bytes, (aes_key * (len(data_bytes) // 32 + 1))[:len(data_bytes)]))
                ).decode('utf-8')
            
            return {
                'encrypted_data': encrypted_data,
                'quantum_ciphertext': ciphertext,
                'algorithm': self.quantum_keypairs[public_key_id].algorithm,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Hybrid encryption failed: {e}")
            raise
    
    def hybrid_decrypt(self, encrypted_package: Dict[str, str], private_key_id: str) -> bytes:
        """
        Hybrid decryption using quantum-resistant KEM + symmetric decryption
        """
        try:
            # Extract components
            encrypted_data = encrypted_package['encrypted_data']
            quantum_ciphertext = encrypted_package['quantum_ciphertext']
            
            # Recover shared secret using quantum KEM
            shared_secret_b64 = self.quantum_decapsulate(private_key_id, quantum_ciphertext)
            shared_secret = base64.b64decode(shared_secret_b64)
            
            # Use first 32 bytes as AES key
            aes_key = shared_secret[:32]
            
            # Decrypt data with AES
            from .crypto_manager import crypto_manager
            if crypto_manager:
                # Create temporary symmetric key
                temp_key_id = f"temp_{secrets.token_hex(8)}"
                crypto_manager.keys[temp_key_id] = type('Key', (), {
                    'key_data': aes_key,
                    'algorithm': 'AES-256',
                    'key_type': 'symmetric',
                    'is_active': True,
                    'expires_at': None,
                    'usage_count': 0
                })()
                
                # Decrypt data
                decrypted_data = crypto_manager.decrypt_data(encrypted_data, temp_key_id)
                
                # Clean up temporary key
                del crypto_manager.keys[temp_key_id]
            else:
                # Fallback: simple XOR decryption
                encrypted_bytes = base64.b64decode(encrypted_data)
                decrypted_data = bytes(
                    a ^ b for a, b in zip(encrypted_bytes, (aes_key * (len(encrypted_bytes) // 32 + 1))[:len(encrypted_bytes)])
                )
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Hybrid decryption failed: {e}")
            raise
    
    def get_quantum_security_level(self, algorithm: str) -> int:
        """Get security level in bits for quantum algorithm"""
        return self.security_levels.get(algorithm, 0)
    
    def rotate_quantum_keys(self, key_id: str) -> str:
        """Rotate quantum-resistant keys"""
        try:
            if key_id not in self.quantum_keypairs:
                raise ValueError(f"Key not found: {key_id}")
            
            old_keypair = self.quantum_keypairs[key_id]
            
            # Generate new keypair with same algorithm
            new_key_id = f"{key_id}_rotated_{datetime.now().strftime('%Y%m%d')}"
            
            if old_keypair.algorithm in self.kem_algorithms:
                new_public_key = self.generate_kem_keypair(new_key_id, old_keypair.algorithm)
            else:
                new_public_key = self.generate_signature_keypair(new_key_id, old_keypair.algorithm)
            
            # Deactivate old key
            old_keypair.is_active = False
            
            logger.info(f"Rotated quantum key: {key_id} -> {new_key_id}")
            
            return new_public_key
            
        except Exception as e:
            logger.error(f"Quantum key rotation failed: {e}")
            raise
    
    def get_quantum_stats(self) -> Dict[str, Any]:
        """Get quantum cryptography statistics"""
        if not PQCRYPTO_AVAILABLE:
            return {'available': False}
        
        active_keys = sum(1 for key in self.quantum_keypairs.values() if key.is_active)
        total_signatures = len(self.quantum_signatures)
        total_encapsulations = len(self.quantum_encapsulations)
        
        algorithm_usage = {}
        for key in self.quantum_keypairs.values():
            algorithm_usage[key.algorithm] = algorithm_usage.get(key.algorithm, 0) + key.usage_count
        
        return {
            'available': True,
            'active_keys': active_keys,
            'total_keys': len(self.quantum_keypairs),
            'total_signatures': total_signatures,
            'total_encapsulations': total_encapsulations,
            'algorithm_usage': algorithm_usage,
            'supported_kem_algorithms': list(self.kem_algorithms.keys()),
            'supported_signature_algorithms': list(self.signature_algorithms.keys()),
            'default_kem': self.default_kem,
            'default_signature': self.default_signature
        }

# Global quantum crypto manager
quantum_crypto = QuantumCryptoManager() if PQCRYPTO_AVAILABLE else None
