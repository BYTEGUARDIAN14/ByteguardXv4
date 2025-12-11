#!/usr/bin/env python3
"""
Advanced Cryptographic Security Manager for ByteGuardX
Implements military-grade encryption, key management, and cryptographic operations
"""

import logging
import os
import secrets
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, MultiFernet
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class EncryptionKey:
    """Represents an encryption key with metadata"""
    key_id: str
    key_type: str  # 'symmetric', 'asymmetric_private', 'asymmetric_public'
    algorithm: str
    key_data: bytes
    created_at: datetime
    expires_at: Optional[datetime]
    usage_count: int
    max_usage: Optional[int]
    is_active: bool

@dataclass
class CryptoOperation:
    """Represents a cryptographic operation"""
    operation_id: str
    operation_type: str  # 'encrypt', 'decrypt', 'sign', 'verify'
    key_id: str
    timestamp: datetime
    data_size: int
    success: bool
    error_message: Optional[str]

class AdvancedCryptoManager:
    """
    Military-grade cryptographic security manager
    """
    
    def __init__(self):
        if not CRYPTO_AVAILABLE:
            logger.error("Cryptography library not available - install cryptography package")
            return
        
        self.keys: Dict[str, EncryptionKey] = {}
        self.operations: List[CryptoOperation] = []
        self.backend = default_backend()
        
        # Initialize master keys
        self._initialize_master_keys()
        
        # Cryptographic configuration
        self.symmetric_algorithm = algorithms.AES
        self.symmetric_key_size = 256  # bits
        self.asymmetric_key_size = 4096  # bits for RSA
        self.hash_algorithm = hashes.SHA256()
        self.kdf_iterations = 100000  # PBKDF2 iterations
        
        # Key rotation settings
        self.key_rotation_interval = timedelta(days=90)
        self.max_key_usage = 1000000  # Max operations per key
    
    def _initialize_master_keys(self):
        """Initialize master encryption keys"""
        try:
            # Check for existing master key in environment
            master_key_env = os.environ.get('BYTEGUARDX_MASTER_KEY')
            if master_key_env:
                master_key = base64.b64decode(master_key_env)
            else:
                # Generate new master key
                master_key = Fernet.generate_key()
                logger.warning("Generated new master key. Set BYTEGUARDX_MASTER_KEY environment variable for production.")
            
            # Create primary Fernet instance
            self.primary_fernet = Fernet(master_key)
            
            # Generate additional keys for key rotation
            rotation_key = Fernet.generate_key()
            self.rotation_fernet = Fernet(rotation_key)
            
            # Create MultiFernet for seamless key rotation
            self.multi_fernet = MultiFernet([self.primary_fernet, self.rotation_fernet])
            
            # Store master keys
            self.keys['master_primary'] = EncryptionKey(
                key_id='master_primary',
                key_type='symmetric',
                algorithm='Fernet',
                key_data=master_key,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=90),  # 90 days rotation
                usage_count=0,
                max_usage=1000000,  # 1M operations
                is_active=True
            )
            
            logger.info("Master encryption keys initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize master keys: {e}")
            raise
    
    def generate_symmetric_key(self, key_id: str, algorithm: str = 'AES-256') -> str:
        """Generate a new symmetric encryption key"""
        try:
            if algorithm == 'AES-256':
                key_data = secrets.token_bytes(32)  # 256 bits
            elif algorithm == 'Fernet':
                key_data = Fernet.generate_key()
            else:
                raise ValueError(f"Unsupported symmetric algorithm: {algorithm}")
            
            encryption_key = EncryptionKey(
                key_id=key_id,
                key_type='symmetric',
                algorithm=algorithm,
                key_data=key_data,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=90),  # 90 days rotation
                usage_count=0,
                max_usage=1000000,  # 1M operations
                is_active=True
            )
            
            self.keys[key_id] = encryption_key
            
            # Encrypt and store the key securely
            encrypted_key = self.multi_fernet.encrypt(key_data)
            
            logger.info(f"Generated symmetric key: {key_id} ({algorithm})")
            return base64.b64encode(encrypted_key).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to generate symmetric key: {e}")
            raise
    
    def generate_asymmetric_keypair(self, key_id: str, algorithm: str = 'RSA-4096') -> Tuple[str, str]:
        """Generate asymmetric key pair"""
        try:
            if algorithm == 'RSA-4096':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096,
                    backend=self.backend
                )
                public_key = private_key.public_key()
                
            elif algorithm == 'EC-P384':
                private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
                public_key = private_key.public_key()
                
            else:
                raise ValueError(f"Unsupported asymmetric algorithm: {algorithm}")
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store private key
            private_key_obj = EncryptionKey(
                key_id=f"{key_id}_private",
                key_type='asymmetric_private',
                algorithm=algorithm,
                key_data=private_pem,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=90),  # 90 days rotation
                usage_count=0,
                max_usage=1000000,  # 1M operations
                is_active=True
            )
            
            # Store public key
            public_key_obj = EncryptionKey(
                key_id=f"{key_id}_public",
                key_type='asymmetric_public',
                algorithm=algorithm,
                key_data=public_pem,
                created_at=datetime.now(),
                expires_at=None,  # Public keys don't expire
                usage_count=0,
                max_usage=None,
                is_active=True
            )
            
            self.keys[f"{key_id}_private"] = private_key_obj
            self.keys[f"{key_id}_public"] = public_key_obj
            
            # Encrypt private key for storage
            encrypted_private = self.multi_fernet.encrypt(private_pem)
            
            logger.info(f"Generated asymmetric keypair: {key_id} ({algorithm})")
            
            return (
                base64.b64encode(encrypted_private).decode('utf-8'),
                base64.b64encode(public_pem).decode('utf-8')
            )
            
        except Exception as e:
            logger.error(f"Failed to generate asymmetric keypair: {e}")
            raise
    
    def encrypt_data(self, data: Union[str, bytes], key_id: str) -> str:
        """Encrypt data using specified key"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            
            key_obj = self.keys[key_id]
            
            if not key_obj.is_active:
                raise ValueError(f"Key is not active: {key_id}")
            
            if key_obj.expires_at and datetime.now() > key_obj.expires_at:
                raise ValueError(f"Key has expired: {key_id}")
            
            # Encrypt based on key type
            if key_obj.key_type == 'symmetric':
                if key_obj.algorithm == 'Fernet':
                    fernet = Fernet(key_obj.key_data)
                    encrypted_data = fernet.encrypt(data)
                elif key_obj.algorithm == 'AES-256':
                    # Generate random IV
                    iv = secrets.token_bytes(16)
                    cipher = Cipher(
                        algorithms.AES(key_obj.key_data),
                        modes.CBC(iv),
                        backend=self.backend
                    )
                    encryptor = cipher.encryptor()
                    
                    # Pad data to block size
                    padded_data = self._pad_data(data, 16)
                    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
                else:
                    raise ValueError(f"Unsupported symmetric algorithm: {key_obj.algorithm}")
                    
            elif key_obj.key_type == 'asymmetric_public':
                if key_obj.algorithm.startswith('RSA'):
                    public_key = load_pem_public_key(key_obj.key_data, backend=self.backend)
                    encrypted_data = public_key.encrypt(
                        data,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                else:
                    raise ValueError(f"Encryption not supported for algorithm: {key_obj.algorithm}")
            else:
                raise ValueError(f"Cannot encrypt with key type: {key_obj.key_type}")
            
            # Update usage count
            key_obj.usage_count += 1
            
            # Log operation
            self._log_crypto_operation('encrypt', key_id, len(data), True)
            
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self._log_crypto_operation('encrypt', key_id, len(data) if data else 0, False, str(e))
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str, key_id: str) -> bytes:
        """Decrypt data using specified key"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            
            key_obj = self.keys[key_id]
            
            if not key_obj.is_active:
                raise ValueError(f"Key is not active: {key_id}")
            
            # Decrypt based on key type
            if key_obj.key_type == 'symmetric':
                if key_obj.algorithm == 'Fernet':
                    fernet = Fernet(key_obj.key_data)
                    decrypted_data = fernet.decrypt(encrypted_bytes)
                elif key_obj.algorithm == 'AES-256':
                    # Extract IV and encrypted data
                    iv = encrypted_bytes[:16]
                    ciphertext = encrypted_bytes[16:]
                    
                    cipher = Cipher(
                        algorithms.AES(key_obj.key_data),
                        modes.CBC(iv),
                        backend=self.backend
                    )
                    decryptor = cipher.decryptor()
                    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                    decrypted_data = self._unpad_data(padded_data)
                else:
                    raise ValueError(f"Unsupported symmetric algorithm: {key_obj.algorithm}")
                    
            elif key_obj.key_type == 'asymmetric_private':
                if key_obj.algorithm.startswith('RSA'):
                    private_key = load_pem_private_key(key_obj.key_data, password=None, backend=self.backend)
                    decrypted_data = private_key.decrypt(
                        encrypted_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                else:
                    raise ValueError(f"Decryption not supported for algorithm: {key_obj.algorithm}")
            else:
                raise ValueError(f"Cannot decrypt with key type: {key_obj.key_type}")
            
            # Update usage count
            key_obj.usage_count += 1
            
            # Log operation
            self._log_crypto_operation('decrypt', key_id, len(encrypted_bytes), True)
            
            return decrypted_data
            
        except Exception as e:
            self._log_crypto_operation('decrypt', key_id, len(encrypted_data), False, str(e))
            logger.error(f"Decryption failed: {e}")
            raise
    
    def sign_data(self, data: Union[str, bytes], key_id: str) -> str:
        """Sign data using private key"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            
            key_obj = self.keys[key_id]
            
            if key_obj.key_type != 'asymmetric_private':
                raise ValueError(f"Cannot sign with key type: {key_obj.key_type}")
            
            if key_obj.algorithm.startswith('RSA'):
                private_key = load_pem_private_key(key_obj.key_data, password=None, backend=self.backend)
                signature = private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif key_obj.algorithm.startswith('EC'):
                private_key = load_pem_private_key(key_obj.key_data, password=None, backend=self.backend)
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            else:
                raise ValueError(f"Signing not supported for algorithm: {key_obj.algorithm}")
            
            # Update usage count
            key_obj.usage_count += 1
            
            # Log operation
            self._log_crypto_operation('sign', key_id, len(data), True)
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            self._log_crypto_operation('sign', key_id, len(data) if data else 0, False, str(e))
            logger.error(f"Signing failed: {e}")
            raise
    
    def verify_signature(self, data: Union[str, bytes], signature: str, key_id: str) -> bool:
        """Verify signature using public key"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            signature_bytes = base64.b64decode(signature)
            
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            
            key_obj = self.keys[key_id]
            
            if key_obj.key_type != 'asymmetric_public':
                raise ValueError(f"Cannot verify with key type: {key_obj.key_type}")
            
            if key_obj.algorithm.startswith('RSA'):
                public_key = load_pem_public_key(key_obj.key_data, backend=self.backend)
                public_key.verify(
                    signature_bytes,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif key_obj.algorithm.startswith('EC'):
                public_key = load_pem_public_key(key_obj.key_data, backend=self.backend)
                public_key.verify(signature_bytes, data, ec.ECDSA(hashes.SHA256()))
            else:
                raise ValueError(f"Verification not supported for algorithm: {key_obj.algorithm}")
            
            # Update usage count
            key_obj.usage_count += 1
            
            # Log operation
            self._log_crypto_operation('verify', key_id, len(data), True)
            
            return True
            
        except Exception as e:
            self._log_crypto_operation('verify', key_id, len(data) if data else 0, False, str(e))
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def derive_key(self, password: str, salt: bytes, key_length: int = 32, algorithm: str = 'PBKDF2') -> bytes:
        """Derive encryption key from password"""
        try:
            if algorithm == 'PBKDF2':
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_length,
                    salt=salt,
                    iterations=self.kdf_iterations,
                    backend=self.backend
                )
            elif algorithm == 'Scrypt':
                kdf = Scrypt(
                    algorithm=hashes.SHA256(),
                    length=key_length,
                    salt=salt,
                    n=2**14,
                    r=8,
                    p=1,
                    backend=self.backend
                )
            else:
                raise ValueError(f"Unsupported KDF algorithm: {algorithm}")
            
            derived_key = kdf.derive(password.encode('utf-8'))
            
            logger.info(f"Derived key using {algorithm}")
            return derived_key
            
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise
    
    def _pad_data(self, data: bytes, block_size: int) -> bytes:
        """PKCS7 padding"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def _log_crypto_operation(self, operation_type: str, key_id: str, data_size: int, success: bool, error_message: Optional[str] = None):
        """Log cryptographic operation"""
        operation = CryptoOperation(
            operation_id=secrets.token_hex(16),
            operation_type=operation_type,
            key_id=key_id,
            timestamp=datetime.now(),
            data_size=data_size,
            success=success,
            error_message=error_message
        )
        
        self.operations.append(operation)
        
        # Keep only recent operations
        if len(self.operations) > 10000:
            self.operations = self.operations[-10000:]
    
    def rotate_key(self, key_id: str) -> str:
        """Rotate encryption key"""
        try:
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            
            old_key = self.keys[key_id]
            
            # Generate new key with same parameters
            if old_key.key_type == 'symmetric':
                new_key_data = self.generate_symmetric_key(f"{key_id}_new", old_key.algorithm)
            else:
                raise ValueError("Key rotation only supported for symmetric keys")
            
            # Deactivate old key
            old_key.is_active = False
            
            logger.info(f"Rotated key: {key_id}")
            return new_key_data
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            raise
    
    def get_crypto_stats(self) -> Dict[str, Any]:
        """Get cryptographic operation statistics"""
        total_ops = len(self.operations)
        successful_ops = sum(1 for op in self.operations if op.success)
        
        operation_types = {}
        for op in self.operations:
            operation_types[op.operation_type] = operation_types.get(op.operation_type, 0) + 1
        
        active_keys = sum(1 for key in self.keys.values() if key.is_active)
        
        return {
            'total_operations': total_ops,
            'successful_operations': successful_ops,
            'success_rate': (successful_ops / total_ops * 100) if total_ops > 0 else 0,
            'operation_types': operation_types,
            'active_keys': active_keys,
            'total_keys': len(self.keys)
        }

# Global crypto manager instance
crypto_manager = AdvancedCryptoManager() if CRYPTO_AVAILABLE else None
