"""
Data Encryption and Secure Storage for ByteGuardX
Implements AES-256 encryption for sensitive data at rest
"""

import os
import base64
import secrets
import logging
from typing import Optional, Dict, Any, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Custom exception for encryption operations"""
    pass

class DataEncryption:
    """AES-256 encryption for sensitive data"""
    
    def __init__(self, master_key: Optional[str] = None):
        self.backend = default_backend()
        self.master_key = master_key or self._get_or_create_master_key()
        
    def _get_or_create_master_key(self) -> str:
        """Get master key from environment or create one"""
        key = os.environ.get('BYTEGUARDX_MASTER_KEY')
        if not key:
            # Generate a new master key
            key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
            logger.warning("Generated new master key. Set BYTEGUARDX_MASTER_KEY environment variable for production.")
        return key
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_data(self, data: Union[str, bytes], password: Optional[str] = None) -> str:
        """
        Encrypt data using AES-256-GCM
        Returns base64-encoded encrypted data with salt and nonce
        """
        try:
            # Convert string to bytes if necessary
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Use master key if no password provided
            key_source = password or self.master_key
            
            # Generate random salt and nonce
            salt = secrets.token_bytes(16)  # 128 bits
            nonce = secrets.token_bytes(12)  # 96 bits for GCM
            
            # Derive key
            key = self._derive_key(key_source, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Combine salt, nonce, tag, and ciphertext
            encrypted_data = salt + nonce + encryptor.tag + ciphertext
            
            # Return base64-encoded result
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt data: {str(e)}")
    
    def decrypt_data(self, encrypted_data: str, password: Optional[str] = None) -> bytes:
        """
        Decrypt data encrypted with encrypt_data
        Returns decrypted bytes
        """
        try:
            # Decode from base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            
            # Extract components
            salt = encrypted_bytes[:16]
            nonce = encrypted_bytes[16:28]
            tag = encrypted_bytes[28:44]
            ciphertext = encrypted_bytes[44:]
            
            # Use master key if no password provided
            key_source = password or self.master_key
            
            # Derive key
            key = self._derive_key(key_source, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt data: {str(e)}")
    
    def decrypt_to_string(self, encrypted_data: str, password: Optional[str] = None) -> str:
        """Decrypt data and return as string"""
        decrypted_bytes = self.decrypt_data(encrypted_data, password)
        return decrypted_bytes.decode('utf-8')
    
    def encrypt_json(self, data: Dict[str, Any], password: Optional[str] = None) -> str:
        """Encrypt JSON-serializable data"""
        json_str = json.dumps(data, separators=(',', ':'))
        return self.encrypt_data(json_str, password)
    
    def decrypt_json(self, encrypted_data: str, password: Optional[str] = None) -> Dict[str, Any]:
        """Decrypt and parse JSON data"""
        json_str = self.decrypt_to_string(encrypted_data, password)
        return json.loads(json_str)

class SecureStorage:
    """Secure file storage with encryption"""
    
    def __init__(self, storage_dir: str = "data/secure", encryption: Optional[DataEncryption] = None):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.encryption = encryption or DataEncryption()
    
    def _get_file_path(self, key: str) -> Path:
        """Get secure file path for a key"""
        # Hash the key to create a safe filename
        import hashlib
        hashed_key = hashlib.sha256(key.encode('utf-8')).hexdigest()
        return self.storage_dir / f"{hashed_key}.enc"
    
    def store(self, key: str, data: Union[str, Dict[str, Any]], password: Optional[str] = None) -> bool:
        """Store data securely"""
        try:
            file_path = self._get_file_path(key)
            
            # Encrypt data
            if isinstance(data, dict):
                encrypted_data = self.encryption.encrypt_json(data, password)
            else:
                encrypted_data = self.encryption.encrypt_data(str(data), password)
            
            # Write to file with secure permissions
            with open(file_path, 'w') as f:
                f.write(encrypted_data)
            
            # Set restrictive file permissions (owner read/write only)
            os.chmod(file_path, 0o600)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to store data for key {key}: {e}")
            return False
    
    def retrieve(self, key: str, password: Optional[str] = None, as_json: bool = False) -> Optional[Union[str, Dict[str, Any]]]:
        """Retrieve data securely"""
        try:
            file_path = self._get_file_path(key)
            
            if not file_path.exists():
                return None
            
            # Read encrypted data
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            if as_json:
                return self.encryption.decrypt_json(encrypted_data, password)
            else:
                return self.encryption.decrypt_to_string(encrypted_data, password)
                
        except Exception as e:
            logger.error(f"Failed to retrieve data for key {key}: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete stored data"""
        try:
            file_path = self._get_file_path(key)
            
            if file_path.exists():
                # Securely delete file
                self._secure_delete(file_path)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete data for key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in storage"""
        file_path = self._get_file_path(key)
        return file_path.exists()
    
    def list_keys(self) -> list:
        """List all stored keys (returns hashed keys for security)"""
        try:
            return [f.stem for f in self.storage_dir.glob("*.enc")]
        except Exception as e:
            logger.error(f"Failed to list keys: {e}")
            return []
    
    def _secure_delete(self, file_path: Path):
        """Securely delete a file by overwriting it"""
        try:
            if not file_path.exists():
                return
            
            # Get file size
            file_size = file_path.stat().st_size
            
            # Overwrite with random data multiple times
            with open(file_path, 'r+b') as f:
                for _ in range(3):  # 3 passes
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            file_path.unlink()
            
        except Exception as e:
            logger.error(f"Secure delete failed for {file_path}: {e}")
            # Fallback to regular delete
            try:
                file_path.unlink()
            except Exception:
                pass

class RSAEncryption:
    """RSA encryption for key exchange and digital signatures"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.backend = default_backend()
    
    def generate_key_pair(self) -> tuple:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def serialize_private_key(self, private_key, password: Optional[str] = None) -> bytes:
        """Serialize private key to PEM format"""
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def serialize_public_key(self, public_key) -> bytes:
        """Serialize public key to PEM format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def load_private_key(self, key_data: bytes, password: Optional[str] = None):
        """Load private key from PEM data"""
        password_bytes = password.encode('utf-8') if password else None
        return serialization.load_pem_private_key(
            key_data, password=password_bytes, backend=self.backend
        )
    
    def load_public_key(self, key_data: bytes):
        """Load public key from PEM data"""
        return serialization.load_pem_public_key(key_data, backend=self.backend)
    
    def encrypt_with_public_key(self, data: bytes, public_key) -> bytes:
        """Encrypt data with public key"""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_with_private_key(self, encrypted_data: bytes, private_key) -> bytes:
        """Decrypt data with private key"""
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

class FieldEncryption:
    """Utility for encrypting specific database fields"""
    
    def __init__(self, encryption: Optional[DataEncryption] = None):
        self.encryption = encryption or DataEncryption()
        
        # Fields that should be encrypted
        self.encrypted_fields = {
            'password_hash',  # Already hashed, but encrypt for extra security
            'api_keys',
            'tokens',
            'secrets',
            'private_keys',
            'backup_codes',
            'personal_info',
            'sensitive_config'
        }
    
    def should_encrypt_field(self, field_name: str) -> bool:
        """Check if a field should be encrypted"""
        return any(sensitive in field_name.lower() for sensitive in self.encrypted_fields)
    
    def encrypt_field(self, field_name: str, value: Any) -> str:
        """Encrypt a field value if it should be encrypted"""
        if not self.should_encrypt_field(field_name):
            return value
        
        if value is None:
            return None
        
        # Convert to string if not already
        str_value = str(value) if not isinstance(value, str) else value
        
        return self.encryption.encrypt_data(str_value)
    
    def decrypt_field(self, field_name: str, encrypted_value: str) -> str:
        """Decrypt a field value if it was encrypted"""
        if not self.should_encrypt_field(field_name) or not encrypted_value:
            return encrypted_value
        
        try:
            return self.encryption.decrypt_to_string(encrypted_value)
        except EncryptionError:
            # If decryption fails, assume it's not encrypted
            return encrypted_value

# Global instances
data_encryption = DataEncryption()
secure_storage = SecureStorage()
field_encryption = FieldEncryption()
rsa_encryption = RSAEncryption()
