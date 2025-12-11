#!/usr/bin/env python3
"""
Database Encryption at Rest for ByteGuardX
Implements transparent database encryption for sensitive data
"""

import logging
import os
import json
import base64
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime
import sqlite3
import hashlib

try:
    from cryptography.fernet import Fernet, MultiFernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class EncryptedField:
    """Represents an encrypted database field"""
    table_name: str
    column_name: str
    encryption_key_id: str
    created_at: datetime
    last_rotated: datetime

class DatabaseEncryption:
    """
    Database encryption at rest manager
    """
    
    def __init__(self, db_path: str = "data/byteguardx.db"):
        if not CRYPTO_AVAILABLE:
            logger.error("Cryptography not available - database encryption disabled")
            self.enabled = False
            return
        
        self.db_path = db_path
        self.enabled = True
        
        # Initialize encryption keys
        self._init_encryption_keys()
        
        # Encrypted fields configuration
        self.encrypted_fields = {
            'users': ['password_hash', 'email', 'phone', 'api_key'],
            'scan_results': ['file_content', 'vulnerability_details'],
            'audit_logs': ['sensitive_data', 'user_data'],
            'sessions': ['session_data', 'device_fingerprint'],
            'secrets': ['secret_value', 'encrypted_data'],
            'reports': ['report_data', 'compliance_data']
        }
        
        # Initialize database encryption
        self._setup_database_encryption()
        
        logger.info("Database encryption at rest initialized")
    
    def _init_encryption_keys(self):
        """Initialize database encryption keys"""
        try:
            # Get master key from environment or generate
            master_key_b64 = os.environ.get('DATABASE_ENCRYPTION_KEY')
            
            if master_key_b64:
                master_key = base64.b64decode(master_key_b64)
            else:
                # Generate new master key
                master_key = Fernet.generate_key()
                logger.warning("Generated new database encryption key - set DATABASE_ENCRYPTION_KEY environment variable")
                logger.warning(f"DATABASE_ENCRYPTION_KEY={base64.b64encode(master_key).decode()}")
            
            # Create primary encryption instance
            self.primary_fernet = Fernet(master_key)
            
            # Generate rotation key for key rotation
            rotation_key = Fernet.generate_key()
            self.rotation_fernet = Fernet(rotation_key)
            
            # Create MultiFernet for seamless key rotation
            self.multi_fernet = MultiFernet([self.primary_fernet, self.rotation_fernet])
            
            # Store keys securely (in production, use HSM or key management service)
            self.encryption_keys = {
                'primary': master_key,
                'rotation': rotation_key
            }
            
        except Exception as e:
            logger.error(f"Failed to initialize encryption keys: {e}")
            self.enabled = False
    
    def _setup_database_encryption(self):
        """Setup database with encryption support"""
        try:
            # Create encrypted fields tracking table
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS encrypted_fields (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        table_name TEXT NOT NULL,
                        column_name TEXT NOT NULL,
                        encryption_key_id TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_rotated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(table_name, column_name)
                    )
                ''')
                
                # Register encrypted fields
                for table_name, columns in self.encrypted_fields.items():
                    for column_name in columns:
                        conn.execute('''
                            INSERT OR IGNORE INTO encrypted_fields 
                            (table_name, column_name, encryption_key_id)
                            VALUES (?, ?, ?)
                        ''', (table_name, column_name, 'primary'))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Database encryption setup failed: {e}")
            self.enabled = False
    
    def encrypt_value(self, value: Union[str, bytes], key_id: str = 'primary') -> str:
        """Encrypt a value for database storage"""
        if not self.enabled or not value:
            return value
        
        try:
            # Convert to bytes if string
            if isinstance(value, str):
                value_bytes = value.encode('utf-8')
            else:
                value_bytes = value
            
            # Encrypt with MultiFernet
            encrypted_bytes = self.multi_fernet.encrypt(value_bytes)
            
            # Return base64 encoded string
            return base64.b64encode(encrypted_bytes).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Value encryption failed: {e}")
            return value  # Return original value on error
    
    def decrypt_value(self, encrypted_value: str, key_id: str = 'primary') -> str:
        """Decrypt a value from database storage"""
        if not self.enabled or not encrypted_value:
            return encrypted_value
        
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_value)
            
            # Decrypt with MultiFernet (handles key rotation automatically)
            decrypted_bytes = self.multi_fernet.decrypt(encrypted_bytes)
            
            # Return as string
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Value decryption failed: {e}")
            return encrypted_value  # Return encrypted value on error
    
    def encrypt_json(self, data: Dict[str, Any], key_id: str = 'primary') -> str:
        """Encrypt JSON data for database storage"""
        if not self.enabled or not data:
            return json.dumps(data) if data else ''
        
        try:
            # Serialize to JSON
            json_str = json.dumps(data, sort_keys=True)
            
            # Encrypt the JSON string
            return self.encrypt_value(json_str, key_id)
            
        except Exception as e:
            logger.error(f"JSON encryption failed: {e}")
            return json.dumps(data) if data else ''
    
    def decrypt_json(self, encrypted_json: str, key_id: str = 'primary') -> Dict[str, Any]:
        """Decrypt JSON data from database storage"""
        if not self.enabled or not encrypted_json:
            try:
                return json.loads(encrypted_json) if encrypted_json else {}
            except:
                return {}
        
        try:
            # Decrypt the JSON string
            json_str = self.decrypt_value(encrypted_json, key_id)
            
            # Parse JSON
            return json.loads(json_str)
            
        except Exception as e:
            logger.error(f"JSON decryption failed: {e}")
            try:
                return json.loads(encrypted_json)  # Try as unencrypted
            except:
                return {}
    
    def is_field_encrypted(self, table_name: str, column_name: str) -> bool:
        """Check if a field should be encrypted"""
        return (table_name in self.encrypted_fields and 
                column_name in self.encrypted_fields[table_name])
    
    def encrypt_row_data(self, table_name: str, row_data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields in row data"""
        if not self.enabled:
            return row_data
        
        encrypted_data = row_data.copy()
        
        for column_name, value in row_data.items():
            if self.is_field_encrypted(table_name, column_name) and value is not None:
                if isinstance(value, dict):
                    encrypted_data[column_name] = self.encrypt_json(value)
                else:
                    encrypted_data[column_name] = self.encrypt_value(str(value))
        
        return encrypted_data
    
    def decrypt_row_data(self, table_name: str, row_data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive fields in row data"""
        if not self.enabled:
            return row_data
        
        decrypted_data = row_data.copy()
        
        for column_name, value in row_data.items():
            if self.is_field_encrypted(table_name, column_name) and value is not None:
                try:
                    # Try to decrypt as JSON first
                    decrypted_data[column_name] = self.decrypt_json(str(value))
                except:
                    # Fall back to string decryption
                    decrypted_data[column_name] = self.decrypt_value(str(value))
        
        return decrypted_data
    
    def rotate_encryption_keys(self) -> bool:
        """Rotate database encryption keys"""
        if not self.enabled:
            return False
        
        try:
            logger.info("Starting database encryption key rotation")
            
            # Generate new rotation key
            new_rotation_key = Fernet.generate_key()
            new_rotation_fernet = Fernet(new_rotation_key)
            
            # Create new MultiFernet with new rotation key as primary
            new_multi_fernet = MultiFernet([new_rotation_fernet, self.primary_fernet])
            
            # Re-encrypt all encrypted data with new key
            self._reencrypt_database_data(new_multi_fernet)
            
            # Update keys
            self.rotation_fernet = new_rotation_fernet
            self.multi_fernet = new_multi_fernet
            self.encryption_keys['rotation'] = new_rotation_key
            
            # Update rotation timestamp
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE encrypted_fields 
                    SET last_rotated = CURRENT_TIMESTAMP
                ''')
                conn.commit()
            
            logger.info("Database encryption key rotation completed")
            return True
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False
    
    def _reencrypt_database_data(self, new_fernet: MultiFernet):
        """Re-encrypt all database data with new keys"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get all encrypted fields
                cursor = conn.execute('SELECT table_name, column_name FROM encrypted_fields')
                encrypted_fields = cursor.fetchall()
                
                for table_name, column_name in encrypted_fields:
                    # Check if table exists
                    cursor = conn.execute('''
                        SELECT name FROM sqlite_master 
                        WHERE type='table' AND name=?
                    ''', (table_name,))
                    
                    if not cursor.fetchone():
                        continue
                    
                    # Get all rows with encrypted data
                    cursor = conn.execute(f'SELECT rowid, {column_name} FROM {table_name} WHERE {column_name} IS NOT NULL')
                    rows = cursor.fetchall()
                    
                    for rowid, encrypted_value in rows:
                        if encrypted_value:
                            try:
                                # Decrypt with old key
                                decrypted_value = self.multi_fernet.decrypt(base64.b64decode(encrypted_value))
                                
                                # Encrypt with new key
                                new_encrypted_value = base64.b64encode(new_fernet.encrypt(decrypted_value)).decode('utf-8')
                                
                                # Update database
                                conn.execute(f'UPDATE {table_name} SET {column_name} = ? WHERE rowid = ?', 
                                           (new_encrypted_value, rowid))
                                
                            except Exception as e:
                                logger.warning(f"Failed to re-encrypt {table_name}.{column_name} row {rowid}: {e}")
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Database re-encryption failed: {e}")
            raise
    
    def get_encryption_status(self) -> Dict[str, Any]:
        """Get database encryption status"""
        if not self.enabled:
            return {
                'enabled': False,
                'reason': 'Cryptography not available or initialization failed'
            }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM encrypted_fields')
                encrypted_fields_count = cursor.fetchone()[0]
                
                cursor = conn.execute('''
                    SELECT table_name, COUNT(*) as field_count
                    FROM encrypted_fields 
                    GROUP BY table_name
                ''')
                tables_info = cursor.fetchall()
        
        except Exception as e:
            logger.error(f"Failed to get encryption status: {e}")
            return {'enabled': True, 'error': str(e)}
        
        return {
            'enabled': True,
            'encrypted_fields_count': encrypted_fields_count,
            'encrypted_tables': dict(tables_info),
            'encryption_keys': list(self.encryption_keys.keys()),
            'crypto_available': CRYPTO_AVAILABLE
        }
    
    def verify_encryption_integrity(self) -> Dict[str, Any]:
        """Verify database encryption integrity"""
        if not self.enabled:
            return {'enabled': False}
        
        results = {
            'enabled': True,
            'total_checks': 0,
            'successful_decryptions': 0,
            'failed_decryptions': 0,
            'errors': []
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT table_name, column_name FROM encrypted_fields')
                encrypted_fields = cursor.fetchall()
                
                for table_name, column_name in encrypted_fields:
                    try:
                        # Check if table exists
                        cursor = conn.execute('''
                            SELECT name FROM sqlite_master 
                            WHERE type='table' AND name=?
                        ''', (table_name,))
                        
                        if not cursor.fetchone():
                            continue
                        
                        # Sample a few encrypted values
                        cursor = conn.execute(f'''
                            SELECT {column_name} FROM {table_name} 
                            WHERE {column_name} IS NOT NULL 
                            LIMIT 10
                        ''')
                        
                        for (encrypted_value,) in cursor.fetchall():
                            results['total_checks'] += 1
                            
                            try:
                                # Try to decrypt
                                self.decrypt_value(encrypted_value)
                                results['successful_decryptions'] += 1
                                
                            except Exception as e:
                                results['failed_decryptions'] += 1
                                results['errors'].append(f"{table_name}.{column_name}: {str(e)}")
                    
                    except Exception as e:
                        results['errors'].append(f"Table {table_name}: {str(e)}")
        
        except Exception as e:
            results['errors'].append(f"Database access error: {str(e)}")
        
        return results

# Global database encryption instance
db_encryption = DatabaseEncryption()
