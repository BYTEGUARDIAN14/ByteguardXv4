"""
Database Schema Drift Detection for ByteGuardX
Validates database schema against expected structure and detects migrations
"""

import os
import json
import logging
import hashlib
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import sqlite3

logger = logging.getLogger(__name__)

class SchemaDriftDetector:
    """Detects schema drift and validates database structure"""
    
    def __init__(self, db_path: str = "data/byteguardx.db"):
        self.db_path = Path(db_path)
        self.schema_file = Path("database/expected_schema.json")
        self.migrations_dir = Path("database/migrations")
        
        # Expected schema structure
        self.expected_schema = {
            "users": {
                "columns": [
                    {"name": "id", "type": "TEXT", "primary_key": True},
                    {"name": "email", "type": "TEXT", "unique": True, "not_null": True},
                    {"name": "username", "type": "TEXT", "unique": True, "not_null": True},
                    {"name": "password_hash", "type": "TEXT", "not_null": True},
                    {"name": "role", "type": "TEXT", "not_null": True},
                    {"name": "created_at", "type": "TIMESTAMP", "not_null": True},
                    {"name": "last_login", "type": "TIMESTAMP"},
                    {"name": "email_verified", "type": "BOOLEAN", "default": False},
                    {"name": "has_2fa_enabled", "type": "BOOLEAN", "default": False},
                    {"name": "requires_2fa", "type": "BOOLEAN", "default": False}
                ],
                "indexes": [
                    {"name": "idx_users_email", "columns": ["email"]},
                    {"name": "idx_users_username", "columns": ["username"]}
                ]
            },
            "scans": {
                "columns": [
                    {"name": "id", "type": "TEXT", "primary_key": True},
                    {"name": "user_id", "type": "TEXT", "not_null": True},
                    {"name": "scan_type", "type": "TEXT", "not_null": True},
                    {"name": "status", "type": "TEXT", "not_null": True},
                    {"name": "created_at", "type": "TIMESTAMP", "not_null": True},
                    {"name": "completed_at", "type": "TIMESTAMP"},
                    {"name": "results", "type": "TEXT"},  # JSON
                    {"name": "file_path", "type": "TEXT"},
                    {"name": "findings_count", "type": "INTEGER", "default": 0}
                ],
                "indexes": [
                    {"name": "idx_scans_user_id", "columns": ["user_id"]},
                    {"name": "idx_scans_created_at", "columns": ["created_at"]}
                ]
            },
            "audit_logs": {
                "columns": [
                    {"name": "id", "type": "TEXT", "primary_key": True},
                    {"name": "user_id", "type": "TEXT"},
                    {"name": "action", "type": "TEXT", "not_null": True},
                    {"name": "resource", "type": "TEXT"},
                    {"name": "timestamp", "type": "TIMESTAMP", "not_null": True},
                    {"name": "ip_address", "type": "TEXT"},
                    {"name": "user_agent", "type": "TEXT"},
                    {"name": "details", "type": "TEXT"}  # JSON
                ],
                "indexes": [
                    {"name": "idx_audit_user_id", "columns": ["user_id"]},
                    {"name": "idx_audit_timestamp", "columns": ["timestamp"]},
                    {"name": "idx_audit_action", "columns": ["action"]}
                ]
            },
            "refresh_tokens": {
                "columns": [
                    {"name": "token_hash", "type": "TEXT", "primary_key": True},
                    {"name": "user_id", "type": "TEXT", "not_null": True},
                    {"name": "created_at", "type": "TIMESTAMP", "not_null": True},
                    {"name": "expires_at", "type": "TIMESTAMP", "not_null": True},
                    {"name": "is_active", "type": "BOOLEAN", "default": True},
                    {"name": "device_info", "type": "TEXT"}
                ],
                "indexes": [
                    {"name": "idx_tokens_user_id", "columns": ["user_id"]},
                    {"name": "idx_tokens_expires_at", "columns": ["expires_at"]}
                ]
            }
        }
    
    def validate_schema_on_startup(self) -> Tuple[bool, List[str]]:
        """
        Validate database schema on application startup
        Returns: (is_valid, issues)
        """
        issues = []
        
        try:
            # Check if database exists
            if not self.db_path.exists():
                issues.append("Database file does not exist")
                return False, issues
            
            # Connect to database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get current schema
                current_schema = self._get_current_schema(cursor)
                
                # Compare with expected schema
                schema_issues = self._compare_schemas(current_schema, self.expected_schema)
                issues.extend(schema_issues)
                
                # Check for pending migrations
                migration_issues = self._check_pending_migrations(cursor)
                issues.extend(migration_issues)
                
                # Validate data integrity
                integrity_issues = self._validate_data_integrity(cursor)
                issues.extend(integrity_issues)
            
            return len(issues) == 0, issues
            
        except Exception as e:
            logger.error(f"Schema validation error: {e}")
            issues.append(f"Schema validation failed: {str(e)}")
            return False, issues
    
    def _get_current_schema(self, cursor) -> Dict:
        """Get current database schema"""
        schema = {}
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        for (table_name,) in tables:
            if table_name.startswith('sqlite_'):
                continue
                
            schema[table_name] = {
                'columns': [],
                'indexes': []
            }
            
            # Get table info
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            for col in columns:
                column_info = {
                    'name': col[1],
                    'type': col[2],
                    'not_null': bool(col[3]),
                    'default': col[4],
                    'primary_key': bool(col[5])
                }
                schema[table_name]['columns'].append(column_info)
            
            # Get indexes
            cursor.execute(f"PRAGMA index_list({table_name})")
            indexes = cursor.fetchall()
            
            for idx in indexes:
                if not idx[1].startswith('sqlite_autoindex'):
                    cursor.execute(f"PRAGMA index_info({idx[1]})")
                    index_columns = [col[2] for col in cursor.fetchall()]
                    
                    schema[table_name]['indexes'].append({
                        'name': idx[1],
                        'columns': index_columns,
                        'unique': bool(idx[2])
                    })
        
        return schema
    
    def _compare_schemas(self, current: Dict, expected: Dict) -> List[str]:
        """Compare current schema with expected schema"""
        issues = []
        
        # Check for missing tables
        for table_name in expected:
            if table_name not in current:
                issues.append(f"Missing table: {table_name}")
                continue
            
            # Check columns
            current_columns = {col['name']: col for col in current[table_name]['columns']}
            expected_columns = {col['name']: col for col in expected[table_name]['columns']}
            
            # Missing columns
            for col_name in expected_columns:
                if col_name not in current_columns:
                    issues.append(f"Missing column: {table_name}.{col_name}")
                else:
                    # Check column properties
                    current_col = current_columns[col_name]
                    expected_col = expected_columns[col_name]
                    
                    if current_col['type'] != expected_col['type']:
                        issues.append(f"Column type mismatch: {table_name}.{col_name} "
                                    f"(expected {expected_col['type']}, got {current_col['type']})")
            
            # Check indexes
            current_indexes = {idx['name']: idx for idx in current[table_name]['indexes']}
            expected_indexes = {idx['name']: idx for idx in expected[table_name].get('indexes', [])}
            
            for idx_name in expected_indexes:
                if idx_name not in current_indexes:
                    issues.append(f"Missing index: {idx_name}")
        
        # Check for extra tables (might be okay)
        for table_name in current:
            if table_name not in expected:
                logger.warning(f"Unexpected table found: {table_name}")
        
        return issues
    
    def _check_pending_migrations(self, cursor) -> List[str]:
        """Check for pending database migrations"""
        issues = []
        
        try:
            # Check if migrations table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='schema_migrations'
            """)
            
            if not cursor.fetchone():
                # Create migrations table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE schema_migrations (
                        version TEXT PRIMARY KEY,
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                logger.info("Created schema_migrations table")
            
            # Get applied migrations
            cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
            applied_migrations = {row[0] for row in cursor.fetchall()}
            
            # Get available migrations
            if self.migrations_dir.exists():
                available_migrations = set()
                for migration_file in self.migrations_dir.glob("*.sql"):
                    version = migration_file.stem
                    available_migrations.add(version)
                
                # Check for pending migrations
                pending_migrations = available_migrations - applied_migrations
                
                if pending_migrations:
                    issues.append(f"Pending migrations: {sorted(pending_migrations)}")
                    logger.warning(f"Found {len(pending_migrations)} pending migrations")
            
        except Exception as e:
            logger.error(f"Migration check error: {e}")
            issues.append(f"Migration check failed: {str(e)}")
        
        return issues
    
    def _validate_data_integrity(self, cursor) -> List[str]:
        """Validate data integrity"""
        issues = []
        
        try:
            # Check foreign key constraints
            cursor.execute("PRAGMA foreign_key_check")
            fk_violations = cursor.fetchall()
            
            if fk_violations:
                issues.append(f"Foreign key violations found: {len(fk_violations)}")
            
            # Check for orphaned records
            cursor.execute("""
                SELECT COUNT(*) FROM scans 
                WHERE user_id NOT IN (SELECT id FROM users)
            """)
            orphaned_scans = cursor.fetchone()[0]
            
            if orphaned_scans > 0:
                issues.append(f"Orphaned scan records: {orphaned_scans}")
            
            # Check for duplicate users
            cursor.execute("""
                SELECT email, COUNT(*) FROM users 
                GROUP BY email HAVING COUNT(*) > 1
            """)
            duplicate_emails = cursor.fetchall()
            
            if duplicate_emails:
                issues.append(f"Duplicate email addresses: {len(duplicate_emails)}")
            
        except Exception as e:
            logger.error(f"Data integrity check error: {e}")
            issues.append(f"Data integrity check failed: {str(e)}")
        
        return issues
    
    def apply_pending_migrations(self) -> Tuple[bool, List[str]]:
        """Apply pending database migrations"""
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get applied migrations
                cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
                applied_migrations = {row[0] for row in cursor.fetchall()}
                
                # Apply pending migrations
                if self.migrations_dir.exists():
                    migration_files = sorted(self.migrations_dir.glob("*.sql"))
                    
                    for migration_file in migration_files:
                        version = migration_file.stem
                        
                        if version not in applied_migrations:
                            logger.info(f"Applying migration: {version}")
                            
                            # Read migration SQL
                            with open(migration_file, 'r') as f:
                                migration_sql = f.read()
                            
                            # Execute migration
                            cursor.executescript(migration_sql)
                            
                            # Record migration
                            cursor.execute(
                                "INSERT INTO schema_migrations (version) VALUES (?)",
                                (version,)
                            )
                            
                            results.append(f"Applied migration: {version}")
                
                conn.commit()
                return True, results
                
        except Exception as e:
            logger.error(f"Migration application error: {e}")
            return False, [f"Migration failed: {str(e)}"]
    
    def generate_schema_hash(self) -> str:
        """Generate hash of current schema for change detection"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                schema = self._get_current_schema(cursor)
                
                # Create deterministic hash
                schema_str = json.dumps(schema, sort_keys=True)
                return hashlib.sha256(schema_str.encode()).hexdigest()
                
        except Exception as e:
            logger.error(f"Schema hash generation error: {e}")
            return ""

# Global instance
schema_validator = SchemaDriftDetector()
