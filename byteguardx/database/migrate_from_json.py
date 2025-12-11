"""
Migration script to convert existing JSON data to database
Helps users transition from file-based storage to SQLAlchemy database
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import uuid

from .connection_pool import db_manager, init_db
from .models import User, Organization, ScanResult, Finding, UserFeedback, AuditLog

logger = logging.getLogger(__name__)

class JSONToDBMigrator:
    """Migrates existing JSON data to database"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.migration_log = []
        
    def migrate_all(self, database_url: str = None):
        """Migrate all JSON data to database"""
        logger.info("Starting migration from JSON to database")
        
        # Initialize database
        if database_url:
            init_db(database_url)
        else:
            init_db()
        
        try:
            # Migrate in order of dependencies
            self.migrate_organizations()
            self.migrate_users()
            self.migrate_audit_logs()
            self.migrate_user_feedback()
            
            # Note: Scan results are stored in memory in the old system,
            # so we can't migrate them. Users will need to re-run scans.
            
            logger.info("Migration completed successfully")
            self.print_migration_summary()
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            raise
    
    def migrate_organizations(self):
        """Migrate organizations from JSON"""
        orgs_file = self.data_dir / "organizations.json"
        
        if not orgs_file.exists():
            logger.info("No organizations file found, skipping")
            return
        
        try:
            with open(orgs_file, 'r') as f:
                orgs_data = json.load(f)
            
            if not orgs_data:
                logger.info("No organizations to migrate")
                return
            
            migrated_count = 0
            
            with db_manager.get_session() as session:
                for org_data in orgs_data:
                    try:
                        # Create organization
                        org = Organization(
                            id=org_data.get('id', str(uuid.uuid4())),
                            name=org_data.get('name', ''),
                            domain=org_data.get('domain'),
                            settings=org_data.get('settings', {}),
                            subscription_tier=org_data.get('subscription_tier', 'free'),
                            is_active=org_data.get('is_active', True),
                            created_at=self._parse_datetime(org_data.get('created_at')),
                            updated_at=self._parse_datetime(org_data.get('updated_at'))
                        )
                        
                        session.add(org)
                        migrated_count += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to migrate organization {org_data.get('name', 'unknown')}: {e}")
                
                session.commit()
            
            self.migration_log.append(f"Migrated {migrated_count} organizations")
            logger.info(f"Migrated {migrated_count} organizations")
            
        except Exception as e:
            logger.error(f"Failed to migrate organizations: {e}")
            raise
    
    def migrate_users(self):
        """Migrate users from JSON"""
        users_file = self.data_dir / "users.json"
        
        if not users_file.exists():
            logger.info("No users file found, skipping")
            return
        
        try:
            with open(users_file, 'r') as f:
                users_data = json.load(f)
            
            if not users_data:
                logger.info("No users to migrate")
                return
            
            migrated_count = 0
            
            with db_manager.get_session() as session:
                for user_data in users_data:
                    try:
                        # Create user
                        user = User(
                            id=user_data.get('id', str(uuid.uuid4())),
                            email=user_data.get('email', ''),
                            username=user_data.get('username', ''),
                            password_hash=user_data.get('password_hash', ''),
                            first_name=user_data.get('first_name'),
                            last_name=user_data.get('last_name'),
                            role=user_data.get('role', 'developer'),
                            subscription_tier=user_data.get('subscription_tier', 'free'),
                            organization_id=user_data.get('organization_id'),
                            is_active=user_data.get('is_active', True),
                            email_verified=user_data.get('email_verified', False),
                            created_at=self._parse_datetime(user_data.get('created_at')),
                            updated_at=self._parse_datetime(user_data.get('updated_at')),
                            last_login=self._parse_datetime(user_data.get('last_login')),
                            scans_this_month=user_data.get('scans_this_month', 0),
                            total_scans=user_data.get('total_scans', 0),
                            preferences=user_data.get('preferences', {})
                        )
                        
                        session.add(user)
                        migrated_count += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to migrate user {user_data.get('email', 'unknown')}: {e}")
                
                session.commit()
            
            self.migration_log.append(f"Migrated {migrated_count} users")
            logger.info(f"Migrated {migrated_count} users")
            
        except Exception as e:
            logger.error(f"Failed to migrate users: {e}")
            raise
    
    def migrate_audit_logs(self):
        """Migrate audit logs from JSON"""
        audit_file = self.data_dir / "audit_logs.json"
        
        if not audit_file.exists():
            logger.info("No audit logs file found, skipping")
            return
        
        try:
            with open(audit_file, 'r') as f:
                audit_data = json.load(f)
            
            if not audit_data:
                logger.info("No audit logs to migrate")
                return
            
            migrated_count = 0
            
            with db_manager.get_session() as session:
                for log_data in audit_data:
                    try:
                        # Create audit log
                        audit_log = AuditLog(
                            id=log_data.get('id', str(uuid.uuid4())),
                            user_id=log_data.get('user_id'),
                            action=log_data.get('action', ''),
                            resource_type=log_data.get('resource_type', ''),
                            resource_id=log_data.get('resource_id'),
                            ip_address=log_data.get('ip_address'),
                            user_agent=log_data.get('user_agent'),
                            endpoint=log_data.get('endpoint'),
                            method=log_data.get('method'),
                            status_code=log_data.get('status_code'),
                            success=log_data.get('success', True),
                            error_message=log_data.get('error_message'),
                            metadata=log_data.get('metadata', {}),
                            created_at=self._parse_datetime(log_data.get('created_at'))
                        )
                        
                        session.add(audit_log)
                        migrated_count += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to migrate audit log: {e}")
                
                session.commit()
            
            self.migration_log.append(f"Migrated {migrated_count} audit logs")
            logger.info(f"Migrated {migrated_count} audit logs")
            
        except Exception as e:
            logger.error(f"Failed to migrate audit logs: {e}")
            raise
    
    def migrate_user_feedback(self):
        """Migrate user feedback from ML learning data"""
        feedback_file = self.data_dir / "ml" / "user_feedback.json"
        
        if not feedback_file.exists():
            logger.info("No user feedback file found, skipping")
            return
        
        try:
            with open(feedback_file, 'r') as f:
                feedback_data = json.load(f)
            
            if not feedback_data:
                logger.info("No user feedback to migrate")
                return
            
            migrated_count = 0
            
            with db_manager.get_session() as session:
                for feedback_item in feedback_data:
                    try:
                        # Note: We can't migrate finding_id since findings are not stored in JSON
                        # This is a limitation of the old system
                        feedback = UserFeedback(
                            id=feedback_item.get('id', str(uuid.uuid4())),
                            user_id=feedback_item.get('user_id'),
                            finding_id=None,  # Will need to be updated after re-scanning
                            is_false_positive=feedback_item.get('is_false_positive', False),
                            feedback_type=feedback_item.get('feedback_type', 'false_positive'),
                            comments=feedback_item.get('comments'),
                            suggested_severity=feedback_item.get('suggested_severity'),
                            confidence=feedback_item.get('confidence', 1.0),
                            metadata=feedback_item.get('metadata', {}),
                            created_at=self._parse_datetime(feedback_item.get('created_at'))
                        )
                        
                        session.add(feedback)
                        migrated_count += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to migrate user feedback: {e}")
                
                session.commit()
            
            self.migration_log.append(f"Migrated {migrated_count} user feedback items")
            logger.info(f"Migrated {migrated_count} user feedback items")
            
        except Exception as e:
            logger.error(f"Failed to migrate user feedback: {e}")
            raise
    
    def _parse_datetime(self, date_str: str) -> datetime:
        """Parse datetime string"""
        if not date_str:
            return datetime.now()
        
        try:
            # Try ISO format first
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            try:
                # Try common formats
                return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
            except:
                return datetime.now()
    
    def print_migration_summary(self):
        """Print migration summary"""
        print("\n" + "="*50)
        print("MIGRATION SUMMARY")
        print("="*50)
        
        for log_entry in self.migration_log:
            print(f"✅ {log_entry}")
        
        print("\n📝 IMPORTANT NOTES:")
        print("- Scan results were not migrated (stored in memory in old system)")
        print("- Users will need to re-run scans to populate the database")
        print("- User feedback items may need finding_id updates after re-scanning")
        print("- Backup your JSON files before deleting them")
        
        print("\n🚀 Next steps:")
        print("1. Test the new database-backed application")
        print("2. Run some test scans to verify functionality")
        print("3. Update your deployment to use the new enhanced_app.py")
        print("4. Archive the old JSON files once you're satisfied")
        
        print("="*50)

def run_migration(data_dir: str = "data", database_url: str = None):
    """Run the migration process"""
    migrator = JSONToDBMigrator(data_dir)
    migrator.migrate_all(database_url)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Migrate ByteGuardX JSON data to database")
    parser.add_argument("--data-dir", default="data", help="Data directory containing JSON files")
    parser.add_argument("--database-url", help="Database URL (default: SQLite)")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    run_migration(args.data_dir, args.database_url)
