"""
Database migrations for ByteGuardX
Handles schema changes and data migrations
"""

import os
import logging
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class Migration:
    """Base migration class"""
    
    def __init__(self, version: str, description: str):
        self.version = version
        self.description = description
        self.timestamp = datetime.now()
    
    def up(self, session):
        """Apply migration"""
        raise NotImplementedError("Migration must implement up() method")
    
    def down(self, session):
        """Rollback migration"""
        raise NotImplementedError("Migration must implement down() method")

class MigrationRunner:
    """Migration runner and tracker"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.migrations_dir = Path(__file__).parent
        self.applied_migrations = set()
        
    def _create_migration_table(self, session):
        """Create migration tracking table"""
        session.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(50) PRIMARY KEY,
                description TEXT,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        session.commit()
    
    def _load_applied_migrations(self, session):
        """Load list of applied migrations"""
        try:
            result = session.execute("SELECT version FROM schema_migrations")
            self.applied_migrations = {row[0] for row in result}
        except Exception:
            # Table doesn't exist yet
            self.applied_migrations = set()
    
    def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations"""
        # Import all migration modules
        migrations = []
        
        # Add initial migration
        from .v001_initial_schema import InitialSchemaMigration
        migrations.append(InitialSchemaMigration())
        
        # Filter out already applied migrations
        pending = [m for m in migrations if m.version not in self.applied_migrations]
        return sorted(pending, key=lambda x: x.version)
    
    def run_migrations(self):
        """Run all pending migrations"""
        with self.db_manager.get_session() as session:
            self._create_migration_table(session)
            self._load_applied_migrations(session)
            
            pending = self.get_pending_migrations()
            
            if not pending:
                logger.info("No pending migrations")
                return
            
            logger.info(f"Running {len(pending)} migrations")
            
            for migration in pending:
                try:
                    logger.info(f"Applying migration {migration.version}: {migration.description}")
                    migration.up(session)
                    
                    # Record migration as applied
                    session.execute(
                        "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                        (migration.version, migration.description)
                    )
                    session.commit()
                    
                    logger.info(f"Migration {migration.version} applied successfully")
                    
                except Exception as e:
                    logger.error(f"Migration {migration.version} failed: {e}")
                    session.rollback()
                    raise

def run_migrations(db_manager):
    """Run database migrations"""
    runner = MigrationRunner(db_manager)
    runner.run_migrations()
