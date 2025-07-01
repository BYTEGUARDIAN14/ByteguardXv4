"""
Initial schema migration for ByteGuardX database
Creates all base tables and indexes
"""

from . import Migration

class InitialSchemaMigration(Migration):
    """Initial database schema migration"""
    
    def __init__(self):
        super().__init__("001", "Create initial database schema")
    
    def up(self, session):
        """Create initial schema"""
        # This migration is handled by SQLAlchemy's create_all()
        # since we're using declarative models
        pass
    
    def down(self, session):
        """Drop all tables"""
        # Drop tables in reverse dependency order
        tables_to_drop = [
            'audit_logs',
            'user_feedback', 
            'findings',
            'scan_results',
            'patterns',
            'users',
            'organizations'
        ]
        
        for table in tables_to_drop:
            session.execute(f"DROP TABLE IF EXISTS {table}")
        
        session.commit()
