"""
Database connection pool and management for ByteGuardX
Provides thread-safe database connections with connection pooling
"""

import os
import logging
from contextlib import contextmanager
from typing import Optional, Dict, Any
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError
import threading
import time

from .models import Base

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Thread-safe database connection manager with connection pooling
    Supports SQLite for offline mode and PostgreSQL for production
    """
    
    def __init__(self, database_url: Optional[str] = None, **kwargs):
        self.database_url = database_url or self._get_database_url()
        self.engine = None
        self.SessionLocal = None
        self._lock = threading.Lock()
        self._initialized = False
        
        # Configuration
        self.config = {
            'pool_size': kwargs.get('pool_size', 10),
            'max_overflow': kwargs.get('max_overflow', 20),
            'pool_timeout': kwargs.get('pool_timeout', 30),
            'pool_recycle': kwargs.get('pool_recycle', 3600),
            'pool_pre_ping': kwargs.get('pool_pre_ping', True),
            'echo': kwargs.get('echo', False),
            'connect_args': kwargs.get('connect_args', {})
        }
        
        # Health monitoring
        self._connection_errors = 0
        self._last_health_check = 0
        self._health_check_interval = 60  # seconds
        
    def _get_database_url(self) -> str:
        """Get database URL from environment or default to SQLite"""
        # Check for production database URL
        db_url = os.environ.get('DATABASE_URL')
        if db_url:
            return db_url
            
        # Check for individual components
        db_type = os.environ.get('DB_TYPE', 'sqlite')
        
        if db_type.lower() == 'postgresql':
            host = os.environ.get('DB_HOST', 'localhost')
            port = os.environ.get('DB_PORT', '5432')
            name = os.environ.get('DB_NAME', 'byteguardx')
            user = os.environ.get('DB_USER', 'byteguardx')
            password = os.environ.get('DB_PASSWORD', '')
            return f"postgresql://{user}:{password}@{host}:{port}/{name}"
        
        # Default to SQLite for offline mode
        db_path = os.environ.get('DB_PATH', 'data/byteguardx.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        return f"sqlite:///{db_path}"
    
    def initialize(self):
        """Initialize database connection and create tables"""
        with self._lock:
            if self._initialized:
                return
                
            try:
                # Configure engine based on database type
                if self.database_url.startswith('sqlite'):
                    self._configure_sqlite_engine()
                else:
                    self._configure_postgresql_engine()
                
                # Create session factory
                self.SessionLocal = scoped_session(sessionmaker(
                    autocommit=False,
                    autoflush=False,
                    bind=self.engine
                ))
                
                # Create tables
                self._create_tables()
                
                # Set up event listeners
                self._setup_event_listeners()
                
                self._initialized = True
                logger.info(f"Database initialized successfully: {self._mask_url(self.database_url)}")
                
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise
    
    def _configure_sqlite_engine(self):
        """Configure SQLite engine for offline mode"""
        connect_args = {
            'check_same_thread': False,
            'timeout': 30,
            **self.config['connect_args']
        }
        
        self.engine = create_engine(
            self.database_url,
            poolclass=StaticPool,
            connect_args=connect_args,
            echo=self.config['echo']
        )
        
        # Enable WAL mode for better concurrency
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=10000")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.close()
    
    def _configure_postgresql_engine(self):
        """Configure PostgreSQL engine for production"""
        self.engine = create_engine(
            self.database_url,
            poolclass=QueuePool,
            pool_size=self.config['pool_size'],
            max_overflow=self.config['max_overflow'],
            pool_timeout=self.config['pool_timeout'],
            pool_recycle=self.config['pool_recycle'],
            pool_pre_ping=self.config['pool_pre_ping'],
            connect_args=self.config['connect_args'],
            echo=self.config['echo']
        )
    
    def _create_tables(self):
        """Create database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    def _setup_event_listeners(self):
        """Set up database event listeners for monitoring"""
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            logger.debug("Database connection established")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug("Database connection checked out from pool")
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            logger.debug("Database connection returned to pool")
        
        @event.listens_for(self.engine, "invalidate")
        def receive_invalidate(dbapi_connection, connection_record, exception):
            logger.warning(f"Database connection invalidated: {exception}")
            self._connection_errors += 1
    
    @contextmanager
    def get_session(self):
        """
        Get database session with automatic cleanup
        Usage:
            with db_manager.get_session() as session:
                # Use session here
                pass
        """
        if not self._initialized:
            self.initialize()
        
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def get_raw_session(self):
        """Get raw session (manual management required)"""
        if not self._initialized:
            self.initialize()
        return self.SessionLocal()
    
    def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        current_time = time.time()
        
        # Skip if recently checked
        if current_time - self._last_health_check < self._health_check_interval:
            return {'status': 'cached', 'healthy': self._connection_errors == 0}
        
        try:
            with self.get_session() as session:
                # Simple query to test connection
                session.execute("SELECT 1")
                
            self._last_health_check = current_time
            healthy = True
            status = 'healthy'
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            healthy = False
            status = 'unhealthy'
            self._connection_errors += 1
        
        # Get pool status
        pool_status = {}
        if hasattr(self.engine.pool, 'size'):
            pool_status = {
                'pool_size': self.engine.pool.size(),
                'checked_in': self.engine.pool.checkedin(),
                'checked_out': self.engine.pool.checkedout(),
                'overflow': getattr(self.engine.pool, 'overflow', 0),
                'invalid': getattr(self.engine.pool, 'invalid', 0)
            }
        
        return {
            'status': status,
            'healthy': healthy,
            'connection_errors': self._connection_errors,
            'database_url': self._mask_url(self.database_url),
            'pool_status': pool_status,
            'last_check': current_time
        }
    
    def reset_connection_errors(self):
        """Reset connection error counter"""
        self._connection_errors = 0
    
    def close(self):
        """Close all connections and cleanup"""
        if self.SessionLocal:
            self.SessionLocal.remove()
        if self.engine:
            self.engine.dispose()
        self._initialized = False
        logger.info("Database connections closed")
    
    def _mask_url(self, url: str) -> str:
        """Mask sensitive information in database URL"""
        if '://' not in url:
            return url
        
        scheme, rest = url.split('://', 1)
        if '@' in rest:
            credentials, host_part = rest.split('@', 1)
            # Mask password
            if ':' in credentials:
                user, _ = credentials.split(':', 1)
                return f"{scheme}://{user}:***@{host_part}"
        
        return url

# Global database manager instance
db_manager = DatabaseManager()

def get_db_session():
    """Get database session - for dependency injection"""
    return db_manager.get_session()

def init_db(database_url: Optional[str] = None, **kwargs):
    """Initialize global database manager"""
    global db_manager
    if database_url or kwargs:
        db_manager = DatabaseManager(database_url, **kwargs)
    db_manager.initialize()
    return db_manager
