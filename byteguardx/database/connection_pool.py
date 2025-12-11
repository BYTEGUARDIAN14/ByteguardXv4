"""
Database connection pool and management for ByteGuardX
Provides thread-safe database connections with connection pooling
"""

import os
import logging
from contextlib import contextmanager
from typing import Optional, Dict, Any, List
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque

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
        
        # Enhanced health monitoring and leak detection
        self._connection_errors = 0
        self._last_health_check = 0
        self._health_check_interval = 60  # seconds

        # Connection leak detection
        self._connection_tracking = {}
        self._max_connection_errors = 10
        self._connection_leak_threshold = 50
        self._active_connections = 0
        self._peak_connections = 0

        # Performance metrics
        self._connection_metrics = {
            'total_connections_created': 0,
            'total_connections_closed': 0,
            'connection_errors': 0,
            'pool_exhaustions': 0,
            'average_connection_time': 0.0,
            'connection_timeouts': 0,
            'connection_leaks_detected': 0,
            'pool_refreshes': 0
        }

        # Connection timing
        self._connection_start_times = {}
        self._connection_durations = deque(maxlen=1000)

        # Start connection monitoring
        self._start_connection_monitor()

    def _start_connection_monitor(self):
        """Start connection monitoring thread"""
        import threading

        def connection_monitor_loop():
            while True:
                try:
                    self._monitor_connections()
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    logger.error(f"Connection monitor error: {e}")
                    time.sleep(30)

        monitor_thread = threading.Thread(target=connection_monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Database connection monitor started")

    def _monitor_connections(self):
        """Monitor connection pool health and detect leaks"""
        try:
            current_time = time.time()

            # Check for connection leaks
            if self.engine and hasattr(self.engine.pool, 'size'):
                pool_size = self.engine.pool.size()
                checked_out = self.engine.pool.checkedout()

                # Update peak connections
                if checked_out > self._peak_connections:
                    self._peak_connections = checked_out

                # Detect potential leaks
                if checked_out > self._connection_leak_threshold:
                    logger.warning(f"Potential connection leak: {checked_out} connections checked out")
                    self._connection_metrics['connection_leaks_detected'] += 1
                    self._handle_connection_leak()

                # Log connection pool status
                if checked_out > pool_size * 0.8:  # 80% utilization
                    logger.warning(f"High connection pool utilization: {checked_out}/{pool_size}")

            # Clean up old connection tracking
            self._cleanup_connection_tracking(current_time)

            # Update health check timestamp
            self._last_health_check = current_time

        except Exception as e:
            logger.error(f"Connection monitoring failed: {e}")

    def _handle_connection_leak(self):
        """Handle detected connection leak"""
        try:
            logger.warning("Handling connection leak - refreshing pool")

            # Refresh connection pool
            if self.engine:
                self.engine.dispose()
                self._connection_metrics['pool_refreshes'] += 1

                # Reinitialize if needed
                if self._initialized:
                    self._initialized = False
                    self.initialize()

            # Reset connection tracking
            self._connection_tracking.clear()
            self._connection_errors = 0

            logger.info("Connection pool refreshed due to leak detection")

        except Exception as e:
            logger.error(f"Connection leak handling failed: {e}")

    def _cleanup_connection_tracking(self, current_time: float):
        """Clean up old connection tracking entries"""
        try:
            # Remove connections older than 1 hour
            cutoff_time = current_time - 3600

            expired_connections = [
                conn_id for conn_id, start_time in self._connection_start_times.items()
                if start_time < cutoff_time
            ]

            for conn_id in expired_connections:
                self._connection_start_times.pop(conn_id, None)
                self._connection_tracking.pop(conn_id, None)

        except Exception as e:
            logger.error(f"Connection tracking cleanup failed: {e}")
        
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
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
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
        Get database session with automatic cleanup and connection leak prevention
        Usage:
            with db_manager.get_session() as session:
                # Use session here
                pass
        """
        if not self._initialized:
            self.initialize()

        session = None
        try:
            session = self.SessionLocal()
            # Set session timeout to prevent hanging connections
            # Set session timeout to prevent hanging connections (PostgreSQL only)
            if hasattr(session.bind, 'execute') and session.bind.dialect.name == 'postgresql':
                session.execute('SET statement_timeout = 30000')

            yield session
            session.commit()

        except Exception as e:
            if session:
                try:
                    session.rollback()
                except Exception as rollback_error:
                    logger.error(f"Session rollback failed: {rollback_error}")

            logger.error(f"Database session error: {e}")
            self._connection_errors += 1

            # Force connection refresh on repeated errors
            if self._connection_errors > 10:
                logger.warning("High connection error count, refreshing connection pool")
                self._refresh_connection_pool()

            raise
        finally:
            if session:
                try:
                    session.close()
                except Exception as close_error:
                    logger.error(f"Session close failed: {close_error}")

    def _refresh_connection_pool(self):
        """Refresh connection pool to prevent connection leaks"""
        try:
            if self.engine:
                self.engine.dispose()
                logger.info("Connection pool refreshed")
                self._connection_errors = 0
        except Exception as e:
            logger.error(f"Failed to refresh connection pool: {e}")
    
    def get_raw_session(self):
        """Get raw session (manual management required)"""
        if not self._initialized:
            self.initialize()
        return self.SessionLocal()
    
    def get_pool_status(self) -> Dict[str, Any]:
        """Get connection pool status"""
        if not self.engine:
            return {}
            
        pool_status = {}
        if hasattr(self.engine.pool, 'size'):
            pool_status = {
                'pool_size': self.engine.pool.size(),
                'checked_in': self.engine.pool.checkedin(),
                'checked_out': self.engine.pool.checkedout(),
                'overflow': getattr(self.engine.pool, 'overflow', 0),
                'active_connections': self.engine.pool.checkedout()
            }
        return pool_status

    def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        current_time = time.time()
        
        # Skip if recently checked
        if current_time - self._last_health_check < self._health_check_interval:
            return {'status': 'cached', 'healthy': self._connection_errors == 0}
        
        try:
            with self.get_session() as session:
                from sqlalchemy import text
                # Simple query to test connection
                session.execute(text("SELECT 1"))
                
            self._last_health_check = current_time
            healthy = True
            status = 'healthy'
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            healthy = False
            status = 'unhealthy'
            self._connection_errors += 1
        
        # Get pool status
        pool_status = self.get_pool_status()
        
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
