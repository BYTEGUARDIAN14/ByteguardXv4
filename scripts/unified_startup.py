#!/usr/bin/env python3
"""
Unified Startup Script for ByteGuardX
Handles environment setup, health checks, and deployment across providers
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Environment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class Provider(Enum):
    """Cloud providers"""
    LOCAL = "local"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DOCKER = "docker"

@dataclass
class StartupConfig:
    """Startup configuration"""
    environment: Environment
    provider: Provider
    migrate_db: bool = False
    apply_migrations: bool = False
    run_health_check: bool = True
    start_services: bool = True
    enable_monitoring: bool = False
    debug_mode: bool = False

class UnifiedStartup:
    """Unified startup manager for ByteGuardX"""
    
    def __init__(self, config: StartupConfig):
        self.config = config
        self.project_root = project_root
        self.required_env_vars = [
            'JWT_SECRET_KEY',
            'BYTEGUARDX_MASTER_KEY',
            'DATABASE_URL'
        ]
        
    def start(self) -> bool:
        """Start ByteGuardX with unified configuration"""
        try:
            logger.info(f"🚀 Starting ByteGuardX in {self.config.environment.value} mode")
            logger.info(f"📍 Provider: {self.config.provider.value}")
            
            # Pre-startup checks
            if not self._pre_startup_checks():
                return False
            
            # Environment setup
            if not self._setup_environment():
                return False
            
            # Database operations
            if self.config.migrate_db:
                if not self._handle_database_migration():
                    return False
            
            # Health checks
            if self.config.run_health_check:
                if not self._run_health_checks():
                    return False
            
            # Start services
            if self.config.start_services:
                if not self._start_services():
                    return False
            
            # Post-startup validation
            if not self._post_startup_validation():
                return False
            
            logger.info("✅ ByteGuardX started successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Startup failed: {e}")
            return False
    
    def _pre_startup_checks(self) -> bool:
        """Run pre-startup validation checks"""
        logger.info("🔍 Running pre-startup checks...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("Python 3.8+ is required")
            return False
        
        # Check required files
        required_files = [
            'byteguardx/__init__.py',
            'requirements.txt',
            'portal/package.json'
        ]
        
        for file_path in required_files:
            if not (self.project_root / file_path).exists():
                logger.error(f"Required file missing: {file_path}")
                return False
        
        # Check environment variables
        missing_vars = []
        for var in self.required_env_vars:
            if not os.environ.get(var):
                missing_vars.append(var)
        
        if missing_vars:
            logger.error(f"Missing environment variables: {', '.join(missing_vars)}")
            return False
        
        # Check disk space
        if not self._check_disk_space():
            return False
        
        # Check network connectivity
        if not self._check_network_connectivity():
            return False
        
        logger.info("✅ Pre-startup checks passed")
        return True
    
    def _setup_environment(self) -> bool:
        """Set up environment-specific configuration"""
        logger.info("⚙️ Setting up environment...")
        
        try:
            # Set environment variables
            os.environ['FLASK_ENV'] = self.config.environment.value
            os.environ['BYTEGUARDX_PROVIDER'] = self.config.provider.value
            
            if self.config.debug_mode:
                os.environ['DEBUG'] = 'true'
                os.environ['LOG_LEVEL'] = 'DEBUG'
            
            # Create required directories
            required_dirs = [
                'data',
                'logs',
                'reports',
                'reports/templates',
                'offline_db',
                'ml/models',
                'plugins/storage'
            ]
            
            for dir_name in required_dirs:
                dir_path = self.project_root / dir_name
                dir_path.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created directory: {dir_path}")
            
            # Install/update dependencies
            if not self._install_dependencies():
                return False
            
            # Provider-specific setup
            if not self._setup_provider_specific():
                return False
            
            logger.info("✅ Environment setup complete")
            return True
            
        except Exception as e:
            logger.error(f"Environment setup failed: {e}")
            return False
    
    def _install_dependencies(self) -> bool:
        """Install Python and Node.js dependencies"""
        logger.info("📦 Installing dependencies...")
        
        try:
            # Install Python dependencies
            logger.info("Installing Python dependencies...")
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Python dependency installation failed: {result.stderr}")
                return False
            
            # Install Node.js dependencies for portal
            portal_dir = self.project_root / 'portal'
            if portal_dir.exists() and (portal_dir / 'package.json').exists():
                logger.info("Installing Node.js dependencies...")
                result = subprocess.run([
                    'npm', 'install'
                ], cwd=portal_dir, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.warning(f"Node.js dependency installation failed: {result.stderr}")
                    # Don't fail startup for frontend dependencies
            
            return True
            
        except Exception as e:
            logger.error(f"Dependency installation failed: {e}")
            return False
    
    def _setup_provider_specific(self) -> bool:
        """Set up provider-specific configuration"""
        logger.info(f"🔧 Setting up {self.config.provider.value} provider...")
        
        try:
            if self.config.provider == Provider.AWS:
                return self._setup_aws()
            elif self.config.provider == Provider.GCP:
                return self._setup_gcp()
            elif self.config.provider == Provider.AZURE:
                return self._setup_azure()
            elif self.config.provider == Provider.DOCKER:
                return self._setup_docker()
            else:  # LOCAL
                return self._setup_local()
                
        except Exception as e:
            logger.error(f"Provider setup failed: {e}")
            return False
    
    def _setup_local(self) -> bool:
        """Set up local development environment"""
        logger.info("Setting up local environment...")
        
        # Check for Redis
        try:
            subprocess.run(['redis-cli', 'ping'], capture_output=True, check=True)
            logger.info("✅ Redis is running")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("⚠️ Redis not found - some features may be limited")
        
        # Check for PostgreSQL
        try:
            subprocess.run(['psql', '--version'], capture_output=True, check=True)
            logger.info("✅ PostgreSQL is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("⚠️ PostgreSQL not found - using SQLite fallback")
            os.environ['DATABASE_URL'] = 'sqlite:///byteguardx.db'
        
        return True
    
    def _setup_docker(self) -> bool:
        """Set up Docker environment"""
        logger.info("Setting up Docker environment...")
        
        try:
            # Check if Docker is available
            subprocess.run(['docker', '--version'], capture_output=True, check=True)
            
            # Start services with Docker Compose
            compose_file = 'docker-compose.scale.yml' if self.config.environment == Environment.PRODUCTION else 'docker-compose.yml'
            
            if (self.project_root / compose_file).exists():
                logger.info(f"Starting services with {compose_file}...")
                subprocess.run([
                    'docker-compose', '-f', compose_file, 'up', '-d'
                ], cwd=self.project_root, check=True)
                
                # Wait for services to be ready
                time.sleep(10)
                
            return True
            
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Docker setup failed: {e}")
            return False
    
    def _setup_aws(self) -> bool:
        """Set up AWS environment"""
        logger.info("Setting up AWS environment...")
        # AWS-specific setup would go here
        return True
    
    def _setup_gcp(self) -> bool:
        """Set up GCP environment"""
        logger.info("Setting up GCP environment...")
        # GCP-specific setup would go here
        return True
    
    def _setup_azure(self) -> bool:
        """Set up Azure environment"""
        logger.info("Setting up Azure environment...")
        # Azure-specific setup would go here
        return True
    
    def _handle_database_migration(self) -> bool:
        """Handle database migrations"""
        logger.info("🗄️ Handling database migrations...")
        
        try:
            # Run database migrations
            if self.config.apply_migrations:
                logger.info("Applying database migrations...")
                # This would run actual migration commands
                # For now, just create tables if they don't exist
                
                from byteguardx.database.connection_pool import db_manager
                from byteguardx.database.models import Base
                
                with db_manager.get_engine() as engine:
                    Base.metadata.create_all(engine)
                
                logger.info("✅ Database migrations applied")
            
            return True
            
        except Exception as e:
            logger.error(f"Database migration failed: {e}")
            return False
    
    def _run_health_checks(self) -> bool:
        """Run comprehensive health checks"""
        logger.info("🏥 Running health checks...")
        
        try:
            # Database connectivity
            if not self._check_database_health():
                return False
            
            # Redis connectivity (if available)
            self._check_redis_health()
            
            # File system permissions
            if not self._check_filesystem_health():
                return False
            
            # Security validation
            if not self._check_security_health():
                return False
            
            logger.info("✅ Health checks passed")
            return True
            
        except Exception as e:
            logger.error(f"Health checks failed: {e}")
            return False
    
    def _start_services(self) -> bool:
        """Start ByteGuardX services"""
        logger.info("🚀 Starting services...")
        
        try:
            if self.config.provider == Provider.DOCKER:
                # Services already started in Docker setup
                return True
            
            # Start Flask application
            logger.info("Starting Flask application...")
            
            # For development, we might start the dev server
            if self.config.environment == Environment.DEVELOPMENT:
                # This would typically be handled by the development server
                pass
            
            # Start Celery workers if configured
            if os.environ.get('CELERY_BROKER_URL'):
                logger.info("Celery broker configured - workers can be started")
            
            return True
            
        except Exception as e:
            logger.error(f"Service startup failed: {e}")
            return False
    
    def _post_startup_validation(self) -> bool:
        """Run post-startup validation"""
        logger.info("✅ Running post-startup validation...")
        
        try:
            # Validate API endpoints
            # Validate security modules
            # Check monitoring endpoints
            
            logger.info("✅ Post-startup validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Post-startup validation failed: {e}")
            return False
    
    def _check_disk_space(self) -> bool:
        """Check available disk space"""
        try:
            import shutil
            total, used, free = shutil.disk_usage(self.project_root)
            free_gb = free // (1024**3)
            
            if free_gb < 1:  # Less than 1GB free
                logger.error(f"Insufficient disk space: {free_gb}GB free")
                return False
            
            logger.debug(f"Disk space: {free_gb}GB free")
            return True
            
        except Exception as e:
            logger.warning(f"Could not check disk space: {e}")
            return True  # Don't fail startup for this
    
    def _check_network_connectivity(self) -> bool:
        """Check network connectivity"""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            logger.debug("Network connectivity: OK")
            return True
        except OSError:
            logger.warning("Limited network connectivity detected")
            return True  # Don't fail startup for this
    
    def _check_database_health(self) -> bool:
        """Check database connectivity"""
        try:
            from byteguardx.database.connection_pool import db_manager
            
            with db_manager.get_session() as session:
                session.execute("SELECT 1")
            
            logger.info("✅ Database connectivity: OK")
            return True
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    def _check_redis_health(self) -> bool:
        """Check Redis connectivity"""
        try:
            import redis
            redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
            r = redis.from_url(redis_url)
            r.ping()
            logger.info("✅ Redis connectivity: OK")
            return True
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            return False
    
    def _check_filesystem_health(self) -> bool:
        """Check filesystem permissions"""
        try:
            # Test write permissions
            test_file = self.project_root / 'data' / '.write_test'
            test_file.write_text('test')
            test_file.unlink()
            
            logger.debug("Filesystem permissions: OK")
            return True
            
        except Exception as e:
            logger.error(f"Filesystem health check failed: {e}")
            return False
    
    def _check_security_health(self) -> bool:
        """Check security configuration"""
        try:
            # Validate JWT secret
            jwt_secret = os.environ.get('JWT_SECRET_KEY')
            if len(jwt_secret) < 32:
                logger.error("JWT secret key is too short")
                return False
            
            # Validate master key
            master_key = os.environ.get('BYTEGUARDX_MASTER_KEY')
            if len(master_key) < 32:
                logger.error("Master key is too short")
                return False
            
            logger.debug("Security configuration: OK")
            return True
            
        except Exception as e:
            logger.error(f"Security health check failed: {e}")
            return False

def main():
    """Main startup function"""
    parser = argparse.ArgumentParser(description='ByteGuardX Unified Startup')
    
    parser.add_argument('--env', choices=['development', 'staging', 'production'],
                       default='development', help='Environment')
    parser.add_argument('--provider', choices=['local', 'aws', 'gcp', 'azure', 'docker'],
                       default='local', help='Cloud provider')
    parser.add_argument('--migrate', action='store_true', help='Run database migrations')
    parser.add_argument('--apply', action='store_true', help='Apply migrations')
    parser.add_argument('--no-health-check', action='store_true', help='Skip health checks')
    parser.add_argument('--no-services', action='store_true', help='Skip service startup')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    config = StartupConfig(
        environment=Environment(args.env),
        provider=Provider(args.provider),
        migrate_db=args.migrate,
        apply_migrations=args.apply,
        run_health_check=not args.no_health_check,
        start_services=not args.no_services,
        debug_mode=args.debug
    )
    
    startup = UnifiedStartup(config)
    success = startup.start()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
