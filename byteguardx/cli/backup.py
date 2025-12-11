"""
ByteGuardX Backup and Disaster Recovery System
Provides automated backup, encryption, and restore capabilities
"""

import os
import json
import logging
import subprocess
import shutil
import gzip
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import click
from cryptography.fernet import Fernet
import tempfile

from ..database.connection_pool import db_manager
from ..security.encryption import DataEncryption

logger = logging.getLogger(__name__)

class BackupManager:
    """Manages backup and restore operations"""
    
    def __init__(self, backup_dir: str = "data/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.encryption = DataEncryption()
        self.backup_config = self._load_backup_config()
        
        # Backup retention settings
        self.retention_days = self.backup_config.get('retention_days', 30)
        self.max_backups = self.backup_config.get('max_backups', 50)
    
    def _load_backup_config(self) -> Dict[str, Any]:
        """Load backup configuration"""
        config_file = self.backup_dir / "backup_config.json"
        
        default_config = {
            'retention_days': 30,
            'max_backups': 50,
            'compression': True,
            'encryption': True,
            'include_logs': False,
            'include_temp_files': False,
            'database_backup': True,
            'file_backup': True
        }
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"Failed to load backup config: {e}")
        
        # Save default config
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        return default_config
    
    def create_backup(self, backup_name: Optional[str] = None, 
                     include_database: bool = True,
                     include_files: bool = True) -> str:
        """Create a complete system backup"""
        try:
            if not backup_name:
                backup_name = f"byteguardx_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            backup_path = self.backup_dir / backup_name
            backup_path.mkdir(exist_ok=True)
            
            backup_manifest = {
                'backup_name': backup_name,
                'created_at': datetime.now().isoformat(),
                'version': '1.0.0',
                'components': [],
                'size_bytes': 0,
                'encrypted': self.backup_config['encryption']
            }
            
            logger.info(f"Starting backup: {backup_name}")
            
            # Database backup
            if include_database and self.backup_config['database_backup']:
                db_backup_path = self._backup_database(backup_path)
                if db_backup_path:
                    backup_manifest['components'].append({
                        'type': 'database',
                        'path': str(db_backup_path.relative_to(backup_path)),
                        'size_bytes': db_backup_path.stat().st_size
                    })
            
            # File system backup
            if include_files and self.backup_config['file_backup']:
                files_backup_path = self._backup_files(backup_path)
                if files_backup_path:
                    backup_manifest['components'].append({
                        'type': 'files',
                        'path': str(files_backup_path.relative_to(backup_path)),
                        'size_bytes': files_backup_path.stat().st_size
                    })
            
            # Configuration backup
            config_backup_path = self._backup_configuration(backup_path)
            if config_backup_path:
                backup_manifest['components'].append({
                    'type': 'configuration',
                    'path': str(config_backup_path.relative_to(backup_path)),
                    'size_bytes': config_backup_path.stat().st_size
                })
            
            # Calculate total size
            backup_manifest['size_bytes'] = sum(
                component['size_bytes'] for component in backup_manifest['components']
            )
            
            # Save manifest
            manifest_path = backup_path / "backup_manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(backup_manifest, f, indent=2)
            
            # Compress and encrypt if configured
            if self.backup_config['compression'] or self.backup_config['encryption']:
                final_backup_path = self._finalize_backup(backup_path, backup_name)
                # Remove uncompressed backup
                shutil.rmtree(backup_path)
                backup_path = final_backup_path
            
            # Cleanup old backups
            self._cleanup_old_backups()
            
            logger.info(f"Backup completed: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise
    
    def _backup_database(self, backup_path: Path) -> Optional[Path]:
        """Backup database"""
        try:
            db_backup_path = backup_path / "database.sql"
            
            # Get database URL
            database_url = os.environ.get('DATABASE_URL', 'sqlite:///data/byteguardx.db')
            
            if database_url.startswith('postgresql://'):
                # PostgreSQL backup
                cmd = [
                    'pg_dump',
                    database_url,
                    '--no-password',
                    '--verbose',
                    '--file', str(db_backup_path)
                ]
                
                # Use secure shell executor
                from ..security.secure_shell import secure_shell
                try:
                    returncode, stdout, stderr = secure_shell.execute_command(
                        cmd, allowed_context='system'
                    )
                    if returncode != 0:
                        logger.error(f"PostgreSQL backup failed: {stderr}")
                        return None
                except Exception as e:
                    logger.error(f"PostgreSQL backup failed: {e}")
                    return None
                    
            elif database_url.startswith('sqlite://'):
                # SQLite backup
                db_file = database_url.replace('sqlite:///', '')
                if os.path.exists(db_file):
                    shutil.copy2(db_file, db_backup_path.with_suffix('.db'))
                    db_backup_path = db_backup_path.with_suffix('.db')
                else:
                    logger.warning(f"SQLite database file not found: {db_file}")
                    return None
            
            # Compress database backup
            if self.backup_config['compression']:
                compressed_path = db_backup_path.with_suffix('.sql.gz')
                with open(db_backup_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(db_backup_path)
                db_backup_path = compressed_path
            
            logger.info(f"Database backup completed: {db_backup_path}")
            return db_backup_path
            
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return None
    
    def _backup_files(self, backup_path: Path) -> Optional[Path]:
        """Backup important files and directories"""
        try:
            files_backup_path = backup_path / "files.tar.gz"
            
            # Directories to backup
            backup_dirs = [
                'data',
                'reports',
                'byteguardx/offline_db',
                'byteguardx/ml/models',
                'config'
            ]
            
            # Files to backup
            backup_files = [
                '.env',
                'requirements.txt',
                'package.json',
                'docker-compose.yml'
            ]
            
            with tarfile.open(files_backup_path, 'w:gz') as tar:
                # Add directories
                for dir_name in backup_dirs:
                    if os.path.exists(dir_name):
                        tar.add(dir_name, arcname=dir_name)
                
                # Add files
                for file_name in backup_files:
                    if os.path.exists(file_name):
                        tar.add(file_name, arcname=file_name)
            
            logger.info(f"Files backup completed: {files_backup_path}")
            return files_backup_path
            
        except Exception as e:
            logger.error(f"Files backup failed: {e}")
            return None
    
    def _backup_configuration(self, backup_path: Path) -> Optional[Path]:
        """Backup system configuration"""
        try:
            config_backup_path = backup_path / "configuration.json"
            
            config_data = {
                'backup_created': datetime.now().isoformat(),
                'system_info': {
                    'python_version': subprocess.check_output(['python', '--version']).decode().strip(),
                    'platform': os.name,
                    'cwd': os.getcwd()
                },
                'environment_variables': {
                    key: value for key, value in os.environ.items()
                    if key.startswith('BYTEGUARDX_') or key in ['DATABASE_URL', 'REDIS_URL']
                },
                'installed_packages': self._get_installed_packages()
            }
            
            with open(config_backup_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Configuration backup completed: {config_backup_path}")
            return config_backup_path
            
        except Exception as e:
            logger.error(f"Configuration backup failed: {e}")
            return None
    
    def _get_installed_packages(self) -> List[str]:
        """Get list of installed Python packages"""
        try:
            result = subprocess.run(['pip', 'freeze'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
        except Exception as e:
            logger.error(f"Failed to get installed packages: {e}")
        return []
    
    def _finalize_backup(self, backup_path: Path, backup_name: str) -> Path:
        """Compress and encrypt backup"""
        try:
            final_path = self.backup_dir / f"{backup_name}.tar.gz"
            
            # Create compressed archive
            with tarfile.open(final_path, 'w:gz') as tar:
                tar.add(backup_path, arcname=backup_name)
            
            # Encrypt if configured
            if self.backup_config['encryption']:
                encrypted_path = final_path.with_suffix('.tar.gz.enc')
                self.encryption.encrypt_file(str(final_path), str(encrypted_path))
                os.remove(final_path)
                final_path = encrypted_path
            
            return final_path
            
        except Exception as e:
            logger.error(f"Failed to finalize backup: {e}")
            raise
    
    def _cleanup_old_backups(self):
        """Remove old backups based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            backup_files = []
            for file_path in self.backup_dir.glob("byteguardx_backup_*"):
                if file_path.is_file():
                    backup_files.append((file_path, file_path.stat().st_mtime))
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: x[1], reverse=True)
            
            # Remove old backups
            removed_count = 0
            for file_path, mtime in backup_files:
                file_date = datetime.fromtimestamp(mtime)
                
                # Keep recent backups and respect max_backups limit
                if (file_date < cutoff_date or 
                    len(backup_files) - removed_count > self.max_backups):
                    try:
                        os.remove(file_path)
                        removed_count += 1
                        logger.info(f"Removed old backup: {file_path}")
                    except Exception as e:
                        logger.error(f"Failed to remove backup {file_path}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} old backups")
                
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups"""
        backups = []
        
        for file_path in self.backup_dir.glob("byteguardx_backup_*"):
            if file_path.is_file():
                stat = file_path.stat()
                backups.append({
                    'name': file_path.name,
                    'path': str(file_path),
                    'size_bytes': stat.st_size,
                    'created_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'encrypted': file_path.suffix == '.enc'
                })
        
        return sorted(backups, key=lambda x: x['created_at'], reverse=True)
    
    def restore_backup(self, backup_path: str, restore_database: bool = True,
                      restore_files: bool = True) -> bool:
        """Restore from backup"""
        try:
            backup_file = Path(backup_path)
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            logger.info(f"Starting restore from: {backup_path}")
            
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Decrypt if needed
                if backup_file.suffix == '.enc':
                    decrypted_path = temp_path / backup_file.stem
                    self.encryption.decrypt_file(str(backup_file), str(decrypted_path))
                    backup_file = decrypted_path
                
                # Extract backup
                with tarfile.open(backup_file, 'r:gz') as tar:
                    tar.extractall(temp_path)
                
                # Find backup directory
                backup_contents = list(temp_path.iterdir())
                if len(backup_contents) == 1 and backup_contents[0].is_dir():
                    backup_dir = backup_contents[0]
                else:
                    backup_dir = temp_path
                
                # Load manifest
                manifest_path = backup_dir / "backup_manifest.json"
                if manifest_path.exists():
                    with open(manifest_path, 'r') as f:
                        manifest = json.load(f)
                    logger.info(f"Restoring backup: {manifest['backup_name']}")
                
                # Restore components
                success = True
                
                if restore_database:
                    success &= self._restore_database(backup_dir)
                
                if restore_files:
                    success &= self._restore_files(backup_dir)
                
                return success
                
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def _restore_database(self, backup_dir: Path) -> bool:
        """Restore database from backup"""
        try:
            # Find database backup file
            db_files = list(backup_dir.glob("database.*"))
            if not db_files:
                logger.warning("No database backup found")
                return True
            
            db_file = db_files[0]
            logger.info(f"Restoring database from: {db_file}")
            
            # Handle compressed files
            if db_file.suffix == '.gz':
                with tempfile.NamedTemporaryFile(suffix='.sql', delete=False) as temp_file:
                    with gzip.open(db_file, 'rb') as f_in:
                        shutil.copyfileobj(f_in, temp_file)
                    db_file = Path(temp_file.name)
            
            database_url = os.environ.get('DATABASE_URL', 'sqlite:///data/byteguardx.db')
            
            if database_url.startswith('postgresql://'):
                # PostgreSQL restore
                cmd = ['psql', database_url, '-f', str(db_file)]
                from ..security.secure_shell import secure_shell
                try:
                    returncode, stdout, stderr = secure_shell.execute_command(
                        cmd, allowed_context='system'
                    )
                    if returncode != 0:
                        logger.error(f"PostgreSQL restore failed: {stderr}")
                        return False
                except Exception as e:
                    logger.error(f"PostgreSQL restore failed: {e}")
                    return False
                    
            elif database_url.startswith('sqlite://'):
                # SQLite restore
                target_db = database_url.replace('sqlite:///', '')
                os.makedirs(os.path.dirname(target_db), exist_ok=True)
                shutil.copy2(db_file, target_db)
            
            logger.info("Database restore completed")
            return True
            
        except Exception as e:
            logger.error(f"Database restore failed: {e}")
            return False
    
    def _restore_files(self, backup_dir: Path) -> bool:
        """Restore files from backup"""
        try:
            files_backup = backup_dir / "files.tar.gz"
            if not files_backup.exists():
                logger.warning("No files backup found")
                return True
            
            logger.info(f"Restoring files from: {files_backup}")
            
            # Extract files to current directory
            with tarfile.open(files_backup, 'r:gz') as tar:
                tar.extractall('.')
            
            logger.info("Files restore completed")
            return True
            
        except Exception as e:
            logger.error(f"Files restore failed: {e}")
            return False

# Global instance
backup_manager = BackupManager()

# CLI commands
@click.group()
def backup():
    """Backup and restore commands"""
    pass

@backup.command()
@click.option('--name', help='Backup name')
@click.option('--no-database', is_flag=True, help='Skip database backup')
@click.option('--no-files', is_flag=True, help='Skip files backup')
def create(name, no_database, no_files):
    """Create a new backup"""
    try:
        backup_path = backup_manager.create_backup(
            backup_name=name,
            include_database=not no_database,
            include_files=not no_files
        )
        click.echo(f"✅ Backup created: {backup_path}")
    except Exception as e:
        click.echo(f"❌ Backup failed: {e}")

@backup.command()
def list():
    """List available backups"""
    backups = backup_manager.list_backups()
    
    if not backups:
        click.echo("No backups found")
        return
    
    click.echo("\nAvailable backups:")
    for backup in backups:
        size_mb = backup['size_bytes'] / (1024 * 1024)
        encrypted = "🔒" if backup['encrypted'] else "🔓"
        click.echo(f"  {encrypted} {backup['name']} ({size_mb:.1f} MB) - {backup['created_at']}")

@backup.command()
@click.argument('backup_path')
@click.option('--no-database', is_flag=True, help='Skip database restore')
@click.option('--no-files', is_flag=True, help='Skip files restore')
@click.confirmation_option(prompt='Are you sure you want to restore? This will overwrite existing data.')
def restore(backup_path, no_database, no_files):
    """Restore from backup"""
    try:
        success = backup_manager.restore_backup(
            backup_path=backup_path,
            restore_database=not no_database,
            restore_files=not no_files
        )
        
        if success:
            click.echo("✅ Restore completed successfully")
        else:
            click.echo("❌ Restore failed")
    except Exception as e:
        click.echo(f"❌ Restore failed: {e}")
