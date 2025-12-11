"""
Plugin Versioning and Rollback System for ByteGuardX
Manages plugin versions, rollbacks, and version history
"""

import os
import json
import logging
import shutil
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

from ..database.connection_pool import db_manager
from ..database.models import Plugin, PluginVersion, PluginExecution

logger = logging.getLogger(__name__)

class VersionStatus(Enum):
    """Plugin version status"""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ROLLBACK = "rollback"
    ARCHIVED = "archived"

@dataclass
class PluginVersionInfo:
    """Plugin version information"""
    version_id: str
    plugin_id: str
    version_number: str
    status: VersionStatus
    created_at: datetime
    created_by: str
    changelog: str
    file_hash: str
    file_size: int
    metadata: Dict[str, Any]

class PluginVersionManager:
    """Manages plugin versions and rollbacks"""
    
    def __init__(self):
        self.plugin_storage_path = Path(os.environ.get('PLUGIN_STORAGE_PATH', 'data/plugins'))
        self.version_storage_path = self.plugin_storage_path / 'versions'
        self.max_versions_per_plugin = 10
        
        # Ensure directories exist
        self.plugin_storage_path.mkdir(parents=True, exist_ok=True)
        self.version_storage_path.mkdir(parents=True, exist_ok=True)
    
    def create_version(self, plugin_id: str, version_number: str, 
                      plugin_file_path: str, changelog: str,
                      created_by: str, metadata: Dict[str, Any] = None) -> str:
        """
        Create a new plugin version
        
        Args:
            plugin_id: Plugin identifier
            version_number: Version number (e.g., "1.2.3")
            plugin_file_path: Path to plugin file
            changelog: Version changelog
            created_by: User who created the version
            metadata: Additional metadata
            
        Returns:
            Version ID
        """
        try:
            # Validate plugin file
            if not Path(plugin_file_path).exists():
                raise ValueError(f"Plugin file not found: {plugin_file_path}")
            
            # Generate version ID
            version_id = f"{plugin_id}_v{version_number}_{int(datetime.now().timestamp())}"
            
            # Calculate file hash and size
            file_hash = self._calculate_file_hash(plugin_file_path)
            file_size = Path(plugin_file_path).stat().st_size
            
            # Store plugin file
            version_file_path = self.version_storage_path / f"{version_id}.py"
            shutil.copy2(plugin_file_path, version_file_path)
            
            # Create version info
            version_info = PluginVersionInfo(
                version_id=version_id,
                plugin_id=plugin_id,
                version_number=version_number,
                status=VersionStatus.ACTIVE,
                created_at=datetime.now(),
                created_by=created_by,
                changelog=changelog,
                file_hash=file_hash,
                file_size=file_size,
                metadata=metadata or {}
            )
            
            # Store in database
            self._store_version_info(version_info)
            
            # Update plugin to use new version
            self._update_plugin_active_version(plugin_id, version_id)
            
            # Cleanup old versions if needed
            self._cleanup_old_versions(plugin_id)
            
            logger.info(f"Created plugin version {version_id} for plugin {plugin_id}")
            return version_id
            
        except Exception as e:
            logger.error(f"Failed to create plugin version: {e}")
            raise
    
    def rollback_to_version(self, plugin_id: str, target_version_id: str,
                           rollback_reason: str, rolled_back_by: str) -> bool:
        """
        Rollback plugin to a specific version
        
        Args:
            plugin_id: Plugin identifier
            target_version_id: Version to rollback to
            rollback_reason: Reason for rollback
            rolled_back_by: User performing rollback
            
        Returns:
            True if rollback successful
        """
        try:
            with db_manager.get_session() as session:
                # Verify target version exists
                target_version = session.query(PluginVersion).filter(
                    PluginVersion.version_id == target_version_id,
                    PluginVersion.plugin_id == plugin_id
                ).first()
                
                if not target_version:
                    raise ValueError(f"Target version {target_version_id} not found")
                
                # Get current active version
                current_plugin = session.query(Plugin).filter(
                    Plugin.id == plugin_id
                ).first()
                
                if not current_plugin:
                    raise ValueError(f"Plugin {plugin_id} not found")
                
                current_version_id = current_plugin.active_version_id
                
                # Update plugin to use target version
                current_plugin.active_version_id = target_version_id
                current_plugin.updated_at = datetime.now()
                
                # Mark target version as active
                target_version.status = VersionStatus.ACTIVE.value
                
                # Mark previous version as rollback
                if current_version_id:
                    current_version = session.query(PluginVersion).filter(
                        PluginVersion.version_id == current_version_id
                    ).first()
                    if current_version:
                        current_version.status = VersionStatus.ROLLBACK.value
                
                # Log rollback
                rollback_metadata = {
                    'rollback_reason': rollback_reason,
                    'rolled_back_by': rolled_back_by,
                    'rollback_timestamp': datetime.now().isoformat(),
                    'previous_version_id': current_version_id
                }
                
                target_version.metadata = json.dumps({
                    **json.loads(target_version.metadata or '{}'),
                    'rollback_info': rollback_metadata
                })
                
                session.commit()
                
                # Copy version file to active location
                self._activate_version_file(target_version_id)
                
                logger.info(f"Rolled back plugin {plugin_id} to version {target_version_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to rollback plugin version: {e}")
            return False
    
    def get_version_history(self, plugin_id: str) -> List[PluginVersionInfo]:
        """
        Get version history for a plugin
        
        Args:
            plugin_id: Plugin identifier
            
        Returns:
            List of plugin versions
        """
        try:
            with db_manager.get_session() as session:
                versions = session.query(PluginVersion).filter(
                    PluginVersion.plugin_id == plugin_id
                ).order_by(PluginVersion.created_at.desc()).all()
                
                version_list = []
                for version in versions:
                    version_info = PluginVersionInfo(
                        version_id=version.version_id,
                        plugin_id=version.plugin_id,
                        version_number=version.version_number,
                        status=VersionStatus(version.status),
                        created_at=version.created_at,
                        created_by=version.created_by,
                        changelog=version.changelog,
                        file_hash=version.file_hash,
                        file_size=version.file_size,
                        metadata=json.loads(version.metadata or '{}')
                    )
                    version_list.append(version_info)
                
                return version_list
                
        except Exception as e:
            logger.error(f"Failed to get version history: {e}")
            return []
    
    def compare_versions(self, version_id_1: str, version_id_2: str) -> Dict[str, Any]:
        """
        Compare two plugin versions
        
        Args:
            version_id_1: First version ID
            version_id_2: Second version ID
            
        Returns:
            Dict containing comparison results
        """
        try:
            # Get version files
            file_1 = self.version_storage_path / f"{version_id_1}.py"
            file_2 = self.version_storage_path / f"{version_id_2}.py"
            
            if not file_1.exists() or not file_2.exists():
                return {"error": "One or both version files not found"}
            
            # Read file contents
            content_1 = file_1.read_text()
            content_2 = file_2.read_text()
            
            # Basic comparison
            lines_1 = content_1.split('\n')
            lines_2 = content_2.split('\n')
            
            # Calculate differences
            added_lines = len(lines_2) - len(lines_1)
            
            # Simple diff (could be enhanced with proper diff algorithm)
            differences = []
            max_lines = max(len(lines_1), len(lines_2))
            
            for i in range(max_lines):
                line_1 = lines_1[i] if i < len(lines_1) else ""
                line_2 = lines_2[i] if i < len(lines_2) else ""
                
                if line_1 != line_2:
                    differences.append({
                        'line_number': i + 1,
                        'version_1': line_1,
                        'version_2': line_2,
                        'change_type': 'modified' if line_1 and line_2 else 
                                     'added' if not line_1 else 'removed'
                    })
            
            return {
                'version_1': version_id_1,
                'version_2': version_id_2,
                'total_differences': len(differences),
                'added_lines': added_lines,
                'differences': differences[:50]  # Limit for performance
            }
            
        except Exception as e:
            logger.error(f"Failed to compare versions: {e}")
            return {"error": str(e)}
    
    def archive_version(self, version_id: str, archive_reason: str) -> bool:
        """
        Archive a plugin version
        
        Args:
            version_id: Version to archive
            archive_reason: Reason for archiving
            
        Returns:
            True if archived successfully
        """
        try:
            with db_manager.get_session() as session:
                version = session.query(PluginVersion).filter(
                    PluginVersion.version_id == version_id
                ).first()
                
                if not version:
                    return False
                
                # Update status
                version.status = VersionStatus.ARCHIVED.value
                
                # Add archive metadata
                metadata = json.loads(version.metadata or '{}')
                metadata['archive_info'] = {
                    'archive_reason': archive_reason,
                    'archived_at': datetime.now().isoformat()
                }
                version.metadata = json.dumps(metadata)
                
                session.commit()
                
                logger.info(f"Archived plugin version {version_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to archive version: {e}")
            return False
    
    def get_version_performance_metrics(self, version_id: str) -> Dict[str, Any]:
        """
        Get performance metrics for a plugin version
        
        Args:
            version_id: Version ID
            
        Returns:
            Dict containing performance metrics
        """
        try:
            with db_manager.get_session() as session:
                # Get executions for this version
                executions = session.query(PluginExecution).filter(
                    PluginExecution.plugin_version_id == version_id
                ).all()
                
                if not executions:
                    return {"error": "No execution data found"}
                
                # Calculate metrics
                total_executions = len(executions)
                successful_executions = sum(1 for e in executions if e.status == 'completed')
                failed_executions = total_executions - successful_executions
                
                execution_times = [e.execution_time for e in executions if e.execution_time]
                avg_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0
                
                return {
                    'version_id': version_id,
                    'total_executions': total_executions,
                    'successful_executions': successful_executions,
                    'failed_executions': failed_executions,
                    'success_rate': successful_executions / total_executions if total_executions > 0 else 0,
                    'average_execution_time': avg_execution_time,
                    'performance_score': self._calculate_performance_score(
                        successful_executions / total_executions if total_executions > 0 else 0,
                        avg_execution_time
                    )
                }
                
        except Exception as e:
            logger.error(f"Failed to get version performance metrics: {e}")
            return {"error": str(e)}
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        import hashlib
        
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _store_version_info(self, version_info: PluginVersionInfo):
        """Store version information in database"""
        with db_manager.get_session() as session:
            version = PluginVersion(
                version_id=version_info.version_id,
                plugin_id=version_info.plugin_id,
                version_number=version_info.version_number,
                status=version_info.status.value,
                created_at=version_info.created_at,
                created_by=version_info.created_by,
                changelog=version_info.changelog,
                file_hash=version_info.file_hash,
                file_size=version_info.file_size,
                metadata=json.dumps(version_info.metadata)
            )
            
            session.add(version)
            session.commit()
    
    def _update_plugin_active_version(self, plugin_id: str, version_id: str):
        """Update plugin's active version"""
        with db_manager.get_session() as session:
            plugin = session.query(Plugin).filter(Plugin.id == plugin_id).first()
            if plugin:
                plugin.active_version_id = version_id
                plugin.updated_at = datetime.now()
                session.commit()
    
    def _cleanup_old_versions(self, plugin_id: str):
        """Clean up old versions beyond the limit"""
        try:
            with db_manager.get_session() as session:
                versions = session.query(PluginVersion).filter(
                    PluginVersion.plugin_id == plugin_id,
                    PluginVersion.status != VersionStatus.ACTIVE.value
                ).order_by(PluginVersion.created_at.desc()).all()
                
                if len(versions) > self.max_versions_per_plugin:
                    versions_to_archive = versions[self.max_versions_per_plugin:]
                    
                    for version in versions_to_archive:
                        version.status = VersionStatus.ARCHIVED.value
                        
                        # Remove file
                        version_file = self.version_storage_path / f"{version.version_id}.py"
                        if version_file.exists():
                            version_file.unlink()
                    
                    session.commit()
                    logger.info(f"Archived {len(versions_to_archive)} old versions for plugin {plugin_id}")
                    
        except Exception as e:
            logger.error(f"Failed to cleanup old versions: {e}")
    
    def _activate_version_file(self, version_id: str):
        """Copy version file to active plugin location"""
        try:
            version_file = self.version_storage_path / f"{version_id}.py"
            if version_file.exists():
                # This would copy to the active plugin directory
                # Implementation depends on plugin loading system
                pass
        except Exception as e:
            logger.error(f"Failed to activate version file: {e}")
    
    def _calculate_performance_score(self, success_rate: float, avg_execution_time: float) -> float:
        """Calculate performance score (0-100)"""
        # Simple scoring: 70% success rate weight, 30% execution time weight
        success_score = success_rate * 70
        
        # Normalize execution time (assuming 1 second is baseline)
        time_score = max(0, 30 - (avg_execution_time - 1.0) * 10)
        
        return min(100, success_score + time_score)

# Global instance
plugin_version_manager = PluginVersionManager()
