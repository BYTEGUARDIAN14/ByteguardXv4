"""
WebSocket Handler for Real-time Scan Progress Updates
Provides real-time communication between frontend and backend during scans
"""

import json
import logging
import threading
import time
from typing import Dict, Set, Any, Optional
from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from datetime import datetime

logger = logging.getLogger(__name__)

class ScanProgressManager:
    """Manages scan progress and WebSocket communications"""
    
    def __init__(self):
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_subscribers: Dict[str, Set[str]] = {}  # scan_id -> set of session_ids
        self.socketio: Optional[SocketIO] = None
        self._lock = threading.RLock()
    
    def initialize_socketio(self, app: Flask) -> SocketIO:
        """Initialize SocketIO with the Flask app"""
        self.socketio = SocketIO(
            app,
            cors_allowed_origins="*",
            async_mode='threading',
            logger=False,
            engineio_logger=False
        )
        
        # Register event handlers
        self._register_handlers()
        
        logger.info("WebSocket support initialized")
        return self.socketio
    
    def _register_handlers(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.debug(f"Client connected: {self.socketio.request.sid}")
            emit('connected', {'status': 'connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            session_id = self.socketio.request.sid
            logger.debug(f"Client disconnected: {session_id}")
            
            # Remove from all scan subscriptions
            with self._lock:
                for scan_id, subscribers in self.scan_subscribers.items():
                    subscribers.discard(session_id)
        
        @self.socketio.on('subscribe_scan')
        def handle_subscribe_scan(data):
            """Subscribe to scan progress updates"""
            session_id = self.socketio.request.sid
            scan_id = data.get('scan_id')
            
            if not scan_id:
                emit('error', {'message': 'scan_id is required'})
                return
            
            with self._lock:
                if scan_id not in self.scan_subscribers:
                    self.scan_subscribers[scan_id] = set()
                
                self.scan_subscribers[scan_id].add(session_id)
                join_room(f"scan_{scan_id}")
            
            logger.debug(f"Client {session_id} subscribed to scan {scan_id}")
            
            # Send current scan status if available
            if scan_id in self.active_scans:
                emit('scan_progress', self.active_scans[scan_id])
            
            emit('subscribed', {'scan_id': scan_id})
        
        @self.socketio.on('unsubscribe_scan')
        def handle_unsubscribe_scan(data):
            """Unsubscribe from scan progress updates"""
            session_id = self.socketio.request.sid
            scan_id = data.get('scan_id')
            
            if not scan_id:
                emit('error', {'message': 'scan_id is required'})
                return
            
            with self._lock:
                if scan_id in self.scan_subscribers:
                    self.scan_subscribers[scan_id].discard(session_id)
                    leave_room(f"scan_{scan_id}")
            
            logger.debug(f"Client {session_id} unsubscribed from scan {scan_id}")
            emit('unsubscribed', {'scan_id': scan_id})
    
    def start_scan(self, scan_id: str, scan_config: Dict[str, Any]):
        """Start tracking a new scan"""
        with self._lock:
            self.active_scans[scan_id] = {
                'scan_id': scan_id,
                'status': 'starting',
                'progress': 0,
                'current_file': '',
                'total_files': 0,
                'processed_files': 0,
                'findings': 0,
                'errors': [],
                'start_time': datetime.now().isoformat(),
                'estimated_time_remaining': None,
                'performance': {
                    'files_per_second': 0,
                    'memory_usage': 0,
                    'cpu_usage': 0,
                    'cache_hit_rate': 0
                },
                'config': scan_config
            }
        
        self._broadcast_scan_update(scan_id)
        logger.info(f"Started tracking scan: {scan_id}")
    
    def update_scan_progress(self, scan_id: str, **updates):
        """Update scan progress and broadcast to subscribers"""
        with self._lock:
            if scan_id not in self.active_scans:
                logger.warning(f"Attempted to update unknown scan: {scan_id}")
                return
            
            scan_data = self.active_scans[scan_id]
            
            # Update fields
            for key, value in updates.items():
                if key in scan_data:
                    scan_data[key] = value
                elif key.startswith('performance.'):
                    perf_key = key.split('.', 1)[1]
                    scan_data['performance'][perf_key] = value
                else:
                    scan_data[key] = value
            
            # Update timestamp
            scan_data['last_update'] = datetime.now().isoformat()
            
            # Calculate estimated time remaining
            if scan_data['processed_files'] > 0 and scan_data['total_files'] > 0:
                elapsed_time = (datetime.now() - datetime.fromisoformat(scan_data['start_time'])).total_seconds()
                files_per_second = scan_data['processed_files'] / elapsed_time if elapsed_time > 0 else 0
                remaining_files = scan_data['total_files'] - scan_data['processed_files']
                
                if files_per_second > 0:
                    estimated_remaining = remaining_files / files_per_second
                    scan_data['estimated_time_remaining'] = estimated_remaining
                    scan_data['performance']['files_per_second'] = files_per_second
        
        self._broadcast_scan_update(scan_id)
    
    def complete_scan(self, scan_id: str, final_results: Dict[str, Any]):
        """Mark scan as completed and broadcast final results"""
        with self._lock:
            if scan_id not in self.active_scans:
                logger.warning(f"Attempted to complete unknown scan: {scan_id}")
                return
            
            scan_data = self.active_scans[scan_id]
            scan_data.update({
                'status': 'completed',
                'progress': 100,
                'completed_at': datetime.now().isoformat(),
                'estimated_time_remaining': 0,
                **final_results
            })
        
        self._broadcast_scan_update(scan_id)
        
        # Clean up after a delay
        threading.Timer(300, self._cleanup_scan, args=[scan_id]).start()  # 5 minutes
        
        logger.info(f"Completed scan: {scan_id}")
    
    def fail_scan(self, scan_id: str, error_message: str):
        """Mark scan as failed and broadcast error"""
        with self._lock:
            if scan_id not in self.active_scans:
                logger.warning(f"Attempted to fail unknown scan: {scan_id}")
                return
            
            scan_data = self.active_scans[scan_id]
            scan_data.update({
                'status': 'failed',
                'completed_at': datetime.now().isoformat(),
                'error': error_message,
                'estimated_time_remaining': 0
            })
        
        self._broadcast_scan_update(scan_id)
        
        # Clean up after a delay
        threading.Timer(60, self._cleanup_scan, args=[scan_id]).start()  # 1 minute
        
        logger.error(f"Failed scan {scan_id}: {error_message}")
    
    def _broadcast_scan_update(self, scan_id: str):
        """Broadcast scan update to all subscribers"""
        if not self.socketio:
            return
        
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            scan_data = self.active_scans[scan_id].copy()
        
        # Broadcast to room
        self.socketio.emit('scan_progress', scan_data, room=f"scan_{scan_id}")
        
        logger.debug(f"Broadcasted update for scan {scan_id} to {len(self.scan_subscribers.get(scan_id, set()))} subscribers")
    
    def _cleanup_scan(self, scan_id: str):
        """Clean up completed/failed scan data"""
        with self._lock:
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            
            if scan_id in self.scan_subscribers:
                del self.scan_subscribers[scan_id]
        
        logger.debug(f"Cleaned up scan data: {scan_id}")
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get current scan status"""
        with self._lock:
            return self.active_scans.get(scan_id)
    
    def get_active_scans(self) -> Dict[str, Dict[str, Any]]:
        """Get all active scans"""
        with self._lock:
            return self.active_scans.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics"""
        with self._lock:
            return {
                'active_scans': len(self.active_scans),
                'total_subscribers': sum(len(subs) for subs in self.scan_subscribers.values()),
                'scan_subscribers': {scan_id: len(subs) for scan_id, subs in self.scan_subscribers.items()}
            }

# Global instance
scan_progress_manager = ScanProgressManager()

def init_websocket_support(app: Flask) -> SocketIO:
    """Initialize WebSocket support for the Flask app"""
    return scan_progress_manager.initialize_socketio(app)

# Context manager for scan progress tracking
class ScanProgressTracker:
    """Context manager for tracking scan progress"""
    
    def __init__(self, scan_id: str, scan_config: Dict[str, Any]):
        self.scan_id = scan_id
        self.scan_config = scan_config
    
    def __enter__(self):
        scan_progress_manager.start_scan(self.scan_id, self.scan_config)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # Scan failed
            error_message = str(exc_val) if exc_val else "Unknown error"
            scan_progress_manager.fail_scan(self.scan_id, error_message)
        else:
            # Scan completed successfully (final results should be set separately)
            pass
    
    def update(self, **kwargs):
        """Update scan progress"""
        scan_progress_manager.update_scan_progress(self.scan_id, **kwargs)
    
    def complete(self, final_results: Dict[str, Any]):
        """Mark scan as completed with final results"""
        scan_progress_manager.complete_scan(self.scan_id, final_results)

def track_scan_progress(scan_id: str, scan_config: Dict[str, Any]) -> ScanProgressTracker:
    """Create a scan progress tracker context manager"""
    return ScanProgressTracker(scan_id, scan_config)
