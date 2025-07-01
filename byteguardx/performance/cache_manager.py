"""
Cache manager for ByteGuardX scan results and file metadata
Provides intelligent caching to avoid re-scanning unchanged files
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
import threading
from dataclasses import dataclass, asdict
import hmac
import gzip
import secrets

logger = logging.getLogger(__name__)

@dataclass
class FileMetadata:
    """File metadata for cache validation"""
    file_path: str
    size: int
    mtime: float  # modification time
    checksum: str
    last_scanned: datetime
    
    def is_valid(self) -> bool:
        """Check if cached metadata is still valid"""
        try:
            stat = os.stat(self.file_path)
            return (
                stat.st_size == self.size and
                stat.st_mtime == self.mtime
            )
        except (OSError, FileNotFoundError):
            return False
    
    @classmethod
    def from_file(cls, file_path: str) -> 'FileMetadata':
        """Create metadata from file"""
        stat = os.stat(file_path)
        
        # Calculate file checksum for content validation
        checksum = cls._calculate_checksum(file_path)
        
        return cls(
            file_path=file_path,
            size=stat.st_size,
            mtime=stat.st_mtime,
            checksum=checksum,
            last_scanned=datetime.now()
        )
    
    @staticmethod
    def _calculate_checksum(file_path: str) -> str:
        """Calculate SHA-256 checksum of file content"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum for {file_path}: {e}")
            return ""

@dataclass
class ScanCache:
    """Cached scan results for a file"""
    file_metadata: FileMetadata
    findings: List[Dict[str, Any]]
    scan_duration: float
    scanner_versions: Dict[str, str]  # Track scanner versions
    cached_at: datetime
    
    def is_valid(self, max_age: timedelta = timedelta(days=7)) -> bool:
        """Check if cache entry is still valid"""
        # Check file metadata
        if not self.file_metadata.is_valid():
            return False
        
        # Check cache age
        if datetime.now() - self.cached_at > max_age:
            return False
        
        # TODO: Check scanner version compatibility
        return True

class CacheManager:
    """
    Intelligent cache manager for scan results
    Supports file-based and memory caching with automatic invalidation
    """
    
    def __init__(self, cache_dir: str = "data/cache", max_memory_entries: int = 1000):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Memory cache for frequently accessed items
        self._memory_cache: Dict[str, ScanCache] = {}
        self._memory_access_times: Dict[str, datetime] = {}
        self.max_memory_entries = max_memory_entries

        # Initialize secure cache key for HMAC signatures
        self.cache_secret = self._get_or_create_cache_secret()
        
        # File cache paths
        self.metadata_file = self.cache_dir / "file_metadata.json"
        self.cache_index_file = self.cache_dir / "cache_index.json"
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Cache statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'invalidations': 0,
            'memory_hits': 0,
            'disk_hits': 0
        }
        
        # Load existing cache index
        self._load_cache_index()

        # Cleanup settings
        self._last_cleanup = datetime.now()

        # Initialize secure cache secret
        self.cache_secret = self._get_or_create_cache_secret()

    def _get_or_create_cache_secret(self) -> bytes:
        """Get or create secure cache secret for HMAC signatures"""
        secret_file = self.cache_dir / ".cache_secret"

        try:
            if secret_file.exists():
                with open(secret_file, 'rb') as f:
                    return f.read()
            else:
                # Generate new secret
                secret = secrets.token_bytes(32)
                with open(secret_file, 'wb') as f:
                    f.write(secret)
                # Set secure permissions (owner read/write only)
                secret_file.chmod(0o600)
                return secret
        except Exception as e:
            logger.error(f"Failed to manage cache secret: {e}")
            # Fallback to in-memory secret (less secure but functional)
            return secrets.token_bytes(32)
        self._cleanup_interval = timedelta(hours=6)
    
    def get_cached_results(self, file_path: str) -> Optional[ScanCache]:
        """Get cached scan results for a file"""
        with self._lock:
            cache_key = self._get_cache_key(file_path)
            
            # Check memory cache first
            if cache_key in self._memory_cache:
                cache_entry = self._memory_cache[cache_key]
                if cache_entry.is_valid():
                    self._memory_access_times[cache_key] = datetime.now()
                    self._stats['hits'] += 1
                    self._stats['memory_hits'] += 1
                    return cache_entry
                else:
                    # Remove invalid entry
                    del self._memory_cache[cache_key]
                    del self._memory_access_times[cache_key]
            
            # Check disk cache
            cache_entry = self._load_from_disk(cache_key)
            if cache_entry and cache_entry.is_valid():
                # Add to memory cache
                self._add_to_memory_cache(cache_key, cache_entry)
                self._stats['hits'] += 1
                self._stats['disk_hits'] += 1
                return cache_entry
            
            self._stats['misses'] += 1
            return None
    
    def cache_results(self, file_path: str, findings: List[Dict[str, Any]], 
                     scan_duration: float, scanner_versions: Dict[str, str]):
        """Cache scan results for a file"""
        with self._lock:
            try:
                # Create file metadata
                file_metadata = FileMetadata.from_file(file_path)
                
                # Create cache entry
                cache_entry = ScanCache(
                    file_metadata=file_metadata,
                    findings=findings,
                    scan_duration=scan_duration,
                    scanner_versions=scanner_versions,
                    cached_at=datetime.now()
                )
                
                cache_key = self._get_cache_key(file_path)
                
                # Save to disk
                self._save_to_disk(cache_key, cache_entry)
                
                # Add to memory cache
                self._add_to_memory_cache(cache_key, cache_entry)
                
                logger.debug(f"Cached results for {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to cache results for {file_path}: {e}")
    
    def invalidate_file(self, file_path: str):
        """Invalidate cache for a specific file"""
        with self._lock:
            cache_key = self._get_cache_key(file_path)
            
            # Remove from memory cache
            self._memory_cache.pop(cache_key, None)
            self._memory_access_times.pop(cache_key, None)
            
            # Remove from disk cache
            cache_file = self.cache_dir / f"{cache_key}.cache"
            if cache_file.exists():
                cache_file.unlink()
            
            self._stats['invalidations'] += 1
            logger.debug(f"Invalidated cache for {file_path}")
    
    def invalidate_directory(self, directory_path: str):
        """Invalidate cache for all files in a directory"""
        with self._lock:
            directory_path = os.path.abspath(directory_path)
            keys_to_remove = []
            
            # Find keys to remove from memory cache
            for cache_key, cache_entry in self._memory_cache.items():
                if cache_entry.file_metadata.file_path.startswith(directory_path):
                    keys_to_remove.append(cache_key)
            
            # Remove from memory cache
            for key in keys_to_remove:
                del self._memory_cache[key]
                self._memory_access_times.pop(key, None)
            
            # Remove from disk cache
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    cache_entry = self._load_from_disk(cache_file.stem)
                    if (cache_entry and 
                        cache_entry.file_metadata.file_path.startswith(directory_path)):
                        cache_file.unlink()
                        self._stats['invalidations'] += 1
                except Exception as e:
                    logger.error(f"Error invalidating cache file {cache_file}: {e}")
            
            logger.info(f"Invalidated cache for directory {directory_path}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                **self._stats,
                'hit_rate_percent': round(hit_rate, 2),
                'memory_cache_size': len(self._memory_cache),
                'disk_cache_files': len(list(self.cache_dir.glob("*.cache"))),
                'cache_dir_size_mb': self._get_cache_dir_size() / (1024 * 1024)
            }
    
    def cleanup_cache(self, max_age: timedelta = timedelta(days=30)):
        """Clean up old cache entries"""
        with self._lock:
            current_time = datetime.now()
            
            # Skip if recently cleaned
            if current_time - self._last_cleanup < self._cleanup_interval:
                return
            
            removed_count = 0
            
            # Clean memory cache
            expired_keys = []
            for key, cache_entry in self._memory_cache.items():
                if not cache_entry.is_valid(max_age):
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._memory_cache[key]
                self._memory_access_times.pop(key, None)
                removed_count += 1
            
            # Clean disk cache
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    cache_entry = self._load_from_disk(cache_file.stem)
                    if not cache_entry or not cache_entry.is_valid(max_age):
                        cache_file.unlink()
                        removed_count += 1
                except Exception as e:
                    logger.error(f"Error cleaning cache file {cache_file}: {e}")
            
            self._last_cleanup = current_time
            
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} expired cache entries")
    
    def _get_cache_key(self, file_path: str) -> str:
        """Generate cache key for file path"""
        # Use hash of absolute path for consistent keys
        abs_path = os.path.abspath(file_path)
        return hashlib.md5(abs_path.encode()).hexdigest()
    
    def _add_to_memory_cache(self, cache_key: str, cache_entry: ScanCache):
        """Add entry to memory cache with LRU eviction"""
        # Check if we need to evict entries
        if len(self._memory_cache) >= self.max_memory_entries:
            self._evict_lru_entries()
        
        self._memory_cache[cache_key] = cache_entry
        self._memory_access_times[cache_key] = datetime.now()
    
    def _evict_lru_entries(self):
        """Evict least recently used entries from memory cache"""
        # Remove 10% of entries
        evict_count = max(1, self.max_memory_entries // 10)
        
        # Sort by access time
        sorted_keys = sorted(
            self._memory_access_times.keys(),
            key=lambda k: self._memory_access_times[k]
        )
        
        # Remove oldest entries
        for key in sorted_keys[:evict_count]:
            del self._memory_cache[key]
            del self._memory_access_times[key]
    
    def _save_to_disk(self, cache_key: str, cache_entry: ScanCache):
        """Save cache entry to disk with secure serialization"""
        cache_file = self.cache_dir / f"{cache_key}.cache"

        try:
            # Convert to dictionary for JSON serialization
            cache_data = {
                'file_metadata': {
                    'file_path': cache_entry.file_metadata.file_path,
                    'file_size': cache_entry.file_metadata.file_size,
                    'modified_time': cache_entry.file_metadata.modified_time.isoformat(),
                    'checksum': cache_entry.file_metadata.checksum,
                    'file_type': cache_entry.file_metadata.file_type
                },
                'findings': cache_entry.findings,
                'scan_duration': cache_entry.scan_duration,
                'scanner_versions': cache_entry.scanner_versions,
                'cached_at': cache_entry.cached_at.isoformat()
            }

            # Serialize to JSON
            json_data = json.dumps(cache_data, separators=(',', ':'))

            # Create HMAC signature
            signature = hmac.new(
                self.cache_secret,
                json_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            # Save with signature
            signed_data = {
                'data': cache_data,
                'signature': signature
            }

            with gzip.open(cache_file, 'wt', encoding='utf-8') as f:
                json.dump(signed_data, f, separators=(',', ':'))

        except Exception as e:
            logger.error(f"Failed to save cache to disk: {e}")
    
    def _load_from_disk(self, cache_key: str) -> Optional[ScanCache]:
        """Load cache entry from disk with signature verification"""
        cache_file = self.cache_dir / f"{cache_key}.cache"

        if not cache_file.exists():
            return None

        try:
            with gzip.open(cache_file, 'rt', encoding='utf-8') as f:
                signed_data = json.load(f)

            # Verify signature
            if 'data' not in signed_data or 'signature' not in signed_data:
                logger.warning(f"Invalid cache file format: {cache_file}")
                cache_file.unlink()
                return None

            # Verify HMAC signature
            cache_data = signed_data['data']
            expected_signature = signed_data['signature']

            json_data = json.dumps(cache_data, separators=(',', ':'))
            actual_signature = hmac.new(
                self.cache_secret,
                json_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(expected_signature, actual_signature):
                logger.warning(f"Cache signature verification failed: {cache_file}")
                cache_file.unlink()
                return None

            # Reconstruct ScanCache object
            file_metadata = FileMetadata(
                file_path=cache_data['file_metadata']['file_path'],
                file_size=cache_data['file_metadata']['file_size'],
                modified_time=datetime.fromisoformat(cache_data['file_metadata']['modified_time']),
                checksum=cache_data['file_metadata']['checksum'],
                file_type=cache_data['file_metadata']['file_type']
            )

            return ScanCache(
                file_metadata=file_metadata,
                findings=cache_data['findings'],
                scan_duration=cache_data['scan_duration'],
                scanner_versions=cache_data['scanner_versions'],
                cached_at=datetime.fromisoformat(cache_data['cached_at'])
            )

        except Exception as e:
            logger.error(f"Failed to load cache from disk: {e}")
            # Remove corrupted cache file
            try:
                cache_file.unlink()
            except:
                pass
            return None
    
    def _load_cache_index(self):
        """Load cache index for faster lookups"""
        # TODO: Implement cache index for faster file lookups
        pass
    
    def _get_cache_dir_size(self) -> int:
        """Get total size of cache directory in bytes"""
        total_size = 0
        try:
            for cache_file in self.cache_dir.rglob("*"):
                if cache_file.is_file():
                    total_size += cache_file.stat().st_size
        except Exception as e:
            logger.error(f"Error calculating cache directory size: {e}")
        return total_size

# Global cache manager instance
cache_manager = CacheManager()
