"""
Lazy Loading System for ByteGuardX
Reduces memory footprint by loading heavy dependencies only when needed
"""

import logging
import importlib
import sys
from typing import Any, Dict, Optional, Callable, Type
from functools import wraps
import threading

logger = logging.getLogger(__name__)

class LazyImport:
    """Lazy import wrapper that loads modules only when accessed"""
    
    def __init__(self, module_name: str, package: Optional[str] = None, 
                 fallback: Optional[Callable] = None):
        self.module_name = module_name
        self.package = package
        self.fallback = fallback
        self._module = None
        self._lock = threading.Lock()
        self._import_attempted = False
    
    def __getattr__(self, name: str) -> Any:
        """Load module on first attribute access"""
        if self._module is None:
            with self._lock:
                if self._module is None and not self._import_attempted:
                    self._import_attempted = True
                    try:
                        self._module = importlib.import_module(self.module_name, self.package)
                        logger.debug(f"Lazy loaded module: {self.module_name}")
                    except ImportError as e:
                        logger.warning(f"Failed to import {self.module_name}: {e}")
                        if self.fallback:
                            logger.info(f"Using fallback for {self.module_name}")
                            self._module = self.fallback()
                        else:
                            raise ImportError(
                                f"Module {self.module_name} not available. "
                                f"Install with: pip install byteguardx[{self._get_feature_name()}]"
                            ) from e
        
        if self._module is None:
            raise ImportError(f"Module {self.module_name} could not be loaded")
        
        return getattr(self._module, name)
    
    def _get_feature_name(self) -> str:
        """Get feature name for installation hint"""
        feature_map = {
            'transformers': 'ai',
            'torch': 'ai',
            'numpy': 'ml-light',
            'pandas': 'ml-full',
            'matplotlib': 'ml-full',
            'WeasyPrint': 'pdf',
            'redis': 'queue',
            'celery': 'queue',
            'docker': 'container',
            'saml': 'enterprise'
        }
        
        for key, feature in feature_map.items():
            if key in self.module_name:
                return feature
        
        return 'all'
    
    @property
    def is_available(self) -> bool:
        """Check if module is available without importing"""
        if self._module is not None:
            return True
        
        try:
            importlib.util.find_spec(self.module_name)
            return True
        except (ImportError, AttributeError, ValueError):
            return False

class LazyClass:
    """Lazy class loader that instantiates classes only when needed"""
    
    def __init__(self, module_name: str, class_name: str, 
                 fallback_class: Optional[Type] = None, *args, **kwargs):
        self.module_name = module_name
        self.class_name = class_name
        self.fallback_class = fallback_class
        self.args = args
        self.kwargs = kwargs
        self._instance = None
        self._lock = threading.Lock()
    
    def __getattr__(self, name: str) -> Any:
        """Load and instantiate class on first method access"""
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    try:
                        module = importlib.import_module(self.module_name)
                        cls = getattr(module, self.class_name)
                        self._instance = cls(*self.args, **self.kwargs)
                        logger.debug(f"Lazy loaded class: {self.module_name}.{self.class_name}")
                    except (ImportError, AttributeError) as e:
                        logger.warning(f"Failed to load {self.module_name}.{self.class_name}: {e}")
                        if self.fallback_class:
                            logger.info(f"Using fallback class for {self.class_name}")
                            self._instance = self.fallback_class(*self.args, **self.kwargs)
                        else:
                            raise ImportError(
                                f"Class {self.module_name}.{self.class_name} not available"
                            ) from e
        
        return getattr(self._instance, name)

def lazy_import(module_name: str, package: Optional[str] = None, 
                fallback: Optional[Callable] = None) -> LazyImport:
    """Create a lazy import wrapper"""
    return LazyImport(module_name, package, fallback)

def requires_optional_dependency(dependency: str, feature: str = None):
    """Decorator to check for optional dependencies"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                importlib.import_module(dependency)
                return func(*args, **kwargs)
            except ImportError:
                feature_name = feature or dependency
                raise ImportError(
                    f"This feature requires {dependency}. "
                    f"Install with: pip install byteguardx[{feature_name}]"
                )
        return wrapper
    return decorator

class FeatureRegistry:
    """Registry for optional features and their dependencies"""
    
    def __init__(self):
        self.features = {}
        self._availability_cache = {}
    
    def register_feature(self, name: str, dependencies: list, 
                        description: str = "", install_hint: str = ""):
        """Register an optional feature"""
        self.features[name] = {
            'dependencies': dependencies,
            'description': description,
            'install_hint': install_hint or f"pip install byteguardx[{name}]"
        }
    
    def is_feature_available(self, name: str) -> bool:
        """Check if a feature is available"""
        if name in self._availability_cache:
            return self._availability_cache[name]
        
        if name not in self.features:
            return False
        
        dependencies = self.features[name]['dependencies']
        available = all(self._is_module_available(dep) for dep in dependencies)
        self._availability_cache[name] = available
        
        return available
    
    def _is_module_available(self, module_name: str) -> bool:
        """Check if a module is available"""
        try:
            importlib.util.find_spec(module_name)
            return True
        except (ImportError, AttributeError, ValueError):
            return False
    
    def get_missing_dependencies(self, name: str) -> list:
        """Get list of missing dependencies for a feature"""
        if name not in self.features:
            return []
        
        dependencies = self.features[name]['dependencies']
        return [dep for dep in dependencies if not self._is_module_available(dep)]
    
    def get_install_hint(self, name: str) -> str:
        """Get installation hint for a feature"""
        if name not in self.features:
            return f"pip install byteguardx[{name}]"
        
        return self.features[name]['install_hint']
    
    def list_available_features(self) -> Dict[str, bool]:
        """List all features and their availability"""
        return {name: self.is_feature_available(name) for name in self.features}

# Global feature registry
feature_registry = FeatureRegistry()

# Register optional features
feature_registry.register_feature(
    'ai', 
    ['transformers', 'torch', 'onnxruntime'],
    'AI-powered vulnerability detection',
    'pip install byteguardx[ai]'
)

feature_registry.register_feature(
    'ml-light',
    ['numpy', 'scikit-learn'],
    'Basic machine learning features',
    'pip install byteguardx[ml-light]'
)

feature_registry.register_feature(
    'ml-full',
    ['numpy', 'pandas', 'scikit-learn', 'matplotlib', 'seaborn'],
    'Full machine learning and data analysis',
    'pip install byteguardx[ml-full]'
)

feature_registry.register_feature(
    'pdf',
    ['weasyprint', 'jinja2'],
    'PDF report generation',
    'pip install byteguardx[pdf]'
)

feature_registry.register_feature(
    'database',
    ['psycopg2', 'pymysql', 'alembic'],
    'Advanced database support',
    'pip install byteguardx[database]'
)

feature_registry.register_feature(
    'queue',
    ['redis', 'celery'],
    'Background task processing',
    'pip install byteguardx[queue]'
)

feature_registry.register_feature(
    'enterprise',
    ['saml2', 'xmlsec', 'ldap3'],
    'Enterprise authentication features',
    'pip install byteguardx[enterprise]'
)

# Lazy imports for heavy dependencies
def create_fallback_numpy():
    """Fallback for numpy - basic array operations"""
    class FallbackArray:
        def __init__(self, data):
            self.data = data
        
        def mean(self):
            return sum(self.data) / len(self.data) if self.data else 0
        
        def std(self):
            if not self.data:
                return 0
            mean_val = self.mean()
            variance = sum((x - mean_val) ** 2 for x in self.data) / len(self.data)
            return variance ** 0.5
    
    class FallbackNumpy:
        def array(self, data):
            return FallbackArray(data)
        
        def mean(self, data):
            return sum(data) / len(data) if data else 0
    
    return FallbackNumpy()

def create_fallback_pandas():
    """Fallback for pandas - basic data operations"""
    class FallbackDataFrame:
        def __init__(self, data):
            self.data = data
        
        def to_dict(self):
            return self.data
        
        def to_json(self):
            import json
            return json.dumps(self.data)
    
    class FallbackPandas:
        def DataFrame(self, data):
            return FallbackDataFrame(data)
    
    return FallbackPandas()

# Lazy imports with fallbacks
numpy = lazy_import('numpy', fallback=create_fallback_numpy)
pandas = lazy_import('pandas', fallback=create_fallback_pandas)
torch = lazy_import('torch')
transformers = lazy_import('transformers')
weasyprint = lazy_import('weasyprint')
redis = lazy_import('redis')
celery = lazy_import('celery')

def get_feature_status() -> Dict[str, Any]:
    """Get status of all optional features"""
    status = {
        'available_features': feature_registry.list_available_features(),
        'loaded_modules': [name for name, module in sys.modules.items() 
                          if any(feat in name for feat in feature_registry.features)],
        'memory_usage': _get_memory_usage(),
    }
    
    return status

def _get_memory_usage() -> Dict[str, float]:
    """Get current memory usage"""
    try:
        import psutil
        process = psutil.Process()
        return {
            'rss_mb': process.memory_info().rss / 1024 / 1024,
            'vms_mb': process.memory_info().vms / 1024 / 1024,
            'percent': process.memory_percent()
        }
    except ImportError:
        return {'error': 'psutil not available'}

def optimize_imports():
    """Optimize imports by removing unused modules"""
    # This is a placeholder for future optimization
    # Could implement module unloading for memory optimization
    pass
