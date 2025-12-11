"""
Base Plugin Classes for ByteGuardX Plugin System
Defines the interface and structure for all plugins
"""

import abc
import logging
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)

class PluginType(Enum):
    """Types of plugins supported"""
    SCANNER = "scanner"
    RULE = "rule"
    FORMATTER = "formatter"
    EXPORTER = "exporter"
    VALIDATOR = "validator"

class PluginStatus(Enum):
    """Plugin status states"""
    INACTIVE = "inactive"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"

@dataclass
class PluginResult:
    """Result from plugin execution"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    warnings: List[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}

@dataclass
class Finding:
    """Standard finding structure for scanner plugins"""
    type: str
    subtype: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    rule_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    fix_suggestion: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class BasePlugin(abc.ABC):
    """Base class for all ByteGuardX plugins"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.status = PluginStatus.INACTIVE
        self.last_error = None
        self.execution_count = 0
        self.total_execution_time = 0.0
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass
    
    @property
    @abc.abstractmethod
    def author(self) -> str:
        """Plugin author"""
        pass
    
    @property
    @abc.abstractmethod
    def plugin_type(self) -> PluginType:
        """Plugin type"""
        pass
    
    @abc.abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin"""
        pass
    
    @abc.abstractmethod
    def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        pass
    
    @abc.abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate plugin configuration"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata"""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'type': self.plugin_type.value,
            'status': self.status.value,
            'execution_count': self.execution_count,
            'total_execution_time': self.total_execution_time,
            'last_error': self.last_error,
            'config': self.config
        }
    
    def update_config(self, config: Dict[str, Any]) -> bool:
        """Update plugin configuration"""
        try:
            if self.validate_config(config):
                self.config.update(config)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to update config: {e}")
            return False
    
    def set_status(self, status: PluginStatus, error: str = None):
        """Set plugin status"""
        self.status = status
        if error:
            self.last_error = error
            self.logger.error(f"Plugin {self.name} error: {error}")

class ScannerPlugin(BasePlugin):
    """Base class for scanner plugins"""
    
    @property
    def plugin_type(self) -> PluginType:
        return PluginType.SCANNER
    
    @abc.abstractmethod
    def scan_content(self, content: str, file_path: str = "", 
                    file_type: str = "") -> PluginResult:
        """
        Scan content for security issues
        
        Args:
            content: File content to scan
            file_path: Path to the file being scanned
            file_type: Type/extension of the file
            
        Returns:
            PluginResult with findings
        """
        pass
    
    @abc.abstractmethod
    def get_supported_file_types(self) -> List[str]:
        """Get list of supported file types/extensions"""
        pass
    
    def can_scan_file(self, file_path: str, file_type: str = "") -> bool:
        """Check if plugin can scan the given file"""
        supported_types = self.get_supported_file_types()
        
        if not supported_types:  # Plugin supports all file types
            return True
        
        # Check file extension
        if file_type:
            return file_type.lower() in [t.lower() for t in supported_types]
        
        # Extract extension from file path
        if '.' in file_path:
            ext = '.' + file_path.split('.')[-1].lower()
            return ext in [t.lower() for t in supported_types]
        
        return False

class RulePlugin(BasePlugin):
    """Base class for rule-based detection plugins"""
    
    @property
    def plugin_type(self) -> PluginType:
        return PluginType.RULE
    
    @abc.abstractmethod
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get detection rules"""
        pass
    
    @abc.abstractmethod
    def apply_rules(self, content: str, file_path: str = "") -> PluginResult:
        """Apply rules to content"""
        pass
    
    def validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate a single rule"""
        required_fields = ['id', 'name', 'pattern', 'severity']
        
        for field in required_fields:
            if field not in rule:
                self.logger.error(f"Rule missing required field: {field}")
                return False
        
        # Validate severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        if rule['severity'].lower() not in valid_severities:
            self.logger.error(f"Invalid severity: {rule['severity']}")
            return False
        
        return True

class FormatterPlugin(BasePlugin):
    """Base class for output formatter plugins"""
    
    @property
    def plugin_type(self) -> PluginType:
        return PluginType.FORMATTER
    
    @abc.abstractmethod
    def format_findings(self, findings: List[Finding]) -> PluginResult:
        """Format findings for output"""
        pass
    
    @abc.abstractmethod
    def get_output_format(self) -> str:
        """Get output format name (e.g., 'json', 'xml', 'csv')"""
        pass

class ExporterPlugin(BasePlugin):
    """Base class for data exporter plugins"""
    
    @property
    def plugin_type(self) -> PluginType:
        return PluginType.EXPORTER
    
    @abc.abstractmethod
    def export_data(self, data: Any, destination: str) -> PluginResult:
        """Export data to destination"""
        pass
    
    @abc.abstractmethod
    def get_supported_destinations(self) -> List[str]:
        """Get supported export destinations"""
        pass

class ValidatorPlugin(BasePlugin):
    """Base class for validation plugins"""
    
    @property
    def plugin_type(self) -> PluginType:
        return PluginType.VALIDATOR
    
    @abc.abstractmethod
    def validate_findings(self, findings: List[Finding]) -> PluginResult:
        """Validate findings for accuracy"""
        pass
    
    @abc.abstractmethod
    def get_validation_criteria(self) -> Dict[str, Any]:
        """Get validation criteria"""
        pass

# Example plugin implementations

class ExampleSecretScannerPlugin(ScannerPlugin):
    """Example implementation of a secret scanner plugin"""
    
    @property
    def name(self) -> str:
        return "Example Secret Scanner"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "Example plugin for scanning secrets in code"
    
    @property
    def author(self) -> str:
        return "ByteGuardX Team"
    
    def initialize(self) -> bool:
        """Initialize the plugin"""
        try:
            # Load patterns, initialize resources, etc.
            self.patterns = self.config.get('patterns', [])
            self.set_status(PluginStatus.ACTIVE)
            return True
        except Exception as e:
            self.set_status(PluginStatus.ERROR, str(e))
            return False
    
    def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        try:
            # Clean up resources
            self.set_status(PluginStatus.INACTIVE)
            return True
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
            return False
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate plugin configuration"""
        # Validate required configuration
        if 'patterns' not in config:
            return False
        
        if not isinstance(config['patterns'], list):
            return False
        
        return True
    
    def scan_content(self, content: str, file_path: str = "", 
                    file_type: str = "") -> PluginResult:
        """Scan content for secrets"""
        import time
        import re
        
        start_time = time.time()
        findings = []
        
        try:
            # Example secret patterns
            secret_patterns = [
                {
                    'id': 'api_key',
                    'name': 'API Key',
                    'pattern': r'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})',
                    'severity': 'high'
                },
                {
                    'id': 'password',
                    'name': 'Password',
                    'pattern': r'password["\']?\s*[:=]\s*["\']?([^"\'\\s]{8,})',
                    'severity': 'medium'
                }
            ]
            
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern_info in secret_patterns:
                    matches = re.finditer(pattern_info['pattern'], line, re.IGNORECASE)
                    
                    for match in matches:
                        finding = Finding(
                            type='secret',
                            subtype=pattern_info['id'],
                            description=f"{pattern_info['name']} detected",
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line.strip(),
                            severity=pattern_info['severity'],
                            confidence=0.8,
                            rule_id=pattern_info['id'],
                            fix_suggestion="Remove or encrypt the secret"
                        )
                        findings.append(finding)
            
            execution_time = time.time() - start_time
            self.execution_count += 1
            self.total_execution_time += execution_time
            
            return PluginResult(
                success=True,
                data=findings,
                execution_time=execution_time,
                metadata={'patterns_used': len(secret_patterns)}
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.set_status(PluginStatus.ERROR, str(e))
            
            return PluginResult(
                success=False,
                error=str(e),
                execution_time=execution_time
            )
    
    def get_supported_file_types(self) -> List[str]:
        """Get supported file types"""
        return ['.py', '.js', '.java', '.php', '.rb', '.go', '.rs', '.cpp', '.c']

class ExampleRulePlugin(RulePlugin):
    """Example implementation of a rule plugin"""
    
    @property
    def name(self) -> str:
        return "Example Rule Plugin"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "Example rule-based detection plugin"
    
    @property
    def author(self) -> str:
        return "ByteGuardX Team"
    
    def initialize(self) -> bool:
        """Initialize the plugin"""
        try:
            self.rules = self.get_rules()
            self.set_status(PluginStatus.ACTIVE)
            return True
        except Exception as e:
            self.set_status(PluginStatus.ERROR, str(e))
            return False
    
    def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        self.set_status(PluginStatus.INACTIVE)
        return True
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate plugin configuration"""
        return True  # No specific config required for this example
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get detection rules"""
        return [
            {
                'id': 'hardcoded_ip',
                'name': 'Hardcoded IP Address',
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'severity': 'low',
                'description': 'Hardcoded IP address detected'
            },
            {
                'id': 'todo_comment',
                'name': 'TODO Comment',
                'pattern': r'#\s*TODO|//\s*TODO|/\*\s*TODO',
                'severity': 'low',
                'description': 'TODO comment found'
            }
        ]
    
    def apply_rules(self, content: str, file_path: str = "") -> PluginResult:
        """Apply rules to content"""
        import time
        import re
        
        start_time = time.time()
        findings = []
        
        try:
            lines = content.split('\n')
            
            for rule in self.rules:
                if not self.validate_rule(rule):
                    continue
                
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(rule['pattern'], line, re.IGNORECASE)
                    
                    for match in matches:
                        finding = Finding(
                            type='rule_violation',
                            subtype=rule['id'],
                            description=rule['description'],
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line.strip(),
                            severity=rule['severity'],
                            confidence=0.7,
                            rule_id=rule['id']
                        )
                        findings.append(finding)
            
            execution_time = time.time() - start_time
            self.execution_count += 1
            self.total_execution_time += execution_time
            
            return PluginResult(
                success=True,
                data=findings,
                execution_time=execution_time,
                metadata={'rules_applied': len(self.rules)}
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.set_status(PluginStatus.ERROR, str(e))
            
            return PluginResult(
                success=False,
                error=str(e),
                execution_time=execution_time
            )
