"""
Shell Injection Prevention System
Provides secure alternatives to shell execution and validates all subprocess calls
"""

import os
import re
import shlex
import logging
import subprocess
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import tempfile

logger = logging.getLogger(__name__)

class ShellInjectionError(Exception):
    """Exception raised when shell injection is detected"""
    pass

class SecureShellExecutor:
    """Secure shell command execution with injection prevention"""
    
    # Dangerous shell patterns that should never be allowed
    DANGEROUS_PATTERNS = [
        r'[;&|`$(){}[\]<>]',  # Shell metacharacters
        r'\\x[0-9a-fA-F]{2}',  # Hex escapes
        r'\\[0-7]{1,3}',  # Octal escapes
        r'\$\{.*\}',  # Variable expansion
        r'\$\(.*\)',  # Command substitution
        r'`.*`',  # Backtick command substitution
        r'>\s*/dev/',  # Device redirection
        r'<\s*/dev/',  # Device input
        r'/proc/',  # Process filesystem
        r'/sys/',  # System filesystem
        r'sudo\s+',  # Privilege escalation
        r'su\s+',  # User switching
        r'chmod\s+',  # Permission changes
        r'chown\s+',  # Ownership changes
        r'rm\s+-rf',  # Dangerous deletion
        r'dd\s+',  # Direct disk access
        r'mkfs\.',  # Filesystem creation
        r'mount\s+',  # Filesystem mounting
        r'umount\s+',  # Filesystem unmounting
        r'kill\s+-9',  # Force kill
        r'killall\s+',  # Kill all processes
        r'pkill\s+',  # Process kill
        r'nc\s+',  # Netcat
        r'telnet\s+',  # Telnet
        r'ssh\s+',  # SSH
        r'scp\s+',  # Secure copy
        r'rsync\s+',  # Remote sync
        r'curl\s+.*\|\s*sh',  # Pipe to shell
        r'wget\s+.*\|\s*sh',  # Pipe to shell
        r'eval\s+',  # Eval command
        r'exec\s+',  # Exec command
        r'source\s+',  # Source command
        r'\.\s+',  # Dot command
    ]
    
    # Allowed commands for specific operations
    ALLOWED_COMMANDS = {
        'git': ['git', 'status', 'log', 'show', 'diff', 'branch', 'tag'],
        'python': ['python', 'python3', '-m', 'pip', 'list', 'show'],
        'node': ['node', 'npm', 'list', 'audit', 'outdated'],
        'file_ops': ['ls', 'cat', 'head', 'tail', 'wc', 'grep', 'find'],
        'archive': ['tar', 'zip', 'unzip', 'gzip', 'gunzip']
    }
    
    def __init__(self, allowed_commands: Optional[List[str]] = None):
        self.allowed_commands = allowed_commands or []
        self.temp_dir = Path(tempfile.gettempdir()) / "byteguardx_secure"
        self.temp_dir.mkdir(exist_ok=True)
    
    def validate_command(self, command: Union[str, List[str]]) -> bool:
        """
        Validate command for shell injection patterns
        Returns: True if safe, False if dangerous
        """
        if isinstance(command, list):
            command_str = ' '.join(command)
        else:
            command_str = command
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command_str, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected in command: {pattern}")
                return False
        
        # Check if command is in allowed list
        if self.allowed_commands:
            if isinstance(command, list):
                base_command = command[0]
            else:
                base_command = command.split()[0]
            
            if base_command not in self.allowed_commands:
                logger.warning(f"Command not in allowed list: {base_command}")
                return False
        
        return True
    
    def sanitize_arguments(self, args: List[str]) -> List[str]:
        """Sanitize command arguments"""
        sanitized = []
        
        for arg in args:
            # Remove null bytes
            arg = arg.replace('\x00', '')
            
            # Validate path arguments
            if '/' in arg or '\\' in arg:
                try:
                    path = Path(arg).resolve()
                    # Ensure path is within allowed directories
                    if not self._is_safe_path(path):
                        raise ShellInjectionError(f"Unsafe path: {arg}")
                    arg = str(path)
                except Exception as e:
                    raise ShellInjectionError(f"Invalid path argument: {arg}")
            
            sanitized.append(arg)
        
        return sanitized
    
    def execute_safe(self, command: List[str], cwd: Optional[str] = None, 
                    timeout: int = 30, capture_output: bool = True) -> subprocess.CompletedProcess:
        """
        Execute command safely with validation
        """
        if not command:
            raise ShellInjectionError("Empty command")
        
        # Validate command
        if not self.validate_command(command):
            raise ShellInjectionError(f"Command failed validation: {command[0]}")
        
        # Sanitize arguments
        try:
            sanitized_command = self.sanitize_arguments(command)
        except ShellInjectionError:
            raise
        except Exception as e:
            raise ShellInjectionError(f"Argument sanitization failed: {e}")
        
        # Validate working directory
        if cwd:
            cwd_path = Path(cwd).resolve()
            if not self._is_safe_path(cwd_path):
                raise ShellInjectionError(f"Unsafe working directory: {cwd}")
            cwd = str(cwd_path)
        
        # Set up secure environment
        env = os.environ.copy()
        
        # Remove dangerous environment variables
        dangerous_env_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']
        for var in dangerous_env_vars:
            env.pop(var, None)
        
        try:
            # Execute with shell=False for security
            result = subprocess.run(
                sanitized_command,
                cwd=cwd,
                env=env,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                shell=False  # NEVER use shell=True
            )
            
            logger.info(f"Executed command safely: {sanitized_command[0]}")
            return result
            
        except subprocess.TimeoutExpired:
            raise ShellInjectionError(f"Command timed out: {command[0]}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}")
            raise
        except Exception as e:
            raise ShellInjectionError(f"Command execution failed: {e}")
    
    def _is_safe_path(self, path: Path) -> bool:
        """Check if path is safe for operations"""
        try:
            resolved_path = path.resolve()
            path_str = str(resolved_path)
            
            # Blocked directories
            blocked_dirs = [
                '/etc', '/proc', '/sys', '/dev', '/root',
                '/boot', '/usr/bin', '/usr/sbin', '/sbin',
                'C:\\Windows', 'C:\\System32', 'C:\\Program Files'
            ]
            
            for blocked in blocked_dirs:
                if path_str.startswith(blocked):
                    return False
            
            # Must be within project directory or temp directory
            project_root = Path.cwd()
            temp_root = Path(tempfile.gettempdir())
            
            try:
                resolved_path.relative_to(project_root)
                return True
            except ValueError:
                pass
            
            try:
                resolved_path.relative_to(temp_root)
                return True
            except ValueError:
                pass
            
            return False
            
        except Exception:
            return False

# Secure wrapper functions for common operations
def secure_git_command(args: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Execute git command securely"""
    executor = SecureShellExecutor(['git'])
    return executor.execute_safe(['git'] + args, cwd=cwd)

def secure_python_command(args: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Execute Python command securely"""
    executor = SecureShellExecutor(['python', 'python3'])
    return executor.execute_safe(['python'] + args, cwd=cwd)

def secure_npm_command(args: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Execute npm command securely"""
    executor = SecureShellExecutor(['npm', 'node'])
    return executor.execute_safe(['npm'] + args, cwd=cwd)

def secure_file_operation(command: str, args: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Execute file operation securely"""
    allowed_file_commands = ['ls', 'cat', 'head', 'tail', 'wc', 'grep', 'find']
    if command not in allowed_file_commands:
        raise ShellInjectionError(f"File command not allowed: {command}")
    
    executor = SecureShellExecutor(allowed_file_commands)
    return executor.execute_safe([command] + args, cwd=cwd)

# Decorator for securing subprocess calls
def secure_subprocess(allowed_commands: Optional[List[str]] = None):
    """Decorator to secure subprocess calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract command from arguments
            if args and isinstance(args[0], (list, str)):
                command = args[0]
                executor = SecureShellExecutor(allowed_commands)
                
                if not executor.validate_command(command):
                    raise ShellInjectionError("Command failed security validation")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Global secure executor instance
secure_executor = SecureShellExecutor()

# Audit function to check existing code for shell injection vulnerabilities
def audit_subprocess_calls(file_path: str) -> List[Dict[str, Any]]:
    """Audit Python file for potentially unsafe subprocess calls"""
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # Patterns to look for
        dangerous_patterns = [
            (r'subprocess\.call\([^)]*shell\s*=\s*True', 'subprocess.call with shell=True'),
            (r'subprocess\.run\([^)]*shell\s*=\s*True', 'subprocess.run with shell=True'),
            (r'subprocess\.Popen\([^)]*shell\s*=\s*True', 'subprocess.Popen with shell=True'),
            (r'os\.system\s*\(', 'os.system call'),
            (r'os\.popen\s*\(', 'os.popen call'),
            (r'commands\.getoutput\s*\(', 'commands.getoutput call'),
            (r'commands\.getstatusoutput\s*\(', 'commands.getstatusoutput call'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in dangerous_patterns:
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'file': file_path,
                        'line': line_num,
                        'code': line.strip(),
                        'vulnerability': description,
                        'severity': 'HIGH'
                    })
        
    except Exception as e:
        logger.error(f"Error auditing file {file_path}: {e}")

    return vulnerabilities

# Global instance
secure_shell_executor = SecureShellExecutor()
