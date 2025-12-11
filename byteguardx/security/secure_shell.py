"""
Secure Shell Execution Utilities for ByteGuardX
Provides safe alternatives to direct shell execution with proper escaping and validation
"""

import os
import subprocess
import shlex
import logging
import signal
from typing import List, Dict, Optional, Tuple, Union
from pathlib import Path
import tempfile
import threading
import time

logger = logging.getLogger(__name__)

class ShellExecutionError(Exception):
    """Custom exception for shell execution errors"""
    pass

class SecureShellExecutor:
    """Secure shell command execution with validation and sandboxing"""
    
    # Allowed commands for different contexts
    ALLOWED_COMMANDS = {
        'git': ['git', 'clone', 'pull', 'status', 'log', 'diff', 'show'],
        'python': ['python', 'python3', 'pip', 'pip3'],
        'node': ['node', 'npm', 'yarn', 'npx'],
        'security': ['bandit', 'safety', 'semgrep', 'eslint', 'pylint'],
        'system': ['ls', 'cat', 'head', 'tail', 'grep', 'find', 'wc']
    }
    
    # Dangerous commands that should never be executed
    DANGEROUS_COMMANDS = [
        'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs',
        'dd', 'chmod', 'chown', 'sudo', 'su', 'passwd',
        'useradd', 'userdel', 'groupadd', 'groupdel',
        'systemctl', 'service', 'init', 'shutdown', 'reboot',
        'iptables', 'netsh', 'route', 'ifconfig',
        'curl', 'wget', 'nc', 'netcat', 'telnet', 'ssh',
        'eval', 'exec', 'source', '.', 'bash', 'sh', 'zsh',
        'powershell', 'cmd', 'command'
    ]
    
    def __init__(self, timeout: int = 30, max_output_size: int = 1024*1024):
        self.timeout = timeout
        self.max_output_size = max_output_size
        self.temp_dir = Path(tempfile.gettempdir()) / "byteguardx_secure"
        self.temp_dir.mkdir(exist_ok=True)
    
    def execute_command(self, command: Union[str, List[str]], 
                       working_dir: Optional[str] = None,
                       env_vars: Optional[Dict[str, str]] = None,
                       allowed_context: str = 'system') -> Tuple[int, str, str]:
        """
        Execute a command securely with validation and sandboxing
        Returns: (return_code, stdout, stderr)
        """
        try:
            # Parse and validate command
            if isinstance(command, str):
                cmd_parts = shlex.split(command)
            else:
                cmd_parts = command
            
            if not cmd_parts:
                raise ShellExecutionError("Empty command")
            
            # Validate command
            if not self._validate_command(cmd_parts, allowed_context):
                raise ShellExecutionError(f"Command not allowed: {cmd_parts[0]}")
            
            # Prepare environment
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)
            
            # Set secure environment variables
            env['PATH'] = self._get_secure_path()
            env.pop('LD_PRELOAD', None)  # Remove potentially dangerous env vars
            env.pop('LD_LIBRARY_PATH', None)
            
            # Validate working directory
            if working_dir:
                working_dir = self._validate_working_directory(working_dir)
            
            # Execute command with security measures
            return self._execute_with_timeout(cmd_parts, working_dir, env)
            
        except Exception as e:
            logger.error(f"Secure shell execution error: {e}")
            raise ShellExecutionError(f"Execution failed: {str(e)}")
    
    def execute_python_script(self, script_content: str, 
                            script_args: List[str] = None,
                            working_dir: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute Python script securely"""
        try:
            # Create temporary script file
            script_file = self.temp_dir / f"script_{int(time.time())}.py"
            
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            # Prepare command
            cmd = ['python3', str(script_file)]
            if script_args:
                cmd.extend(script_args)
            
            # Execute with Python context
            result = self.execute_command(cmd, working_dir, allowed_context='python')
            
            # Cleanup
            script_file.unlink(missing_ok=True)
            
            return result
            
        except Exception as e:
            logger.error(f"Python script execution error: {e}")
            raise ShellExecutionError(f"Python execution failed: {str(e)}")
    
    def execute_security_scan(self, tool: str, target_path: str, 
                            extra_args: List[str] = None) -> Tuple[int, str, str]:
        """Execute security scanning tools safely"""
        try:
            # Validate tool
            if tool not in ['bandit', 'safety', 'semgrep', 'eslint', 'pylint']:
                raise ShellExecutionError(f"Security tool not allowed: {tool}")
            
            # Validate target path
            target_path = self._validate_scan_target(target_path)
            
            # Prepare command
            cmd = [tool, target_path]
            if extra_args:
                cmd.extend(extra_args)
            
            # Execute with security context
            return self.execute_command(cmd, allowed_context='security')
            
        except Exception as e:
            logger.error(f"Security scan execution error: {e}")
            raise ShellExecutionError(f"Security scan failed: {str(e)}")
    
    def _validate_command(self, cmd_parts: List[str], context: str) -> bool:
        """Validate command against allowed lists"""
        if not cmd_parts:
            return False
        
        command = cmd_parts[0]
        
        # Check if command is dangerous
        if command in self.DANGEROUS_COMMANDS:
            return False
        
        # Check if command is allowed in context
        allowed_commands = self.ALLOWED_COMMANDS.get(context, [])
        if allowed_commands and command not in allowed_commands:
            return False
        
        # Additional validation for arguments
        for arg in cmd_parts[1:]:
            if self._is_dangerous_argument(arg):
                return False
        
        return True
    
    def _is_dangerous_argument(self, arg: str) -> bool:
        """Check if argument contains dangerous patterns"""
        dangerous_patterns = [
            '$(', '`', '|', '&', ';', '>', '<', '*',
            '../', '..\\', '/etc/', '/proc/', '/sys/',
            'C:\\Windows\\', 'C:\\System32\\'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in arg:
                return True
        
        return False
    
    def _get_secure_path(self) -> str:
        """Get secure PATH environment variable"""
        secure_paths = [
            '/usr/local/bin',
            '/usr/bin',
            '/bin',
            '/usr/local/sbin',
            '/usr/sbin',
            '/sbin'
        ]
        
        # Filter existing paths
        existing_paths = [p for p in secure_paths if Path(p).exists()]
        return ':'.join(existing_paths)
    
    def _validate_working_directory(self, working_dir: str) -> str:
        """Validate and normalize working directory"""
        path = Path(working_dir).resolve()
        
        # Ensure directory exists and is accessible
        if not path.exists():
            raise ShellExecutionError(f"Working directory does not exist: {working_dir}")
        
        if not path.is_dir():
            raise ShellExecutionError(f"Working directory is not a directory: {working_dir}")
        
        # Check for dangerous paths
        dangerous_paths = ['/etc', '/proc', '/sys', '/root', '/boot']
        for dangerous_path in dangerous_paths:
            if str(path).startswith(dangerous_path):
                raise ShellExecutionError(f"Access to directory not allowed: {working_dir}")
        
        return str(path)
    
    def _validate_scan_target(self, target_path: str) -> str:
        """Validate scan target path"""
        path = Path(target_path).resolve()
        
        # Ensure path exists
        if not path.exists():
            raise ShellExecutionError(f"Scan target does not exist: {target_path}")
        
        # Check for path traversal
        if '..' in str(path):
            raise ShellExecutionError(f"Path traversal detected: {target_path}")
        
        return str(path)
    
    def _execute_with_timeout(self, cmd_parts: List[str], 
                            working_dir: Optional[str],
                            env: Dict[str, str]) -> Tuple[int, str, str]:
        """Execute command with timeout and output limits"""
        try:
            # Start process
            process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=working_dir,
                env=env,
                shell=False,  # Never use shell=True
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                # Kill process group
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
                
                process.wait(timeout=5)
                raise ShellExecutionError(f"Command timed out after {self.timeout} seconds")
            
            # Decode output
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            
            # Limit output size
            if len(stdout_str) > self.max_output_size:
                stdout_str = stdout_str[:self.max_output_size] + "\n[OUTPUT TRUNCATED]"
            
            if len(stderr_str) > self.max_output_size:
                stderr_str = stderr_str[:self.max_output_size] + "\n[OUTPUT TRUNCATED]"
            
            return process.returncode, stdout_str, stderr_str
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            raise ShellExecutionError(f"Execution failed: {str(e)}")

# Global instance
secure_shell = SecureShellExecutor()
