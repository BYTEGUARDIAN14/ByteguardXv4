"""
Code sandboxing for secure execution of untrusted code analysis
Provides isolated environment for running potentially dangerous scans
"""

import os
import subprocess
import tempfile
import shutil
import logging
import signal
import threading
import time
import resource
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
import psutil
import docker
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class SandboxType(Enum):
    """Types of sandboxing"""
    PROCESS = "process"  # Process-level isolation
    CONTAINER = "container"  # Docker container isolation
    CHROOT = "chroot"  # Chroot jail isolation

@dataclass
class SandboxConfig:
    """Sandbox configuration"""
    sandbox_type: SandboxType = SandboxType.PROCESS
    max_memory_mb: int = 512
    max_cpu_percent: float = 50.0
    max_execution_time: int = 300  # seconds
    max_file_size_mb: int = 100
    max_files: int = 1000
    network_access: bool = False
    temp_dir_size_mb: int = 1024
    allowed_syscalls: List[str] = None
    blocked_paths: List[str] = None
    
    def __post_init__(self):
        if self.allowed_syscalls is None:
            self.allowed_syscalls = [
                'read', 'write', 'open', 'close', 'stat', 'fstat',
                'lstat', 'poll', 'lseek', 'mmap', 'mprotect', 'munmap',
                'brk', 'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
                'ioctl', 'pread64', 'pwrite64', 'readv', 'writev',
                'access', 'pipe', 'select', 'sched_yield', 'mremap',
                'msync', 'mincore', 'madvise', 'shmget', 'shmat', 'shmctl',
                'dup', 'dup2', 'pause', 'nanosleep', 'getitimer',
                'alarm', 'setitimer', 'getpid', 'sendfile', 'socket',
                'connect', 'accept', 'sendto', 'recvfrom', 'sendmsg',
                'recvmsg', 'shutdown', 'bind', 'listen', 'getsockname',
                'getpeername', 'socketpair', 'setsockopt', 'getsockopt',
                'clone', 'fork', 'vfork', 'execve', 'exit', 'wait4',
                'kill', 'uname', 'semget', 'semop', 'semctl', 'shmdt',
                'msgget', 'msgsnd', 'msgrcv', 'msgctl', 'fcntl', 'flock',
                'fsync', 'fdatasync', 'truncate', 'ftruncate', 'getdents',
                'getcwd', 'chdir', 'fchdir', 'rename', 'mkdir', 'rmdir',
                'creat', 'link', 'unlink', 'symlink', 'readlink', 'chmod',
                'fchmod', 'chown', 'fchown', 'lchown', 'umask', 'gettimeofday',
                'getrlimit', 'getrusage', 'sysinfo', 'times', 'ptrace',
                'getuid', 'syslog', 'getgid', 'setuid', 'setgid', 'geteuid',
                'getegid', 'setpgid', 'getppid', 'getpgrp', 'setsid',
                'setreuid', 'setregid', 'getgroups', 'setgroups', 'setresuid',
                'getresuid', 'setresgid', 'getresgid', 'getpgid', 'setfsuid',
                'setfsgid', 'getsid', 'capget', 'capset', 'rt_sigpending',
                'rt_sigtimedwait', 'rt_sigqueueinfo', 'rt_sigsuspend',
                'sigaltstack', 'utime', 'mknod', 'uselib', 'personality',
                'ustat', 'statfs', 'fstatfs', 'sysfs', 'getpriority',
                'setpriority', 'sched_setparam', 'sched_getparam',
                'sched_setscheduler', 'sched_getscheduler', 'sched_get_priority_max',
                'sched_get_priority_min', 'sched_rr_get_interval', 'mlock',
                'munlock', 'mlockall', 'munlockall', 'vhangup', 'modify_ldt',
                'pivot_root', '_sysctl', 'prctl', 'arch_prctl', 'adjtimex',
                'setrlimit', 'chroot', 'sync', 'acct', 'settimeofday',
                'mount', 'umount2', 'swapon', 'swapoff', 'reboot', 'sethostname',
                'setdomainname', 'iopl', 'ioperm', 'create_module', 'init_module',
                'delete_module', 'get_kernel_syms', 'query_module', 'quotactl',
                'nfsservctl', 'getpmsg', 'putpmsg', 'afs_syscall', 'tuxcall',
                'security', 'gettid', 'readahead', 'setxattr', 'lsetxattr',
                'fsetxattr', 'getxattr', 'lgetxattr', 'fgetxattr', 'listxattr',
                'llistxattr', 'flistxattr', 'removexattr', 'lremovexattr',
                'fremovexattr', 'tkill', 'time', 'futex', 'sched_setaffinity',
                'sched_getaffinity', 'set_thread_area', 'io_setup', 'io_destroy',
                'io_getevents', 'io_submit', 'io_cancel', 'get_thread_area',
                'lookup_dcookie', 'epoll_create', 'epoll_ctl_old', 'epoll_wait_old',
                'remap_file_pages', 'getdents64', 'set_tid_address', 'restart_syscall',
                'semtimedop', 'fadvise64', 'timer_create', 'timer_settime',
                'timer_gettime', 'timer_getoverrun', 'timer_delete', 'clock_settime',
                'clock_gettime', 'clock_getres', 'clock_nanosleep', 'exit_group',
                'epoll_wait', 'epoll_ctl', 'tgkill', 'utimes', 'vserver',
                'mbind', 'set_mempolicy', 'get_mempolicy', 'mq_open', 'mq_unlink',
                'mq_timedsend', 'mq_timedreceive', 'mq_notify', 'mq_getsetattr',
                'kexec_load', 'waitid', 'add_key', 'request_key', 'keyctl',
                'ioprio_set', 'ioprio_get', 'inotify_init', 'inotify_add_watch',
                'inotify_rm_watch', 'migrate_pages', 'openat', 'mkdirat',
                'mknodat', 'fchownat', 'futimesat', 'newfstatat', 'unlinkat',
                'renameat', 'linkat', 'symlinkat', 'readlinkat', 'fchmodat',
                'faccessat', 'pselect6', 'ppoll', 'unshare', 'set_robust_list',
                'get_robust_list', 'splice', 'tee', 'sync_file_range',
                'vmsplice', 'move_pages', 'utimensat', 'epoll_pwait',
                'signalfd', 'timerfd_create', 'eventfd', 'fallocate',
                'timerfd_settime', 'timerfd_gettime', 'accept4', 'signalfd4',
                'eventfd2', 'epoll_create1', 'dup3', 'pipe2', 'inotify_init1',
                'preadv', 'pwritev', 'rt_tgsigqueueinfo', 'perf_event_open',
                'recvmmsg', 'fanotify_init', 'fanotify_mark', 'prlimit64',
                'name_to_handle_at', 'open_by_handle_at', 'clock_adjtime',
                'syncfs', 'sendmmsg', 'setns', 'getcpu', 'process_vm_readv',
                'process_vm_writev', 'kcmp', 'finit_module'
            ]
        
        if self.blocked_paths is None:
            self.blocked_paths = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/proc/sys', '/sys', '/dev', '/boot',
                '/root', '/home', '/var/log', '/tmp'
            ]

class CodeSandbox:
    """
    Secure code execution sandbox with multiple isolation levels
    Provides safe environment for running potentially dangerous code analysis
    """
    
    def __init__(self, config: SandboxConfig = None):
        self.config = config or SandboxConfig()
        self.docker_client = None
        self.active_containers = set()
        self.active_processes = set()
        
        # Initialize Docker client if container sandboxing is enabled
        if self.config.sandbox_type == SandboxType.CONTAINER:
            try:
                self.docker_client = docker.from_env()
                logger.info("Docker client initialized for container sandboxing")
            except Exception as e:
                logger.warning(f"Failed to initialize Docker client: {e}")
                logger.info("Falling back to process sandboxing")
                self.config.sandbox_type = SandboxType.PROCESS
    
    @contextmanager
    def create_sandbox(self, code_content: str, language: str = "python"):
        """Create isolated sandbox environment"""
        if self.config.sandbox_type == SandboxType.CONTAINER:
            with self._create_container_sandbox(code_content, language) as sandbox:
                yield sandbox
        else:
            with self._create_process_sandbox(code_content, language) as sandbox:
                yield sandbox
    
    @contextmanager
    def _create_container_sandbox(self, code_content: str, language: str):
        """Create Docker container sandbox"""
        container = None
        temp_dir = None
        
        try:
            # Create temporary directory for code
            temp_dir = tempfile.mkdtemp(prefix="byteguardx_sandbox_")
            
            # Write code to file
            if language == "python":
                code_file = Path(temp_dir) / "scan_code.py"
                dockerfile_content = """
FROM python:3.9-slim
RUN useradd -m -s /bin/bash sandbox
WORKDIR /app
COPY scan_code.py .
RUN chown sandbox:sandbox scan_code.py
USER sandbox
CMD ["python", "scan_code.py"]
"""
            else:
                raise ValueError(f"Unsupported language for container sandbox: {language}")
            
            code_file.write_text(code_content)
            
            # Create Dockerfile
            dockerfile = Path(temp_dir) / "Dockerfile"
            dockerfile.write_text(dockerfile_content)
            
            # Build image
            image_tag = f"byteguardx-sandbox-{int(time.time())}"
            image, build_logs = self.docker_client.images.build(
                path=str(temp_dir),
                tag=image_tag,
                rm=True
            )
            
            # Create container with resource limits
            container = self.docker_client.containers.create(
                image_tag,
                mem_limit=f"{self.config.max_memory_mb}m",
                cpu_quota=int(self.config.max_cpu_percent * 1000),
                cpu_period=100000,
                network_disabled=not self.config.network_access,
                read_only=True,
                tmpfs={'/tmp': f'size={self.config.temp_dir_size_mb}m'},
                security_opt=['no-new-privileges:true'],
                cap_drop=['ALL'],
                cap_add=['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID']
            )
            
            self.active_containers.add(container.id)
            
            sandbox_info = {
                'type': 'container',
                'container': container,
                'temp_dir': temp_dir,
                'image_tag': image_tag
            }
            
            yield sandbox_info
            
        except Exception as e:
            logger.error(f"Failed to create container sandbox: {e}")
            raise
        finally:
            # Cleanup
            if container:
                try:
                    container.remove(force=True)
                    self.active_containers.discard(container.id)
                except:
                    pass
            
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Remove image
            try:
                if 'image_tag' in locals():
                    self.docker_client.images.remove(image_tag, force=True)
            except:
                pass
    
    @contextmanager
    def _create_process_sandbox(self, code_content: str, language: str):
        """Create process-level sandbox"""
        temp_dir = None
        
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix="byteguardx_sandbox_")
            
            # Write code to file
            if language == "python":
                code_file = Path(temp_dir) / "scan_code.py"
                code_file.write_text(code_content)
            else:
                raise ValueError(f"Unsupported language for process sandbox: {language}")
            
            sandbox_info = {
                'type': 'process',
                'temp_dir': temp_dir,
                'code_file': str(code_file)
            }
            
            yield sandbox_info
            
        except Exception as e:
            logger.error(f"Failed to create process sandbox: {e}")
            raise
        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def execute_in_sandbox(self, sandbox_info: Dict[str, Any], 
                          command: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Execute command in sandbox"""
        if sandbox_info['type'] == 'container':
            return self._execute_in_container(sandbox_info, command, timeout)
        else:
            return self._execute_in_process(sandbox_info, command, timeout)
    
    def _execute_in_container(self, sandbox_info: Dict[str, Any], 
                             command: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Execute command in Docker container"""
        container = sandbox_info['container']
        timeout = timeout or self.config.max_execution_time
        
        try:
            # Start container
            container.start()
            
            # Wait for completion with timeout
            result = container.wait(timeout=timeout)
            exit_code = result['StatusCode']
            
            # Get logs
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')
            
            return exit_code, logs, ""
            
        except docker.errors.ContainerError as e:
            return e.exit_status, "", str(e)
        except Exception as e:
            return -1, "", str(e)

    def _validate_command(self, command: List[str]) -> bool:
        """Validate command for security"""
        if not command or not isinstance(command, list):
            return False

        # Whitelist of allowed executables
        allowed_executables = {
            'python', 'python3', 'python3.8', 'python3.9', 'python3.10', 'python3.11',
            'node', 'nodejs',
            'java', 'javac',
            'gcc', 'g++', 'clang', 'clang++',
            'go', 'rustc',
            'php',
            'ruby',
            'sh', 'bash'  # Only for specific controlled scripts
        }

        executable = command[0]
        if executable not in allowed_executables:
            logger.warning(f"Disallowed executable: {executable}")
            return False

        # Check for dangerous patterns in arguments
        dangerous_patterns = [
            ';', '&&', '||', '|', '>', '<', '`', '$(',
            'rm ', 'del ', 'format ', 'mkfs', 'dd ',
            'wget', 'curl', 'nc ', 'netcat', 'telnet',
            'ssh', 'scp', 'ftp', 'sftp',
            'sudo', 'su ', 'chmod', 'chown',
            'eval', 'exec', 'system', 'popen',
            '../', '..\\', '/etc/', '/proc/', '/sys/',
            'C:\\Windows', 'C:\\System32'
        ]

        command_str = ' '.join(command)
        for pattern in dangerous_patterns:
            if pattern in command_str:
                logger.warning(f"Dangerous pattern detected in command: {pattern}")
                return False

        return True

    def _execute_in_process(self, sandbox_info: Dict[str, Any],
                           command: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Execute command in sandboxed process"""
        timeout = timeout or self.config.max_execution_time

        # Validate command before execution
        if not self._validate_command(command):
            return -1, "", "Command validation failed: unsafe command detected"

        try:
            # Set resource limits
            def set_limits():
                # Memory limit
                resource.setrlimit(resource.RLIMIT_AS, 
                                 (self.config.max_memory_mb * 1024 * 1024, 
                                  self.config.max_memory_mb * 1024 * 1024))
                
                # CPU time limit
                resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
                
                # File size limit
                resource.setrlimit(resource.RLIMIT_FSIZE, 
                                 (self.config.max_file_size_mb * 1024 * 1024,
                                  self.config.max_file_size_mb * 1024 * 1024))
                
                # Number of files limit
                resource.setrlimit(resource.RLIMIT_NOFILE, 
                                 (self.config.max_files, self.config.max_files))
                
                # Disable core dumps
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            
            # Execute with limits and shell=False for security
            process = subprocess.Popen(
                command,
                cwd=sandbox_info['temp_dir'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=set_limits,
                text=True,
                shell=False  # Critical: Never use shell=True
            )
            
            self.active_processes.add(process.pid)
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return process.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return -1, stdout, f"Process timed out after {timeout} seconds"
            finally:
                self.active_processes.discard(process.pid)
                
        except Exception as e:
            return -1, "", str(e)
    
    def scan_code_safely(self, code_content: str, scanner_type: str = "all") -> Dict[str, Any]:
        """Safely scan code in sandbox"""
        try:
            # Create scanner code
            scanner_code = self._generate_scanner_code(code_content, scanner_type)
            
            with self.create_sandbox(scanner_code, "python") as sandbox:
                # Execute scanner
                if sandbox['type'] == 'container':
                    exit_code, output, error = self.execute_in_sandbox(sandbox, [], timeout=300)
                else:
                    command = ["python", sandbox['code_file']]
                    exit_code, output, error = self.execute_in_sandbox(sandbox, command, timeout=300)
                
                if exit_code == 0:
                    # Parse scanner output
                    try:
                        import json
                        results = json.loads(output)
                        return {
                            'success': True,
                            'results': results,
                            'error': None
                        }
                    except json.JSONDecodeError:
                        return {
                            'success': False,
                            'results': None,
                            'error': f"Failed to parse scanner output: {output}"
                        }
                else:
                    return {
                        'success': False,
                        'results': None,
                        'error': f"Scanner failed with exit code {exit_code}: {error}"
                    }
                    
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return {
                'success': False,
                'results': None,
                'error': str(e)
            }
    
    def _generate_scanner_code(self, code_content: str, scanner_type: str) -> str:
        """Generate scanner code for sandbox execution"""
        # This is a simplified scanner - in production would use actual scanner modules
        scanner_template = '''
import json
import re
import sys

def scan_secrets(content):
    """Simple secret scanner"""
    patterns = {
        'api_key': r'api[_-]?key[\\s]*[=:][\\s]*["\']([^"\'\\s]+)["\']',
        'password': r'password[\\s]*[=:][\\s]*["\']([^"\'\\s]+)["\']',
        'token': r'token[\\s]*[=:][\\s]*["\']([^"\'\\s]+)["\']'
    }
    
    findings = []
    lines = content.split('\\n')
    
    for line_num, line in enumerate(lines, 1):
        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': 'secret',
                    'subtype': pattern_name,
                    'line': line_num,
                    'content': line.strip(),
                    'severity': 'high'
                })
    
    return findings

def scan_vulnerabilities(content):
    """Simple vulnerability scanner"""
    patterns = {
        'sql_injection': r'(SELECT|INSERT|UPDATE|DELETE).*\\+.*',
        'command_injection': r'(os\\.system|subprocess\\.call|exec)\\s*\\(',
        'path_traversal': r'\\.\\.[\\/\\\\]'
    }
    
    findings = []
    lines = content.split('\\n')
    
    for line_num, line in enumerate(lines, 1):
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    'type': 'vulnerability',
                    'subtype': pattern_name,
                    'line': line_num,
                    'content': line.strip(),
                    'severity': 'medium'
                })
    
    return findings

# Code to scan
code_content = """''' + code_content.replace('"""', '\\"\\"\\"') + '''"""

# Run scanners
results = {
    'secrets': scan_secrets(code_content),
    'vulnerabilities': scan_vulnerabilities(code_content)
}

# Output results as JSON
print(json.dumps(results, indent=2))
'''
        return scanner_template
    
    def cleanup(self):
        """Cleanup all active sandboxes"""
        # Stop containers
        for container_id in list(self.active_containers):
            try:
                container = self.docker_client.containers.get(container_id)
                container.remove(force=True)
            except:
                pass
        self.active_containers.clear()
        
        # Kill processes
        for pid in list(self.active_processes):
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
        self.active_processes.clear()

# Global sandbox instance
code_sandbox = CodeSandbox()
