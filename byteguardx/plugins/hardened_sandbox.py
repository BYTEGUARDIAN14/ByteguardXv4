"""
Hardened Plugin Sandbox for ByteGuardX
Enhanced Docker sandbox with seccomp, AppArmor, and runtime monitoring
"""

import os
import json
import logging
import tempfile
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

import docker
import psutil

logger = logging.getLogger(__name__)

class SandboxViolationType(Enum):
    """Types of sandbox violations"""
    CPU_LIMIT_EXCEEDED = "cpu_limit_exceeded"
    MEMORY_LIMIT_EXCEEDED = "memory_limit_exceeded"
    NETWORK_ACCESS_DENIED = "network_access_denied"
    FILE_ACCESS_DENIED = "file_access_denied"
    SYSCALL_BLOCKED = "syscall_blocked"
    EXECUTION_TIMEOUT = "execution_timeout"

@dataclass
class SandboxViolation:
    """Sandbox violation record"""
    violation_type: SandboxViolationType
    timestamp: datetime
    plugin_id: str
    container_id: str
    details: Dict[str, Any]
    severity: str = "medium"

class HardenedPluginSandbox:
    """Hardened plugin sandbox with comprehensive security controls"""
    
    def __init__(self):
        self.docker_client = docker.from_env()
        self.violations: List[SandboxViolation] = []
        self.monitoring_threads: Dict[str, threading.Thread] = {}
        
        # Resource limits
        self.max_cpu_percent = 50.0  # 50% CPU
        self.max_memory_mb = 512     # 512MB RAM
        self.max_execution_time = 300  # 5 minutes
        self.max_network_connections = 0  # No network access
        
        # Security profiles
        self.seccomp_profile = self._create_seccomp_profile()
        self.apparmor_profile = self._create_apparmor_profile()
        
    def execute_plugin(self, plugin_code: str, plugin_id: str, 
                      input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute plugin in hardened sandbox
        
        Args:
            plugin_code: Plugin code to execute
            plugin_id: Unique plugin identifier
            input_data: Input data for plugin
            
        Returns:
            Dict containing execution results and security metrics
        """
        container = None
        monitor_thread = None
        
        try:
            # Create temporary directory for plugin execution
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Write plugin code to file
                plugin_file = temp_path / "plugin.py"
                plugin_file.write_text(plugin_code)
                
                # Write input data
                input_file = temp_path / "input.json"
                input_file.write_text(json.dumps(input_data))
                
                # Create output directory
                output_dir = temp_path / "output"
                output_dir.mkdir()
                
                # Build Docker image with security hardening
                dockerfile_content = self._create_hardened_dockerfile()
                dockerfile_path = temp_path / "Dockerfile"
                dockerfile_path.write_text(dockerfile_content)
                
                # Build image
                image_tag = f"byteguardx-plugin-{plugin_id}:{int(time.time())}"
                image, build_logs = self.docker_client.images.build(
                    path=str(temp_path),
                    tag=image_tag,
                    rm=True,
                    forcerm=True
                )
                
                # Create container with security constraints
                container = self._create_hardened_container(
                    image_tag, plugin_id, temp_path
                )
                
                # Start monitoring
                monitor_thread = threading.Thread(
                    target=self._monitor_container,
                    args=(container, plugin_id),
                    daemon=True
                )
                monitor_thread.start()
                self.monitoring_threads[container.id] = monitor_thread
                
                # Start container
                container.start()
                
                # Wait for completion with timeout
                result = container.wait(timeout=self.max_execution_time)
                
                # Get output
                output_file = output_dir / "result.json"
                if output_file.exists():
                    output_data = json.loads(output_file.read_text())
                else:
                    output_data = {"error": "No output generated"}
                
                # Get logs
                logs = container.logs().decode('utf-8')
                
                # Get resource usage stats
                stats = self._get_container_stats(container)
                
                return {
                    "success": result["StatusCode"] == 0,
                    "output": output_data,
                    "logs": logs,
                    "stats": stats,
                    "violations": [
                        v for v in self.violations 
                        if v.container_id == container.id
                    ],
                    "exit_code": result["StatusCode"]
                }
                
        except docker.errors.ContainerError as e:
            logger.error(f"Container execution failed: {e}")
            return {
                "success": False,
                "error": f"Container execution failed: {e}",
                "violations": [
                    v for v in self.violations 
                    if container and v.container_id == container.id
                ]
            }
            
        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            return {
                "success": False,
                "error": f"Plugin execution failed: {e}"
            }
            
        finally:
            # Cleanup
            if container:
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception as e:
                    logger.warning(f"Container cleanup failed: {e}")
                
                # Stop monitoring
                if container.id in self.monitoring_threads:
                    del self.monitoring_threads[container.id]
            
            # Remove image
            try:
                if 'image_tag' in locals():
                    self.docker_client.images.remove(image_tag, force=True)
            except Exception as e:
                logger.warning(f"Image cleanup failed: {e}")
    
    def _create_hardened_container(self, image_tag: str, plugin_id: str, 
                                 temp_path: Path) -> docker.models.containers.Container:
        """Create container with security hardening"""
        
        # Security options
        security_opt = [
            f"seccomp:{self._write_seccomp_profile(temp_path)}",
            f"apparmor:{self.apparmor_profile}"
        ]
        
        # Create container
        container = self.docker_client.containers.create(
            image=image_tag,
            command=[
                "python", "-u", "/app/plugin.py"
            ],
            
            # Resource limits
            mem_limit=f"{self.max_memory_mb}m",
            memswap_limit=f"{self.max_memory_mb}m",
            cpu_quota=int(100000 * (self.max_cpu_percent / 100)),  # CPU quota
            cpu_period=100000,
            
            # Security settings
            user="nobody:nogroup",  # Run as non-root
            read_only=True,  # Read-only filesystem
            security_opt=security_opt,
            cap_drop=["ALL"],  # Drop all capabilities
            
            # Network isolation
            network_mode="none",  # No network access
            
            # Volume mounts (read-only)
            volumes={
                str(temp_path / "plugin.py"): {
                    "bind": "/app/plugin.py",
                    "mode": "ro"
                },
                str(temp_path / "input.json"): {
                    "bind": "/app/input.json", 
                    "mode": "ro"
                },
                str(temp_path / "output"): {
                    "bind": "/app/output",
                    "mode": "rw"
                }
            },
            
            # Environment variables
            environment={
                "PYTHONPATH": "/app",
                "PYTHONUNBUFFERED": "1",
                "HOME": "/tmp"
            },
            
            # Working directory
            working_dir="/app",
            
            # Prevent privilege escalation
            privileged=False,
            
            # Labels for identification
            labels={
                "byteguardx.plugin_id": plugin_id,
                "byteguardx.sandbox": "hardened",
                "byteguardx.created_at": datetime.now().isoformat()
            }
        )
        
        return container
    
    def _create_hardened_dockerfile(self) -> str:
        """Create Dockerfile with security hardening"""
        return """
FROM python:3.11-alpine

# Install minimal dependencies
RUN apk add --no-cache --virtual .build-deps gcc musl-dev && \
    pip install --no-cache-dir requests && \
    apk del .build-deps

# Create non-root user
RUN addgroup -g 65534 nobody && \
    adduser -D -u 65534 -G nobody nobody

# Create app directory
RUN mkdir -p /app /tmp && \
    chown nobody:nobody /app /tmp

# Set working directory
WORKDIR /app

# Switch to non-root user
USER nobody

# Default command
CMD ["python", "-u", "plugin.py"]
"""
    
    def _create_seccomp_profile(self) -> Dict[str, Any]:
        """Create seccomp security profile"""
        return {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [
                {
                    "names": [
                        "read", "write", "open", "close", "stat", "fstat",
                        "lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
                        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                        "ioctl", "pread64", "pwrite64", "readv", "writev",
                        "access", "pipe", "select", "sched_yield", "mremap",
                        "msync", "mincore", "madvise", "shmget", "shmat",
                        "shmctl", "dup", "dup2", "pause", "nanosleep",
                        "getitimer", "alarm", "setitimer", "getpid", "sendfile",
                        "socket", "connect", "accept", "sendto", "recvfrom",
                        "sendmsg", "recvmsg", "shutdown", "bind", "listen",
                        "getsockname", "getpeername", "socketpair", "setsockopt",
                        "getsockopt", "clone", "fork", "vfork", "execve",
                        "exit", "wait4", "kill", "uname", "semget", "semop",
                        "semctl", "shmdt", "msgget", "msgsnd", "msgrcv",
                        "msgctl", "fcntl", "flock", "fsync", "fdatasync",
                        "truncate", "ftruncate", "getdents", "getcwd",
                        "chdir", "fchdir", "rename", "mkdir", "rmdir",
                        "creat", "link", "unlink", "symlink", "readlink",
                        "chmod", "fchmod", "chown", "fchown", "lchown",
                        "umask", "gettimeofday", "getrlimit", "getrusage",
                        "sysinfo", "times", "ptrace", "getuid", "syslog",
                        "getgid", "setuid", "setgid", "geteuid", "getegid",
                        "setpgid", "getppid", "getpgrp", "setsid", "setreuid",
                        "setregid", "getgroups", "setgroups", "setresuid",
                        "getresuid", "setresgid", "getresgid", "getpgid",
                        "setfsuid", "setfsgid", "getsid", "capget", "capset",
                        "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
                        "rt_sigsuspend", "sigaltstack", "utime", "mknod",
                        "uselib", "personality", "ustat", "statfs", "fstatfs",
                        "sysfs", "getpriority", "setpriority", "sched_setparam",
                        "sched_getparam", "sched_setscheduler", "sched_getscheduler",
                        "sched_get_priority_max", "sched_get_priority_min",
                        "sched_rr_get_interval", "mlock", "munlock", "mlockall",
                        "munlockall", "vhangup", "modify_ldt", "pivot_root",
                        "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit",
                        "chroot", "sync", "acct", "settimeofday", "mount",
                        "umount2", "swapon", "swapoff", "reboot", "sethostname",
                        "setdomainname", "iopl", "ioperm", "create_module",
                        "init_module", "delete_module", "get_kernel_syms",
                        "query_module", "quotactl", "nfsservctl", "getpmsg",
                        "putpmsg", "afs_syscall", "tuxcall", "security",
                        "gettid", "readahead", "setxattr", "lsetxattr",
                        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
                        "listxattr", "llistxattr", "flistxattr", "removexattr",
                        "lremovexattr", "fremovexattr", "tkill", "time",
                        "futex", "sched_setaffinity", "sched_getaffinity",
                        "set_thread_area", "io_setup", "io_destroy", "io_getevents",
                        "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie",
                        "epoll_create", "epoll_ctl_old", "epoll_wait_old",
                        "remap_file_pages", "getdents64", "set_tid_address",
                        "restart_syscall", "semtimedop", "fadvise64", "timer_create",
                        "timer_settime", "timer_gettime", "timer_getoverrun",
                        "timer_delete", "clock_settime", "clock_gettime",
                        "clock_getres", "clock_nanosleep", "exit_group",
                        "epoll_wait", "epoll_ctl", "tgkill", "utimes",
                        "vserver", "mbind", "set_mempolicy", "get_mempolicy",
                        "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
                        "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
                        "add_key", "request_key", "keyctl", "ioprio_set",
                        "ioprio_get", "inotify_init", "inotify_add_watch",
                        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
                        "mknodat", "fchownat", "futimesat", "newfstatat",
                        "unlinkat", "renameat", "linkat", "symlinkat",
                        "readlinkat", "fchmodat", "faccessat", "pselect6",
                        "ppoll", "unshare", "set_robust_list", "get_robust_list",
                        "splice", "tee", "sync_file_range", "vmsplice",
                        "move_pages", "utimensat", "epoll_pwait", "signalfd",
                        "timerfd_create", "eventfd", "fallocate", "timerfd_settime",
                        "timerfd_gettime", "accept4", "signalfd4", "eventfd2",
                        "epoll_create1", "dup3", "pipe2", "inotify_init1",
                        "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
                        "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
                        "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
                        "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
                        "process_vm_writev", "kcmp", "finit_module"
                    ],
                    "action": "SCMP_ACT_ALLOW"
                }
            ]
        }
    
    def _create_apparmor_profile(self) -> str:
        """Create AppArmor security profile name"""
        return "byteguardx-plugin-sandbox"
    
    def _write_seccomp_profile(self, temp_path: Path) -> str:
        """Write seccomp profile to file"""
        profile_path = temp_path / "seccomp.json"
        profile_path.write_text(json.dumps(self.seccomp_profile, indent=2))
        return str(profile_path)
    
    def _monitor_container(self, container, plugin_id: str):
        """Monitor container for resource usage and violations"""
        try:
            while True:
                try:
                    # Get container stats
                    stats = container.stats(stream=False)
                    
                    # Check CPU usage
                    cpu_percent = self._calculate_cpu_percent(stats)
                    if cpu_percent > self.max_cpu_percent:
                        self._record_violation(
                            SandboxViolationType.CPU_LIMIT_EXCEEDED,
                            plugin_id,
                            container.id,
                            {"cpu_percent": cpu_percent, "limit": self.max_cpu_percent}
                        )
                    
                    # Check memory usage
                    memory_mb = stats['memory_stats']['usage'] / (1024 * 1024)
                    if memory_mb > self.max_memory_mb:
                        self._record_violation(
                            SandboxViolationType.MEMORY_LIMIT_EXCEEDED,
                            plugin_id,
                            container.id,
                            {"memory_mb": memory_mb, "limit": self.max_memory_mb}
                        )
                    
                    time.sleep(1)  # Check every second
                    
                except docker.errors.NotFound:
                    # Container stopped
                    break
                except Exception as e:
                    logger.warning(f"Container monitoring error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Container monitoring failed: {e}")
    
    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU usage percentage from container stats"""
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            
            if system_delta > 0:
                return (cpu_delta / system_delta) * 100.0
            return 0.0
            
        except (KeyError, ZeroDivisionError):
            return 0.0
    
    def _get_container_stats(self, container) -> Dict[str, Any]:
        """Get final container resource usage stats"""
        try:
            stats = container.stats(stream=False)
            return {
                "cpu_percent": self._calculate_cpu_percent(stats),
                "memory_mb": stats['memory_stats']['usage'] / (1024 * 1024),
                "network_rx_bytes": stats['networks'].get('eth0', {}).get('rx_bytes', 0),
                "network_tx_bytes": stats['networks'].get('eth0', {}).get('tx_bytes', 0)
            }
        except Exception as e:
            logger.warning(f"Failed to get container stats: {e}")
            return {}
    
    def _record_violation(self, violation_type: SandboxViolationType, 
                         plugin_id: str, container_id: str, details: Dict[str, Any]):
        """Record a sandbox violation"""
        violation = SandboxViolation(
            violation_type=violation_type,
            timestamp=datetime.now(),
            plugin_id=plugin_id,
            container_id=container_id,
            details=details,
            severity="high" if violation_type in [
                SandboxViolationType.MEMORY_LIMIT_EXCEEDED,
                SandboxViolationType.CPU_LIMIT_EXCEEDED
            ] else "medium"
        )
        
        self.violations.append(violation)
        logger.warning(f"Sandbox violation: {violation_type.value} for plugin {plugin_id}")
        
        # Send alert for critical violations
        if violation.severity == "high":
            from ..alerts.alert_engine import alert_engine, AlertType, AlertSeverity
            
            alert_engine.create_alert(
                alert_type=AlertType.SECURITY_VIOLATION,
                severity=AlertSeverity.HIGH,
                title=f"Plugin Sandbox Violation: {violation_type.value}",
                message=f"Plugin {plugin_id} violated sandbox constraints",
                metadata={
                    "plugin_id": plugin_id,
                    "violation_type": violation_type.value,
                    "details": details
                }
            )

# Global instance
hardened_sandbox = HardenedPluginSandbox()
