"""
Next-Generation Isolation with Landlock LSM + eBPF
Zero-trust plugin framework with runtime security monitoring
"""

import os
import ctypes
import logging
import json
import time
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import subprocess
import tempfile
from pathlib import Path

class Capability(Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    NETWORK_ACCESS = "network_access"
    PROCESS_SPAWN = "process_spawn"
    SYSTEM_INFO = "system_info"

@dataclass
class DigitalSignature:
    signature: bytes
    public_key: bytes
    algorithm: str
    timestamp: float
    
@dataclass
class IsolationContext:
    allowed_paths: Set[str]
    denied_paths: Set[str]
    capabilities: Set[Capability]
    memory_limit: int
    cpu_limit: float
    network_policy: Dict[str, Any]

@dataclass
class PluginAuthority:
    signature: DigitalSignature
    capabilities: List[Capability]
    revocation_list: Set[str]
    execution_context: IsolationContext
    trust_level: float

class LandlockSandbox:
    """Advanced Landlock LSM integration"""
    
    def __init__(self):
        self.landlock_available = self._check_landlock_support()
        self.landlock_abi_version = self._get_abi_version()
        
    def _check_landlock_support(self) -> bool:
        """Check comprehensive Landlock support"""
        try:
            # Check kernel support
            if not os.path.exists('/proc/sys/kernel/landlock'):
                return False
            
            # Check syscall availability
            result = subprocess.run(['getconf', '_SC_LANDLOCK'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logging.warning(f"Landlock support check failed: {e}")
            return False
    
    def _get_abi_version(self) -> int:
        """Get Landlock ABI version"""
        try:
            with open('/proc/sys/kernel/landlock/abi', 'r') as f:
                return int(f.read().strip())
        except:
            return 1  # Fallback to version 1
    
    def create_landlock_ruleset(self, context: IsolationContext) -> Dict[str, Any]:
        """Create comprehensive Landlock ruleset"""
        ruleset = {
            'version': self.landlock_abi_version,
            'filesystem_rules': [],
            'network_rules': [],
            'capabilities': []
        }
        
        # Filesystem access rules
        for path in context.allowed_paths:
            rule = {
                'path': path,
                'access': self._determine_access_rights(path, context.capabilities)
            }
            ruleset['filesystem_rules'].append(rule)
        
        # Network access rules
        if Capability.NETWORK_ACCESS in context.capabilities:
            ruleset['network_rules'] = context.network_policy.get('rules', [])
        else:
            ruleset['network_rules'] = [{'action': 'deny', 'target': 'all'}]
        
        return ruleset
    
    def _determine_access_rights(self, path: str, capabilities: Set[Capability]) -> List[str]:
        """Determine filesystem access rights for path"""
        rights = []
        
        if Capability.READ_FILE in capabilities:
            rights.extend(['read_file', 'read_dir'])
        
        if Capability.WRITE_FILE in capabilities:
            # Restrict write access to specific directories
            if any(allowed in path for allowed in ['/tmp/', '/var/tmp/', '/workspace/']):
                rights.extend(['write_file', 'make_dir', 'remove_file'])
        
        return rights
    
    async def apply_landlock_restrictions(self, pid: int, ruleset: Dict[str, Any]) -> bool:
        """Apply Landlock restrictions to process"""
        try:
            # Create temporary ruleset file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(ruleset, f)
                ruleset_file = f.name
            
            # Apply restrictions using landlock utility
            cmd = [
                'landlock-restrict',
                '--pid', str(pid),
                '--ruleset', ruleset_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Cleanup
            os.unlink(ruleset_file)
            
            if result.returncode == 0:
                logging.info(f"Landlock restrictions applied to PID {pid}")
                return True
            else:
                logging.error(f"Landlock restriction failed: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Landlock application error: {e}")
            return False

class eBPFSecurityMonitor:
    """eBPF-based runtime security monitoring"""
    
    def __init__(self):
        self.ebpf_available = self._check_ebpf_support()
        self.monitoring_programs: Dict[str, Any] = {}
        self.security_events: List[Dict[str, Any]] = []
        
    def _check_ebpf_support(self) -> bool:
        """Check eBPF support and capabilities"""
        try:
            # Check if BPF syscall is available
            result = subprocess.run(['bpftool', 'prog', 'list'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    async def deploy_security_monitors(self, plugin_id: str, context: IsolationContext) -> bool:
        """Deploy eBPF programs for security monitoring"""
        if not self.ebpf_available:
            logging.warning("eBPF not available, using fallback monitoring")
            return False
        
        try:
            # System call monitoring program
            syscall_monitor = await self._create_syscall_monitor(plugin_id, context)
            
            # Network activity monitor
            network_monitor = await self._create_network_monitor(plugin_id, context)
            
            # File access monitor
            file_monitor = await self._create_file_monitor(plugin_id, context)
            
            # Memory access monitor
            memory_monitor = await self._create_memory_monitor(plugin_id, context)
            
            self.monitoring_programs[plugin_id] = {
                'syscall': syscall_monitor,
                'network': network_monitor,
                'file': file_monitor,
                'memory': memory_monitor
            }
            
            return True
            
        except Exception as e:
            logging.error(f"eBPF monitor deployment failed: {e}")
            return False
    
    async def _create_syscall_monitor(self, plugin_id: str, context: IsolationContext) -> str:
        """Create eBPF program for syscall monitoring"""
        # eBPF C code for syscall monitoring
        ebpf_code = f"""
        #include <linux/bpf.h>
        #include <linux/ptrace.h>
        #include <bpf/bpf_helpers.h>
        
        struct syscall_event {{
            u32 pid;
            u32 syscall_nr;
            u64 timestamp;
            char plugin_id[64];
        }};
        
        struct {{
            __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
            __uint(key_size, sizeof(u32));
            __uint(value_size, sizeof(u32));
        }} events SEC(".maps");
        
        SEC("tracepoint/raw_syscalls/sys_enter")
        int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {{
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            
            // Filter for our plugin process
            if (pid != {plugin_id}) {{
                return 0;
            }}
            
            struct syscall_event event = {{}};
            event.pid = pid;
            event.syscall_nr = ctx->id;
            event.timestamp = bpf_ktime_get_ns();
            bpf_probe_read_str(event.plugin_id, sizeof(event.plugin_id), "{plugin_id}");
            
            // Check against allowed syscalls
            if (!is_syscall_allowed(ctx->id)) {{
                // Log security violation
                bpf_perf_event_output(ctx, &events, BPF_F