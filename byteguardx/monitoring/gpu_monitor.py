"""
GPU/TPU Utilization Monitoring and Fallback System
Monitors GPU availability and performance, provides CPU fallback
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import psutil
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AcceleratorType(Enum):
    """Types of hardware accelerators"""
    CPU = "cpu"
    GPU_NVIDIA = "gpu_nvidia"
    GPU_AMD = "gpu_amd"
    TPU = "tpu"
    INTEL_GPU = "intel_gpu"

class AcceleratorStatus(Enum):
    """Accelerator availability status"""
    AVAILABLE = "available"
    BUSY = "busy"
    ERROR = "error"
    UNAVAILABLE = "unavailable"

@dataclass
class AcceleratorInfo:
    """Information about hardware accelerator"""
    device_id: str
    accelerator_type: AcceleratorType
    name: str
    memory_total: int  # MB
    memory_used: int   # MB
    utilization: float  # 0-100%
    temperature: Optional[float] = None  # Celsius
    power_usage: Optional[float] = None  # Watts
    status: AcceleratorStatus = AcceleratorStatus.AVAILABLE
    last_updated: datetime = None

@dataclass
class AcceleratorMetrics:
    """Performance metrics for accelerator"""
    device_id: str
    timestamp: datetime
    utilization: float
    memory_usage: float
    temperature: Optional[float]
    power_usage: Optional[float]
    inference_time: Optional[float]  # seconds
    throughput: Optional[float]  # inferences/second

class GPUMonitor:
    """
    Comprehensive GPU/TPU monitoring and fallback system
    """
    
    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self.accelerators: Dict[str, AcceleratorInfo] = {}
        self.metrics_history: List[AcceleratorMetrics] = []
        self.fallback_enabled = True
        self.monitoring_active = False
        self._lock = threading.RLock()
        self._monitor_thread = None
        
        # Performance thresholds
        self.thresholds = {
            'max_utilization': 95.0,
            'max_memory_usage': 90.0,
            'max_temperature': 85.0,  # Celsius
            'max_power_usage': 300.0,  # Watts
            'min_available_memory': 1024,  # MB
        }
        
        # Initialize accelerator detection
        self._detect_accelerators()
    
    def _detect_accelerators(self):
        """Detect available hardware accelerators"""
        try:
            # Always add CPU as fallback
            cpu_info = AcceleratorInfo(
                device_id="cpu_0",
                accelerator_type=AcceleratorType.CPU,
                name=f"CPU ({psutil.cpu_count()} cores)",
                memory_total=int(psutil.virtual_memory().total / (1024**2)),
                memory_used=int(psutil.virtual_memory().used / (1024**2)),
                utilization=psutil.cpu_percent(),
                status=AcceleratorStatus.AVAILABLE,
                last_updated=datetime.now()
            )
            self.accelerators["cpu_0"] = cpu_info
            
            # Try to detect NVIDIA GPUs
            self._detect_nvidia_gpus()
            
            # Try to detect AMD GPUs
            self._detect_amd_gpus()
            
            # Try to detect TPUs
            self._detect_tpus()
            
            # Try to detect Intel GPUs
            self._detect_intel_gpus()
            
            logger.info(f"Detected {len(self.accelerators)} accelerators: {list(self.accelerators.keys())}")
            
        except Exception as e:
            logger.error(f"Error detecting accelerators: {e}")
    
    def _detect_nvidia_gpus(self):
        """Detect NVIDIA GPUs using nvidia-ml-py"""
        try:
            import pynvml
            pynvml.nvmlInit()
            
            device_count = pynvml.nvmlDeviceGetCount()
            for i in range(device_count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                name = pynvml.nvmlDeviceGetName(handle).decode('utf-8')
                
                # Get memory info
                mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                memory_total = int(mem_info.total / (1024**2))
                memory_used = int(mem_info.used / (1024**2))
                
                # Get utilization
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                utilization = float(util.gpu)
                
                # Get temperature
                try:
                    temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
                except:
                    temp = None
                
                # Get power usage
                try:
                    power = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0  # Convert to watts
                except:
                    power = None
                
                gpu_info = AcceleratorInfo(
                    device_id=f"gpu_{i}",
                    accelerator_type=AcceleratorType.GPU_NVIDIA,
                    name=name,
                    memory_total=memory_total,
                    memory_used=memory_used,
                    utilization=utilization,
                    temperature=temp,
                    power_usage=power,
                    status=AcceleratorStatus.AVAILABLE,
                    last_updated=datetime.now()
                )
                
                self.accelerators[f"gpu_{i}"] = gpu_info
                
        except ImportError:
            logger.debug("pynvml not available, skipping NVIDIA GPU detection")
        except Exception as e:
            logger.warning(f"Error detecting NVIDIA GPUs: {e}")
    
    def _detect_amd_gpus(self):
        """Detect AMD GPUs"""
        try:
            # AMD GPU detection would go here
            # This is a placeholder for future implementation
            pass
        except Exception as e:
            logger.warning(f"Error detecting AMD GPUs: {e}")
    
    def _detect_tpus(self):
        """Detect TPUs"""
        try:
            # TPU detection would go here
            # This is a placeholder for future implementation
            pass
        except Exception as e:
            logger.warning(f"Error detecting TPUs: {e}")
    
    def _detect_intel_gpus(self):
        """Detect Intel GPUs"""
        try:
            # Intel GPU detection would go here
            # This is a placeholder for future implementation
            pass
        except Exception as e:
            logger.warning(f"Error detecting Intel GPUs: {e}")
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("GPU monitoring started")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("GPU monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._update_accelerator_status()
                self._record_metrics()
                self._check_health()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.check_interval)
    
    def _update_accelerator_status(self):
        """Update status of all accelerators"""
        with self._lock:
            for device_id, accelerator in self.accelerators.items():
                try:
                    if accelerator.accelerator_type == AcceleratorType.CPU:
                        self._update_cpu_status(accelerator)
                    elif accelerator.accelerator_type == AcceleratorType.GPU_NVIDIA:
                        self._update_nvidia_gpu_status(accelerator)
                    # Add other accelerator types as needed
                    
                    accelerator.last_updated = datetime.now()
                    
                except Exception as e:
                    logger.error(f"Error updating {device_id} status: {e}")
                    accelerator.status = AcceleratorStatus.ERROR
    
    def _update_cpu_status(self, cpu_info: AcceleratorInfo):
        """Update CPU status"""
        cpu_info.utilization = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        cpu_info.memory_total = int(memory.total / (1024**2))
        cpu_info.memory_used = int(memory.used / (1024**2))
        cpu_info.status = AcceleratorStatus.AVAILABLE
    
    def _update_nvidia_gpu_status(self, gpu_info: AcceleratorInfo):
        """Update NVIDIA GPU status"""
        try:
            import pynvml
            device_index = int(gpu_info.device_id.split('_')[1])
            handle = pynvml.nvmlDeviceGetHandleByIndex(device_index)
            
            # Update memory info
            mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            gpu_info.memory_total = int(mem_info.total / (1024**2))
            gpu_info.memory_used = int(mem_info.used / (1024**2))
            
            # Update utilization
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            gpu_info.utilization = float(util.gpu)
            
            # Update temperature
            try:
                gpu_info.temperature = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
            except:
                pass
            
            # Update power usage
            try:
                gpu_info.power_usage = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
            except:
                pass
            
            # Determine status
            if gpu_info.utilization > self.thresholds['max_utilization']:
                gpu_info.status = AcceleratorStatus.BUSY
            elif gpu_info.temperature and gpu_info.temperature > self.thresholds['max_temperature']:
                gpu_info.status = AcceleratorStatus.ERROR
            else:
                gpu_info.status = AcceleratorStatus.AVAILABLE
                
        except Exception as e:
            logger.error(f"Error updating NVIDIA GPU status: {e}")
            gpu_info.status = AcceleratorStatus.ERROR

    def _record_metrics(self):
        """Record performance metrics"""
        with self._lock:
            for device_id, accelerator in self.accelerators.items():
                metrics = AcceleratorMetrics(
                    device_id=device_id,
                    timestamp=datetime.now(),
                    utilization=accelerator.utilization,
                    memory_usage=(accelerator.memory_used / accelerator.memory_total) * 100,
                    temperature=accelerator.temperature,
                    power_usage=accelerator.power_usage,
                    inference_time=None,  # Set during inference
                    throughput=None  # Set during inference
                )

                self.metrics_history.append(metrics)

                # Keep only last 1000 metrics per device
                if len(self.metrics_history) > 1000 * len(self.accelerators):
                    self.metrics_history = self.metrics_history[-1000 * len(self.accelerators):]

    def _check_health(self):
        """Check accelerator health and update status"""
        with self._lock:
            for device_id, accelerator in self.accelerators.items():
                # Check temperature
                if accelerator.temperature and accelerator.temperature > self.thresholds['max_temperature']:
                    logger.warning(f"High temperature on {device_id}: {accelerator.temperature}°C")
                    accelerator.status = AcceleratorStatus.ERROR

                # Check memory usage
                memory_usage_pct = (accelerator.memory_used / accelerator.memory_total) * 100
                if memory_usage_pct > self.thresholds['max_memory_usage']:
                    logger.warning(f"High memory usage on {device_id}: {memory_usage_pct:.1f}%")

                # Check available memory
                available_memory = accelerator.memory_total - accelerator.memory_used
                if available_memory < self.thresholds['min_available_memory']:
                    logger.warning(f"Low available memory on {device_id}: {available_memory}MB")

    def get_best_accelerator(self, memory_required: int = 0,
                           preferred_types: List[AcceleratorType] = None) -> Optional[AcceleratorInfo]:
        """
        Get the best available accelerator for a task

        Args:
            memory_required: Minimum memory required in MB
            preferred_types: List of preferred accelerator types

        Returns:
            Best available accelerator or None
        """
        with self._lock:
            available_accelerators = [
                acc for acc in self.accelerators.values()
                if acc.status == AcceleratorStatus.AVAILABLE
                and (acc.memory_total - acc.memory_used) >= memory_required
            ]

            if not available_accelerators:
                return None

            # Filter by preferred types if specified
            if preferred_types:
                preferred_accelerators = [
                    acc for acc in available_accelerators
                    if acc.accelerator_type in preferred_types
                ]
                if preferred_accelerators:
                    available_accelerators = preferred_accelerators

            # Sort by preference: GPU > TPU > CPU, then by available memory
            def sort_key(acc):
                type_priority = {
                    AcceleratorType.GPU_NVIDIA: 0,
                    AcceleratorType.GPU_AMD: 1,
                    AcceleratorType.TPU: 2,
                    AcceleratorType.INTEL_GPU: 3,
                    AcceleratorType.CPU: 4
                }
                available_memory = acc.memory_total - acc.memory_used
                return (type_priority.get(acc.accelerator_type, 99), -available_memory)

            available_accelerators.sort(key=sort_key)
            return available_accelerators[0]

    def get_accelerator_info(self, device_id: str) -> Optional[AcceleratorInfo]:
        """Get information about specific accelerator"""
        with self._lock:
            return self.accelerators.get(device_id)

    def get_all_accelerators(self) -> Dict[str, AcceleratorInfo]:
        """Get information about all accelerators"""
        with self._lock:
            return self.accelerators.copy()

    def get_metrics_history(self, device_id: str = None,
                          hours: int = 1) -> List[AcceleratorMetrics]:
        """Get metrics history for accelerator(s)"""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        with self._lock:
            filtered_metrics = [
                m for m in self.metrics_history
                if m.timestamp >= cutoff_time
                and (device_id is None or m.device_id == device_id)
            ]

            return sorted(filtered_metrics, key=lambda x: x.timestamp)

    def record_inference_metrics(self, device_id: str, inference_time: float,
                               throughput: float = None):
        """Record inference performance metrics"""
        with self._lock:
            accelerator = self.accelerators.get(device_id)
            if not accelerator:
                return

            metrics = AcceleratorMetrics(
                device_id=device_id,
                timestamp=datetime.now(),
                utilization=accelerator.utilization,
                memory_usage=(accelerator.memory_used / accelerator.memory_total) * 100,
                temperature=accelerator.temperature,
                power_usage=accelerator.power_usage,
                inference_time=inference_time,
                throughput=throughput
            )

            self.metrics_history.append(metrics)

    def should_fallback_to_cpu(self, device_id: str = None) -> bool:
        """Check if should fallback to CPU"""
        if not self.fallback_enabled:
            return False

        with self._lock:
            if device_id:
                accelerator = self.accelerators.get(device_id)
                if not accelerator:
                    return True
                return accelerator.status != AcceleratorStatus.AVAILABLE
            else:
                # Check if any GPU is available
                gpu_available = any(
                    acc.status == AcceleratorStatus.AVAILABLE
                    for acc in self.accelerators.values()
                    if acc.accelerator_type in [AcceleratorType.GPU_NVIDIA, AcceleratorType.GPU_AMD]
                )
                return not gpu_available

    def get_status_summary(self) -> Dict[str, Any]:
        """Get summary of accelerator status"""
        with self._lock:
            summary = {
                'total_accelerators': len(self.accelerators),
                'available_accelerators': 0,
                'busy_accelerators': 0,
                'error_accelerators': 0,
                'accelerator_types': {},
                'total_memory': 0,
                'used_memory': 0,
                'monitoring_active': self.monitoring_active
            }

            for accelerator in self.accelerators.values():
                if accelerator.status == AcceleratorStatus.AVAILABLE:
                    summary['available_accelerators'] += 1
                elif accelerator.status == AcceleratorStatus.BUSY:
                    summary['busy_accelerators'] += 1
                elif accelerator.status == AcceleratorStatus.ERROR:
                    summary['error_accelerators'] += 1

                acc_type = accelerator.accelerator_type.value
                if acc_type not in summary['accelerator_types']:
                    summary['accelerator_types'][acc_type] = 0
                summary['accelerator_types'][acc_type] += 1

                summary['total_memory'] += accelerator.memory_total
                summary['used_memory'] += accelerator.memory_used

            summary['memory_usage_percent'] = (
                (summary['used_memory'] / summary['total_memory']) * 100
                if summary['total_memory'] > 0 else 0
            )

            return summary

# Global instance
gpu_monitor = GPUMonitor()
