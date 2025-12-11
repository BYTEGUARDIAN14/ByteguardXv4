/**
 * Performance Monitor Component
 * Real-time performance monitoring with Core Web Vitals tracking
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Activity, 
  Zap, 
  Clock, 
  Eye, 
  Cpu, 
  MemoryStick,
  Wifi,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  TrendingDown
} from 'lucide-react';
import { QuantumGlassCard } from '../advanced/QuantumGlassmorphism';

const PerformanceMonitor = () => {
  const [isVisible, setIsVisible] = useState(false);
  const [metrics, setMetrics] = useState({
    fps: 0,
    memory: { used: 0, total: 0 },
    loadTime: 0,
    cls: 0,
    fid: 0,
    lcp: 0,
    fcp: 0,
    ttfb: 0,
    networkSpeed: 'unknown',
    renderTime: 0
  });
  
  const [alerts, setAlerts] = useState([]);
  const frameCountRef = useRef(0);
  const lastTimeRef = useRef(performance.now());
  const animationFrameRef = useRef();

  // Performance thresholds
  const thresholds = {
    fps: { good: 55, poor: 30 },
    memory: { good: 50, poor: 80 }, // percentage
    lcp: { good: 2500, poor: 4000 }, // ms
    fid: { good: 100, poor: 300 }, // ms
    cls: { good: 0.1, poor: 0.25 },
    fcp: { good: 1800, poor: 3000 }, // ms
    ttfb: { good: 800, poor: 1800 } // ms
  };

  useEffect(() => {
    initializePerformanceMonitoring();
    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, []);

  const initializePerformanceMonitoring = () => {
    // Monitor FPS
    measureFPS();
    
    // Monitor memory usage
    if ('memory' in performance) {
      monitorMemory();
    }
    
    // Monitor Core Web Vitals
    monitorWebVitals();
    
    // Monitor network speed
    monitorNetworkSpeed();
    
    // Monitor render performance
    monitorRenderPerformance();
  };

  const measureFPS = () => {
    const measure = (currentTime) => {
      frameCountRef.current++;
      
      if (currentTime - lastTimeRef.current >= 1000) {
        const fps = Math.round((frameCountRef.current * 1000) / (currentTime - lastTimeRef.current));
        
        setMetrics(prev => ({ ...prev, fps }));
        
        // Check for performance issues
        if (fps < thresholds.fps.poor) {
          addAlert('Low FPS detected', `Current FPS: ${fps}`, 'warning');
        }
        
        frameCountRef.current = 0;
        lastTimeRef.current = currentTime;
      }
      
      animationFrameRef.current = requestAnimationFrame(measure);
    };
    
    animationFrameRef.current = requestAnimationFrame(measure);
  };

  const monitorMemory = () => {
    const updateMemory = () => {
      if ('memory' in performance) {
        const memory = performance.memory;
        const used = Math.round(memory.usedJSHeapSize / 1024 / 1024);
        const total = Math.round(memory.totalJSHeapSize / 1024 / 1024);
        const percentage = Math.round((used / total) * 100);
        
        setMetrics(prev => ({ 
          ...prev, 
          memory: { used, total, percentage } 
        }));
        
        if (percentage > thresholds.memory.poor) {
          addAlert('High memory usage', `Memory usage: ${percentage}%`, 'error');
        }
      }
    };
    
    updateMemory();
    setInterval(updateMemory, 5000);
  };

  const monitorWebVitals = () => {
    // Use web-vitals library if available
    if (typeof window !== 'undefined') {
      import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
        getCLS((metric) => {
          setMetrics(prev => ({ ...prev, cls: metric.value }));
          if (metric.value > thresholds.cls.poor) {
            addAlert('Poor CLS score', `CLS: ${metric.value.toFixed(3)}`, 'warning');
          }
        });
        
        getFID((metric) => {
          setMetrics(prev => ({ ...prev, fid: metric.value }));
          if (metric.value > thresholds.fid.poor) {
            addAlert('Poor FID score', `FID: ${metric.value}ms`, 'warning');
          }
        });
        
        getFCP((metric) => {
          setMetrics(prev => ({ ...prev, fcp: metric.value }));
        });
        
        getLCP((metric) => {
          setMetrics(prev => ({ ...prev, lcp: metric.value }));
          if (metric.value > thresholds.lcp.poor) {
            addAlert('Poor LCP score', `LCP: ${metric.value}ms`, 'error');
          }
        });
        
        getTTFB((metric) => {
          setMetrics(prev => ({ ...prev, ttfb: metric.value }));
        });
      }).catch(() => {
        console.log('Web Vitals library not available');
      });
    }
  };

  const monitorNetworkSpeed = () => {
    if ('connection' in navigator) {
      const connection = navigator.connection;
      setMetrics(prev => ({ 
        ...prev, 
        networkSpeed: connection.effectiveType || 'unknown' 
      }));
    }
  };

  const monitorRenderPerformance = () => {
    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      entries.forEach((entry) => {
        if (entry.entryType === 'measure') {
          setMetrics(prev => ({ 
            ...prev, 
            renderTime: entry.duration 
          }));
        }
      });
    });
    
    observer.observe({ entryTypes: ['measure'] });
  };

  const addAlert = (title, message, type) => {
    const alert = {
      id: Date.now(),
      title,
      message,
      type,
      timestamp: new Date()
    };
    
    setAlerts(prev => [...prev.slice(-4), alert]); // Keep only last 5 alerts
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
      setAlerts(prev => prev.filter(a => a.id !== alert.id));
    }, 10000);
  };

  const getMetricStatus = (value, metric) => {
    const threshold = thresholds[metric];
    if (!threshold) return 'unknown';
    
    if (metric === 'fps') {
      return value >= threshold.good ? 'good' : value >= threshold.poor ? 'fair' : 'poor';
    } else {
      return value <= threshold.good ? 'good' : value <= threshold.poor ? 'fair' : 'poor';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'good': return 'text-green-400';
      case 'fair': return 'text-yellow-400';
      case 'poor': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'good': return CheckCircle;
      case 'fair': return AlertTriangle;
      case 'poor': return AlertTriangle;
      default: return Activity;
    }
  };

  const performanceMetrics = [
    { 
      key: 'fps', 
      label: 'FPS', 
      value: metrics.fps, 
      unit: '', 
      icon: Zap,
      description: 'Frames per second'
    },
    { 
      key: 'memory', 
      label: 'Memory', 
      value: metrics.memory.percentage || 0, 
      unit: '%', 
      icon: MemoryStick,
      description: `${metrics.memory.used}MB / ${metrics.memory.total}MB`
    },
    { 
      key: 'lcp', 
      label: 'LCP', 
      value: Math.round(metrics.lcp), 
      unit: 'ms', 
      icon: Eye,
      description: 'Largest Contentful Paint'
    },
    { 
      key: 'fid', 
      label: 'FID', 
      value: Math.round(metrics.fid), 
      unit: 'ms', 
      icon: Clock,
      description: 'First Input Delay'
    },
    { 
      key: 'cls', 
      label: 'CLS', 
      value: metrics.cls.toFixed(3), 
      unit: '', 
      icon: TrendingUp,
      description: 'Cumulative Layout Shift'
    }
  ];

  return (
    <>
      {/* Toggle Button */}
      <motion.button
        className="fixed top-4 right-20 z-50 p-2 bg-gradient-to-r from-green-500 to-emerald-500 text-white rounded-lg shadow-lg"
        onClick={() => setIsVisible(!isVisible)}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        title="Performance Monitor"
      >
        <Activity className="h-4 w-4" />
      </motion.button>

      {/* Performance Panel */}
      <AnimatePresence>
        {isVisible && (
          <motion.div
            className="fixed top-16 right-4 z-50 w-80"
            initial={{ opacity: 0, x: 300 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 300 }}
            transition={{ duration: 0.3 }}
          >
            <QuantumGlassCard variant="elevated" className="p-4">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white flex items-center space-x-2">
                  <Cpu className="h-5 w-5 text-green-400" />
                  <span>Performance</span>
                </h3>
                <button
                  onClick={() => setIsVisible(false)}
                  className="text-gray-400 hover:text-white"
                >
                  ✕
                </button>
              </div>

              {/* Metrics Grid */}
              <div className="space-y-3 mb-4">
                {performanceMetrics.map((metric) => {
                  const status = getMetricStatus(metric.value, metric.key);
                  const StatusIcon = getStatusIcon(status);
                  
                  return (
                    <div key={metric.key} className="flex items-center justify-between p-2 bg-white/5 rounded-lg">
                      <div className="flex items-center space-x-2">
                        <metric.icon className="h-4 w-4 text-gray-400" />
                        <div>
                          <div className="text-white text-sm font-medium">{metric.label}</div>
                          <div className="text-xs text-gray-400">{metric.description}</div>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <span className={`text-sm font-mono ${getStatusColor(status)}`}>
                          {metric.value}{metric.unit}
                        </span>
                        <StatusIcon className={`h-3 w-3 ${getStatusColor(status)}`} />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Network Info */}
              <div className="flex items-center justify-between p-2 bg-white/5 rounded-lg mb-4">
                <div className="flex items-center space-x-2">
                  <Wifi className="h-4 w-4 text-gray-400" />
                  <span className="text-white text-sm">Network</span>
                </div>
                <span className="text-cyan-400 text-sm font-mono">
                  {metrics.networkSpeed}
                </span>
              </div>

              {/* Performance Alerts */}
              {alerts.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-white">Recent Alerts</h4>
                  {alerts.slice(-3).map((alert) => (
                    <motion.div
                      key={alert.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`p-2 rounded-lg text-xs ${
                        alert.type === 'error' ? 'bg-red-500/20 text-red-400' :
                        alert.type === 'warning' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}
                    >
                      <div className="font-medium">{alert.title}</div>
                      <div className="opacity-75">{alert.message}</div>
                    </motion.div>
                  ))}
                </div>
              )}
            </QuantumGlassCard>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default PerformanceMonitor;
