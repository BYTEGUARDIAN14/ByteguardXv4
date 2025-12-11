/**
 * Real-time scan progress tracker with advanced visualizations
 * Shows detailed progress, performance metrics, and live updates
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Pause, 
  Square, 
  Activity, 
  Clock, 
  FileText, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  Zap,
  Database,
  Cpu,
  HardDrive
} from 'lucide-react';

const ScanProgressTracker = ({ 
  scanId, 
  onScanComplete, 
  onScanError,
  realTimeUpdates = true 
}) => {
  const [scanStatus, setScanStatus] = useState({
    status: 'pending',
    progress: 0,
    currentFile: '',
    totalFiles: 0,
    processedFiles: 0,
    findings: 0,
    errors: [],
    startTime: null,
    estimatedTimeRemaining: null,
    performance: {
      filesPerSecond: 0,
      memoryUsage: 0,
      cpuUsage: 0,
      cacheHitRate: 0
    }
  });

  const [isRunning, setIsRunning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const intervalRef = useRef(null);
  const wsRef = useRef(null);

  // WebSocket connection for real-time updates
  useEffect(() => {
    if (realTimeUpdates && scanId) {
      const wsUrl = `ws://localhost:5000/ws/scan/${scanId}`;
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateScanStatus(data);
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        // Fallback to polling
        startPolling();
      };

      return () => {
        if (wsRef.current) {
          wsRef.current.close();
        }
      };
    } else if (scanId) {
      startPolling();
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [scanId, realTimeUpdates]);

  const startPolling = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
    }

    intervalRef.current = setInterval(async () => {
      try {
        const response = await fetch(`/api/scan/status/${scanId}`);
        const data = await response.json();
        updateScanStatus(data);
      } catch (error) {
        console.error('Failed to fetch scan status:', error);
      }
    }, 1000);
  };

  const updateScanStatus = (data) => {
    setScanStatus(prevStatus => ({
      ...prevStatus,
      ...data,
      progress: Math.min(100, Math.max(0, data.progress || 0))
    }));

    // Handle scan completion
    if (data.status === 'completed') {
      setIsRunning(false);
      if (onScanComplete) {
        onScanComplete(data);
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    } else if (data.status === 'failed') {
      setIsRunning(false);
      if (onScanError) {
        onScanError(data.error || 'Scan failed');
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    } else if (data.status === 'running') {
      setIsRunning(true);
    }
  };

  const handlePauseScan = async () => {
    try {
      await fetch(`/api/scan/pause/${scanId}`, { method: 'POST' });
      setIsPaused(true);
    } catch (error) {
      console.error('Failed to pause scan:', error);
    }
  };

  const handleResumeScan = async () => {
    try {
      await fetch(`/api/scan/resume/${scanId}`, { method: 'POST' });
      setIsPaused(false);
    } catch (error) {
      console.error('Failed to resume scan:', error);
    }
  };

  const handleCancelScan = async () => {
    try {
      await fetch(`/api/scan/cancel/${scanId}`, { method: 'POST' });
      setIsRunning(false);
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    } catch (error) {
      console.error('Failed to cancel scan:', error);
    }
  };

  const formatTime = (seconds) => {
    if (!seconds) return '--:--';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-400';
      case 'failed': return 'text-red-400';
      case 'running': return 'text-cyan-400';
      case 'paused': return 'text-yellow-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-5 h-5" />;
      case 'failed': return <XCircle className="w-5 h-5" />;
      case 'running': return <Activity className="w-5 h-5 animate-pulse" />;
      case 'paused': return <Pause className="w-5 h-5" />;
      default: return <Clock className="w-5 h-5" />;
    }
  };

  return (
    <div className="bg-black/40 backdrop-blur-sm border border-white/10 rounded-lg p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className={`${getStatusColor(scanStatus.status)}`}>
            {getStatusIcon(scanStatus.status)}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">
              Scan Progress
            </h3>
            <p className="text-sm text-gray-400 capitalize">
              Status: {scanStatus.status}
            </p>
          </div>
        </div>

        {/* Control Buttons */}
        <div className="flex items-center space-x-2">
          {isRunning && !isPaused && (
            <button
              onClick={handlePauseScan}
              className="p-2 bg-yellow-500/20 hover:bg-yellow-500/30 border border-yellow-500/30 rounded-lg transition-colors"
              title="Pause Scan"
            >
              <Pause className="w-4 h-4 text-yellow-400" />
            </button>
          )}
          
          {isPaused && (
            <button
              onClick={handleResumeScan}
              className="p-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg transition-colors"
              title="Resume Scan"
            >
              <Play className="w-4 h-4 text-green-400" />
            </button>
          )}
          
          {(isRunning || isPaused) && (
            <button
              onClick={handleCancelScan}
              className="p-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg transition-colors"
              title="Cancel Scan"
            >
              <Square className="w-4 h-4 text-red-400" />
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-6">
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm text-gray-400">Overall Progress</span>
          <span className="text-sm font-mono text-cyan-400">
            {scanStatus.progress.toFixed(1)}%
          </span>
        </div>
        <div className="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300 ease-out"
            style={{ width: `${scanStatus.progress}%` }}
          >
            <div className="h-full bg-white/20 animate-pulse"></div>
          </div>
        </div>
      </div>

      {/* Current File */}
      {scanStatus.currentFile && (
        <div className="mb-6 p-3 bg-gray-800/50 rounded-lg">
          <div className="flex items-center space-x-2 mb-1">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span className="text-sm text-gray-400">Currently Scanning:</span>
          </div>
          <p className="text-sm font-mono text-white truncate">
            {scanStatus.currentFile}
          </p>
        </div>
      )}

      {/* Statistics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center space-x-2 mb-1">
            <FileText className="w-4 h-4 text-blue-400" />
            <span className="text-xs text-gray-400">Files</span>
          </div>
          <p className="text-lg font-semibold text-white">
            {scanStatus.processedFiles} / {scanStatus.totalFiles}
          </p>
        </div>

        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center space-x-2 mb-1">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span className="text-xs text-gray-400">Findings</span>
          </div>
          <p className="text-lg font-semibold text-white">
            {scanStatus.findings}
          </p>
        </div>

        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center space-x-2 mb-1">
            <Zap className="w-4 h-4 text-green-400" />
            <span className="text-xs text-gray-400">Speed</span>
          </div>
          <p className="text-lg font-semibold text-white">
            {scanStatus.performance.filesPerSecond.toFixed(1)} f/s
          </p>
        </div>

        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center space-x-2 mb-1">
            <Clock className="w-4 h-4 text-purple-400" />
            <span className="text-xs text-gray-400">ETA</span>
          </div>
          <p className="text-lg font-semibold text-white">
            {formatTime(scanStatus.estimatedTimeRemaining)}
          </p>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-orange-400" />
              <span className="text-xs text-gray-400">CPU Usage</span>
            </div>
            <span className="text-xs font-mono text-orange-400">
              {scanStatus.performance.cpuUsage.toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div 
              className="h-full bg-orange-400 rounded-full transition-all duration-300"
              style={{ width: `${scanStatus.performance.cpuUsage}%` }}
            ></div>
          </div>
        </div>

        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <HardDrive className="w-4 h-4 text-purple-400" />
              <span className="text-xs text-gray-400">Memory</span>
            </div>
            <span className="text-xs font-mono text-purple-400">
              {scanStatus.performance.memoryUsage.toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div 
              className="h-full bg-purple-400 rounded-full transition-all duration-300"
              style={{ width: `${scanStatus.performance.memoryUsage}%` }}
            ></div>
          </div>
        </div>

        <div className="bg-gray-800/30 rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span className="text-xs text-gray-400">Cache Hit</span>
            </div>
            <span className="text-xs font-mono text-cyan-400">
              {scanStatus.performance.cacheHitRate.toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div 
              className="h-full bg-cyan-400 rounded-full transition-all duration-300"
              style={{ width: `${scanStatus.performance.cacheHitRate}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Errors */}
      {scanStatus.errors && scanStatus.errors.length > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <XCircle className="w-4 h-4 text-red-400" />
            <span className="text-sm font-semibold text-red-400">
              Errors ({scanStatus.errors.length})
            </span>
          </div>
          <div className="max-h-32 overflow-y-auto space-y-1">
            {scanStatus.errors.map((error, index) => (
              <p key={index} className="text-xs text-red-300 font-mono">
                {error}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanProgressTracker;
