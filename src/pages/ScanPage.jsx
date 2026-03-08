import React, { useState, useEffect } from 'react';
import ScanResults from '../components/ScanResults';
import {
  Play,
  Square,
  FolderOpen,
  FileText,
  Clock,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Settings,
  History
} from 'lucide-react';

const ScanPage = () => {
  const [scanPath, setScanPath] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScan, setCurrentScan] = useState(null);
  const [scanResults, setScanResults] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [scanOptions, setScanOptions] = useState({
    recursive: true,
    useCache: true,
    useIncremental: true,
    priority: 'normal'
  });

  useEffect(() => { loadScanHistory(); }, []);

  const loadScanHistory = async () => {
    try {
      const response = await fetch('/api/scan/list?limit=10');
      if (response.ok) {
        const data = await response.json();
        setScanHistory(data.scans || []);
      }
    } catch (error) { console.error('Failed to load scan history:', error); }
  };

  const startScan = async () => {
    if (!scanPath.trim()) { alert('Please enter a path to scan'); return; }
    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);
    try {
      const response = await fetch('/api/scan/directory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          directory_path: scanPath,
          recursive: scanOptions.recursive,
          use_cache: scanOptions.useCache,
          use_incremental: scanOptions.useIncremental,
          priority: scanOptions.priority
        }),
      });
      if (!response.ok) throw new Error('Failed to start scan');
      const data = await response.json();
      setCurrentScan(data);
      pollScanProgress(data.scan_id);
    } catch (error) {
      console.error('Scan failed:', error);
      setIsScanning(false);
      alert('Failed to start scan: ' + error.message);
    }
  };

  const pollScanProgress = async (scanId) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/scan/results/${scanId}`);
        if (response.ok) {
          const data = await response.json();
          if (data.status === 'running') {
            setScanProgress(prev => Math.min(prev + 10, 90));
          } else if (data.status === 'completed') {
            setScanProgress(100);
            setScanResults(data);
            setIsScanning(false);
            clearInterval(pollInterval);
            loadScanHistory();
          } else if (data.status === 'failed') {
            setIsScanning(false);
            clearInterval(pollInterval);
            alert('Scan failed: ' + (data.error || 'Unknown error'));
          }
        }
      } catch (error) { console.error('Failed to poll scan progress:', error); }
    }, 2000);
    setTimeout(() => {
      clearInterval(pollInterval);
      if (isScanning) { setIsScanning(false); alert('Scan timeout'); }
    }, 300000);
  };

  const stopScan = async () => {
    if (currentScan) {
      try {
        await fetch(`/api/scan/stop/${currentScan.scan_id}`, { method: 'POST' });
        setIsScanning(false);
        setScanProgress(0);
        setCurrentScan(null);
      } catch (error) { console.error('Failed to stop scan:', error); }
    }
  };

  const selectDirectory = () => {
    const path = prompt('Enter directory path:', '/src');
    if (path) setScanPath(path);
  };

  const loadPreviousScan = async (scanId) => {
    try {
      const response = await fetch(`/api/scan/results/${scanId}`);
      if (response.ok) {
        const data = await response.json();
        setScanResults(data);
        setScanPath(data.directory_path || '');
      }
    } catch (error) { console.error('Failed to load previous scan:', error); }
  };

  const getStatusColor = (status) => ({
    completed: 'text-emerald-400', running: 'text-yellow-400', failed: 'text-red-400'
  }[status] || 'text-text-disabled');

  const getStatusIcon = (status) => ({
    completed: <CheckCircle className="h-3.5 w-3.5" />,
    running: <Loader2 className="h-3.5 w-3.5 animate-spin" />,
    failed: <AlertTriangle className="h-3.5 w-3.5" />
  }[status] || <Clock className="h-3.5 w-3.5" />);

  return (
    <div className="p-6 space-y-5 overflow-y-auto">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Security Scan</h1>
        <p className="text-xs text-text-muted mt-0.5">Scan your codebase for vulnerabilities</p>
      </div>

      {/* Scan Configuration */}
      <div className="desktop-panel p-4 space-y-3">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
          <Settings className="h-3.5 w-3.5 text-primary-400" />
          Configuration
        </h3>

        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              type="text"
              placeholder="Enter directory path to scan (e.g., /src, /app)"
              value={scanPath}
              onChange={(e) => setScanPath(e.target.value)}
              disabled={isScanning}
              className="input text-xs py-1.5"
            />
          </div>
          <button
            onClick={selectDirectory}
            disabled={isScanning}
            className="btn-ghost text-xs px-3 py-1.5 inline-flex items-center gap-1"
          >
            <FolderOpen className="h-3.5 w-3.5" /> Browse
          </button>
        </div>

        <div className="flex items-center gap-4">
          {[
            { key: 'recursive', label: 'Recursive' },
            { key: 'useCache', label: 'Cache' },
            { key: 'useIncremental', label: 'Incremental' }
          ].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={scanOptions[key]}
                onChange={(e) => setScanOptions(prev => ({ ...prev, [key]: e.target.checked }))}
                disabled={isScanning}
                className="w-3 h-3 rounded border-desktop-border"
              />
              <span className="text-xs text-text-secondary">{label}</span>
            </label>
          ))}
          <select
            value={scanOptions.priority}
            onChange={(e) => setScanOptions(prev => ({ ...prev, priority: e.target.value }))}
            disabled={isScanning}
            className="input text-xs py-1 w-auto"
          >
            <option value="low">Low</option>
            <option value="normal">Normal</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          {!isScanning ? (
            <button onClick={startScan} className="btn-primary text-xs px-4 py-1.5 inline-flex items-center gap-1.5">
              <Play className="h-3.5 w-3.5" /> Start Scan
            </button>
          ) : (
            <button onClick={stopScan} className="text-xs px-4 py-1.5 inline-flex items-center gap-1.5 rounded-desktop border border-red-400/20 text-red-400 hover:bg-red-400/5 transition-colors">
              <Square className="h-3.5 w-3.5" /> Stop
            </button>
          )}
        </div>

        {isScanning && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-text-muted">Scanning...</span>
              <span className="text-text-primary font-medium">{scanProgress}%</span>
            </div>
            <div className="w-full bg-desktop-border rounded-full h-1.5">
              <div
                className="bg-primary-600 h-1.5 rounded-full transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
            {currentScan && (
              <p className="text-[11px] text-text-disabled">ID: {currentScan.scan_id}</p>
            )}
          </div>
        )}
      </div>

      {/* Scan Results */}
      {scanResults && <ScanResults results={scanResults} />}

      {/* Scan History */}
      <div className="desktop-panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
          <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
            <History className="h-3.5 w-3.5 text-primary-400" /> Recent Scans
          </h3>
        </div>

        {scanHistory.length > 0 ? (
          <div className="divide-y divide-desktop-border">
            {scanHistory.map((scan) => (
              <div
                key={scan.scan_id}
                className="flex items-center justify-between px-4 py-2 hover:bg-white/[0.02] cursor-pointer transition-colors"
                onClick={() => loadPreviousScan(scan.scan_id)}
              >
                <div className="flex items-center gap-2.5">
                  <div className={getStatusColor(scan.status)}>
                    {getStatusIcon(scan.status)}
                  </div>
                  <div>
                    <p className="text-xs font-medium text-text-primary">{scan.directory_path || 'Unknown path'}</p>
                    <p className="text-[11px] text-text-disabled">{new Date(scan.started_at).toLocaleString()}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[11px] px-1.5 py-0.5 rounded-desktop border ${scan.total_findings > 0 ? 'border-red-400/20 text-red-400 bg-red-400/5' : 'border-desktop-border text-text-disabled'
                    }`}>
                    {scan.total_findings || 0} issues
                  </span>
                  <span className={`text-[11px] px-1.5 py-0.5 rounded-desktop border border-desktop-border ${getStatusColor(scan.status)}`}>
                    {scan.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <FileText className="h-6 w-6 text-text-disabled mx-auto mb-2" />
            <p className="text-xs text-text-muted">No previous scans</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanPage;
