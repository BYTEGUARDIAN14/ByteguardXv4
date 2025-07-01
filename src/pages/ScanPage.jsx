import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Alert, AlertDescription } from '../components/ui/alert';
import { Progress } from '../components/ui/progress';
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

  useEffect(() => {
    loadScanHistory();
  }, []);

  const loadScanHistory = async () => {
    try {
      const response = await fetch('/api/scan/list?limit=10');
      if (response.ok) {
        const data = await response.json();
        setScanHistory(data.scans || []);
      }
    } catch (error) {
      console.error('Failed to load scan history:', error);
    }
  };

  const startScan = async () => {
    if (!scanPath.trim()) {
      alert('Please enter a path to scan');
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);

    try {
      const response = await fetch('/api/scan/directory', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          directory_path: scanPath,
          recursive: scanOptions.recursive,
          use_cache: scanOptions.useCache,
          use_incremental: scanOptions.useIncremental,
          priority: scanOptions.priority
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to start scan');
      }

      const data = await response.json();
      setCurrentScan(data);

      // Poll for scan progress
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
          
          // Update progress based on status
          if (data.status === 'running') {
            setScanProgress(prev => Math.min(prev + 10, 90));
          } else if (data.status === 'completed') {
            setScanProgress(100);
            setScanResults(data);
            setIsScanning(false);
            clearInterval(pollInterval);
            loadScanHistory(); // Refresh history
          } else if (data.status === 'failed') {
            setIsScanning(false);
            clearInterval(pollInterval);
            alert('Scan failed: ' + (data.error || 'Unknown error'));
          }
        }
      } catch (error) {
        console.error('Failed to poll scan progress:', error);
      }
    }, 2000);

    // Cleanup after 5 minutes
    setTimeout(() => {
      clearInterval(pollInterval);
      if (isScanning) {
        setIsScanning(false);
        alert('Scan timeout - please check scan status manually');
      }
    }, 300000);
  };

  const stopScan = async () => {
    if (currentScan) {
      try {
        await fetch(`/api/scan/stop/${currentScan.scan_id}`, {
          method: 'POST'
        });
        setIsScanning(false);
        setScanProgress(0);
        setCurrentScan(null);
      } catch (error) {
        console.error('Failed to stop scan:', error);
      }
    }
  };

  const selectDirectory = () => {
    // In a real app, this would open a directory picker
    // For now, we'll use some common paths
    const commonPaths = [
      '/src',
      '/app',
      '/components',
      '/pages',
      '/utils',
      '/api',
      '/lib',
      '/config'
    ];
    
    const path = prompt('Enter directory path:', commonPaths[0]);
    if (path) {
      setScanPath(path);
    }
  };

  const loadPreviousScan = async (scanId) => {
    try {
      const response = await fetch(`/api/scan/results/${scanId}`);
      if (response.ok) {
        const data = await response.json();
        setScanResults(data);
        setScanPath(data.directory_path || '');
      }
    } catch (error) {
      console.error('Failed to load previous scan:', error);
    }
  };

  const getScanStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-600';
      case 'running': return 'text-yellow-600';
      case 'failed': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getScanStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'running': return <Loader2 className="h-4 w-4 animate-spin" />;
      case 'failed': return <AlertTriangle className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Scan</h1>
          <p className="text-gray-600 mt-1">
            Scan your codebase for security vulnerabilities
          </p>
        </div>
      </div>

      {/* Scan Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Settings className="h-5 w-5 mr-2" />
            Scan Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Path Input */}
          <div className="flex space-x-2">
            <div className="flex-1">
              <Input
                placeholder="Enter directory path to scan (e.g., /src, /app)"
                value={scanPath}
                onChange={(e) => setScanPath(e.target.value)}
                disabled={isScanning}
              />
            </div>
            <Button
              variant="outline"
              onClick={selectDirectory}
              disabled={isScanning}
            >
              <FolderOpen className="h-4 w-4 mr-2" />
              Browse
            </Button>
          </div>

          {/* Scan Options */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={scanOptions.recursive}
                onChange={(e) => setScanOptions(prev => ({ ...prev, recursive: e.target.checked }))}
                disabled={isScanning}
                className="rounded"
              />
              <span className="text-sm">Recursive</span>
            </label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={scanOptions.useCache}
                onChange={(e) => setScanOptions(prev => ({ ...prev, useCache: e.target.checked }))}
                disabled={isScanning}
                className="rounded"
              />
              <span className="text-sm">Use Cache</span>
            </label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={scanOptions.useIncremental}
                onChange={(e) => setScanOptions(prev => ({ ...prev, useIncremental: e.target.checked }))}
                disabled={isScanning}
                className="rounded"
              />
              <span className="text-sm">Incremental</span>
            </label>
            <select
              value={scanOptions.priority}
              onChange={(e) => setScanOptions(prev => ({ ...prev, priority: e.target.value }))}
              disabled={isScanning}
              className="text-sm border rounded px-2 py-1"
            >
              <option value="low">Low Priority</option>
              <option value="normal">Normal Priority</option>
              <option value="high">High Priority</option>
              <option value="critical">Critical Priority</option>
            </select>
          </div>

          {/* Scan Controls */}
          <div className="flex space-x-2">
            {!isScanning ? (
              <Button onClick={startScan} className="bg-cyan-600 hover:bg-cyan-700">
                <Play className="h-4 w-4 mr-2" />
                Start Scan
              </Button>
            ) : (
              <Button onClick={stopScan} variant="destructive">
                <Square className="h-4 w-4 mr-2" />
                Stop Scan
              </Button>
            )}
          </div>

          {/* Scan Progress */}
          {isScanning && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Scanning in progress...</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="w-full" />
              {currentScan && (
                <p className="text-sm text-gray-600">
                  Scan ID: {currentScan.scan_id}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Results */}
      {scanResults && (
        <ScanResults data={scanResults} />
      )}

      {/* Scan History */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <History className="h-5 w-5 mr-2" />
            Recent Scans
          </CardTitle>
        </CardHeader>
        <CardContent>
          {scanHistory.length > 0 ? (
            <div className="space-y-3">
              {scanHistory.map((scan) => (
                <div
                  key={scan.scan_id}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer transition-colors"
                  onClick={() => loadPreviousScan(scan.scan_id)}
                >
                  <div className="flex items-center space-x-3">
                    <div className={getScanStatusColor(scan.status)}>
                      {getScanStatusIcon(scan.status)}
                    </div>
                    <div>
                      <p className="font-medium text-sm">{scan.directory_path || 'Unknown path'}</p>
                      <p className="text-xs text-gray-600">
                        {new Date(scan.started_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant={scan.total_findings > 0 ? "destructive" : "secondary"}>
                      {scan.total_findings || 0} issues
                    </Badge>
                    <Badge variant="outline" className={getScanStatusColor(scan.status)}>
                      {scan.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No previous scans found</p>
              <p className="text-sm">Start your first scan to see results here</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default ScanPage;
