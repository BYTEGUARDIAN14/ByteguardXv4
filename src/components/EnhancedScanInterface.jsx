import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Play,
  Pause,
  Settings,
  FileText,
  Upload,
  Zap,
  Shield,
  CheckCircle,
  AlertTriangle,
  Clock,
  Filter,
  Download,
  Eye,
  Puzzle,
  FolderOpen
} from 'lucide-react';

const UPLOAD_CONSTANTS = {
  MAX_TOTAL_SIZE: 2 * 1024 * 1024 * 1024,
  MAX_INDIVIDUAL_FILE_SIZE: 500 * 1024 * 1024,
  MAX_FILE_COUNT: 10000,
  ALLOWED_EXTENSIONS: [
    'py', 'js', 'jsx', 'ts', 'tsx', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb',
    'go', 'rs', 'swift', 'kt', 'scala', 'json', 'xml', 'yml', 'yaml', 'txt',
    'md', 'rst', 'dockerfile', 'sh', 'bat', 'ps1', 'sql', 'html', 'css', 'scss',
    'sass', 'less', 'vue', 'svelte', 'dart', 'r', 'matlab', 'm', 'pl', 'pm'
  ],
  BLOCKED_EXTENSIONS: [
    'exe', 'dll', 'so', 'dylib', 'bin', 'app', 'deb', 'rpm', 'msi', 'dmg',
    'iso', 'img', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'
  ],
  DANGEROUS_PATTERNS: [/\.\./g, /^\//, /^\\/, /\0/, /[\x00-\x1f\x7f-\x9f]/]
};

const EnhancedScanInterface = () => {
  const navigate = useNavigate();
  const [scanConfig, setScanConfig] = useState({
    mode: 'comprehensive', enablePlugins: true, selectedPlugins: [],
    confidenceThreshold: 0.6, enableML: true
  });
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [availablePlugins, setAvailablePlugins] = useState([]);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [uploadMode, setUploadMode] = useState('file');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [totalUploadSize, setTotalUploadSize] = useState(0);
  const [fileCount, setFileCount] = useState(0);
  const [isUploading, setIsUploading] = useState(false);

  useEffect(() => { fetchAvailablePlugins(); }, []);

  const validateFileName = (fileName) => {
    for (const pattern of UPLOAD_CONSTANTS.DANGEROUS_PATTERNS) {
      if (pattern.test(fileName)) return { valid: false, reason: 'File path contains dangerous characters' };
    }
    const ext = fileName.split('.').pop()?.toLowerCase();
    if (!ext) return { valid: false, reason: 'File has no extension' };
    if (UPLOAD_CONSTANTS.BLOCKED_EXTENSIONS.includes(ext)) return { valid: false, reason: `File type .${ext} is blocked` };
    if (!UPLOAD_CONSTANTS.ALLOWED_EXTENSIONS.includes(ext)) return { valid: false, reason: `File type .${ext} is not supported` };
    return { valid: true };
  };

  const validateFileSize = (file) => {
    if (file.size > UPLOAD_CONSTANTS.MAX_INDIVIDUAL_FILE_SIZE) {
      return { valid: false, reason: `${file.name} too large (${formatFileSize(file.size)}). Max: ${formatFileSize(UPLOAD_CONSTANTS.MAX_INDIVIDUAL_FILE_SIZE)}` };
    }
    return { valid: true };
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const validateTotalUpload = (files) => {
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    if (totalSize > UPLOAD_CONSTANTS.MAX_TOTAL_SIZE) return { valid: false, reason: `Total size (${formatFileSize(totalSize)}) exceeds 2GB` };
    if (files.length > UPLOAD_CONSTANTS.MAX_FILE_COUNT) return { valid: false, reason: `Too many files (${files.length}). Max: ${UPLOAD_CONSTANTS.MAX_FILE_COUNT}` };
    return { valid: true, totalSize, fileCount: files.length };
  };

  const fetchAvailablePlugins = async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      const response = await fetch('/api/v2/plugins', {
        credentials: 'include', signal: controller.signal,
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
      });
      clearTimeout(timeoutId);
      if (response.ok) {
        const data = await response.json();
        if (!data || typeof data !== 'object') throw new Error('Invalid response');
        const plugins = data?.marketplace?.categories?.flatMap(cat => {
          if (!cat || !Array.isArray(cat.plugins)) return [];
          return cat.plugins.filter(p => p && typeof p === 'object' && (p.name || p.manifest?.name));
        }) || [];
        setAvailablePlugins(plugins);
      } else { setAvailablePlugins([]); }
    } catch (error) { console.error('Failed to fetch plugins:', error); setAvailablePlugins([]); }
  };

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;
    setIsUploading(true); setUploadProgress(0);
    try {
      const validationErrors = []; const validFiles = [];
      for (const file of files) {
        const nameV = validateFileName(file.name);
        if (!nameV.valid) { validationErrors.push(`${file.name}: ${nameV.reason}`); continue; }
        const sizeV = validateFileSize(file);
        if (!sizeV.valid) { validationErrors.push(sizeV.reason); continue; }
        validFiles.push(file);
      }
      if (validationErrors.length > 0) {
        alert(`Validation failed:\n${validationErrors.slice(0, 5).join('\n')}${validationErrors.length > 5 ? `\n...${validationErrors.length - 5} more` : ''}`);
        if (validFiles.length === 0) { event.target.value = ''; setIsUploading(false); return; }
      }
      const totalV = validateTotalUpload(validFiles);
      if (!totalV.valid) { alert(totalV.reason); event.target.value = ''; setIsUploading(false); return; }
      if (uploadMode === 'file' && validFiles.length === 1) { setUploadedFile(validFiles[0]); setUploadedFiles([]); }
      else { setUploadedFiles(validFiles); setUploadedFile(null); }
      setTotalUploadSize(totalV.totalSize); setFileCount(totalV.fileCount);
    } catch (error) { console.error('Upload error:', error); alert('Upload error.'); event.target.value = ''; }
    finally { setIsUploading(false); setUploadProgress(100); }
  };

  const handleFolderUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;
    setIsUploading(true); setUploadProgress(0);
    try {
      const folderStructure = {}; const validFiles = []; const validationErrors = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i]; setUploadProgress((i / files.length) * 50);
        const relativePath = file.webkitRelativePath || file.name;
        const folderPath = relativePath.substring(0, relativePath.lastIndexOf('/')) || 'root';
        if (!folderStructure[folderPath]) folderStructure[folderPath] = [];
        const nameV = validateFileName(relativePath);
        if (!nameV.valid) { validationErrors.push(`${relativePath}: ${nameV.reason}`); continue; }
        const sizeV = validateFileSize(file);
        if (!sizeV.valid) { validationErrors.push(sizeV.reason); continue; }
        validFiles.push(file); folderStructure[folderPath].push(file);
      }
      const totalV = validateTotalUpload(validFiles);
      if (!totalV.valid) { alert(totalV.reason); event.target.value = ''; setIsUploading(false); return; }
      if (validationErrors.length > 0 && validFiles.length === 0) { alert('No valid files.'); event.target.value = ''; setIsUploading(false); return; }
      setUploadedFiles(validFiles); setUploadedFile(null);
      setTotalUploadSize(totalV.totalSize); setFileCount(totalV.fileCount);
      setUploadProgress(100);
    } catch (error) { console.error('Folder upload error:', error); event.target.value = ''; }
    finally { setIsUploading(false); }
  };

  const startScan = async () => {
    const hasFiles = uploadedFile || (uploadedFiles && uploadedFiles.length > 0);
    if (!hasFiles) { alert('Please upload files to scan'); return; }
    setIsScanning(true); setScanResults(null); setUploadProgress(0);
    let progressInterval; let currentProgress = 0;
    progressInterval = setInterval(() => {
      currentProgress += Math.random() * 5;
      if (currentProgress > 90) { currentProgress = 90; clearInterval(progressInterval); }
      setUploadProgress(Math.min(90, Math.round(currentProgress)));
    }, 500);
    try {
      const formData = new FormData();
      if (uploadedFile) { formData.append('files', uploadedFile); formData.append('upload_type', 'single_file'); }
      else if (uploadedFiles && uploadedFiles.length > 0) {
        uploadedFiles.forEach((file, i) => {
          formData.append('files', file);
          if (file.webkitRelativePath) formData.append(`file_paths[${i}]`, file.webkitRelativePath);
        });
        formData.append('upload_type', 'multiple_files');
        formData.append('file_count', uploadedFiles.length.toString());
        formData.append('total_size', totalUploadSize.toString());
      }
      formData.append('scan_mode', scanConfig.mode);
      formData.append('enable_plugins', scanConfig.enablePlugins);
      formData.append('confidence_threshold', scanConfig.confidenceThreshold);
      formData.append('enable_ml', scanConfig.enableML);
      if (scanConfig.selectedPlugins.length > 0) formData.append('selected_plugins', JSON.stringify(scanConfig.selectedPlugins));
      const endpoint = uploadedFiles && uploadedFiles.length > 1 ? '/api/scan/folder' : '/api/scan/file';
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort('Scan timed out'), 900000);
      const response = await fetch(endpoint, {
        method: 'POST', body: formData, credentials: 'include', signal: controller.signal,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      });
      clearTimeout(timeoutId);
      if (response.ok) {
        const results = await response.json();
        if (results && typeof results === 'object') {
          setScanResults(results);
          navigate(`/report/${results.scan_id}`, { state: { scanResults: results } });
        } else throw new Error('Invalid response');
      } else {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Scan failed (${response.status})`);
      }
    } catch (error) {
      console.error('Scan error:', error);
      let msg = error.message || 'Scan failed.';
      if (error.name === 'AbortError' || msg.includes('timeout')) msg = 'Scan timed out. Try smaller batches.';
      alert(msg);
    } finally {
      if (progressInterval) clearInterval(progressInterval);
      setIsScanning(false); setUploadProgress(100);
    }
  };

  const hasFiles = uploadedFile || (uploadedFiles && uploadedFiles.length > 0);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text-primary">Enhanced Security Scanner</h2>
          <p className="text-[11px] text-text-muted">22+ plugins · AI-powered analysis</p>
        </div>
        <div className="flex items-center gap-1 text-[11px] text-text-disabled">
          <Puzzle className="h-3 w-3" />
          <span>{availablePlugins.length} plugins</span>
        </div>
      </div>

      {/* Scan Configuration */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Settings className="h-3.5 w-3.5 text-primary-400" /> Configuration
        </h3>

        <div className="grid grid-cols-4 gap-3 mb-3">
          <div>
            <label className="block text-[11px] text-text-muted mb-1">Scan Mode</label>
            <select
              value={scanConfig.mode}
              onChange={(e) => setScanConfig({ ...scanConfig, mode: e.target.value })}
              className="input text-xs py-1.5"
            >
              <option value="static">Static</option>
              <option value="dynamic">Dynamic</option>
              <option value="hybrid">Hybrid</option>
              <option value="ml_enhanced">ML Enhanced</option>
              <option value="comprehensive">Comprehensive</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] text-text-muted mb-1">Confidence: {(scanConfig.confidenceThreshold * 100).toFixed(0)}%</label>
            <input
              type="range" min="0.1" max="1.0" step="0.1"
              value={scanConfig.confidenceThreshold}
              onChange={(e) => setScanConfig({ ...scanConfig, confidenceThreshold: parseFloat(e.target.value) })}
              className="w-full accent-primary-500"
            />
          </div>

          <div className="flex flex-col justify-end">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input type="checkbox" checked={scanConfig.enablePlugins}
                onChange={(e) => setScanConfig({ ...scanConfig, enablePlugins: e.target.checked })}
                className="w-3 h-3 rounded border-desktop-border" />
              <span className="text-xs text-text-secondary">Plugins</span>
            </label>
          </div>

          <div className="flex flex-col justify-end">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input type="checkbox" checked={scanConfig.enableML}
                onChange={(e) => setScanConfig({ ...scanConfig, enableML: e.target.checked })}
                className="w-3 h-3 rounded border-desktop-border" />
              <span className="text-xs text-text-secondary">AI/ML</span>
            </label>
          </div>
        </div>

        {scanConfig.enablePlugins && (
          <div>
            <label className="block text-[11px] text-text-muted mb-1">Select Plugins (empty = all)</label>
            <div className="grid grid-cols-4 gap-1 max-h-24 overflow-y-auto">
              {Array.isArray(availablePlugins) && availablePlugins.slice(0, 12).map((plugin, index) => {
                const pluginName = plugin?.manifest?.name || plugin?.name || `plugin-${index}`;
                const displayName = plugin?.name || pluginName?.replace(/_/g, ' ') || 'Unknown';
                return (
                  <label key={`plugin-${index}`} className="flex items-center gap-1 text-[11px] cursor-pointer">
                    <input type="checkbox" checked={scanConfig.selectedPlugins.includes(pluginName)}
                      onChange={(e) => {
                        try {
                          setScanConfig(prev => ({
                            ...prev,
                            selectedPlugins: e.target.checked
                              ? [...prev.selectedPlugins, pluginName]
                              : prev.selectedPlugins.filter(p => p !== pluginName)
                          }));
                        } catch (err) { console.error(err); }
                      }}
                      className="w-2.5 h-2.5 rounded border-desktop-border" />
                    <span className="text-text-muted truncate">{displayName}</span>
                  </label>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* File Upload */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Upload className="h-3.5 w-3.5 text-primary-400" /> Upload
        </h3>

        <div className="flex gap-1 mb-3">
          {['file', 'folder'].map(mode => (
            <button key={mode} onClick={() => setUploadMode(mode)}
              className={`text-xs px-3 py-1 rounded-desktop transition-colors ${uploadMode === mode ? 'bg-primary-600 text-white' : 'text-text-muted hover:text-text-secondary hover:bg-white/[0.04]'
                }`}
            >
              {mode === 'file' ? 'Single File' : 'Folder / Multiple'}
            </button>
          ))}
        </div>

        <div className="border border-dashed border-desktop-border rounded-desktop p-6 text-center">
          {uploadMode === 'file' ? (
            <>
              <input type="file" onChange={handleFileUpload} className="hidden" id="file-upload"
                accept=".py,.js,.jsx,.ts,.tsx,.java,.cs,.php,.go,.rb,.cpp,.c,.h,.json,.yaml,.yml,.tf,.dockerfile,.html,.css,.scss,.md,.txt,.sql,.sh,.bat,.ps1" />
              <label htmlFor="file-upload" className="cursor-pointer">
                <FileText className="h-8 w-8 text-text-disabled mx-auto mb-2" />
                <p className="text-xs text-text-primary">{uploadedFile ? uploadedFile.name : 'Click to upload a file'}</p>
                <p className="text-[10px] text-text-disabled mt-0.5">Max: 500MB per file</p>
              </label>
            </>
          ) : (
            <>
              <input type="file" onChange={handleFolderUpload} className="hidden" id="folder-upload" webkitdirectory="" mozdirectory="" directory="" multiple />
              <input type="file" onChange={handleFileUpload} className="hidden" id="multi-upload" multiple
                accept=".py,.js,.jsx,.ts,.tsx,.java,.cs,.php,.go,.rb,.cpp,.c,.h,.json,.yaml,.yml,.tf,.dockerfile,.html,.css,.scss,.md,.txt,.sql,.sh,.bat,.ps1" />
              <div className="space-y-2">
                <label htmlFor="folder-upload" className="cursor-pointer block">
                  <FolderOpen className="h-8 w-8 text-text-disabled mx-auto mb-1" />
                  <p className="text-xs text-text-primary">Upload entire folder</p>
                </label>
                <span className="text-[10px] text-text-disabled">or</span>
                <label htmlFor="multi-upload" className="cursor-pointer block">
                  <p className="text-xs text-text-primary">Select multiple files</p>
                </label>
              </div>
            </>
          )}
        </div>

        {/* Upload Progress */}
        {isUploading && (
          <div className="mt-2 p-2 bg-desktop-card rounded-desktop border border-desktop-border">
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-text-muted">Processing...</span>
              <span className="text-primary-400">{uploadProgress}%</span>
            </div>
            <div className="w-full bg-desktop-border rounded-full h-1">
              <div className="bg-primary-600 h-1 rounded-full transition-all" style={{ width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}

        {/* File info */}
        {uploadedFile && !isUploading && (
          <div className="mt-2 flex items-center justify-between p-2 bg-desktop-card rounded-desktop border border-desktop-border">
            <div>
              <p className="text-xs text-text-primary">{uploadedFile.name}</p>
              <p className="text-[10px] text-text-disabled">{formatFileSize(uploadedFile.size)}</p>
            </div>
            <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
          </div>
        )}

        {uploadedFiles && uploadedFiles.length > 0 && !isUploading && (
          <div className="mt-2 p-2 bg-desktop-card rounded-desktop border border-desktop-border">
            <div className="flex items-center justify-between mb-1.5">
              <div>
                <p className="text-xs text-text-primary">{fileCount} files selected</p>
                <p className="text-[10px] text-text-disabled">Total: {formatFileSize(totalUploadSize)}</p>
              </div>
              <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
            </div>
            <div className="space-y-0.5 max-h-20 overflow-y-auto">
              {uploadedFiles.slice(0, 5).map((file, i) => (
                <div key={i} className="flex items-center justify-between text-[10px]">
                  <span className="text-text-muted truncate">{file.webkitRelativePath || file.name}</span>
                  <span className="text-text-disabled ml-2">{formatFileSize(file.size)}</span>
                </div>
              ))}
              {uploadedFiles.length > 5 && (
                <p className="text-[10px] text-text-disabled text-center">...and {uploadedFiles.length - 5} more</p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Scan Controls */}
      <div className="desktop-panel p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
            <Zap className="h-3.5 w-3.5 text-primary-400" /> Controls
          </h3>
          <button
            onClick={startScan}
            disabled={!hasFiles || isScanning}
            className={`text-xs px-4 py-1.5 rounded-desktop inline-flex items-center gap-1.5 transition-colors ${!hasFiles || isScanning
                ? 'bg-desktop-card text-text-disabled cursor-not-allowed border border-desktop-border'
                : 'btn-primary'
              }`}
          >
            {isScanning ? (
              <>
                <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <><Play className="h-3.5 w-3.5" /> Start Scan</>
            )}
          </button>
        </div>

        {isScanning && (
          <div className="mt-3">
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-text-muted">Scanning with {scanConfig.enablePlugins ? '22+' : '4'} scanners...</span>
              <span className="text-text-primary">{Math.round(uploadProgress)}%</span>
            </div>
            <div className="w-full bg-desktop-border rounded-full h-1.5">
              <div className="bg-primary-600 h-1.5 rounded-full transition-all" style={{ width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* Scan Results Preview */}
      {scanResults && (
        <div className="desktop-panel p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-primary-400" /> Results
            </h3>
            <div className="flex gap-0.5">
              <button className="p-1 text-text-muted hover:text-text-primary hover:bg-white/[0.04] rounded transition-colors">
                <Download className="h-3.5 w-3.5" />
              </button>
              <button className="p-1 text-text-muted hover:text-text-primary hover:bg-white/[0.04] rounded transition-colors">
                <Eye className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-4 gap-3 mb-3">
            {[
              { label: 'Critical', count: scanResults.summary?.critical || 0, color: 'text-red-400' },
              { label: 'High', count: scanResults.summary?.high || 0, color: 'text-amber-400' },
              { label: 'Medium', count: scanResults.summary?.medium || 0, color: 'text-yellow-400' },
              { label: 'Low', count: scanResults.summary?.low || 0, color: 'text-blue-400' }
            ].map(({ label, count, color }) => (
              <div key={label} className="text-center p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                <div className={`text-base font-semibold ${color}`}>{count}</div>
                <div className="text-[10px] text-text-disabled">{label}</div>
              </div>
            ))}
          </div>

          <div className="space-y-1">
            {scanResults.findings?.slice(0, 5).map((finding, index) => (
              <div key={index} className="p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <div className={`w-1.5 h-1.5 rounded-full ${finding.severity === 'critical' ? 'bg-red-400' :
                      finding.severity === 'high' ? 'bg-amber-400' :
                        finding.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                    }`} />
                  <span className="text-xs text-text-primary">{finding.title}</span>
                  {finding.scanner_name && (
                    <span className="text-[10px] text-primary-400 bg-primary-400/5 px-1 rounded">{finding.scanner_name}</span>
                  )}
                </div>
                <p className="text-[11px] text-text-muted mb-0.5">{finding.description}</p>
                <p className="text-[10px] text-text-disabled">L{finding.line_number} · {(finding.confidence * 100).toFixed(0)}%</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default EnhancedScanInterface;
