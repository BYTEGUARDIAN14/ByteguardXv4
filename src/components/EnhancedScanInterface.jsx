import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
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

// Security constants for file/folder uploads
const UPLOAD_CONSTANTS = {
  MAX_TOTAL_SIZE: 2 * 1024 * 1024 * 1024, // 2GB
  MAX_INDIVIDUAL_FILE_SIZE: 500 * 1024 * 1024, // 500MB per file
  MAX_FILE_COUNT: 10000, // Maximum files per upload
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
  DANGEROUS_PATTERNS: [
    /\.\./g, // Path traversal
    /^\//, // Absolute paths
    /^\\/, // Windows absolute paths
    /\0/, // Null bytes
    /[\x00-\x1f\x7f-\x9f]/, // Control characters
  ]
};

const EnhancedScanInterface = () => {
  const navigate = useNavigate();
  const [scanConfig, setScanConfig] = useState({
    mode: 'comprehensive',
    enablePlugins: true,
    selectedPlugins: [],
    confidenceThreshold: 0.6,
    enableML: true
  });
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [availablePlugins, setAvailablePlugins] = useState([]);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [uploadMode, setUploadMode] = useState('file'); // 'file' or 'folder'
  const [uploadProgress, setUploadProgress] = useState(0);
  const [totalUploadSize, setTotalUploadSize] = useState(0);
  const [fileCount, setFileCount] = useState(0);
  const [isUploading, setIsUploading] = useState(false);

  useEffect(() => {
    fetchAvailablePlugins();
  }, []);

  // Security validation functions
  const validateFileName = (fileName) => {
    // Check for dangerous patterns
    for (const pattern of UPLOAD_CONSTANTS.DANGEROUS_PATTERNS) {
      if (pattern.test(fileName)) {
        return { valid: false, reason: 'File path contains dangerous characters' };
      }
    }

    // Check file extension
    const extension = fileName.split('.').pop()?.toLowerCase();
    if (!extension) {
      return { valid: false, reason: 'File has no extension' };
    }

    if (UPLOAD_CONSTANTS.BLOCKED_EXTENSIONS.includes(extension)) {
      return { valid: false, reason: `File type .${extension} is not allowed for security reasons` };
    }

    if (!UPLOAD_CONSTANTS.ALLOWED_EXTENSIONS.includes(extension)) {
      return { valid: false, reason: `File type .${extension} is not supported` };
    }

    return { valid: true };
  };

  const validateFileSize = (file) => {
    if (file.size > UPLOAD_CONSTANTS.MAX_INDIVIDUAL_FILE_SIZE) {
      return {
        valid: false,
        reason: `File ${file.name} is too large (${formatFileSize(file.size)}). Maximum individual file size is ${formatFileSize(UPLOAD_CONSTANTS.MAX_INDIVIDUAL_FILE_SIZE)}`
      };
    }
    return { valid: true };
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const validateTotalUpload = (files) => {
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);

    if (totalSize > UPLOAD_CONSTANTS.MAX_TOTAL_SIZE) {
      return {
        valid: false,
        reason: `Total upload size (${formatFileSize(totalSize)}) exceeds 2GB limit`
      };
    }

    if (files.length > UPLOAD_CONSTANTS.MAX_FILE_COUNT) {
      return {
        valid: false,
        reason: `Too many files (${files.length}). Maximum is ${UPLOAD_CONSTANTS.MAX_FILE_COUNT} files`
      };
    }

    return { valid: true, totalSize, fileCount: files.length };
  };

  const fetchAvailablePlugins = async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch('/api/v2/plugins', {
        credentials: 'include',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        }
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();

        // Validate response structure
        if (!data || typeof data !== 'object') {
          throw new Error('Invalid response format');
        }

        // Safely extract plugins with comprehensive null checks
        const plugins = data?.marketplace?.categories?.flatMap(cat => {
          if (!cat || !Array.isArray(cat.plugins)) return [];
          return cat.plugins.filter(plugin =>
            plugin &&
            typeof plugin === 'object' &&
            (plugin.name || plugin.manifest?.name)
          );
        }) || [];

        setAvailablePlugins(plugins);
      } else {
        console.warn('Failed to fetch plugins:', response.status, response.statusText);
        setAvailablePlugins([]); // Set empty array as fallback
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        console.warn('Plugin fetch request timed out');
      } else {
        console.error('Failed to fetch plugins:', error);
      }
      setAvailablePlugins([]); // Set empty array as fallback
    }
  };

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setIsUploading(true);
    setUploadProgress(0);

    try {
      // Validate each file
      const validationErrors = [];
      const validFiles = [];

      for (const file of files) {
        // Validate file name
        const nameValidation = validateFileName(file.name);
        if (!nameValidation.valid) {
          validationErrors.push(`${file.name}: ${nameValidation.reason}`);
          continue;
        }

        // Validate file size
        const sizeValidation = validateFileSize(file);
        if (!sizeValidation.valid) {
          validationErrors.push(sizeValidation.reason);
          continue;
        }

        validFiles.push(file);
      }

      // Show validation errors if any
      if (validationErrors.length > 0) {
        const errorMessage = validationErrors.slice(0, 5).join('\n');
        const remainingErrors = validationErrors.length > 5 ? `\n... and ${validationErrors.length - 5} more errors` : '';
        alert(`Upload validation failed:\n${errorMessage}${remainingErrors}`);

        if (validFiles.length === 0) {
          event.target.value = '';
          setIsUploading(false);
          return;
        }
      }

      // Validate total upload
      const totalValidation = validateTotalUpload(validFiles);
      if (!totalValidation.valid) {
        alert(totalValidation.reason);
        event.target.value = '';
        setIsUploading(false);
        return;
      }

      // Update state with valid files
      if (uploadMode === 'file' && validFiles.length === 1) {
        setUploadedFile(validFiles[0]);
        setUploadedFiles([]);
      } else {
        setUploadedFiles(validFiles);
        setUploadedFile(null);
      }

      setTotalUploadSize(totalValidation.totalSize);
      setFileCount(totalValidation.fileCount);

      // Show success message
      if (validationErrors.length > 0) {
        alert(`Upload partially successful: ${validFiles.length} files accepted, ${validationErrors.length} files rejected.`);
      } else {
        console.log(`Upload successful: ${validFiles.length} files (${formatFileSize(totalValidation.totalSize)}) ready for scanning.`);
      }

    } catch (error) {
      console.error('Upload error:', error);
      alert('An error occurred during file upload. Please try again.');
      event.target.value = '';
    } finally {
      setIsUploading(false);
      setUploadProgress(100);
    }
  };

  const handleFolderUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setIsUploading(true);
    setUploadProgress(0);

    try {
      // Process folder structure
      const folderStructure = {};
      const validFiles = [];
      const validationErrors = [];

      // Group files by folder and validate
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setUploadProgress((i / files.length) * 50); // First 50% for validation

        // Extract folder path (webkitRelativePath includes folder structure)
        const relativePath = file.webkitRelativePath || file.name;
        const folderPath = relativePath.substring(0, relativePath.lastIndexOf('/')) || 'root';

        // Initialize folder structure
        if (!folderStructure[folderPath]) {
          folderStructure[folderPath] = [];
        }

        // Validate file name and path
        const nameValidation = validateFileName(relativePath);
        if (!nameValidation.valid) {
          validationErrors.push(`${relativePath}: ${nameValidation.reason}`);
          continue;
        }

        // Validate file size
        const sizeValidation = validateFileSize(file);
        if (!sizeValidation.valid) {
          validationErrors.push(sizeValidation.reason);
          continue;
        }

        // Add to valid files and folder structure
        validFiles.push(file);
        folderStructure[folderPath].push(file);
      }

      // Validate total upload
      const totalValidation = validateTotalUpload(validFiles);
      if (!totalValidation.valid) {
        alert(totalValidation.reason);
        event.target.value = '';
        setIsUploading(false);
        return;
      }

      // Show validation summary
      if (validationErrors.length > 0) {
        const errorMessage = validationErrors.slice(0, 5).join('\n');
        const remainingErrors = validationErrors.length > 5 ? `\n... and ${validationErrors.length - 5} more errors` : '';
        alert(`Folder upload validation:\n${errorMessage}${remainingErrors}\n\nAccepted: ${validFiles.length} files`);

        if (validFiles.length === 0) {
          event.target.value = '';
          setIsUploading(false);
          return;
        }
      }

      // Update state
      setUploadedFiles(validFiles);
      setUploadedFile(null);
      setTotalUploadSize(totalValidation.totalSize);
      setFileCount(totalValidation.fileCount);

      // Log folder structure
      console.log('Folder structure:', Object.keys(folderStructure).map(folder =>
        `${folder}: ${folderStructure[folder].length} files`
      ).join(', '));

      setUploadProgress(100);
      alert(`Folder upload successful: ${Object.keys(folderStructure).length} folders, ${validFiles.length} files (${formatFileSize(totalValidation.totalSize)})`);

    } catch (error) {
      console.error('Folder upload error:', error);
      alert('An error occurred during folder upload. Please try again.');
      event.target.value = '';
    } finally {
      setIsUploading(false);
    }
  };

  const startScan = async () => {
    // Check if we have files to scan
    const hasFiles = uploadedFile || (uploadedFiles && uploadedFiles.length > 0);
    if (!hasFiles) {
      alert('Please upload files or a folder to scan');
      return;
    }

    setIsScanning(true);
    setScanResults(null);
    setUploadProgress(0);
    // Start proper progress simulation
    let progressInterval;
    let currentProgress = 0;

    // Reset any previous progress
    setUploadProgress(0);

    // Animate progress 0-90%
    progressInterval = setInterval(() => {
      currentProgress += Math.random() * 5;
      if (currentProgress > 90) {
        currentProgress = 90;
        clearInterval(progressInterval);
      }
      setUploadProgress(Math.min(90, Math.round(currentProgress)));
    }, 500);

    try {
      const formData = new FormData();

      // Handle single file upload
      if (uploadedFile) {
        formData.append('files', uploadedFile);
        formData.append('upload_type', 'single_file');
      }
      // Handle multiple files/folder upload
      else if (uploadedFiles && uploadedFiles.length > 0) {
        // Append each file with relative path information
        uploadedFiles.forEach((file, index) => {
          formData.append('files', file);
          // Include relative path for folder structure
          if (file.webkitRelativePath) {
            formData.append(`file_paths[${index}]`, file.webkitRelativePath);
          }
        });
        formData.append('upload_type', 'multiple_files');
        formData.append('file_count', uploadedFiles.length.toString());
        formData.append('total_size', totalUploadSize.toString());
      }

      // Add scan configuration
      formData.append('scan_mode', scanConfig.mode);
      formData.append('enable_plugins', scanConfig.enablePlugins);
      formData.append('confidence_threshold', scanConfig.confidenceThreshold);
      formData.append('enable_ml', scanConfig.enableML);

      if (scanConfig.selectedPlugins.length > 0) {
        formData.append('selected_plugins', JSON.stringify(scanConfig.selectedPlugins));
      }

      // Use appropriate endpoint based on upload type
      const endpoint = uploadedFiles && uploadedFiles.length > 1 ? '/api/scan/folder' : '/api/scan/file';

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort('Scan timed out after 15 minutes'), 900000); // 15 minute timeout for scans

      const response = await fetch(endpoint, {
        method: 'POST',
        body: formData,
        credentials: 'include',
        signal: controller.signal,
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
          // Don't set Content-Type for FormData, let browser set it with boundary
        }
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const results = await response.json();
        // Validate response structure
        if (results && typeof results === 'object') {
          setScanResults(results);

          // Show scan summary
          const fileCount = uploadedFiles ? uploadedFiles.length : 1;
          const summary = `Scan completed: ${fileCount} files processed`;
          if (results.summary) {
            console.log(`${summary}. Found ${results.summary.total_issues || 0} issues.`);
          }

          // Redirect to report page
          navigate(`/report/${results.scan_id}`, { state: { scanResults: results } });

        } else {
          throw new Error('Invalid response format');
        }
      } else {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Scan failed with status ${response.status}`);
      }
    } catch (error) {
      console.error('Scan error:', error);
      let errorMessage = error.message || 'Scan failed. Please try again.';

      if (error.name === 'AbortError' || error.message.includes('timeout') || error.message.includes('aborted')) {
        errorMessage = 'Scan timed out. The file might be too large or complex. Try uploading smaller batches.';
      }

      alert(errorMessage);
    } finally {
      if (progressInterval) clearInterval(progressInterval);
      setIsScanning(false);
      setUploadProgress(100);
    }
  };

  const renderScanConfiguration = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card mb-6"
    >
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
        <Settings className="w-5 h-5 mr-2 text-cyan-400" />
        Scan Configuration
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {/* Scan Mode */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Scan Mode
          </label>
          <select
            value={scanConfig.mode}
            onChange={(e) => setScanConfig({ ...scanConfig, mode: e.target.value })}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="static">Static Analysis</option>
            <option value="dynamic">Dynamic Analysis</option>
            <option value="hybrid">Hybrid Scan</option>
            <option value="ml_enhanced">ML Enhanced</option>
            <option value="comprehensive">Comprehensive</option>
          </select>
        </div>

        {/* Confidence Threshold */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Confidence Threshold
          </label>
          <input
            type="range"
            min="0.1"
            max="1.0"
            step="0.1"
            value={scanConfig.confidenceThreshold}
            onChange={(e) => setScanConfig({ ...scanConfig, confidenceThreshold: parseFloat(e.target.value) })}
            className="w-full"
          />
          <div className="text-xs text-gray-400 mt-1">
            {(scanConfig.confidenceThreshold * 100).toFixed(0)}%
          </div>
        </div>

        {/* Enable Plugins */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Plugin System
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={scanConfig.enablePlugins}
              onChange={(e) => setScanConfig({ ...scanConfig, enablePlugins: e.target.checked })}
              className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
            />
            <span className="text-white">Enable Plugins</span>
          </div>
        </div>

        {/* Enable ML */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            AI/ML Features
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={scanConfig.enableML}
              onChange={(e) => setScanConfig({ ...scanConfig, enableML: e.target.checked })}
              className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
            />
            <span className="text-white">Enable ML</span>
          </div>
        </div>
      </div>

      {/* Plugin Selection */}
      {scanConfig.enablePlugins && (
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Select Plugins (leave empty for all)
          </label>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-40 overflow-y-auto">
            {Array.isArray(availablePlugins) && availablePlugins.slice(0, 12).map((plugin, index) => {
              // Safe plugin name extraction with fallbacks
              const pluginName = plugin?.manifest?.name || plugin?.name || `plugin-${index}`;
              const displayName = plugin?.name || pluginName?.replace(/_/g, ' ') || 'Unknown Plugin';

              return (
                <label key={`plugin-${index}-${pluginName}`} className="flex items-center space-x-2 text-sm">
                  <input
                    type="checkbox"
                    checked={scanConfig.selectedPlugins.includes(pluginName)}
                    onChange={(e) => {
                      try {
                        if (e.target.checked) {
                          setScanConfig(prev => ({
                            ...prev,
                            selectedPlugins: [...prev.selectedPlugins, pluginName]
                          }));
                        } else {
                          setScanConfig(prev => ({
                            ...prev,
                            selectedPlugins: prev.selectedPlugins.filter(p => p !== pluginName)
                          }));
                        }
                      } catch (error) {
                        console.error('Error updating plugin selection:', error);
                      }
                    }}
                    className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
                  />
                  <span className="text-gray-300 truncate" title={displayName}>
                    {displayName}
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      )}
    </motion.div>
  );

  const renderFileUpload = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="glass-card mb-6"
    >
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
        <Upload className="w-5 h-5 mr-2 text-cyan-400" />
        File & Folder Upload
      </h3>

      {/* Upload Mode Toggle */}
      <div className="flex space-x-4 mb-4">
        <button
          onClick={() => setUploadMode('file')}
          className={`px-4 py-2 rounded-lg transition-all duration-200 ${uploadMode === 'file'
            ? 'bg-cyan-600 text-white'
            : 'bg-white/10 text-gray-300 hover:bg-white/20'
            }`}
        >
          Single File
        </button>
        <button
          onClick={() => setUploadMode('folder')}
          className={`px-4 py-2 rounded-lg transition-all duration-200 ${uploadMode === 'folder'
            ? 'bg-cyan-600 text-white'
            : 'bg-white/10 text-gray-300 hover:bg-white/20'
            }`}
        >
          Folder/Multiple Files
        </button>
      </div>

      {/* Upload Area */}
      <div className="border-2 border-dashed border-white/20 rounded-lg p-8 text-center">
        {uploadMode === 'file' ? (
          <>
            <input
              type="file"
              onChange={handleFileUpload}
              className="hidden"
              id="file-upload"
              accept=".py,.js,.jsx,.ts,.tsx,.java,.cs,.php,.go,.rb,.cpp,.c,.h,.json,.yaml,.yml,.tf,.dockerfile,.html,.css,.scss,.md,.txt,.sql,.sh,.bat,.ps1"
            />
            <label htmlFor="file-upload" className="cursor-pointer">
              <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <p className="text-white mb-2">
                {uploadedFile ? uploadedFile.name : 'Click to upload a single file'}
              </p>
              <p className="text-gray-400 text-sm">
                Max size: 500MB per file
              </p>
            </label>
          </>
        ) : (
          <>
            <input
              type="file"
              onChange={handleFolderUpload}
              className="hidden"
              id="folder-upload"
              webkitdirectory=""
              mozdirectory=""
              directory=""
              multiple
            />
            <input
              type="file"
              onChange={handleFileUpload}
              className="hidden"
              id="multiple-file-upload"
              multiple
              accept=".py,.js,.jsx,.ts,.tsx,.java,.cs,.php,.go,.rb,.cpp,.c,.h,.json,.yaml,.yml,.tf,.dockerfile,.html,.css,.scss,.md,.txt,.sql,.sh,.bat,.ps1"
            />
            <div className="space-y-4">
              <label htmlFor="folder-upload" className="cursor-pointer block">
                <FolderOpen className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-white mb-2">Click to upload entire folder</p>
                <p className="text-gray-400 text-sm">Includes all subdirectories</p>
              </label>
              <div className="text-gray-400">or</div>
              <label htmlFor="multiple-file-upload" className="cursor-pointer block">
                <FileText className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                <p className="text-white mb-2">Select multiple files</p>
              </label>
            </div>
          </>
        )}
      </div>

      {/* Upload Progress */}
      {isUploading && (
        <div className="mt-4 p-3 bg-black/20 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-white text-sm">Processing upload...</span>
            <span className="text-cyan-400 text-sm">{uploadProgress}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-gradient-to-r from-cyan-500 to-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${uploadProgress}%` }}
            ></div>
          </div>
        </div>
      )}

      {/* Single File Display */}
      {uploadedFile && !isUploading && (
        <div className="mt-4 p-3 bg-black/20 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-white font-medium">{uploadedFile.name}</div>
              <div className="text-gray-400 text-sm">
                {formatFileSize(uploadedFile.size)}
              </div>
            </div>
            <CheckCircle className="w-5 h-5 text-green-400" />
          </div>
        </div>
      )}

      {/* Multiple Files Display */}
      {uploadedFiles && uploadedFiles.length > 0 && !isUploading && (
        <div className="mt-4 p-3 bg-black/20 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-white font-medium">
                {fileCount} files selected
              </div>
              <div className="text-gray-400 text-sm">
                Total size: {formatFileSize(totalUploadSize)}
              </div>
            </div>
            <CheckCircle className="w-5 h-5 text-green-400" />
          </div>

          {/* File List (show first 5 files) */}
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {uploadedFiles.slice(0, 5).map((file, index) => (
              <div key={index} className="flex items-center justify-between text-sm">
                <span className="text-gray-300 truncate">
                  {file.webkitRelativePath || file.name}
                </span>
                <span className="text-gray-400 ml-2">
                  {formatFileSize(file.size)}
                </span>
              </div>
            ))}
            {uploadedFiles.length > 5 && (
              <div className="text-gray-400 text-sm text-center pt-2">
                ... and {uploadedFiles.length - 5} more files
              </div>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );

  const renderScanControls = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="glass-card mb-6"
    >
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white flex items-center">
          <Zap className="w-5 h-5 mr-2 text-cyan-400" />
          Scan Controls
        </h3>

        <div className="flex items-center space-x-3">
          <motion.button
            onClick={startScan}
            disabled={(!uploadedFile && (!uploadedFiles || uploadedFiles.length === 0)) || isScanning}
            className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-medium transition-all ${(!uploadedFile && (!uploadedFiles || uploadedFiles.length === 0)) || isScanning
              ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-600 hover:to-blue-700'
              }`}
            whileHover={(!uploadedFile && (!uploadedFiles || uploadedFiles.length === 0)) || isScanning ? {} : { scale: 1.02 }}
            whileTap={!uploadedFile || isScanning ? {} : { scale: 0.98 }}
          >
            {isScanning ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Start Scan</span>
              </>
            )}
          </motion.button>
        </div>
      </div>

      {isScanning && (
        <div className="mt-4">
          <div className="flex items-center justify-between text-sm text-gray-400 mb-2">
            <span>Scanning with {scanConfig.enablePlugins ? '22+' : '4'} scanners...</span>
            <span>Progress: {Math.round(uploadProgress)}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div className="bg-gradient-to-r from-cyan-500 to-blue-600 h-2 rounded-full transition-all duration-300" style={{ width: `${uploadProgress}%` }} />
          </div>
        </div>
      )}
    </motion.div>
  );

  const renderScanResults = () => {
    if (!scanResults) return null;

    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white flex items-center">
            <Shield className="w-5 h-5 mr-2 text-cyan-400" />
            Scan Results
          </h3>
          <div className="flex items-center space-x-2">
            <button className="p-2 text-gray-400 hover:text-white transition-colors">
              <Download className="w-4 h-4" />
            </button>
            <button className="p-2 text-gray-400 hover:text-white transition-colors">
              <Eye className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">
              {scanResults.summary?.critical || 0}
            </div>
            <div className="text-gray-400 text-sm">Critical</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-400">
              {scanResults.summary?.high || 0}
            </div>
            <div className="text-gray-400 text-sm">High</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">
              {scanResults.summary?.medium || 0}
            </div>
            <div className="text-gray-400 text-sm">Medium</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-400">
              {scanResults.summary?.low || 0}
            </div>
            <div className="text-gray-400 text-sm">Low</div>
          </div>
        </div>

        <div className="space-y-3">
          {scanResults.findings?.slice(0, 5).map((finding, index) => (
            <div key={index} className="p-4 bg-black/20 rounded-lg border border-white/10">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <div className={`w-2 h-2 rounded-full ${finding.severity === 'critical' ? 'bg-red-400' :
                      finding.severity === 'high' ? 'bg-orange-400' :
                        finding.severity === 'medium' ? 'bg-yellow-400' :
                          'bg-blue-400'
                      }`} />
                    <span className="text-white font-medium">{finding.title}</span>
                    {finding.scanner_name && (
                      <span className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded">
                        {finding.scanner_name}
                      </span>
                    )}
                  </div>
                  <p className="text-gray-400 text-sm mb-2">{finding.description}</p>
                  <div className="text-xs text-gray-500">
                    Line {finding.line_number} • Confidence: {(finding.confidence * 100).toFixed(0)}%
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Enhanced Security Scanner</h2>
          <p className="text-gray-400">
            Advanced scanning with 22+ plugins and AI-powered analysis
          </p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-400">
          <Puzzle className="w-4 h-4" />
          <span>{availablePlugins.length} plugins available</span>
        </div>
      </div>

      {renderScanConfiguration()}
      {renderFileUpload()}
      {renderScanControls()}
      {renderScanResults()}
    </div>
  );
};

export default EnhancedScanInterface;
