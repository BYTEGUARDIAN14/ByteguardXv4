import React, { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useDropzone } from 'react-dropzone'
import toast from 'react-hot-toast'
import { 
  Upload, 
  File, 
  Folder, 
  X, 
  Play, 
  Loader2,
  AlertTriangle,
  CheckCircle,
  Shield,
  Bug,
  Cpu
} from 'lucide-react'
import ScanResults from '../components/ScanResults'
import ScanProgress from '../components/ScanProgress'
import apiService from '../services/api'

const { scan: scanService } = apiService

const Scan = () => {
  const navigate = useNavigate()
  const [files, setFiles] = useState([])
  const [directoryPath, setDirectoryPath] = useState('')
  const [scanMode, setScanMode] = useState('upload') // 'upload' or 'directory'
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(null)
  const [scanResults, setScanResults] = useState(null)
  const [scanOptions, setScanOptions] = useState({
    secrets: true,
    dependencies: true,
    aiPatterns: true,
    generateFixes: true
  })

  const onDrop = useCallback((acceptedFiles) => {
    const newFiles = acceptedFiles.map(file => ({
      file,
      id: Math.random().toString(36).substr(2, 9),
      name: file.name,
      size: file.size,
      type: file.type
    }))
    setFiles(prev => [...prev, ...newFiles])
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/*': ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala'],
      'application/json': ['.json'],
      'application/xml': ['.xml'],
      'text/yaml': ['.yml', '.yaml'],
      'text/plain': ['.txt', '.md', '.rst', '.dockerfile', '.sh', '.bat', '.ps1', '.sql', '.html', '.css', '.scss', '.sass', '.less']
    },
    maxSize: 5 * 1024 * 1024, // 5MB
    onDropRejected: (rejectedFiles) => {
      rejectedFiles.forEach(({ file, errors }) => {
        errors.forEach(error => {
          if (error.code === 'file-too-large') {
            toast.error(`File ${file.name} is too large (max 5MB)`)
          } else if (error.code === 'file-invalid-type') {
            toast.error(`File ${file.name} has unsupported type`)
          }
        })
      })
    }
  })

  const removeFile = (id) => {
    setFiles(files.filter(file => file.id !== id))
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const handleScan = async () => {
    if (scanMode === 'upload' && files.length === 0) {
      toast.error('Please upload files to scan')
      return
    }

    if (scanMode === 'directory' && !directoryPath.trim()) {
      toast.error('Please enter a directory path')
      return
    }

    setIsScanning(true)
    setScanProgress({ stage: 'uploading', progress: 0 })
    setScanResults(null)

    try {
      let scanId

      if (scanMode === 'upload') {
        // Upload files
        const formData = new FormData()
        files.forEach(({ file }) => {
          formData.append('files', file)
        })

        setScanProgress({ stage: 'uploading', progress: 50 })
        const uploadResponse = await scanService.uploadFiles(formData)
        scanId = uploadResponse.scan_id
        setScanProgress({ stage: 'uploading', progress: 100 })
      }

      // Start comprehensive scan
      setScanProgress({ stage: 'scanning', progress: 0 })
      
      let scanResponse
      if (scanMode === 'directory') {
        scanResponse = await scanService.scanDirectory(directoryPath)
        scanId = scanResponse.scan_id
      } else {
        scanResponse = await scanService.scanAll(scanId)
      }

      setScanProgress({ stage: 'scanning', progress: 100 })
      setScanResults(scanResponse)
      
      toast.success(`Scan completed! Found ${scanResponse.total_findings} issues`)

      // Navigate to report page with scan results
      if (scanResponse.total_findings > 0) {
        setTimeout(() => {
          navigate(`/report/${scanId}`, { state: { scanResults: scanResponse } })
        }, 2000)
      }

    } catch (error) {
      console.error('Scan error:', error)
      toast.error(error.message || 'Scan failed. Please try again.')
    } finally {
      setIsScanning(false)
      setScanProgress(null)
    }
  }

  const getScanTypeIcon = (type) => {
    switch (type) {
      case 'secrets': return Shield
      case 'dependencies': return Bug
      case 'aiPatterns': return Cpu
      default: return Shield
    }
  }

  return (
    <div className="min-h-screen pt-8 pb-16">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <h1 className="text-4xl font-bold text-white mb-4">
            Security Scan
          </h1>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Upload your files or specify a directory to scan for security vulnerabilities, 
            secrets, and AI-generated anti-patterns.
          </p>
        </motion.div>

        {/* Scan Mode Toggle */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-8"
        >
          <div className="flex justify-center">
            <div className="bg-gray-900 p-1 rounded-lg border border-gray-700">
              <button
                onClick={() => setScanMode('upload')}
                className={`px-6 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  scanMode === 'upload'
                    ? 'bg-primary-500 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <Upload className="inline-block w-4 h-4 mr-2" />
                Upload Files
              </button>
              <button
                onClick={() => setScanMode('directory')}
                className={`px-6 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  scanMode === 'directory'
                    ? 'bg-primary-500 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <Folder className="inline-block w-4 h-4 mr-2" />
                Directory Path
              </button>
            </div>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Scan Area */}
          <div className="lg:col-span-2">
            {scanMode === 'upload' ? (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="card"
              >
                {/* File Upload Area */}
                <div
                  {...getRootProps()}
                  className={`
                    border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-200
                    ${isDragActive 
                      ? 'border-primary-500 bg-primary-500 bg-opacity-5' 
                      : 'border-gray-600 hover:border-gray-500'
                    }
                  `}
                >
                  <input {...getInputProps()} />
                  <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                  
                  {isDragActive ? (
                    <p className="text-primary-400 text-lg font-medium">
                      Drop files here to upload
                    </p>
                  ) : (
                    <div>
                      <p className="text-gray-300 text-lg font-medium mb-2">
                        Drag & drop files here, or click to select
                      </p>
                      <p className="text-gray-500 text-sm">
                        Supports: Python, JavaScript, Java, C++, Go, Rust, PHP, and more
                      </p>
                      <p className="text-gray-500 text-xs mt-1">
                        Max file size: 5MB
                      </p>
                    </div>
                  )}
                </div>

                {/* Uploaded Files List */}
                {files.length > 0 && (
                  <div className="mt-6">
                    <h3 className="text-lg font-medium text-white mb-4">
                      Uploaded Files ({files.length})
                    </h3>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {files.map((fileItem) => (
                        <div
                          key={fileItem.id}
                          className="flex items-center justify-between p-3 bg-gray-800 rounded-lg"
                        >
                          <div className="flex items-center space-x-3">
                            <File className="h-5 w-5 text-gray-400" />
                            <div>
                              <p className="text-sm font-medium text-white">
                                {fileItem.name}
                              </p>
                              <p className="text-xs text-gray-400">
                                {formatFileSize(fileItem.size)}
                              </p>
                            </div>
                          </div>
                          <button
                            onClick={() => removeFile(fileItem.id)}
                            className="p-1 text-gray-400 hover:text-red-400 transition-colors duration-200"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="card"
              >
                <h3 className="text-lg font-medium text-white mb-4">
                  Directory Path
                </h3>
                <input
                  type="text"
                  value={directoryPath}
                  onChange={(e) => setDirectoryPath(e.target.value)}
                  placeholder="/path/to/your/project"
                  className="input"
                />
                <p className="text-sm text-gray-400 mt-2">
                  Enter the absolute path to the directory you want to scan
                </p>
              </motion.div>
            )}

            {/* Scan Progress */}
            {isScanning && scanProgress && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-6"
              >
                <ScanProgress progress={scanProgress} />
              </motion.div>
            )}

            {/* Scan Results */}
            {scanResults && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-6"
              >
                <ScanResults results={scanResults} />
              </motion.div>
            )}
          </div>

          {/* Scan Options Sidebar */}
          <div className="space-y-6">
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
              className="card"
            >
              <h3 className="text-lg font-medium text-white mb-4">
                Scan Options
              </h3>
              
              <div className="space-y-4">
                {Object.entries(scanOptions).map(([key, value]) => {
                  const labels = {
                    secrets: 'Secret Detection',
                    dependencies: 'Dependency Scan',
                    aiPatterns: 'AI Pattern Analysis',
                    generateFixes: 'Generate Fixes'
                  }
                  
                  const descriptions = {
                    secrets: 'Find hardcoded API keys and credentials',
                    dependencies: 'Check for vulnerable packages',
                    aiPatterns: 'Detect unsafe AI-generated patterns',
                    generateFixes: 'Provide fix suggestions'
                  }

                  const Icon = getScanTypeIcon(key)

                  return (
                    <label key={key} className="flex items-start space-x-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={value}
                        onChange={(e) => setScanOptions(prev => ({
                          ...prev,
                          [key]: e.target.checked
                        }))}
                        className="mt-1 h-4 w-4 text-primary-500 bg-gray-800 border-gray-600 rounded focus:ring-primary-500 focus:ring-2"
                      />
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <Icon className="h-4 w-4 text-primary-400" />
                          <span className="text-sm font-medium text-white">
                            {labels[key]}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 mt-1">
                          {descriptions[key]}
                        </p>
                      </div>
                    </label>
                  )
                })}
              </div>
            </motion.div>

            {/* Scan Button */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.4 }}
            >
              <button
                onClick={handleScan}
                disabled={isScanning || (scanMode === 'upload' && files.length === 0)}
                className="w-full btn-primary text-lg py-4 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="animate-spin h-5 w-5 mr-2" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Play className="h-5 w-5 mr-2" />
                    Start Scan
                  </>
                )}
              </button>
            </motion.div>

            {/* Info Card */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5 }}
              className="card bg-primary-500 bg-opacity-5 border-primary-500 border-opacity-20"
            >
              <div className="flex items-start space-x-3">
                <Shield className="h-5 w-5 text-primary-400 mt-0.5" />
                <div>
                  <h4 className="text-sm font-medium text-primary-400 mb-1">
                    Privacy First
                  </h4>
                  <p className="text-xs text-gray-300">
                    All scanning happens locally. Your code never leaves your environment.
                  </p>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Scan
