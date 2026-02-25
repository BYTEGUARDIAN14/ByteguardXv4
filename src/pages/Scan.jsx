import React, { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { Shield, Zap, Lock, Search } from 'lucide-react'
import toast from 'react-hot-toast'
import EnhancedScanInterface from '../components/EnhancedScanInterface'
import { scanService } from '../services/api'

const Scan = () => {
  const [files, setFiles] = useState([])
  const [directoryPath, setDirectoryPath] = useState('')
  const [scanMode, setScanMode] = useState('upload')
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
    maxSize: 5 * 1024 * 1024,
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
        const formData = new FormData()
        files.forEach(({ file }) => {
          formData.append('files', file)
        })

        setScanProgress({ stage: 'uploading', progress: 50 })
        const uploadResponse = await scanService.uploadFiles(formData)
        scanId = uploadResponse.scan_id
        setScanProgress({ stage: 'uploading', progress: 100 })
      }

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

      if (scanResponse.total_findings > 0) {
        setTimeout(() => {
          // navigate to report
        }, 2000)
      }

    } catch (error) {
      console.error('Scan error:', error)
      let errorMessage = error.message || 'Scan failed. Please try again.'
      if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
        errorMessage = 'The scan timed out. The file might be too large or complex.'
      }
      toast.error(errorMessage)
      setScanResults(null)
    } finally {
      setIsScanning(false)
      setScanProgress(null)
    }
  }

  if (isScanning) {
    return (
      <div className="p-6 flex items-center justify-center h-full">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-primary-600 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-text-muted">Analyzing your code for security vulnerabilities...</p>
          {scanProgress && (
            <div className="mt-3 w-48 mx-auto">
              <div className="h-1 bg-desktop-border rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary-600 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress.progress}%` }}
                />
              </div>
              <p className="text-xs text-text-disabled mt-1 capitalize">{scanProgress.stage}</p>
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6 overflow-y-auto">
      {/* Page Title */}
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Security Scanner</h1>
        <p className="text-xs text-text-muted mt-0.5">
          Upload files or specify a directory to scan for vulnerabilities
        </p>
      </div>

      {/* Feature Cards (compact) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { icon: Shield, title: 'Security', desc: 'Multi-layer detection' },
          { icon: Zap, title: 'Fast', desc: 'Real-time results' },
          { icon: Lock, title: 'Secrets', desc: 'Credential detection' },
          { icon: Search, title: 'Deep Analysis', desc: 'Code inspection' }
        ].map((feature, index) => (
          <div key={index} className="desktop-panel p-3 flex items-center gap-3">
            <div className="p-1.5 rounded-desktop bg-white/[0.04] text-primary-400">
              <feature.icon className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-text-primary">{feature.title}</p>
              <p className="text-[11px] text-text-muted">{feature.desc}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Scan Interface */}
      <div className="desktop-panel p-5">
        <EnhancedScanInterface />
      </div>
    </div>
  )
}

export default Scan
