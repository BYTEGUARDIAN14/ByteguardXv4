import React, { useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { useDropzone } from 'react-dropzone'
import { Shield, Zap, Lock, Search, FileText, Settings, Upload, FolderOpen } from 'lucide-react'
import toast from 'react-hot-toast'
import Sidebar from '../components/layout/Sidebar'
import Header from '../components/layout/Header'
import EnhancedScanInterface from '../components/EnhancedScanInterface'
import { slideUp } from '../utils/animations'
import { scanService } from '../services/api'

const Scan = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
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
  const [currentStep, setCurrentStep] = useState(0)

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

  const scanSteps = [
    { title: 'Upload', description: 'Select files or directory' },
    { title: 'Configure', description: 'Set scan options' },
    { title: 'Scan', description: 'Analyze for vulnerabilities' },
    { title: 'Results', description: 'Review findings' }
  ]

  const scanModeOptions = [
    { value: 'upload', label: 'Upload Files' },
    { value: 'directory', label: 'Directory Path' }
  ]

  if (isScanning) {
    return (
      <div className="min-h-screen bg-black text-white">
        <Sidebar
          isCollapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        />

        <div className={`
          transition-all duration-300 pt-16
          ${sidebarCollapsed ? 'ml-20' : 'ml-72'}
        `}>
          <div className="p-8 flex items-center justify-center min-h-screen">
            <ScanningLoader
              text="Analyzing your code for security vulnerabilities..."
              progress={scanProgress?.progress || 0}
            />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen text-white relative">

      <Sidebar
        isCollapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      <Header
        onMenuToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        sidebarCollapsed={sidebarCollapsed}
      />

      <main className={`
        transition-all duration-300 pt-16
        ${sidebarCollapsed ? 'ml-20' : 'ml-72'}
      `}>
        <motion.div
          className="p-8"
          variants={slideUp}
          initial="hidden"
          animate="visible"
        >
          {/* Enhanced Header Section */}
          <div className="mb-12">
            <motion.div
              className="text-center mb-8"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full mb-6 shadow-lg shadow-cyan-500/25">
                <Shield className="h-10 w-10 text-white" />
              </div>
              <h1 className="text-6xl font-bold text-white mb-6 bg-gradient-to-r from-white via-cyan-100 to-blue-100 bg-clip-text text-transparent">
                Security Scanner
              </h1>
              <p className="text-xl text-gray-300 max-w-4xl mx-auto leading-relaxed mb-8">
                Advanced AI-powered vulnerability detection system. Upload your files or specify directory paths
                to scan for security issues, secrets, dependencies, and potential threats with enterprise-grade accuracy.
              </p>

              {/* Feature Highlights */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-5xl mx-auto">
                {[
                  { icon: Shield, title: 'Advanced Security', desc: 'Multi-layer vulnerability detection', color: 'from-red-500 to-pink-500' },
                  { icon: Zap, title: 'Lightning Fast', desc: 'Real-time scanning results', color: 'from-yellow-500 to-orange-500' },
                  { icon: Lock, title: 'Secret Detection', desc: 'Find hardcoded credentials', color: 'from-green-500 to-emerald-500' },
                  { icon: Search, title: 'Deep Analysis', desc: 'Comprehensive code inspection', color: 'from-blue-500 to-cyan-500' }
                ].map((feature, index) => (
                  <motion.div
                    key={index}
                    className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-6 hover:bg-white/10 transition-all duration-300 hover:border-cyan-400/30 hover:shadow-lg hover:shadow-cyan-400/10 group"
                    whileHover={{ y: -8, scale: 1.05 }}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.1 * index }}
                  >
                    <div className="flex flex-col items-center text-center">
                      <div className={`w-12 h-12 bg-gradient-to-r ${feature.color} rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300`}>
                        <feature.icon className="h-6 w-6 text-white" />
                      </div>
                      <h3 className="text-white font-semibold mb-2 text-lg">{feature.title}</h3>
                      <p className="text-gray-400 text-sm leading-relaxed">{feature.desc}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>

          {/* Enhanced Scan Interface */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.6 }}
            className="bg-gradient-to-br from-white/5 to-white/10 backdrop-blur-sm border border-white/10 rounded-2xl p-8 shadow-2xl"
          >
            <EnhancedScanInterface />
          </motion.div>
        </motion.div>
      </main>
    </div>
  )
}

export default Scan
