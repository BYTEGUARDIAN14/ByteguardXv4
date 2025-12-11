import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, File, X, AlertCircle, CheckCircle } from 'lucide-react'
import { useDropzone } from 'react-dropzone'
import GlassCard from '../ui/GlassCard'

const FileUploadZone = ({ 
  files = [], 
  onFilesAdded, 
  onFileRemoved, 
  maxSize = 5 * 1024 * 1024,
  acceptedTypes = {},
  disabled = false 
}) => {
  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop: onFilesAdded,
    accept: acceptedTypes,
    maxSize,
    disabled,
    multiple: true
  })

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getFileIcon = (file) => {
    const ext = file.name.split('.').pop()?.toLowerCase()
    const iconClass = "h-4 w-4"
    
    switch (ext) {
      case 'js':
      case 'jsx':
      case 'ts':
      case 'tsx':
        return <File className={`${iconClass} text-yellow-400`} />
      case 'py':
        return <File className={`${iconClass} text-blue-400`} />
      case 'java':
        return <File className={`${iconClass} text-red-400`} />
      case 'cpp':
      case 'c':
        return <File className={`${iconClass} text-blue-500`} />
      default:
        return <File className={`${iconClass} text-gray-400`} />
    }
  }

  return (
    <div className="space-y-6">
      {/* Upload Zone */}
      <motion.div
        {...getRootProps()}
        className={`
          relative border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer
          transition-all duration-300 backdrop-blur-sm
          ${isDragActive && !isDragReject 
            ? 'border-cyan-400 bg-cyan-400/10' 
            : isDragReject 
            ? 'border-red-400 bg-red-400/10'
            : 'border-white/20 hover:border-cyan-400/50 hover:bg-white/5'
          }
          ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
        `}
        whileHover={!disabled ? { scale: 1.01 } : {}}
        whileTap={!disabled ? { scale: 0.99 } : {}}
      >
        <input {...getInputProps()} />
        
        <motion.div
          animate={isDragActive ? { scale: 1.1 } : { scale: 1 }}
          transition={{ duration: 0.2 }}
        >
          <Upload className={`
            h-12 w-12 mx-auto mb-4 
            ${isDragActive && !isDragReject 
              ? 'text-cyan-400' 
              : isDragReject 
              ? 'text-red-400'
              : 'text-gray-400'
            }
          `} />
        </motion.div>

        <h3 className="text-lg font-semibold text-white mb-2">
          {isDragActive 
            ? isDragReject 
              ? 'Invalid file type' 
              : 'Drop files here'
            : 'Upload your code files'
          }
        </h3>
        
        <p className="text-gray-400 mb-4">
          Drag & drop files or click to browse
        </p>
        
        <div className="text-xs text-gray-500">
          Supported: .py, .js, .jsx, .ts, .tsx, .java, .cpp, .c, .h, .cs, .php, .rb, .go, .rs
          <br />
          Max file size: {formatFileSize(maxSize)}
        </div>
      </motion.div>

      {/* File List */}
      <AnimatePresence>
        {files.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-2"
          >
            <h4 className="text-sm font-medium text-gray-300 mb-3">
              Uploaded Files ({files.length})
            </h4>
            
            {files.map((fileItem, index) => (
              <motion.div
                key={fileItem.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ delay: index * 0.05 }}
              >
                <GlassCard className="p-3 flex items-center justify-between group">
                  <div className="flex items-center space-x-3">
                    {getFileIcon(fileItem)}
                    <div>
                      <p className="text-sm font-medium text-white">
                        {fileItem.name}
                      </p>
                      <p className="text-xs text-gray-400">
                        {formatFileSize(fileItem.size)}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="h-4 w-4 text-green-400" />
                    <motion.button
                      onClick={() => onFileRemoved(fileItem.id)}
                      className="p-1 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <X className="h-4 w-4" />
                    </motion.button>
                  </div>
                </GlassCard>
              </motion.div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default FileUploadZone
