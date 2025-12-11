import React from 'react'
import { motion } from 'framer-motion'
import { 
  Upload, 
  Search, 
  Shield, 
  Bug, 
  Cpu, 
  CheckCircle, 
  Loader2 
} from 'lucide-react'

const ScanProgress = ({ progress }) => {
  const stages = [
    {
      id: 'uploading',
      label: 'Uploading Files',
      icon: Upload,
      description: 'Securely uploading your files...'
    },
    {
      id: 'scanning',
      label: 'Security Analysis',
      icon: Search,
      description: 'Analyzing code for vulnerabilities...'
    },
    {
      id: 'secrets',
      label: 'Secret Detection',
      icon: Shield,
      description: 'Scanning for hardcoded secrets...'
    },
    {
      id: 'dependencies',
      label: 'Dependency Check',
      icon: Bug,
      description: 'Checking for vulnerable packages...'
    },
    {
      id: 'ai_patterns',
      label: 'AI Pattern Analysis',
      icon: Cpu,
      description: 'Detecting AI-generated anti-patterns...'
    },
    {
      id: 'complete',
      label: 'Complete',
      icon: CheckCircle,
      description: 'Scan completed successfully!'
    }
  ]

  const getCurrentStageIndex = () => {
    return stages.findIndex(stage => stage.id === progress.stage)
  }

  const currentStageIndex = getCurrentStageIndex()

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white mb-2">
          Scanning in Progress
        </h3>
        <p className="text-gray-400">
          {stages[currentStageIndex]?.description || 'Processing...'}
        </p>
      </div>

      {/* Progress Bar */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-300">
            {stages[currentStageIndex]?.label || 'Processing'}
          </span>
          <span className="text-sm text-gray-400">
            {Math.round(progress.progress || 0)}%
          </span>
        </div>
        
        <div className="progress-bar">
          <motion.div
            className="progress-fill"
            initial={{ width: 0 }}
            animate={{ width: `${progress.progress || 0}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
          />
        </div>
      </div>

      {/* Stage Indicators */}
      <div className="space-y-4">
        {stages.map((stage, index) => {
          const Icon = stage.icon
          const isActive = index === currentStageIndex
          const isCompleted = index < currentStageIndex
          const isPending = index > currentStageIndex

          return (
            <motion.div
              key={stage.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`
                flex items-center space-x-4 p-3 rounded-lg transition-all duration-300
                ${isActive 
                  ? 'bg-primary-500 bg-opacity-10 border border-primary-500 border-opacity-20' 
                  : isCompleted
                    ? 'bg-green-500 bg-opacity-10 border border-green-500 border-opacity-20'
                    : 'bg-gray-800 border border-gray-700'
                }
              `}
            >
              <div className={`
                flex items-center justify-center w-10 h-10 rounded-full transition-all duration-300
                ${isActive
                  ? 'bg-primary-500 bg-opacity-20'
                  : isCompleted
                    ? 'bg-green-500 bg-opacity-20'
                    : 'bg-gray-700'
                }
              `}>
                {isActive ? (
                  <Loader2 className="h-5 w-5 text-primary-400 animate-spin" />
                ) : (
                  <Icon className={`
                    h-5 w-5 transition-colors duration-300
                    ${isCompleted 
                      ? 'text-green-400' 
                      : isActive 
                        ? 'text-primary-400' 
                        : 'text-gray-400'
                    }
                  `} />
                )}
              </div>

              <div className="flex-1">
                <h4 className={`
                  font-medium transition-colors duration-300
                  ${isActive 
                    ? 'text-primary-400' 
                    : isCompleted 
                      ? 'text-green-400' 
                      : 'text-gray-400'
                  }
                `}>
                  {stage.label}
                </h4>
                
                {isActive && (
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-sm text-gray-400 mt-1"
                  >
                    {stage.description}
                  </motion.p>
                )}
              </div>

              {isCompleted && (
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                >
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </motion.div>
              )}
            </motion.div>
          )
        })}
      </div>

      {/* Estimated Time */}
      <div className="mt-6 pt-6 border-t border-gray-700">
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-400">
            Estimated time remaining
          </span>
          <span className="text-gray-300 font-medium">
            {currentStageIndex < stages.length - 1 ? '~2 minutes' : 'Almost done!'}
          </span>
        </div>
      </div>

      {/* Security Notice */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1 }}
        className="mt-4 p-3 bg-blue-500 bg-opacity-10 border border-blue-500 border-opacity-20 rounded-lg"
      >
        <div className="flex items-start space-x-2">
          <Shield className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-xs text-blue-400 font-medium">
              Privacy Protected
            </p>
            <p className="text-xs text-gray-400 mt-1">
              All analysis happens locally. Your code never leaves your environment.
            </p>
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}

export default ScanProgress
