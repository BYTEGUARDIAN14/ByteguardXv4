import React from 'react'
import { motion } from 'framer-motion'
import { CheckCircle, Circle, Loader2 } from 'lucide-react'

const ProgressIndicator = ({ 
  steps = [], 
  currentStep = 0, 
  variant = 'horizontal',
  showLabels = true,
  animated = true 
}) => {
  const getStepStatus = (index) => {
    if (index < currentStep) return 'completed'
    if (index === currentStep) return 'active'
    return 'pending'
  }

  const getStepIcon = (step, index) => {
    const status = getStepStatus(index)
    const iconClass = "h-5 w-5"
    
    switch (status) {
      case 'completed':
        return <CheckCircle className={`${iconClass} text-green-400`} />
      case 'active':
        return animated ? 
          <Loader2 className={`${iconClass} text-cyan-400 animate-spin`} /> :
          <Circle className={`${iconClass} text-cyan-400 fill-current`} />
      default:
        return <Circle className={`${iconClass} text-gray-500`} />
    }
  }

  const getStepClasses = (index) => {
    const status = getStepStatus(index)
    const baseClasses = "flex items-center justify-center w-10 h-10 rounded-full border-2 transition-all duration-300"
    
    switch (status) {
      case 'completed':
        return `${baseClasses} border-green-400 bg-green-400/20`
      case 'active':
        return `${baseClasses} border-cyan-400 bg-cyan-400/20 shadow-lg shadow-cyan-400/25`
      default:
        return `${baseClasses} border-gray-500 bg-gray-500/10`
    }
  }

  const getConnectorClasses = (index) => {
    const isCompleted = index < currentStep
    return `flex-1 h-0.5 transition-all duration-500 ${
      isCompleted ? 'bg-green-400' : 'bg-gray-600'
    }`
  }

  if (variant === 'vertical') {
    return (
      <div className="space-y-4">
        {steps.map((step, index) => (
          <motion.div
            key={index}
            className="flex items-start space-x-4"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <div className={getStepClasses(index)}>
              {getStepIcon(step, index)}
            </div>
            
            {showLabels && (
              <div className="flex-1 min-w-0">
                <h3 className={`text-sm font-medium ${
                  getStepStatus(index) === 'active' ? 'text-cyan-400' :
                  getStepStatus(index) === 'completed' ? 'text-green-400' :
                  'text-gray-400'
                }`}>
                  {step.title}
                </h3>
                {step.description && (
                  <p className="text-xs text-gray-500 mt-1">
                    {step.description}
                  </p>
                )}
              </div>
            )}
          </motion.div>
        ))}
      </div>
    )
  }

  return (
    <div className="flex items-center space-x-4">
      {steps.map((step, index) => (
        <React.Fragment key={index}>
          <motion.div
            className="flex flex-col items-center space-y-2"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <div className={getStepClasses(index)}>
              {getStepIcon(step, index)}
            </div>
            
            {showLabels && (
              <div className="text-center">
                <p className={`text-xs font-medium ${
                  getStepStatus(index) === 'active' ? 'text-cyan-400' :
                  getStepStatus(index) === 'completed' ? 'text-green-400' :
                  'text-gray-400'
                }`}>
                  {step.title}
                </p>
              </div>
            )}
          </motion.div>
          
          {index < steps.length - 1 && (
            <motion.div
              className={getConnectorClasses(index)}
              initial={{ scaleX: 0 }}
              animate={{ scaleX: 1 }}
              transition={{ delay: index * 0.1 + 0.2, duration: 0.5 }}
            />
          )}
        </React.Fragment>
      ))}
    </div>
  )
}

// Circular Progress
export const CircularProgress = ({ 
  progress = 0, 
  size = 120, 
  strokeWidth = 8,
  color = 'cyan',
  showPercentage = true,
  animated = true 
}) => {
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const strokeDasharray = circumference
  const strokeDashoffset = circumference - (progress / 100) * circumference

  const colors = {
    cyan: '#06b6d4',
    green: '#10b981',
    blue: '#3b82f6',
    red: '#ef4444',
    yellow: '#f59e0b'
  }

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg
        width={size}
        height={size}
        className="transform -rotate-90"
      >
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255, 255, 255, 0.1)"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        
        {/* Progress circle */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={colors[color]}
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={strokeDasharray}
          strokeDashoffset={animated ? strokeDashoffset : 0}
          strokeLinecap="round"
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1, ease: 'easeInOut' }}
          style={{
            filter: `drop-shadow(0 0 8px ${colors[color]}40)`
          }}
        />
      </svg>
      
      {showPercentage && (
        <motion.div
          className="absolute inset-0 flex items-center justify-center"
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5 }}
        >
          <span className="text-2xl font-bold text-white">
            {Math.round(progress)}%
          </span>
        </motion.div>
      )}
    </div>
  )
}

export default ProgressIndicator
