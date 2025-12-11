import React from 'react'
import { motion } from 'framer-motion'
import { Loader2, Shield, Zap } from 'lucide-react'

const LoadingSpinner = ({ 
  size = 'md', 
  text = 'Loading...', 
  variant = 'default',
  fullScreen = false,
  showIcon = true 
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16'
  }

  const textSizeClasses = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
    xl: 'text-xl'
  }

  const getIcon = () => {
    switch (variant) {
      case 'security':
        return Shield
      case 'scan':
        return Zap
      default:
        return Loader2
    }
  }

  const Icon = getIcon()

  const spinner = (
    <div className="flex flex-col items-center justify-center space-y-4">
      {showIcon && (
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className={`${sizeClasses[size]} text-cyan-500`}
        >
          <Icon className="w-full h-full" />
        </motion.div>
      )}
      
      {text && (
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className={`${textSizeClasses[size]} text-gray-300 font-medium`}
        >
          {text}
        </motion.p>
      )}
    </div>
  )

  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50">
        <div className="bg-gray-900/90 border border-gray-700 rounded-xl p-8">
          {spinner}
        </div>
      </div>
    )
  }

  return spinner
}

// Skeleton loader for content
export const SkeletonLoader = ({ lines = 3, className = '' }) => {
  return (
    <div className={`space-y-3 ${className}`}>
      {Array.from({ length: lines }).map((_, index) => (
        <motion.div
          key={index}
          className="h-4 bg-gray-700 rounded animate-pulse"
          style={{ width: `${Math.random() * 40 + 60}%` }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: index * 0.1 }}
        />
      ))}
    </div>
  )
}

// Card skeleton loader
export const CardSkeleton = ({ className = '' }) => {
  return (
    <div className={`bg-gray-800 border border-gray-700 rounded-xl p-6 ${className}`}>
      <div className="animate-pulse">
        <div className="flex items-center space-x-4 mb-4">
          <div className="w-12 h-12 bg-gray-700 rounded-lg"></div>
          <div className="flex-1">
            <div className="h-4 bg-gray-700 rounded w-3/4 mb-2"></div>
            <div className="h-3 bg-gray-700 rounded w-1/2"></div>
          </div>
        </div>
        <div className="space-y-2">
          <div className="h-3 bg-gray-700 rounded"></div>
          <div className="h-3 bg-gray-700 rounded w-5/6"></div>
        </div>
      </div>
    </div>
  )
}

export default LoadingSpinner
