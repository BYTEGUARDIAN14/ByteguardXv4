import React from 'react'
import { motion } from 'framer-motion'
import { Shield, Loader2, Zap } from 'lucide-react'

// Skeleton Loader
export const SkeletonLoader = ({ className = '', lines = 3, height = 'h-4' }) => (
  <div className={`space-y-3 ${className}`}>
    {Array.from({ length: lines }).map((_, i) => (
      <motion.div
        key={i}
        className={`${height} bg-white/10 rounded-lg`}
        animate={{ opacity: [0.5, 1, 0.5] }}
        transition={{ duration: 1.5, repeat: Infinity, delay: i * 0.1 }}
      />
    ))}
  </div>
)

// Pulse Loader
export const PulseLoader = ({ size = 'md', color = 'cyan' }) => {
  const sizes = {
    sm: 'w-8 h-8',
    md: 'w-12 h-12',
    lg: 'w-16 h-16'
  }

  const colors = {
    cyan: 'text-cyan-400',
    blue: 'text-blue-400',
    green: 'text-green-400',
    red: 'text-red-400'
  }

  return (
    <motion.div
      className={`${sizes[size]} ${colors[color]} flex items-center justify-center`}
      animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }}
      transition={{ duration: 1.5, repeat: Infinity }}
    >
      <Shield className="w-full h-full" />
    </motion.div>
  )
}

// Scanning Animation
export const ScanningLoader = ({ text = 'Scanning...', progress = 0 }) => (
  <div className="glass-card p-8 text-center max-w-md mx-auto">
    <motion.div
      className="relative mb-6"
      animate={{ rotate: 360 }}
      transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
    >
      <div className="w-16 h-16 mx-auto relative">
        <div className="absolute inset-0 border-4 border-cyan-400/20 rounded-full"></div>
        <div className="absolute inset-0 border-4 border-transparent border-t-cyan-400 rounded-full animate-spin"></div>
        <Shield className="w-8 h-8 text-cyan-400 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
      </div>
    </motion.div>

    <motion.h3
      className="text-lg font-semibold text-white mb-2"
      animate={{ opacity: [0.7, 1, 0.7] }}
      transition={{ duration: 1.5, repeat: Infinity }}
    >
      {text}
    </motion.h3>

    {progress > 0 && (
      <div className="w-full bg-gray-800 rounded-full h-2 mb-4">
        <motion.div
          className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.5 }}
        />
      </div>
    )}

    <div className="flex justify-center space-x-1">
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          className="w-2 h-2 bg-cyan-400 rounded-full"
          animate={{ scale: [1, 1.5, 1], opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 1, repeat: Infinity, delay: i * 0.2 }}
        />
      ))}
    </div>
  </div>
)

// Floating Action Loader
export const FloatingLoader = ({ icon: Icon = Zap, text = 'Processing...' }) => (
  <motion.div
    className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
  >
    <motion.div
      className="glass-card p-8 text-center"
      initial={{ scale: 0.8, y: 20 }}
      animate={{ scale: 1, y: 0 }}
      exit={{ scale: 0.8, y: 20 }}
    >
      <motion.div
        className="mb-4"
        animate={{ y: [-5, 5, -5] }}
        transition={{ duration: 2, repeat: Infinity }}
      >
        <Icon className="w-12 h-12 text-cyan-400 mx-auto" />
      </motion.div>
      <p className="text-white font-medium">{text}</p>
    </motion.div>
  </motion.div>
)

// Card Loading State
export const CardLoader = ({ count = 3 }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    {Array.from({ length: count }).map((_, i) => (
      <motion.div
        key={i}
        className="glass-card p-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: i * 0.1 }}
      >
        <SkeletonLoader lines={4} />
      </motion.div>
    ))}
  </div>
)
