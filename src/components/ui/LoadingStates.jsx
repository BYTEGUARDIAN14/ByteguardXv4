import React from 'react'
import { Shield, Loader2, Zap } from 'lucide-react'

// Skeleton Loader
export const SkeletonLoader = ({ className = '', lines = 3, height = 'h-4' }) => (
  <div className={`space-y-2 ${className}`}>
    {Array.from({ length: lines }).map((_, i) => (
      <div
        key={i}
        className={`${height} bg-desktop-border/50 rounded animate-pulse`}
        style={{ animationDelay: `${i * 100}ms` }}
      />
    ))}
  </div>
)

// Pulse Loader
export const PulseLoader = ({ size = 'md', color = 'cyan' }) => {
  const sizes = { sm: 'w-6 h-6', md: 'w-8 h-8', lg: 'w-12 h-12' }
  return (
    <div className={`${sizes[size]} flex items-center justify-center`}>
      <Loader2 className="w-full h-full text-primary-400 animate-spin" />
    </div>
  )
}

// Scanning Animation
export const ScanningLoader = ({ text = 'Scanning...', progress = 0 }) => (
  <div className="desktop-panel p-6 text-center max-w-sm mx-auto">
    <div className="mb-4">
      <div className="w-10 h-10 mx-auto relative">
        <div className="absolute inset-0 border-2 border-desktop-border rounded-full" />
        <div className="absolute inset-0 border-2 border-transparent border-t-primary-500 rounded-full animate-spin" />
        <Shield className="w-5 h-5 text-primary-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
      </div>
    </div>

    <h3 className="text-sm font-medium text-text-primary mb-2">{text}</h3>

    {progress > 0 && (
      <div className="w-full bg-desktop-border rounded-full h-1.5 mb-2">
        <div
          className="bg-primary-600 h-1.5 rounded-full transition-all duration-300"
          style={{ width: `${progress}%` }}
        />
      </div>
    )}
  </div>
)

// Floating Action Loader
export const FloatingLoader = ({ icon: Icon = Zap, text = 'Processing...' }) => (
  <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
    <div className="desktop-panel p-6 text-center">
      <Icon className="w-8 h-8 text-primary-400 mx-auto mb-3" />
      <p className="text-sm text-text-primary font-medium">{text}</p>
    </div>
  </div>
)

// Card Loading State
export const CardLoader = ({ count = 3 }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
    {Array.from({ length: count }).map((_, i) => (
      <div key={i} className="desktop-panel p-4">
        <SkeletonLoader lines={4} />
      </div>
    ))}
  </div>
)
