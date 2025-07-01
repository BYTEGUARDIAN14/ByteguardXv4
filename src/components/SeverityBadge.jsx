import React from 'react'
import { AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-react'

const SeverityBadge = ({ severity, size = 'sm', showIcon = true }) => {
  const severityConfig = {
    critical: {
      label: 'Critical',
      icon: AlertTriangle,
      className: 'bg-red-500 bg-opacity-10 text-red-400 border-red-500 border-opacity-20',
      textColor: 'text-red-400'
    },
    high: {
      label: 'High',
      icon: AlertTriangle,
      className: 'bg-orange-500 bg-opacity-10 text-orange-400 border-orange-500 border-opacity-20',
      textColor: 'text-orange-400'
    },
    medium: {
      label: 'Medium',
      icon: AlertCircle,
      className: 'bg-yellow-500 bg-opacity-10 text-yellow-400 border-yellow-500 border-opacity-20',
      textColor: 'text-yellow-400'
    },
    low: {
      label: 'Low',
      icon: Info,
      className: 'bg-green-500 bg-opacity-10 text-green-400 border-green-500 border-opacity-20',
      textColor: 'text-green-400'
    },
    info: {
      label: 'Info',
      icon: CheckCircle,
      className: 'bg-blue-500 bg-opacity-10 text-blue-400 border-blue-500 border-opacity-20',
      textColor: 'text-blue-400'
    }
  }

  const config = severityConfig[severity?.toLowerCase()] || severityConfig.info
  const Icon = config.icon

  const sizeClasses = {
    xs: 'px-1.5 py-0.5 text-xs',
    sm: 'px-2 py-1 text-xs',
    md: 'px-3 py-1.5 text-sm',
    lg: 'px-4 py-2 text-base'
  }

  const iconSizes = {
    xs: 'h-3 w-3',
    sm: 'h-3 w-3',
    md: 'h-4 w-4',
    lg: 'h-5 w-5'
  }

  return (
    <span className={`
      inline-flex items-center font-medium rounded-full border
      ${config.className}
      ${sizeClasses[size]}
    `}>
      {showIcon && (
        <Icon className={`${iconSizes[size]} mr-1`} />
      )}
      {config.label}
    </span>
  )
}

export default SeverityBadge
