import React from 'react'
import { CheckCircle, Circle, Loader2 } from 'lucide-react'

const ProgressIndicator = ({
  steps = [],
  currentStep = 0,
  variant = 'horizontal',
  showLabels = true
}) => {
  const getStepStatus = (index) => {
    if (index < currentStep) return 'completed'
    if (index === currentStep) return 'active'
    return 'pending'
  }

  const getStepIcon = (step, index) => {
    const status = getStepStatus(index)
    const iconClass = 'h-4 w-4'

    switch (status) {
      case 'completed':
        return <CheckCircle className={`${iconClass} text-emerald-400`} />
      case 'active':
        return <Loader2 className={`${iconClass} text-primary-400 animate-spin`} />
      default:
        return <Circle className={`${iconClass} text-text-disabled`} />
    }
  }

  if (variant === 'vertical') {
    return (
      <div className="space-y-3">
        {steps.map((step, index) => (
          <div key={index} className="flex items-start gap-3">
            <div className={`
              flex items-center justify-center w-7 h-7 rounded-full border
              ${getStepStatus(index) === 'completed' ? 'border-emerald-400/40 bg-emerald-400/10' :
                getStepStatus(index) === 'active' ? 'border-primary-400/40 bg-primary-400/10' :
                  'border-desktop-border bg-desktop-card'}
            `}>
              {getStepIcon(step, index)}
            </div>
            {showLabels && (
              <div className="flex-1 min-w-0 pt-0.5">
                <h3 className={`text-xs font-medium ${getStepStatus(index) === 'active' ? 'text-primary-400' :
                    getStepStatus(index) === 'completed' ? 'text-emerald-400' :
                      'text-text-muted'
                  }`}>
                  {step.title}
                </h3>
                {step.description && (
                  <p className="text-[11px] text-text-disabled mt-0.5">{step.description}</p>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-3">
      {steps.map((step, index) => (
        <React.Fragment key={index}>
          <div className="flex flex-col items-center gap-1.5">
            <div className={`
              flex items-center justify-center w-7 h-7 rounded-full border
              ${getStepStatus(index) === 'completed' ? 'border-emerald-400/40 bg-emerald-400/10' :
                getStepStatus(index) === 'active' ? 'border-primary-400/40 bg-primary-400/10' :
                  'border-desktop-border bg-desktop-card'}
            `}>
              {getStepIcon(step, index)}
            </div>
            {showLabels && (
              <p className={`text-[11px] font-medium ${getStepStatus(index) === 'active' ? 'text-primary-400' :
                  getStepStatus(index) === 'completed' ? 'text-emerald-400' :
                    'text-text-muted'
                }`}>
                {step.title}
              </p>
            )}
          </div>
          {index < steps.length - 1 && (
            <div className={`flex-1 h-px ${index < currentStep ? 'bg-emerald-400/50' : 'bg-desktop-border'
              }`} />
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
  showPercentage = true
}) => {
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const strokeDashoffset = circumference - (progress / 100) * circumference

  const colors = {
    cyan: '#0891b2',
    green: '#10b981',
    blue: '#3b82f6',
    red: '#ef4444',
    yellow: '#f59e0b'
  }

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#222"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={colors[color]}
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      {showPercentage && (
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-lg font-semibold text-text-primary">
            {Math.round(progress)}%
          </span>
        </div>
      )}
    </div>
  )
}

export default ProgressIndicator
