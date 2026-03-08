import React from 'react'
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
    { id: 'uploading', label: 'Uploading Files', icon: Upload, description: 'Securely uploading your files...' },
    { id: 'scanning', label: 'Security Analysis', icon: Search, description: 'Analyzing code for vulnerabilities...' },
    { id: 'secrets', label: 'Secret Detection', icon: Shield, description: 'Scanning for hardcoded secrets...' },
    { id: 'dependencies', label: 'Dependency Check', icon: Bug, description: 'Checking for vulnerable packages...' },
    { id: 'ai_patterns', label: 'AI Pattern Analysis', icon: Cpu, description: 'Detecting AI-generated anti-patterns...' },
    { id: 'complete', label: 'Complete', icon: CheckCircle, description: 'Scan completed successfully!' }
  ]

  const currentStageIndex = stages.findIndex(stage => stage.id === progress.stage)

  return (
    <div className="desktop-panel p-4">
      <div className="mb-4">
        <h3 className="text-xs font-semibold text-text-primary mb-0.5">Scanning in Progress</h3>
        <p className="text-[11px] text-text-muted">
          {stages[currentStageIndex]?.description || 'Processing...'}
        </p>
      </div>

      {/* Progress Bar */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1 text-[11px]">
          <span className="text-text-secondary">{stages[currentStageIndex]?.label || 'Processing'}</span>
          <span className="text-text-primary font-medium">{Math.round(progress.progress || 0)}%</span>
        </div>
        <div className="w-full bg-desktop-border rounded-full h-1.5">
          <div
            className="bg-primary-600 h-1.5 rounded-full transition-all duration-500"
            style={{ width: `${progress.progress || 0}%` }}
          />
        </div>
      </div>

      {/* Stage Indicators */}
      <div className="space-y-1">
        {stages.map((stage, index) => {
          const Icon = stage.icon
          const isActive = index === currentStageIndex
          const isCompleted = index < currentStageIndex

          return (
            <div
              key={stage.id}
              className={`
                flex items-center gap-3 px-2.5 py-1.5 rounded-desktop transition-colors
                ${isActive ? 'bg-primary-500/5 border border-primary-500/15' :
                  isCompleted ? 'bg-emerald-400/5 border border-emerald-400/10' :
                    'border border-transparent'}
              `}
            >
              <div className={`
                flex items-center justify-center w-6 h-6 rounded-full
                ${isActive ? 'bg-primary-500/10' : isCompleted ? 'bg-emerald-400/10' : 'bg-desktop-card'}
              `}>
                {isActive ? (
                  <Loader2 className="h-3.5 w-3.5 text-primary-400 animate-spin" />
                ) : (
                  <Icon className={`h-3.5 w-3.5 ${isCompleted ? 'text-emerald-400' : 'text-text-disabled'}`} />
                )}
              </div>

              <div className="flex-1">
                <h4 className={`text-xs font-medium ${isActive ? 'text-primary-400' : isCompleted ? 'text-emerald-400' : 'text-text-disabled'
                  }`}>
                  {stage.label}
                </h4>
                {isActive && (
                  <p className="text-[10px] text-text-muted mt-0.5">{stage.description}</p>
                )}
              </div>

              {isCompleted && <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />}
            </div>
          )
        })}
      </div>

      {/* Estimated Time */}
      <div className="mt-3 pt-3 border-t border-desktop-border flex items-center justify-between text-[11px]">
        <span className="text-text-disabled">Estimated time remaining</span>
        <span className="text-text-secondary">
          {currentStageIndex < stages.length - 1 ? '~2 minutes' : 'Almost done!'}
        </span>
      </div>

      {/* Privacy Notice */}
      <div className="mt-2 p-2 bg-blue-500/5 border border-blue-500/10 rounded-desktop flex items-start gap-1.5">
        <Shield className="h-3 w-3 text-blue-400 mt-0.5 flex-shrink-0" />
        <div>
          <p className="text-[10px] text-blue-400 font-medium">Privacy Protected</p>
          <p className="text-[10px] text-text-disabled">All analysis happens locally.</p>
        </div>
      </div>
    </div>
  )
}

export default ScanProgress
