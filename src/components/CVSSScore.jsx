import React, { useState } from 'react'
import {
  Info,
  ChevronDown,
  ChevronUp,
  Shield,
  AlertTriangle,
  AlertCircle,
  CheckCircle
} from 'lucide-react'

const CVSSScore = ({
  score = 0,
  severity = 'None',
  vector = null,
  showDetails = false,
  className = ''
}) => {
  const [isExpanded, setIsExpanded] = useState(false)

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return { bg: 'bg-red-500', text: 'text-red-400', border: 'border-red-500', icon: AlertTriangle }
      case 'high': return { bg: 'bg-amber-500', text: 'text-amber-400', border: 'border-amber-500', icon: AlertCircle }
      case 'medium': return { bg: 'bg-yellow-500', text: 'text-yellow-400', border: 'border-yellow-500', icon: Info }
      case 'low': return { bg: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500', icon: Info }
      default: return { bg: 'bg-gray-500', text: 'text-text-disabled', border: 'border-desktop-border', icon: CheckCircle }
    }
  }

  const parseVector = (vectorString) => {
    if (!vectorString || !vectorString.startsWith('CVSS:3.1/')) return null
    const parts = vectorString.replace('CVSS:3.1/', '').split('/')
    const metrics = {}
    parts.forEach(part => { const [key, value] = part.split(':'); metrics[key] = value })

    const desc = (fn) => fn
    return {
      attackVector: { key: 'AV', value: metrics.AV, label: 'Attack Vector', description: getAttackVectorDescription(metrics.AV) },
      attackComplexity: { key: 'AC', value: metrics.AC, label: 'Attack Complexity', description: getAttackComplexityDescription(metrics.AC) },
      privilegesRequired: { key: 'PR', value: metrics.PR, label: 'Privileges Required', description: getPrivilegesRequiredDescription(metrics.PR) },
      userInteraction: { key: 'UI', value: metrics.UI, label: 'User Interaction', description: getUserInteractionDescription(metrics.UI) },
      scope: { key: 'S', value: metrics.S, label: 'Scope', description: getScopeDescription(metrics.S) },
      confidentiality: { key: 'C', value: metrics.C, label: 'Confidentiality', description: getImpactDescription(metrics.C) },
      integrity: { key: 'I', value: metrics.I, label: 'Integrity', description: getImpactDescription(metrics.I) },
      availability: { key: 'A', value: metrics.A, label: 'Availability', description: getImpactDescription(metrics.A) }
    }
  }

  const getAttackVectorDescription = (v) => ({ N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }[v] || 'Unknown')
  const getAttackComplexityDescription = (v) => ({ L: 'Low', H: 'High' }[v] || 'Unknown')
  const getPrivilegesRequiredDescription = (v) => ({ N: 'None', L: 'Low', H: 'High' }[v] || 'Unknown')
  const getUserInteractionDescription = (v) => ({ N: 'None', R: 'Required' }[v] || 'Unknown')
  const getScopeDescription = (v) => ({ U: 'Unchanged', C: 'Changed' }[v] || 'Unknown')
  const getImpactDescription = (v) => ({ N: 'None', L: 'Low', H: 'High' }[v] || 'Unknown')

  const colors = getSeverityColor(severity)
  const Icon = colors.icon
  const parsedVector = vector ? parseVector(vector) : null

  return (
    <div className={className}>
      <div className="flex items-center gap-2">
        <div className={`flex items-center gap-1.5 px-2 py-1 rounded-desktop border ${colors.bg}/10 ${colors.border}/20`}>
          <Icon className={`h-3 w-3 ${colors.text}`} />
          <span className={`text-xs font-semibold ${colors.text}`}>
            CVSS {score.toFixed(1)}
          </span>
          <span className={`text-[11px] ${colors.text}`}>({severity})</span>
        </div>

        <div className="flex-1 max-w-24">
          <div className="w-full bg-desktop-border rounded-full h-1">
            <div
              className={`h-1 rounded-full ${colors.bg} transition-all duration-500`}
              style={{ width: `${(score / 10) * 100}%` }}
            />
          </div>
        </div>

        {showDetails && parsedVector && (
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-0.5 text-text-muted hover:text-text-primary transition-colors rounded"
          >
            {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        )}
      </div>

      {showDetails && parsedVector && isExpanded && (
        <div className="mt-2 p-3 bg-desktop-card rounded-desktop border border-desktop-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Shield className="h-3 w-3 text-primary-400" />
            <h4 className="text-[11px] font-semibold text-text-primary">CVSS v3.1 Breakdown</h4>
          </div>

          <div className="mb-2">
            <code className="text-[10px] bg-desktop-bg px-1.5 py-0.5 rounded text-primary-400 font-mono">{vector}</code>
          </div>

          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(parsedVector).map(([key, metric]) => (
              <div key={key} className="flex justify-between items-center p-1.5 bg-desktop-bg rounded text-[11px]">
                <span className="text-text-muted">{metric.label}</span>
                <span className="font-mono text-primary-400 bg-desktop-card px-1 py-0.5 rounded text-[10px]">{metric.value}</span>
              </div>
            ))}
          </div>

          <div className="mt-2 pt-2 border-t border-desktop-border">
            <div className="flex flex-wrap gap-1 text-[10px]">
              {[
                { label: 'None (0)', color: 'text-text-disabled' },
                { label: 'Low (0.1-3.9)', color: 'text-blue-400' },
                { label: 'Medium (4-6.9)', color: 'text-yellow-400' },
                { label: 'High (7-8.9)', color: 'text-amber-400' },
                { label: 'Critical (9-10)', color: 'text-red-400' }
              ].map(({ label, color }) => (
                <span key={label} className={`${color}`}>{label}</span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default CVSSScore
