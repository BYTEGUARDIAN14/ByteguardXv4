import React, { useState } from 'react'
import { motion } from 'framer-motion'
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
      case 'critical':
        return {
          bg: 'bg-red-500',
          text: 'text-red-400',
          border: 'border-red-500',
          icon: AlertTriangle
        }
      case 'high':
        return {
          bg: 'bg-orange-500',
          text: 'text-orange-400',
          border: 'border-orange-500',
          icon: AlertCircle
        }
      case 'medium':
        return {
          bg: 'bg-yellow-500',
          text: 'text-yellow-400',
          border: 'border-yellow-500',
          icon: Info
        }
      case 'low':
        return {
          bg: 'bg-blue-500',
          text: 'text-blue-400',
          border: 'border-blue-500',
          icon: Info
        }
      default:
        return {
          bg: 'bg-gray-500',
          text: 'text-gray-400',
          border: 'border-gray-500',
          icon: CheckCircle
        }
    }
  }

  const parseVector = (vectorString) => {
    if (!vectorString || !vectorString.startsWith('CVSS:3.1/')) {
      return null
    }

    const parts = vectorString.replace('CVSS:3.1/', '').split('/')
    const metrics = {}

    parts.forEach(part => {
      const [key, value] = part.split(':')
      metrics[key] = value
    })

    return {
      attackVector: {
        key: 'AV',
        value: metrics.AV,
        label: 'Attack Vector',
        description: getAttackVectorDescription(metrics.AV)
      },
      attackComplexity: {
        key: 'AC',
        value: metrics.AC,
        label: 'Attack Complexity',
        description: getAttackComplexityDescription(metrics.AC)
      },
      privilegesRequired: {
        key: 'PR',
        value: metrics.PR,
        label: 'Privileges Required',
        description: getPrivilegesRequiredDescription(metrics.PR)
      },
      userInteraction: {
        key: 'UI',
        value: metrics.UI,
        label: 'User Interaction',
        description: getUserInteractionDescription(metrics.UI)
      },
      scope: {
        key: 'S',
        value: metrics.S,
        label: 'Scope',
        description: getScopeDescription(metrics.S)
      },
      confidentiality: {
        key: 'C',
        value: metrics.C,
        label: 'Confidentiality Impact',
        description: getImpactDescription(metrics.C)
      },
      integrity: {
        key: 'I',
        value: metrics.I,
        label: 'Integrity Impact',
        description: getImpactDescription(metrics.I)
      },
      availability: {
        key: 'A',
        value: metrics.A,
        label: 'Availability Impact',
        description: getImpactDescription(metrics.A)
      }
    }
  }

  const getAttackVectorDescription = (value) => {
    switch (value) {
      case 'N': return 'Network - Remotely exploitable'
      case 'A': return 'Adjacent - Local network access required'
      case 'L': return 'Local - Local access required'
      case 'P': return 'Physical - Physical access required'
      default: return 'Unknown'
    }
  }

  const getAttackComplexityDescription = (value) => {
    switch (value) {
      case 'L': return 'Low - No special conditions required'
      case 'H': return 'High - Special conditions required'
      default: return 'Unknown'
    }
  }

  const getPrivilegesRequiredDescription = (value) => {
    switch (value) {
      case 'N': return 'None - No privileges required'
      case 'L': return 'Low - Basic user privileges required'
      case 'H': return 'High - Administrative privileges required'
      default: return 'Unknown'
    }
  }

  const getUserInteractionDescription = (value) => {
    switch (value) {
      case 'N': return 'None - No user interaction required'
      case 'R': return 'Required - User interaction required'
      default: return 'Unknown'
    }
  }

  const getScopeDescription = (value) => {
    switch (value) {
      case 'U': return 'Unchanged - Impact limited to vulnerable component'
      case 'C': return 'Changed - Impact extends beyond vulnerable component'
      default: return 'Unknown'
    }
  }

  const getImpactDescription = (value) => {
    switch (value) {
      case 'N': return 'None - No impact'
      case 'L': return 'Low - Limited impact'
      case 'H': return 'High - Significant impact'
      default: return 'Unknown'
    }
  }

  const colors = getSeverityColor(severity)
  const Icon = colors.icon
  const parsedVector = vector ? parseVector(vector) : null

  return (
    <div className={`${className}`}>
      {/* Main Score Display */}
      <div className="flex items-center space-x-3">
        <div className={`
          flex items-center space-x-2 px-3 py-2 rounded-lg border
          ${colors.bg}/20 ${colors.border}/30
        `}>
          <Icon className={`h-4 w-4 ${colors.text}`} />
          <span className={`font-semibold ${colors.text}`}>
            CVSS {score.toFixed(1)}
          </span>
          <span className={`text-sm ${colors.text}`}>
            ({severity})
          </span>
        </div>

        {/* Score Bar */}
        <div className="flex-1 max-w-32">
          <div className="w-full bg-gray-700 rounded-full h-2">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(score / 10) * 100}%` }}
              transition={{ duration: 0.5, ease: "easeOut" }}
              className={`h-2 rounded-full ${colors.bg}`}
            />
          </div>
          <div className="flex justify-between text-xs text-gray-400 mt-1">
            <span>0</span>
            <span>10</span>
          </div>
        </div>

        {/* Expand Button */}
        {showDetails && parsedVector && (
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 text-gray-400 hover:text-white transition-colors rounded"
          >
            {isExpanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>
        )}
      </div>

      {/* Detailed Breakdown */}
      {showDetails && parsedVector && isExpanded && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.2 }}
          className="mt-4 p-4 bg-gray-900/50 rounded-lg border border-gray-700"
        >
          <div className="flex items-center space-x-2 mb-3">
            <Shield className="h-4 w-4 text-cyan-400" />
            <h4 className="text-sm font-semibold text-white">CVSS v3.1 Breakdown</h4>
          </div>

          {/* Vector String */}
          <div className="mb-4">
            <p className="text-xs text-gray-400 mb-1">Vector String:</p>
            <code className="text-xs bg-gray-800 px-2 py-1 rounded text-cyan-400 font-mono">
              {vector}
            </code>
          </div>

          {/* Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {Object.entries(parsedVector).map(([key, metric]) => (
              <div key={key} className="flex justify-between items-center p-2 bg-gray-800/50 rounded">
                <div>
                  <p className="text-sm font-medium text-white">{metric.label}</p>
                  <p className="text-xs text-gray-400">{metric.description}</p>
                </div>
                <span className="text-sm font-mono text-cyan-400 bg-gray-700 px-2 py-1 rounded">
                  {metric.value}
                </span>
              </div>
            ))}
          </div>

          {/* Severity Scale Reference */}
          <div className="mt-4 pt-3 border-t border-gray-700">
            <p className="text-xs text-gray-400 mb-2">CVSS v3.1 Severity Scale:</p>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-1 bg-gray-500/20 text-gray-400 rounded">
                None (0.0)
              </span>
              <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded">
                Low (0.1-3.9)
              </span>
              <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded">
                Medium (4.0-6.9)
              </span>
              <span className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded">
                High (7.0-8.9)
              </span>
              <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded">
                Critical (9.0-10.0)
              </span>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}

export default CVSSScore
