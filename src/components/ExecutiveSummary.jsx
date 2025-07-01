import React from 'react'
import { motion } from 'framer-motion'
import { 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle, 
  Shield, 
  Bug, 
  Cpu,
  CheckCircle,
  Clock,
  Target,
  Award,
  BarChart3
} from 'lucide-react'
import RiskMeter from './RiskMeter'

const ExecutiveSummary = ({ data }) => {
  if (!data) return null

  const { findings = [], summary = {}, total_files = 0, total_findings = 0, total_fixes = 0 } = data

  // Calculate metrics
  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length
  const mediumCount = findings.filter(f => f.severity === 'medium').length
  const lowCount = findings.filter(f => f.severity === 'low').length

  const riskScore = Math.min(Math.round(((criticalCount * 10 + highCount * 7 + mediumCount * 4 + lowCount * 1) / Math.max(total_findings * 5, 1)) * 100), 100)

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'Critical', color: 'red', trend: 'up' }
    if (score >= 60) return { level: 'High', color: 'orange', trend: 'up' }
    if (score >= 40) return { level: 'Medium', color: 'yellow', trend: 'stable' }
    if (score >= 20) return { level: 'Low', color: 'green', trend: 'down' }
    return { level: 'Minimal', color: 'green', trend: 'down' }
  }

  const risk = getRiskLevel(riskScore)

  const scanTypes = [
    {
      name: 'Secret Detection',
      icon: Shield,
      data: summary.secrets || { total: 0, by_severity: {} },
      color: 'text-red-400',
      description: 'Hardcoded credentials and API keys'
    },
    {
      name: 'Dependency Vulnerabilities',
      icon: Bug,
      data: summary.dependencies || { total: 0, by_severity: {} },
      color: 'text-orange-400',
      description: 'Known CVEs in third-party packages'
    },
    {
      name: 'AI Pattern Analysis',
      icon: Cpu,
      data: summary.ai_patterns || { total: 0, by_severity: {} },
      color: 'text-blue-400',
      description: 'Unsafe AI-generated code patterns'
    }
  ]

  const recommendations = [
    {
      priority: 'Immediate',
      icon: AlertTriangle,
      color: 'text-red-400',
      items: criticalCount > 0 ? [
        `Address ${criticalCount} critical security issue${criticalCount > 1 ? 's' : ''}`,
        'Review and rotate any exposed credentials',
        'Implement emergency security patches'
      ] : ['No immediate actions required']
    },
    {
      priority: 'Short-term',
      icon: Target,
      color: 'text-orange-400',
      items: highCount > 0 ? [
        `Fix ${highCount} high-severity vulnerability${highCount > 1 ? 'ies' : 'y'}`,
        'Update vulnerable dependencies',
        'Implement additional input validation'
      ] : ['Focus on medium and low priority items']
    },
    {
      priority: 'Long-term',
      icon: Award,
      color: 'text-green-400',
      items: [
        'Implement automated security scanning in CI/CD',
        'Establish security code review processes',
        'Regular security training for development team',
        'Consider implementing security linting tools'
      ]
    }
  ]

  return (
    <div className="space-y-8">
      {/* Executive Overview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-white">Executive Summary</h2>
          <div className="flex items-center space-x-2">
            <BarChart3 className="h-5 w-5 text-primary-400" />
            <span className="text-sm text-gray-400">Security Assessment</span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Key Metrics */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Key Findings</h3>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-primary-500 bg-opacity-10 rounded-lg">
                    <BarChart3 className="h-5 w-5 text-primary-400" />
                  </div>
                  <div>
                    <p className="text-white font-medium">Files Scanned</p>
                    <p className="text-sm text-gray-400">Total codebase coverage</p>
                  </div>
                </div>
                <div className="text-2xl font-bold text-white">{total_files}</div>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-red-500 bg-opacity-10 rounded-lg">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                  </div>
                  <div>
                    <p className="text-white font-medium">Security Issues</p>
                    <p className="text-sm text-gray-400">Total vulnerabilities found</p>
                  </div>
                </div>
                <div className="text-2xl font-bold text-red-400">{total_findings}</div>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-green-500 bg-opacity-10 rounded-lg">
                    <CheckCircle className="h-5 w-5 text-green-400" />
                  </div>
                  <div>
                    <p className="text-white font-medium">Fix Suggestions</p>
                    <p className="text-sm text-gray-400">Automated remediation available</p>
                  </div>
                </div>
                <div className="text-2xl font-bold text-green-400">{total_fixes}</div>
              </div>
            </div>
          </div>

          {/* Risk Assessment */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Risk Assessment</h3>
            
            <div className="p-6 bg-gray-800 rounded-lg">
              <div className="flex items-center justify-between mb-4">
                <span className="text-gray-300">Overall Risk Level</span>
                <div className="flex items-center space-x-2">
                  {risk.trend === 'up' ? (
                    <TrendingUp className={`h-4 w-4 text-${risk.color}-400`} />
                  ) : risk.trend === 'down' ? (
                    <TrendingDown className={`h-4 w-4 text-${risk.color}-400`} />
                  ) : (
                    <div className={`w-4 h-1 bg-${risk.color}-400 rounded`} />
                  )}
                  <span className={`font-medium text-${risk.color}-400`}>
                    {risk.level}
                  </span>
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Risk Score</span>
                  <span className="text-white font-medium">{riskScore}/100</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <motion.div
                    className={`h-2 bg-${risk.color}-500 rounded-full`}
                    initial={{ width: 0 }}
                    animate={{ width: `${riskScore}%` }}
                    transition={{ duration: 1, ease: 'easeOut' }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-400">Critical:</span>
                  <span className="text-red-400 font-medium ml-2">{criticalCount}</span>
                </div>
                <div>
                  <span className="text-gray-400">High:</span>
                  <span className="text-orange-400 font-medium ml-2">{highCount}</span>
                </div>
                <div>
                  <span className="text-gray-400">Medium:</span>
                  <span className="text-yellow-400 font-medium ml-2">{mediumCount}</span>
                </div>
                <div>
                  <span className="text-gray-400">Low:</span>
                  <span className="text-green-400 font-medium ml-2">{lowCount}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Scan Type Breakdown */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card"
      >
        <h3 className="text-xl font-semibold text-white mb-6">Security Analysis Breakdown</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {scanTypes.map((scanType, index) => {
            const Icon = scanType.icon
            const { total = 0, by_severity = {} } = scanType.data
            
            return (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 + index * 0.1 }}
                className="bg-gray-800 rounded-lg p-6"
              >
                <div className="flex items-center space-x-3 mb-4">
                  <div className={`p-2 ${scanType.color.replace('text-', 'bg-').replace('-400', '-500')} bg-opacity-10 rounded-lg`}>
                    <Icon className={`h-5 w-5 ${scanType.color}`} />
                  </div>
                  <div>
                    <h4 className="font-medium text-white">{scanType.name}</h4>
                    <p className="text-xs text-gray-400">{scanType.description}</p>
                  </div>
                </div>
                
                <div className="text-center mb-4">
                  <div className={`text-3xl font-bold ${scanType.color}`}>{total}</div>
                  <div className="text-sm text-gray-400">Issues Found</div>
                </div>
                
                {total > 0 && (
                  <div className="space-y-2">
                    {Object.entries(by_severity).map(([severity, count]) => (
                      <div key={severity} className="flex justify-between text-sm">
                        <span className="text-gray-400 capitalize">{severity}:</span>
                        <span className="text-white font-medium">{count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )
          })}
        </div>
      </motion.div>

      {/* Recommendations */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="card"
      >
        <h3 className="text-xl font-semibold text-white mb-6">Recommended Actions</h3>
        
        <div className="space-y-6">
          {recommendations.map((rec, index) => {
            const Icon = rec.icon
            
            return (
              <div key={index} className="border-l-4 border-gray-600 pl-6">
                <div className="flex items-center space-x-3 mb-3">
                  <Icon className={`h-5 w-5 ${rec.color}`} />
                  <h4 className={`font-medium ${rec.color}`}>{rec.priority} Actions</h4>
                </div>
                
                <ul className="space-y-2">
                  {rec.items.map((item, itemIndex) => (
                    <li key={itemIndex} className="flex items-start space-x-2 text-sm text-gray-300">
                      <span className="text-gray-500 mt-1">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>
      </motion.div>

      {/* Risk Meter Component */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <RiskMeter findings={findings} />
      </motion.div>
    </div>
  )
}

export default ExecutiveSummary
