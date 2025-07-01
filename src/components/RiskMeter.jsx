import React from 'react'
import { motion } from 'framer-motion'
import { AlertTriangle, TrendingUp, TrendingDown, Minus } from 'lucide-react'

const RiskMeter = ({ findings = [] }) => {
  // Calculate risk score based on severity weights
  const calculateRiskScore = () => {
    const weights = {
      critical: 10,
      high: 7,
      medium: 4,
      low: 1
    }

    const totalScore = findings.reduce((score, finding) => {
      const weight = weights[finding.severity?.toLowerCase()] || 0
      return score + weight
    }, 0)

    // Normalize to 0-100 scale (assuming max reasonable score is 100)
    return Math.min(Math.round((totalScore / Math.max(findings.length * 5, 1)) * 100), 100)
  }

  const riskScore = calculateRiskScore()

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'Critical', color: 'red', icon: AlertTriangle }
    if (score >= 60) return { level: 'High', color: 'orange', icon: TrendingUp }
    if (score >= 40) return { level: 'Medium', color: 'yellow', icon: Minus }
    if (score >= 20) return { level: 'Low', color: 'green', icon: TrendingDown }
    return { level: 'Minimal', color: 'green', icon: TrendingDown }
  }

  const risk = getRiskLevel(riskScore)
  const Icon = risk.icon

  const getColorClasses = (color) => {
    const colors = {
      red: {
        bg: 'bg-red-500',
        text: 'text-red-400',
        border: 'border-red-500'
      },
      orange: {
        bg: 'bg-orange-500',
        text: 'text-orange-400',
        border: 'border-orange-500'
      },
      yellow: {
        bg: 'bg-yellow-500',
        text: 'text-yellow-400',
        border: 'border-yellow-500'
      },
      green: {
        bg: 'bg-green-500',
        text: 'text-green-400',
        border: 'border-green-500'
      }
    }
    return colors[color] || colors.green
  }

  const colorClasses = getColorClasses(risk.color)

  const severityCounts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length
  }

  return (
    <div className="card bg-gray-900 border-gray-700">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-white">Risk Assessment</h3>
        <div className={`flex items-center space-x-2 px-3 py-1 rounded-full border ${colorClasses.border} border-opacity-20 ${colorClasses.bg} bg-opacity-10`}>
          <Icon className={`h-4 w-4 ${colorClasses.text}`} />
          <span className={`text-sm font-medium ${colorClasses.text}`}>
            {risk.level} Risk
          </span>
        </div>
      </div>

      {/* Risk Score Meter */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-gray-400">Overall Risk Score</span>
          <span className={`text-lg font-bold ${colorClasses.text}`}>
            {riskScore}/100
          </span>
        </div>
        
        <div className="relative">
          <div className="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
            <motion.div
              className={`h-full ${colorClasses.bg} rounded-full`}
              initial={{ width: 0 }}
              animate={{ width: `${riskScore}%` }}
              transition={{ duration: 1, ease: 'easeOut' }}
            />
          </div>
          
          {/* Risk level markers */}
          <div className="flex justify-between mt-2 text-xs text-gray-500">
            <span>0</span>
            <span>25</span>
            <span>50</span>
            <span>75</span>
            <span>100</span>
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-500 rounded-full"></div>
              <span className="text-sm text-gray-300">Critical</span>
            </div>
            <span className="text-sm font-medium text-white">
              {severityCounts.critical}
            </span>
          </div>
          
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
              <span className="text-sm text-gray-300">High</span>
            </div>
            <span className="text-sm font-medium text-white">
              {severityCounts.high}
            </span>
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
              <span className="text-sm text-gray-300">Medium</span>
            </div>
            <span className="text-sm font-medium text-white">
              {severityCounts.medium}
            </span>
          </div>
          
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <span className="text-sm text-gray-300">Low</span>
            </div>
            <span className="text-sm font-medium text-white">
              {severityCounts.low}
            </span>
          </div>
        </div>
      </div>

      {/* Risk Recommendations */}
      <div className="mt-6 pt-6 border-t border-gray-700">
        <h4 className="text-sm font-medium text-gray-300 mb-3">Recommendations</h4>
        
        <div className="space-y-2 text-sm text-gray-400">
          {riskScore >= 80 && (
            <div className="flex items-start space-x-2">
              <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" />
              <p>Immediate action required. Address critical and high severity issues first.</p>
            </div>
          )}
          
          {riskScore >= 40 && riskScore < 80 && (
            <div className="flex items-start space-x-2">
              <TrendingUp className="h-4 w-4 text-yellow-400 mt-0.5 flex-shrink-0" />
              <p>Review and prioritize high and medium severity findings.</p>
            </div>
          )}
          
          {riskScore < 40 && (
            <div className="flex items-start space-x-2">
              <TrendingDown className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
              <p>Good security posture. Address remaining issues when possible.</p>
            </div>
          )}
          
          <div className="flex items-start space-x-2">
            <Icon className={`h-4 w-4 ${colorClasses.text} mt-0.5 flex-shrink-0`} />
            <p>Consider implementing automated security scanning in your CI/CD pipeline.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default RiskMeter
