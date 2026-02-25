import React from 'react'
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

  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length
  const mediumCount = findings.filter(f => f.severity === 'medium').length
  const lowCount = findings.filter(f => f.severity === 'low').length

  const riskScore = Math.min(Math.round(((criticalCount * 10 + highCount * 7 + mediumCount * 4 + lowCount * 1) / Math.max(total_findings * 5, 1)) * 100), 100)

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'Critical', color: 'red' }
    if (score >= 60) return { level: 'High', color: 'orange' }
    if (score >= 40) return { level: 'Medium', color: 'yellow' }
    if (score >= 20) return { level: 'Low', color: 'green' }
    return { level: 'Minimal', color: 'green' }
  }

  const risk = getRiskLevel(riskScore)

  const riskColorMap = {
    red: { text: 'text-red-400', bg: 'bg-red-500', border: 'border-red-400/20' },
    orange: { text: 'text-amber-400', bg: 'bg-amber-500', border: 'border-amber-400/20' },
    yellow: { text: 'text-yellow-400', bg: 'bg-yellow-500', border: 'border-yellow-400/20' },
    green: { text: 'text-emerald-400', bg: 'bg-emerald-500', border: 'border-emerald-400/20' }
  }
  const rc = riskColorMap[risk.color] || riskColorMap.green

  const scanTypes = [
    { name: 'Secrets', icon: Shield, data: summary.secrets || { total: 0, by_severity: {} }, color: 'text-red-400', desc: 'Hardcoded credentials & API keys' },
    { name: 'Dependencies', icon: Bug, data: summary.dependencies || { total: 0, by_severity: {} }, color: 'text-amber-400', desc: 'Known CVEs in packages' },
    { name: 'AI Patterns', icon: Cpu, data: summary.ai_patterns || { total: 0, by_severity: {} }, color: 'text-blue-400', desc: 'Unsafe AI-generated patterns' }
  ]

  const recommendations = [
    {
      priority: 'Immediate', icon: AlertTriangle, color: 'text-red-400', borderColor: 'border-red-400/30',
      items: criticalCount > 0
        ? [`Address ${criticalCount} critical issue${criticalCount > 1 ? 's' : ''}`, 'Rotate exposed credentials', 'Emergency patches']
        : ['No immediate actions required']
    },
    {
      priority: 'Short-term', icon: Target, color: 'text-amber-400', borderColor: 'border-amber-400/30',
      items: highCount > 0
        ? [`Fix ${highCount} high-severity issue${highCount > 1 ? 's' : ''}`, 'Update vulnerable deps', 'Add input validation']
        : ['Focus on medium/low items']
    },
    {
      priority: 'Long-term', icon: Award, color: 'text-emerald-400', borderColor: 'border-emerald-400/30',
      items: ['Automate security scanning in CI/CD', 'Security code review processes', 'Developer security training']
    }
  ]

  return (
    <div className="space-y-5">
      {/* Overview */}
      <div className="desktop-panel p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-text-primary">Executive Summary</h2>
          <div className="flex items-center gap-1.5">
            <BarChart3 className="h-3.5 w-3.5 text-primary-400" />
            <span className="text-[11px] text-text-muted">Security Assessment</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {/* Key Metrics */}
          <div className="space-y-2">
            <h3 className="text-xs font-medium text-text-secondary mb-2">Key Findings</h3>
            {[
              { label: 'Files Scanned', sub: 'Total coverage', value: total_files, color: 'text-primary-400', icon: BarChart3 },
              { label: 'Security Issues', sub: 'Vulnerabilities found', value: total_findings, color: 'text-red-400', icon: AlertTriangle },
              { label: 'Fix Suggestions', sub: 'Automated remediation', value: total_fixes, color: 'text-emerald-400', icon: CheckCircle }
            ].map(({ label, sub, value, color, icon: Icon }) => (
              <div key={label} className="flex items-center justify-between p-2.5 bg-desktop-card rounded-desktop border border-desktop-border">
                <div className="flex items-center gap-2.5">
                  <Icon className={`h-4 w-4 ${color}`} />
                  <div>
                    <p className="text-xs text-text-primary">{label}</p>
                    <p className="text-[11px] text-text-disabled">{sub}</p>
                  </div>
                </div>
                <div className={`text-base font-semibold ${color}`}>{value}</div>
              </div>
            ))}
          </div>

          {/* Risk Assessment */}
          <div>
            <h3 className="text-xs font-medium text-text-secondary mb-2">Risk Assessment</h3>
            <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border h-[calc(100%-24px)]">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-text-muted">Overall Risk</span>
                <span className={`text-xs font-medium ${rc.text}`}>{risk.level}</span>
              </div>

              <div className="mb-3">
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-text-disabled">Risk Score</span>
                  <span className="text-text-primary font-medium">{riskScore}/100</span>
                </div>
                <div className="w-full bg-desktop-border rounded-full h-1.5">
                  <div
                    className={`h-1.5 ${rc.bg} rounded-full transition-all duration-500`}
                    style={{ width: `${riskScore}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="flex justify-between"><span className="text-text-disabled">Critical:</span><span className="text-red-400 font-medium">{criticalCount}</span></div>
                <div className="flex justify-between"><span className="text-text-disabled">High:</span><span className="text-amber-400 font-medium">{highCount}</span></div>
                <div className="flex justify-between"><span className="text-text-disabled">Medium:</span><span className="text-yellow-400 font-medium">{mediumCount}</span></div>
                <div className="flex justify-between"><span className="text-text-disabled">Low:</span><span className="text-emerald-400 font-medium">{lowCount}</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Scan Type Breakdown */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary mb-3">Analysis Breakdown</h3>
        <div className="grid grid-cols-3 gap-3">
          {scanTypes.map((scanType, index) => {
            const Icon = scanType.icon
            const { total = 0, by_severity = {} } = scanType.data
            return (
              <div key={index} className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`h-3.5 w-3.5 ${scanType.color}`} />
                  <div>
                    <h4 className="text-xs font-medium text-text-primary">{scanType.name}</h4>
                    <p className="text-[10px] text-text-disabled">{scanType.desc}</p>
                  </div>
                </div>
                <div className={`text-lg font-semibold ${scanType.color} mb-1`}>{total}</div>
                {total > 0 && (
                  <div className="space-y-0.5">
                    {Object.entries(by_severity).map(([sev, count]) => (
                      <div key={sev} className="flex justify-between text-[11px]">
                        <span className="text-text-disabled capitalize">{sev}</span>
                        <span className="text-text-secondary">{count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Recommendations */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary mb-3">Recommended Actions</h3>
        <div className="space-y-3">
          {recommendations.map((rec, index) => {
            const Icon = rec.icon
            return (
              <div key={index} className={`border-l-2 ${rec.borderColor} pl-3`}>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Icon className={`h-3.5 w-3.5 ${rec.color}`} />
                  <h4 className={`text-xs font-medium ${rec.color}`}>{rec.priority}</h4>
                </div>
                <ul className="space-y-0.5">
                  {rec.items.map((item, i) => (
                    <li key={i} className="text-[11px] text-text-secondary flex items-start gap-1.5">
                      <span className="text-text-disabled mt-px">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>
      </div>

      {/* Risk Meter */}
      <RiskMeter findings={findings} />
    </div>
  )
}

export default ExecutiveSummary
