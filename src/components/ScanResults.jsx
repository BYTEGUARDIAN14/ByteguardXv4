import React, { useState } from 'react'
import DOMPurify from 'dompurify'
import {
  AlertTriangle,
  Shield,
  Bug,
  Cpu,
  FileText,
  Download,
  Eye,
  EyeOff,
  Filter,
  Search,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  XCircle,
  Clock,
  Info,
  TrendingUp,
  Zap,
  Target,
  Award
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import RiskMeter from './RiskMeter'
import CVSSScore from './CVSSScore'

const sanitizeText = (text) => {
  if (!text) return ''
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
}

const ScanResults = ({ results }) => {
  const [selectedTab, setSelectedTab] = useState('overview')
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [filterVerification, setFilterVerification] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedFindings, setExpandedFindings] = useState(new Set())
  const [showExplanations, setShowExplanations] = useState(false)
  const [selectedFinding, setSelectedFinding] = useState(null)

  if (!results) return null

  const {
    findings = [],
    summary = {},
    total_findings = 0,
    total_fixes = 0,
    verification_stats = {},
    scan_metadata = {}
  } = results

  function getVerificationStatus(finding) { return finding.verification_status || 'pending' }
  function getVerificationIcon(status) {
    return { verified: CheckCircle, cross_validated: Award, failed: XCircle }[status] || Clock
  }
  function getVerificationColor(status) {
    return { verified: 'text-emerald-400', cross_validated: 'text-primary-400', unverified: 'text-yellow-400', failed: 'text-red-400' }[status] || 'text-text-disabled'
  }
  function getVerifiedCount() { return findings.filter(f => ['verified', 'cross_validated'].includes(getVerificationStatus(f))).length }
  function getUnverifiedCount() { return findings.filter(f => ['unverified', 'pending', 'failed'].includes(getVerificationStatus(f))).length }

  const getSeverityCount = (severity) => findings.filter(f => f.severity === severity).length

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'secrets', label: 'Secrets', icon: Shield, count: summary.secrets?.total || 0 },
    { id: 'dependencies', label: 'Deps', icon: Bug, count: summary.dependencies?.total || 0 },
    { id: 'ai_patterns', label: 'AI', icon: Cpu, count: summary.ai_patterns?.total || 0 },
    { id: 'verified', label: 'Verified', icon: CheckCircle, count: getVerifiedCount() },
    { id: 'unverified', label: 'Unverified', icon: Clock, count: getUnverifiedCount() }
  ]

  const getFilteredFindings = () => {
    let filtered = findings
    if (selectedTab !== 'overview') {
      const typeMap = { secrets: 'secret', dependencies: 'vulnerability', ai_patterns: 'ai_pattern' }
      if (selectedTab === 'verified') filtered = filtered.filter(f => ['verified', 'cross_validated'].includes(getVerificationStatus(f)))
      else if (selectedTab === 'unverified') filtered = filtered.filter(f => ['unverified', 'pending', 'failed'].includes(getVerificationStatus(f)))
      else filtered = filtered.filter(f => f.type === typeMap[selectedTab])
    }
    if (filterSeverity !== 'all') filtered = filtered.filter(f => f.severity === filterSeverity)
    if (filterVerification !== 'all') filtered = filtered.filter(f => getVerificationStatus(f) === filterVerification)
    if (searchTerm) {
      filtered = filtered.filter(f =>
        f.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.file_path?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.subtype?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.scanner_source?.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }
    return filtered
  }

  const toggleFindingExpansion = (index) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) newExpanded.delete(index)
    else newExpanded.add(index)
    setExpandedFindings(newExpanded)
  }

  const filteredFindings = getFilteredFindings()

  // Explanation Modal
  const ExplanationModal = ({ finding, onClose }) => {
    if (!finding) return null
    const explanation = finding.explanation || {}
    const featureImportance = finding.feature_importance || {}
    const confidenceBreakdown = finding.confidence_breakdown || {}

    return (
      <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
        <div className="desktop-panel w-full max-w-3xl max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
          <div className="px-5 py-3 border-b border-desktop-border flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary">Finding Explanation</h2>
            <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary rounded transition-colors">
              <XCircle className="h-4 w-4" />
            </button>
          </div>

          <div className="p-5 space-y-4">
            {/* Summary */}
            <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
              <div className="flex items-center gap-2 mb-1.5">
                <SeverityBadge severity={finding.severity} />
                {finding.verification_status && (
                  <div className={`flex items-center gap-1 text-[11px] ${getVerificationColor(finding.verification_status)}`}>
                    {React.createElement(getVerificationIcon(finding.verification_status), { className: "h-3 w-3" })}
                    <span className="capitalize">{finding.verification_status.replace('_', ' ')}</span>
                  </div>
                )}
                <span className="text-[11px] text-text-disabled">{Math.round(finding.confidence * 100)}% confidence</span>
              </div>
              <h3 className="text-xs font-medium text-text-primary mb-0.5">{sanitizeText(finding.description)}</h3>
              <p className="text-[11px] text-text-disabled">{sanitizeText(finding.file_path)} · Line {finding.line_number}</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {/* Detection */}
              <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                <h4 className="text-[11px] font-semibold text-text-secondary flex items-center gap-1.5 mb-2">
                  <Target className="h-3 w-3 text-primary-400" /> Detection
                </h4>
                <div className="space-y-1 text-[11px]">
                  {[
                    ['Scanner', finding.scanner_source || 'Unknown'],
                    ['Method', explanation.detection_method || 'Pattern matching'],
                    ['Pattern', explanation.pattern_matched || 'N/A']
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <span className="text-text-disabled">{k}</span>
                      <span className="text-text-secondary">{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Confidence */}
              <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                <h4 className="text-[11px] font-semibold text-text-secondary flex items-center gap-1.5 mb-2">
                  <TrendingUp className="h-3 w-3 text-emerald-400" /> Confidence
                </h4>
                <div className="space-y-1.5">
                  {Object.entries(confidenceBreakdown).map(([key, value]) => (
                    <div key={key}>
                      <div className="flex justify-between text-[11px] mb-0.5">
                        <span className="text-text-disabled capitalize">{key.replace('_', ' ')}</span>
                        <span className="text-text-secondary">{Math.round(value * 100)}%</span>
                      </div>
                      <div className="w-full bg-desktop-border rounded-full h-1">
                        <div className="bg-primary-600 h-1 rounded-full" style={{ width: `${value * 100}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Feature Importance */}
              {Object.keys(featureImportance).length > 0 && (
                <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                  <h4 className="text-[11px] font-semibold text-text-secondary flex items-center gap-1.5 mb-2">
                    <Zap className="h-3 w-3 text-yellow-400" /> Features
                  </h4>
                  <div className="space-y-1.5">
                    {Object.entries(featureImportance).sort(([, a], [, b]) => b - a).slice(0, 5).map(([feature, imp]) => (
                      <div key={feature}>
                        <div className="flex justify-between text-[11px] mb-0.5">
                          <span className="text-text-disabled capitalize">{feature.replace('_', ' ')}</span>
                          <span className="text-text-secondary">{Math.round(imp * 100)}%</span>
                        </div>
                        <div className="w-full bg-desktop-border rounded-full h-1">
                          <div className="bg-amber-500 h-1 rounded-full" style={{ width: `${imp * 100}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk */}
              <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                <h4 className="text-[11px] font-semibold text-text-secondary flex items-center gap-1.5 mb-2">
                  <AlertTriangle className="h-3 w-3 text-red-400" /> Risk
                </h4>
                <div className="space-y-1 text-[11px]">
                  {[
                    ['Level', explanation.risk_assessment || 'Medium'],
                    ['FP Likelihood', finding.false_positive_likelihood ? `${Math.round(finding.false_positive_likelihood * 100)}%` : 'Unknown'],
                    ['Remediation', explanation.remediation_priority || 'Medium']
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <span className="text-text-disabled">{k}</span>
                      <span className="text-text-secondary">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Confidence Factors */}
            {explanation.confidence_factors && (
              <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                <h4 className="text-[11px] font-semibold text-text-secondary flex items-center gap-1.5 mb-1.5">
                  <Info className="h-3 w-3 text-blue-400" /> Confidence Factors
                </h4>
                <ul className="space-y-0.5">
                  {explanation.confidence_factors.map((factor, i) => (
                    <li key={i} className="text-[11px] text-text-secondary flex items-start gap-1">
                      <span className="text-primary-400">•</span> {factor}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Similar Patterns */}
            {finding.similar_patterns?.length > 0 && (
              <div className="p-3 bg-desktop-card rounded-desktop border border-desktop-border">
                <h4 className="text-[11px] font-semibold text-text-secondary mb-1.5">Similar Patterns</h4>
                <div className="space-y-1">
                  {finding.similar_patterns.slice(0, 3).map((pattern, i) => (
                    <div key={i} className="text-[11px] text-text-secondary bg-desktop-bg rounded p-1.5">
                      {pattern.description || pattern.pattern || 'Similar pattern detected'}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="desktop-panel">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
        <div>
          <h2 className="text-sm font-semibold text-text-primary">Scan Results</h2>
          <p className="text-[11px] text-text-muted">{total_findings} issues across {results.total_files || 0} files</p>
        </div>
        <div className="flex items-center gap-1.5">
          <button className="btn-ghost text-[11px] px-2 py-1 inline-flex items-center gap-1">
            <Download className="h-3 w-3" /> Export
          </button>
          <button className="btn-primary text-[11px] px-2 py-1 inline-flex items-center gap-1">
            <FileText className="h-3 w-3" /> PDF
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Overview Cards */}
        {selectedTab === 'overview' && (
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: 'Critical', count: getSeverityCount('critical'), color: 'text-red-400', borderColor: 'border-red-400/15' },
              { label: 'High', count: getSeverityCount('high'), color: 'text-amber-400', borderColor: 'border-amber-400/15' },
              { label: 'Medium', count: getSeverityCount('medium'), color: 'text-yellow-400', borderColor: 'border-yellow-400/15' },
              { label: 'Low', count: getSeverityCount('low'), color: 'text-emerald-400', borderColor: 'border-emerald-400/15' }
            ].map(({ label, count, color, borderColor }) => (
              <div key={label} className={`p-2.5 bg-desktop-card rounded-desktop border ${borderColor}`}>
                <p className={`text-[11px] ${color}`}>{label}</p>
                <p className="text-base font-semibold text-text-primary">{count}</p>
              </div>
            ))}
          </div>
        )}

        {/* Risk Meter */}
        {selectedTab === 'overview' && <RiskMeter findings={findings} />}

        {/* Tabs */}
        <div className="border-b border-desktop-border">
          <nav className="flex gap-1">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setSelectedTab(tab.id)}
                  className={`flex items-center gap-1 py-1.5 px-2 border-b-2 text-[11px] font-medium transition-colors ${selectedTab === tab.id
                      ? 'border-primary-500 text-primary-400'
                      : 'border-transparent text-text-muted hover:text-text-secondary'
                    }`}
                >
                  <Icon className="h-3 w-3" />
                  <span>{tab.label}</span>
                  {tab.count !== undefined && (
                    <span className="bg-desktop-card text-text-disabled px-1 py-0 rounded text-[10px]">{tab.count}</span>
                  )}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Filters */}
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-disabled" />
            <input
              type="text"
              placeholder="Search findings..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input text-xs py-1.5 pl-8"
            />
          </div>
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className="input text-xs py-1.5 w-auto">
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={filterVerification} onChange={(e) => setFilterVerification(e.target.value)} className="input text-xs py-1.5 w-auto">
            <option value="all">All Status</option>
            <option value="verified">Verified</option>
            <option value="cross_validated">Cross-Validated</option>
            <option value="unverified">Unverified</option>
            <option value="pending">Pending</option>
            <option value="failed">Failed</option>
          </select>
          <button
            onClick={() => setShowExplanations(!showExplanations)}
            className={`text-xs px-2 py-1.5 rounded-desktop border transition-colors ${showExplanations ? 'border-primary-500/30 text-primary-400 bg-primary-500/5' : 'border-desktop-border text-text-muted hover:text-text-secondary'
              }`}
          >
            <Info className="h-3 w-3 mr-0.5 inline" /> AI
          </button>
        </div>

        {/* Findings List */}
        <div className="space-y-1">
          {filteredFindings.length === 0 ? (
            <div className="text-center py-8">
              <EyeOff className="h-6 w-6 text-text-disabled mx-auto mb-2" />
              <p className="text-xs text-text-muted">No findings match your filters</p>
            </div>
          ) : (
            filteredFindings.map((finding, index) => (
              <div key={index} className="border border-desktop-border rounded-desktop overflow-hidden">
                <div
                  className="px-3 py-2 cursor-pointer hover:bg-white/[0.02] transition-colors"
                  onClick={() => toggleFindingExpansion(index)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                        <SeverityBadge severity={finding.severity} />
                        <div className={`flex items-center gap-0.5 text-[10px] ${getVerificationColor(getVerificationStatus(finding))}`}>
                          {React.createElement(getVerificationIcon(getVerificationStatus(finding)), { className: "h-2.5 w-2.5" })}
                          <span className="capitalize">{getVerificationStatus(finding).replace('_', ' ')}</span>
                        </div>
                        {finding.cvss_base_score > 0 && (
                          <CVSSScore score={finding.cvss_base_score} severity={finding.cvss_severity_label} vector={finding.cvss_vector} className="text-[10px]" />
                        )}
                        <span className="text-[10px] text-text-disabled">{sanitizeText(finding.subtype || finding.type)}</span>
                        <span className="text-[10px] text-text-disabled">L{finding.line_number}</span>
                        {finding.scanner_source && (
                          <span className="text-[10px] text-primary-400 bg-primary-400/5 px-1 py-0 rounded">{finding.scanner_source}</span>
                        )}
                      </div>
                      <h3 className="text-xs text-text-primary truncate">{sanitizeText(finding.description)}</h3>
                      <p className="text-[10px] text-text-disabled truncate">{sanitizeText(finding.file_path?.split('/').pop()) || 'Unknown file'}</p>
                    </div>

                    <div className="flex items-center gap-2 ml-2 flex-shrink-0">
                      {finding.confidence && (
                        <span className="text-[10px] text-text-disabled">{Math.round(finding.confidence * 100)}%</span>
                      )}
                      {finding.false_positive_likelihood !== undefined && (
                        <span className="text-[10px] text-amber-400">{Math.round(finding.false_positive_likelihood * 100)}% FP</span>
                      )}
                      {(showExplanations || finding.explanation) && (
                        <button
                          onClick={(e) => { e.stopPropagation(); setSelectedFinding(finding) }}
                          className="text-primary-400 hover:text-primary-300 transition-colors"
                          title="View Explanation"
                        >
                          <Info className="h-3 w-3" />
                        </button>
                      )}
                      {expandedFindings.has(index) ? <ChevronDown className="h-3.5 w-3.5 text-text-muted" /> : <ChevronRight className="h-3.5 w-3.5 text-text-muted" />}
                    </div>
                  </div>
                </div>

                {/* Expanded */}
                {expandedFindings.has(index) && (
                  <div className="border-t border-desktop-border px-3 py-2.5 bg-desktop-card/50">
                    {finding.context && (
                      <div className="mb-2">
                        <h4 className="text-[11px] font-medium text-text-secondary mb-1">Code Context</h4>
                        <pre className="text-[11px] text-text-secondary bg-desktop-bg p-2 rounded-desktop border border-desktop-border overflow-x-auto font-mono">
                          {sanitizeText(finding.context)}
                        </pre>
                      </div>
                    )}
                    {finding.recommendation && (
                      <div className="mb-2">
                        <h4 className="text-[11px] font-medium text-text-secondary mb-1">Recommendation</h4>
                        <p className="text-[11px] text-text-secondary bg-emerald-400/5 border border-emerald-400/10 rounded-desktop p-2">
                          {sanitizeText(finding.recommendation)}
                        </p>
                      </div>
                    )}
                    <div className="flex items-center justify-between text-[10px] text-text-disabled">
                      <span>File: {sanitizeText(finding.file_path)}</span>
                      <span>Type: {sanitizeText(finding.type)}</span>
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-desktop-border flex items-center justify-between text-[11px] text-text-disabled">
          <span>Showing {filteredFindings.length} of {total_findings}</span>
          <div className="flex items-center gap-3">
            {verification_stats && <span>{verification_stats.verified || 0} verified, {verification_stats.unverified || 0} unverified</span>}
            {total_fixes > 0 && <span>{total_fixes} fixes available</span>}
          </div>
        </div>
      </div>

      {/* Explanation Modal */}
      {selectedFinding && (
        <ExplanationModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  )
}

export default ScanResults
