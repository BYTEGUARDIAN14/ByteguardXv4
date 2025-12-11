import React, { useState, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
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

// XSS protection utility
const sanitizeText = (text) => {
  if (!text) return '';
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
};

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

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'secrets', label: 'Secrets', icon: Shield, count: summary.secrets?.total || 0 },
    { id: 'dependencies', label: 'Dependencies', icon: Bug, count: summary.dependencies?.total || 0 },
    { id: 'ai_patterns', label: 'AI Patterns', icon: Cpu, count: summary.ai_patterns?.total || 0 },
    { id: 'verified', label: 'Verified', icon: CheckCircle, count: getVerifiedCount() },
    { id: 'unverified', label: 'Unverified', icon: Clock, count: getUnverifiedCount() }
  ]

  // Enhanced verification status helpers
  function getVerificationStatus(finding) {
    return finding.verification_status || 'pending'
  }

  function getVerificationIcon(status) {
    switch (status) {
      case 'verified': return CheckCircle
      case 'cross_validated': return Award
      case 'unverified': return Clock
      case 'failed': return XCircle
      default: return Clock
    }
  }

  function getVerificationColor(status) {
    switch (status) {
      case 'verified': return 'text-green-400'
      case 'cross_validated': return 'text-cyan-400'
      case 'unverified': return 'text-yellow-400'
      case 'failed': return 'text-red-400'
      default: return 'text-gray-400'
    }
  }

  function getVerifiedCount() {
    return findings.filter(f => ['verified', 'cross_validated'].includes(getVerificationStatus(f))).length
  }

  function getUnverifiedCount() {
    return findings.filter(f => ['unverified', 'pending', 'failed'].includes(getVerificationStatus(f))).length
  }

  const severityColors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-green-400'
  }

  const getSeverityCount = (severity) => {
    return findings.filter(f => f.severity === severity).length
  }

  const getFilteredFindings = () => {
    let filtered = findings

    if (selectedTab !== 'overview') {
      const typeMap = {
        secrets: 'secret',
        dependencies: 'vulnerability',
        ai_patterns: 'ai_pattern',
        verified: null, // Special handling
        unverified: null // Special handling
      }

      if (selectedTab === 'verified') {
        filtered = filtered.filter(f => ['verified', 'cross_validated'].includes(getVerificationStatus(f)))
      } else if (selectedTab === 'unverified') {
        filtered = filtered.filter(f => ['unverified', 'pending', 'failed'].includes(getVerificationStatus(f)))
      } else {
        filtered = filtered.filter(f => f.type === typeMap[selectedTab])
      }
    }

    if (filterSeverity !== 'all') {
      filtered = filtered.filter(f => f.severity === filterSeverity)
    }

    if (filterVerification !== 'all') {
      filtered = filtered.filter(f => getVerificationStatus(f) === filterVerification)
    }

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
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const filteredFindings = getFilteredFindings()

  // Explanation Modal Component
  const ExplanationModal = ({ finding, onClose }) => {
    if (!finding) return null

    const explanation = finding.explanation || {}
    const featureImportance = finding.feature_importance || {}
    const confidenceBreakdown = finding.confidence_breakdown || {}

    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          className="bg-gray-800 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">Finding Explanation</h2>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <XCircle className="h-6 w-6" />
              </button>
            </div>

            {/* Finding Summary */}
            <div className="bg-gray-750 rounded-lg p-4 mb-6">
              <div className="flex items-center space-x-3 mb-3">
                <SeverityBadge severity={finding.severity} />
                {finding.verification_status && (
                  <div className={`flex items-center space-x-1 ${getVerificationColor(finding.verification_status)}`}>
                    {React.createElement(getVerificationIcon(finding.verification_status), { className: "h-4 w-4" })}
                    <span className="text-sm capitalize">{finding.verification_status.replace('_', ' ')}</span>
                  </div>
                )}
                <span className="text-sm text-gray-400">
                  {Math.round(finding.confidence * 100)}% confidence
                </span>
              </div>
              <h3 className="text-lg font-medium text-white mb-2">{sanitizeText(finding.description)}</h3>
              <p className="text-gray-400 text-sm">
                {sanitizeText(finding.file_path)} • Line {finding.line_number}
              </p>
            </div>

            {/* Explanation Sections */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Detection Method */}
              <div className="bg-gray-750 rounded-lg p-4">
                <h4 className="text-lg font-medium text-white mb-3 flex items-center">
                  <Target className="h-5 w-5 mr-2 text-cyan-400" />
                  Detection Method
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Scanner:</span>
                    <span className="text-white">{finding.scanner_source || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Method:</span>
                    <span className="text-white">{explanation.detection_method || 'Pattern matching'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Pattern:</span>
                    <span className="text-white">{explanation.pattern_matched || 'N/A'}</span>
                  </div>
                </div>
              </div>

              {/* Confidence Breakdown */}
              <div className="bg-gray-750 rounded-lg p-4">
                <h4 className="text-lg font-medium text-white mb-3 flex items-center">
                  <TrendingUp className="h-5 w-5 mr-2 text-green-400" />
                  Confidence Analysis
                </h4>
                <div className="space-y-3">
                  {Object.entries(confidenceBreakdown).map(([key, value]) => (
                    <div key={key} className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400 capitalize">{key.replace('_', ' ')}:</span>
                        <span className="text-white">{Math.round(value * 100)}%</span>
                      </div>
                      <div className="w-full bg-gray-600 rounded-full h-2">
                        <div
                          className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-300"
                          style={{ width: `${value * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Feature Importance */}
              {Object.keys(featureImportance).length > 0 && (
                <div className="bg-gray-750 rounded-lg p-4">
                  <h4 className="text-lg font-medium text-white mb-3 flex items-center">
                    <Zap className="h-5 w-5 mr-2 text-yellow-400" />
                    Feature Importance
                  </h4>
                  <div className="space-y-3">
                    {Object.entries(featureImportance)
                      .sort(([,a], [,b]) => b - a)
                      .slice(0, 5)
                      .map(([feature, importance]) => (
                        <div key={feature} className="space-y-1">
                          <div className="flex justify-between text-sm">
                            <span className="text-gray-400 capitalize">{feature.replace('_', ' ')}:</span>
                            <span className="text-white">{Math.round(importance * 100)}%</span>
                          </div>
                          <div className="w-full bg-gray-600 rounded-full h-2">
                            <div
                              className="bg-gradient-to-r from-yellow-500 to-orange-500 h-2 rounded-full transition-all duration-300"
                              style={{ width: `${importance * 100}%` }}
                            />
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Risk Assessment */}
              <div className="bg-gray-750 rounded-lg p-4">
                <h4 className="text-lg font-medium text-white mb-3 flex items-center">
                  <AlertTriangle className="h-5 w-5 mr-2 text-red-400" />
                  Risk Assessment
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Risk Level:</span>
                    <span className="text-white">{explanation.risk_assessment || 'Medium'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">False Positive Likelihood:</span>
                    <span className="text-white">
                      {finding.false_positive_likelihood ?
                        `${Math.round(finding.false_positive_likelihood * 100)}%` :
                        'Unknown'
                      }
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Remediation Priority:</span>
                    <span className="text-white">{explanation.remediation_priority || 'Medium'}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Confidence Factors */}
            {explanation.confidence_factors && (
              <div className="bg-gray-750 rounded-lg p-4 mt-6">
                <h4 className="text-lg font-medium text-white mb-3 flex items-center">
                  <Info className="h-5 w-5 mr-2 text-blue-400" />
                  Confidence Factors
                </h4>
                <ul className="space-y-2">
                  {explanation.confidence_factors.map((factor, index) => (
                    <li key={index} className="text-sm text-gray-300 flex items-start">
                      <span className="text-cyan-400 mr-2">•</span>
                      {factor}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Similar Patterns */}
            {finding.similar_patterns && finding.similar_patterns.length > 0 && (
              <div className="bg-gray-750 rounded-lg p-4 mt-6">
                <h4 className="text-lg font-medium text-white mb-3">Similar Patterns Found</h4>
                <div className="space-y-2">
                  {finding.similar_patterns.slice(0, 3).map((pattern, index) => (
                    <div key={index} className="text-sm text-gray-300 bg-gray-600 rounded p-2">
                      {pattern.description || pattern.pattern || 'Similar pattern detected'}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan Results</h2>
          <p className="text-gray-400 mt-1">
            Found {total_findings} issues across {results.total_files || 0} files
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button className="btn-secondary">
            <Download className="h-4 w-4 mr-2" />
            Export JSON
          </button>
          <button className="btn-primary">
            <FileText className="h-4 w-4 mr-2" />
            Generate PDF
          </button>
        </div>
      </div>

      {/* Overview Cards */}
      {selectedTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-red-500 bg-opacity-10 border border-red-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-400 text-sm font-medium">Critical</p>
                <p className="text-2xl font-bold text-white">{getSeverityCount('critical')}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-400" />
            </div>
          </div>

          <div className="bg-orange-500 bg-opacity-10 border border-orange-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-orange-400 text-sm font-medium">High</p>
                <p className="text-2xl font-bold text-white">{getSeverityCount('high')}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-orange-400" />
            </div>
          </div>

          <div className="bg-yellow-500 bg-opacity-10 border border-yellow-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-yellow-400 text-sm font-medium">Medium</p>
                <p className="text-2xl font-bold text-white">{getSeverityCount('medium')}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-yellow-400" />
            </div>
          </div>

          <div className="bg-green-500 bg-opacity-10 border border-green-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-sm font-medium">Low</p>
                <p className="text-2xl font-bold text-white">{getSeverityCount('low')}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-green-400" />
            </div>
          </div>
        </div>
      )}

      {/* Risk Meter */}
      {selectedTab === 'overview' && (
        <div className="mb-6">
          <RiskMeter findings={findings} />
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-700 mb-6">
        <nav className="flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setSelectedTab(tab.id)}
                className={`
                  flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm transition-colors duration-200
                  ${selectedTab === tab.id
                    ? 'border-primary-500 text-primary-400'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                  }
                `}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full text-xs">
                    {tab.count}
                  </span>
                )}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Enhanced Filters */}
      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        <div className="flex-1">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search findings, files, or scanners..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input pl-10"
            />
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <Filter className="h-4 w-4 text-gray-400" />

          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Verification Status Filter */}
          <select
            value={filterVerification}
            onChange={(e) => setFilterVerification(e.target.value)}
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="all">All Status</option>
            <option value="verified">Verified</option>
            <option value="cross_validated">Cross-Validated</option>
            <option value="unverified">Unverified</option>
            <option value="pending">Pending</option>
            <option value="failed">Failed</option>
          </select>

          {/* Show Explanations Toggle */}
          <button
            onClick={() => setShowExplanations(!showExplanations)}
            className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              showExplanations
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            <Info className="h-4 w-4 mr-1 inline" />
            Explanations
          </button>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="text-center py-12">
            <EyeOff className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-400 text-lg">No findings match your filters</p>
          </div>
        ) : (
          filteredFindings.map((finding, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
              className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden"
            >
              <div 
                className="p-4 cursor-pointer hover:bg-gray-750 transition-colors duration-200"
                onClick={() => toggleFindingExpansion(index)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <SeverityBadge severity={finding.severity} />

                      {/* Verification Status Badge */}
                      <div className={`flex items-center space-x-1 px-2 py-1 rounded-full text-xs ${getVerificationColor(getVerificationStatus(finding))} bg-opacity-10`}>
                        {React.createElement(getVerificationIcon(getVerificationStatus(finding)), { className: "h-3 w-3" })}
                        <span className="capitalize">{getVerificationStatus(finding).replace('_', ' ')}</span>
                      </div>

                      {finding.cvss_base_score > 0 && (
                        <CVSSScore
                          score={finding.cvss_base_score}
                          severity={finding.cvss_severity_label}
                          vector={finding.cvss_vector}
                          className="text-xs"
                        />
                      )}
                      <span className="text-sm text-gray-400">
                        {sanitizeText(finding.subtype || finding.type)}
                      </span>
                      <span className="text-xs text-gray-500">
                        Line {finding.line_number}
                      </span>

                      {/* Scanner Source */}
                      {finding.scanner_source && (
                        <span className="text-xs text-cyan-400 bg-cyan-400 bg-opacity-10 px-2 py-1 rounded">
                          {finding.scanner_source}
                        </span>
                      )}
                    </div>
                    
                    <h3 className="text-white font-medium mb-1">
                      {sanitizeText(finding.description)}
                    </h3>

                    <p className="text-sm text-gray-400">
                      {sanitizeText(finding.file_path?.split('/').pop()) || 'Unknown file'}
                    </p>
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    {/* Confidence Score */}
                    {finding.confidence && (
                      <div className="text-xs text-gray-400 flex items-center space-x-1">
                        <TrendingUp className="h-3 w-3" />
                        <span>{Math.round(finding.confidence * 100)}%</span>
                      </div>
                    )}

                    {/* False Positive Likelihood */}
                    {finding.false_positive_likelihood !== undefined && (
                      <div className="text-xs text-orange-400 flex items-center space-x-1">
                        <AlertTriangle className="h-3 w-3" />
                        <span>{Math.round(finding.false_positive_likelihood * 100)}% FP</span>
                      </div>
                    )}

                    {/* Explanation Button */}
                    {(showExplanations || finding.explanation) && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedFinding(finding)
                        }}
                        className="text-cyan-400 hover:text-cyan-300 transition-colors"
                        title="View Explanation"
                      >
                        <Info className="h-4 w-4" />
                      </button>
                    )}

                    {/* Expand/Collapse */}
                    {expandedFindings.has(index) ? (
                      <ChevronDown className="h-5 w-5 text-gray-400" />
                    ) : (
                      <ChevronRight className="h-5 w-5 text-gray-400" />
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedFindings.has(index) && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="border-t border-gray-700 p-4 bg-gray-850"
                >
                  {finding.context && (
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-gray-300 mb-2">Code Context:</h4>
                      <div className="code-block">
                        <code className="text-sm">{sanitizeText(finding.context)}</code>
                      </div>
                    </div>
                  )}
                  
                  {finding.recommendation && (
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-gray-300 mb-2">Recommendation:</h4>
                      <p className="text-sm text-gray-400 bg-green-500 bg-opacity-10 border border-green-500 border-opacity-20 rounded-lg p-3">
                        {sanitizeText(finding.recommendation)}
                      </p>
                    </div>
                  )}
                  
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>File: {sanitizeText(finding.file_path)}</span>
                    <span>Type: {sanitizeText(finding.type)}</span>
                  </div>
                </motion.div>
              )}
            </motion.div>
          ))
        )}
      </div>

      {/* Summary Footer */}
      <div className="mt-6 pt-6 border-t border-gray-700">
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>
            Showing {filteredFindings.length} of {total_findings} findings
          </span>
          <div className="flex items-center space-x-4">
            {verification_stats && (
              <span>
                {verification_stats.verified || 0} verified, {verification_stats.unverified || 0} unverified
              </span>
            )}
            {total_fixes > 0 && (
              <span>
                {total_fixes} fix suggestions available
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Explanation Modal */}
      <AnimatePresence>
        {selectedFinding && (
          <ExplanationModal
            finding={selectedFinding}
            onClose={() => setSelectedFinding(null)}
          />
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export default ScanResults
