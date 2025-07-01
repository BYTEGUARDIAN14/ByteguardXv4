import React, { useState } from 'react'
import { motion } from 'framer-motion'
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
  ChevronRight
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import RiskMeter from './RiskMeter'

// XSS protection utility
const sanitizeText = (text) => {
  if (!text) return '';
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
};

const ScanResults = ({ results }) => {
  const [selectedTab, setSelectedTab] = useState('overview')
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedFindings, setExpandedFindings] = useState(new Set())

  if (!results) return null

  const { findings = [], summary = {}, total_findings = 0, total_fixes = 0 } = results

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'secrets', label: 'Secrets', icon: Shield, count: summary.secrets?.total || 0 },
    { id: 'dependencies', label: 'Dependencies', icon: Bug, count: summary.dependencies?.total || 0 },
    { id: 'ai_patterns', label: 'AI Patterns', icon: Cpu, count: summary.ai_patterns?.total || 0 }
  ]

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
        ai_patterns: 'ai_pattern'
      }
      filtered = filtered.filter(f => f.type === typeMap[selectedTab])
    }

    if (filterSeverity !== 'all') {
      filtered = filtered.filter(f => f.severity === filterSeverity)
    }

    if (searchTerm) {
      filtered = filtered.filter(f => 
        f.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.file_path?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.subtype?.toLowerCase().includes(searchTerm.toLowerCase())
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

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        <div className="flex-1">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search findings..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input pl-10"
            />
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-400" />
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
                      <span className="text-sm text-gray-400">
                        {sanitizeText(finding.subtype || finding.type)}
                      </span>
                      <span className="text-xs text-gray-500">
                        Line {finding.line_number}
                      </span>
                    </div>
                    
                    <h3 className="text-white font-medium mb-1">
                      {sanitizeText(finding.description)}
                    </h3>

                    <p className="text-sm text-gray-400">
                      {sanitizeText(finding.file_path?.split('/').pop()) || 'Unknown file'}
                    </p>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    {finding.confidence && (
                      <span className="text-xs text-gray-400">
                        {Math.round(finding.confidence * 100)}% confidence
                      </span>
                    )}
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
          {total_fixes > 0 && (
            <span>
              {total_fixes} fix suggestions available
            </span>
          )}
        </div>
      </div>
    </motion.div>
  )
}

export default ScanResults
