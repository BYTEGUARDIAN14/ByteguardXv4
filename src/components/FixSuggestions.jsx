import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Wrench, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronRight,
  Code,
  Lightbulb,
  Star,
  Filter,
  Search
} from 'lucide-react'
import toast from 'react-hot-toast'
import SeverityBadge from './SeverityBadge'

const FixSuggestions = ({ fixes = [] }) => {
  const [expandedFixes, setExpandedFixes] = useState(new Set())
  const [copiedCode, setCopiedCode] = useState(new Set())
  const [filterConfidence, setFilterConfidence] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  const toggleFixExpansion = (index) => {
    const newExpanded = new Set(expandedFixes)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFixes(newExpanded)
  }

  const copyToClipboard = async (code, index) => {
    try {
      await navigator.clipboard.writeText(code)
      setCopiedCode(prev => new Set([...prev, index]))
      toast.success('Code copied to clipboard!')
      
      // Reset copied state after 2 seconds
      setTimeout(() => {
        setCopiedCode(prev => {
          const newSet = new Set(prev)
          newSet.delete(index)
          return newSet
        })
      }, 2000)
    } catch (error) {
      toast.error('Failed to copy code')
    }
  }

  const getConfidenceLevel = (confidence) => {
    if (confidence >= 0.9) return { label: 'Very High', color: 'text-green-400' }
    if (confidence >= 0.8) return { label: 'High', color: 'text-blue-400' }
    if (confidence >= 0.7) return { label: 'Medium', color: 'text-yellow-400' }
    return { label: 'Low', color: 'text-orange-400' }
  }

  const getFilteredFixes = () => {
    let filtered = fixes

    if (filterConfidence !== 'all') {
      const minConfidence = {
        'high': 0.8,
        'medium': 0.6,
        'low': 0.0
      }[filterConfidence]
      
      filtered = filtered.filter(fix => fix.confidence >= minConfidence)
    }

    if (searchTerm) {
      filtered = filtered.filter(fix => 
        fix.vulnerability_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        fix.explanation?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        fix.file_path?.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    return filtered
  }

  const filteredFixes = getFilteredFixes()

  if (fixes.length === 0) {
    return (
      <div className="card text-center py-12">
        <Wrench className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">No Fix Suggestions Available</h3>
        <p className="text-gray-400">
          No automated fixes could be generated for the current findings.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center">
              <Wrench className="h-6 w-6 mr-3 text-primary-400" />
              Fix Suggestions
            </h2>
            <p className="text-gray-400 mt-1">
              Automated code fixes and security recommendations
            </p>
          </div>
          
          <div className="text-right">
            <div className="text-2xl font-bold text-primary-400">{fixes.length}</div>
            <div className="text-sm text-gray-400">Total Fixes</div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-4 mb-6">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search fixes..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-10"
              />
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-gray-400" />
            <select
              value={filterConfidence}
              onChange={(e) => setFilterConfidence(e.target.value)}
              className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option value="all">All Confidence Levels</option>
              <option value="high">High Confidence (80%+)</option>
              <option value="medium">Medium Confidence (60%+)</option>
              <option value="low">Low Confidence</option>
            </select>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-green-500 bg-opacity-10 border border-green-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-sm font-medium">High Confidence</p>
                <p className="text-xl font-bold text-white">
                  {fixes.filter(f => f.confidence >= 0.8).length}
                </p>
              </div>
              <Star className="h-6 w-6 text-green-400" />
            </div>
          </div>

          <div className="bg-blue-500 bg-opacity-10 border border-blue-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-400 text-sm font-medium">Auto-Applicable</p>
                <p className="text-xl font-bold text-white">
                  {fixes.filter(f => f.confidence >= 0.9).length}
                </p>
              </div>
              <Code className="h-6 w-6 text-blue-400" />
            </div>
          </div>

          <div className="bg-purple-500 bg-opacity-10 border border-purple-500 border-opacity-20 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-400 text-sm font-medium">Manual Review</p>
                <p className="text-xl font-bold text-white">
                  {fixes.filter(f => f.confidence < 0.8).length}
                </p>
              </div>
              <Lightbulb className="h-6 w-6 text-purple-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Fix Suggestions List */}
      <div className="space-y-4">
        {filteredFixes.length === 0 ? (
          <div className="card text-center py-8">
            <Search className="h-8 w-8 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-400">No fixes match your current filters</p>
          </div>
        ) : (
          filteredFixes.map((fix, index) => {
            const isExpanded = expandedFixes.has(index)
            const confidenceLevel = getConfidenceLevel(fix.confidence)
            
            return (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="card hover:border-gray-600 transition-all duration-200"
              >
                <div 
                  className="cursor-pointer"
                  onClick={() => toggleFixExpansion(index)}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-medium text-white">
                          {fix.vulnerability_type?.replace(/[._]/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </h3>
                        <span className={`text-xs px-2 py-1 rounded-full bg-opacity-20 border border-opacity-30 ${confidenceLevel.color.replace('text-', 'bg-').replace('-400', '-500')} ${confidenceLevel.color} border-current`}>
                          {Math.round(fix.confidence * 100)}% confidence
                        </span>
                      </div>
                      
                      <p className="text-gray-400 mb-2">
                        {fix.explanation}
                      </p>
                      
                      <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span>📁 {fix.file_path?.split('/').pop()}</span>
                        <span>📍 Line {fix.line_number}</span>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <span className={`text-sm font-medium ${confidenceLevel.color}`}>
                        {confidenceLevel.label}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="h-5 w-5 text-gray-400" />
                      ) : (
                        <ChevronRight className="h-5 w-5 text-gray-400" />
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Content */}
                {isExpanded && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="border-t border-gray-700 pt-6"
                  >
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Original Code */}
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <h4 className="text-sm font-medium text-red-400">
                            🔴 Original Code
                          </h4>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              copyToClipboard(fix.original_code, `original-${index}`)
                            }}
                            className="text-xs text-gray-400 hover:text-white transition-colors duration-200 flex items-center space-x-1"
                          >
                            {copiedCode.has(`original-${index}`) ? (
                              <Check className="h-3 w-3" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            <span>Copy</span>
                          </button>
                        </div>
                        <div className="code-block">
                          <pre className="text-sm text-gray-300 whitespace-pre-wrap">
                            {fix.original_code}
                          </pre>
                        </div>
                      </div>

                      {/* Fixed Code */}
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <h4 className="text-sm font-medium text-green-400">
                            ✅ Fixed Code
                          </h4>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              copyToClipboard(fix.fixed_code, `fixed-${index}`)
                            }}
                            className="text-xs text-gray-400 hover:text-white transition-colors duration-200 flex items-center space-x-1"
                          >
                            {copiedCode.has(`fixed-${index}`) ? (
                              <Check className="h-3 w-3" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            <span>Copy</span>
                          </button>
                        </div>
                        <div className="code-block border-green-500 border-opacity-20">
                          <pre className="text-sm text-gray-300 whitespace-pre-wrap">
                            {fix.fixed_code}
                          </pre>
                        </div>
                      </div>
                    </div>

                    {/* Additional Info */}
                    <div className="mt-6 p-4 bg-blue-500 bg-opacity-10 border border-blue-500 border-opacity-20 rounded-lg">
                      <div className="flex items-start space-x-3">
                        <Lightbulb className="h-5 w-5 text-blue-400 mt-0.5 flex-shrink-0" />
                        <div>
                          <h5 className="text-sm font-medium text-blue-400 mb-1">
                            Implementation Notes
                          </h5>
                          <p className="text-sm text-gray-300">
                            {fix.explanation}
                          </p>
                          {fix.confidence < 0.8 && (
                            <p className="text-xs text-yellow-400 mt-2">
                              ⚠️ Manual review recommended due to lower confidence score
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            )
          })
        )}
      </div>
    </div>
  )
}

export default FixSuggestions
