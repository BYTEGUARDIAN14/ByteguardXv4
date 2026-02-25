import React, { useState } from 'react'
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
    if (newExpanded.has(index)) { newExpanded.delete(index) } else { newExpanded.add(index) }
    setExpandedFixes(newExpanded)
  }

  const copyToClipboard = async (code, index) => {
    try {
      await navigator.clipboard.writeText(code)
      setCopiedCode(prev => new Set([...prev, index]))
      toast.success('Copied!')
      setTimeout(() => {
        setCopiedCode(prev => { const s = new Set(prev); s.delete(index); return s })
      }, 2000)
    } catch (error) {
      toast.error('Failed to copy')
    }
  }

  const getConfidenceLevel = (confidence) => {
    if (confidence >= 0.9) return { label: 'Very High', color: 'text-emerald-400' }
    if (confidence >= 0.8) return { label: 'High', color: 'text-blue-400' }
    if (confidence >= 0.7) return { label: 'Medium', color: 'text-yellow-400' }
    return { label: 'Low', color: 'text-amber-400' }
  }

  const getFilteredFixes = () => {
    let filtered = fixes
    if (filterConfidence !== 'all') {
      const min = { high: 0.8, medium: 0.6, low: 0.0 }[filterConfidence]
      filtered = filtered.filter(f => f.confidence >= min)
    }
    if (searchTerm) {
      filtered = filtered.filter(f =>
        f.vulnerability_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.explanation?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.file_path?.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }
    return filtered
  }

  const filteredFixes = getFilteredFixes()

  if (fixes.length === 0) {
    return (
      <div className="desktop-panel text-center py-8">
        <Wrench className="h-6 w-6 text-text-disabled mx-auto mb-2" />
        <h3 className="text-xs font-medium text-text-primary mb-1">No Fix Suggestions</h3>
        <p className="text-[11px] text-text-muted">No automated fixes for the current findings.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header & Filters */}
      <div className="desktop-panel p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Wrench className="h-4 w-4 text-primary-400" />
            <h2 className="text-sm font-semibold text-text-primary">Fix Suggestions</h2>
          </div>
          <div className="text-sm font-semibold text-primary-400">{fixes.length}</div>
        </div>

        <div className="flex gap-3 mb-3">
          <div className="flex-1 relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-disabled" />
            <input
              type="text"
              placeholder="Search fixes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input text-xs py-1.5 pl-8"
            />
          </div>
          <select
            value={filterConfidence}
            onChange={(e) => setFilterConfidence(e.target.value)}
            className="input text-xs py-1.5 w-auto"
          >
            <option value="all">All Confidence</option>
            <option value="high">High (80%+)</option>
            <option value="medium">Medium (60%+)</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'High Confidence', count: fixes.filter(f => f.confidence >= 0.8).length, color: 'text-emerald-400', icon: Star },
            { label: 'Auto-Applicable', count: fixes.filter(f => f.confidence >= 0.9).length, color: 'text-blue-400', icon: Code },
            { label: 'Manual Review', count: fixes.filter(f => f.confidence < 0.8).length, color: 'text-purple-400', icon: Lightbulb }
          ].map(({ label, count, color, icon: Icon }) => (
            <div key={label} className="p-2.5 bg-desktop-card border border-desktop-border rounded-desktop">
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-[11px] ${color}`}>{label}</p>
                  <p className="text-base font-semibold text-text-primary">{count}</p>
                </div>
                <Icon className={`h-4 w-4 ${color}`} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Fix List */}
      <div className="space-y-2">
        {filteredFixes.length === 0 ? (
          <div className="desktop-panel text-center py-6">
            <Search className="h-5 w-5 text-text-disabled mx-auto mb-2" />
            <p className="text-xs text-text-muted">No fixes match your filters</p>
          </div>
        ) : (
          filteredFixes.map((fix, index) => {
            const isExpanded = expandedFixes.has(index)
            const confidence = getConfidenceLevel(fix.confidence)

            return (
              <div key={index} className="desktop-panel overflow-hidden">
                <div
                  className="px-4 py-2.5 cursor-pointer hover:bg-white/[0.02] transition-colors"
                  onClick={() => toggleFixExpansion(index)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <h3 className="text-xs font-medium text-text-primary truncate">
                          {fix.vulnerability_type?.replace(/[._]/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </h3>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-desktop border border-desktop-border ${confidence.color}`}>
                          {Math.round(fix.confidence * 100)}%
                        </span>
                      </div>
                      <p className="text-[11px] text-text-muted truncate">{fix.explanation}</p>
                      <div className="flex items-center gap-3 mt-0.5 text-[10px] text-text-disabled">
                        <span>{fix.file_path?.split('/').pop()}</span>
                        <span>Line {fix.line_number}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 ml-3 flex-shrink-0">
                      <span className={`text-[11px] ${confidence.color}`}>{confidence.label}</span>
                      {isExpanded ? <ChevronDown className="h-3.5 w-3.5 text-text-muted" /> : <ChevronRight className="h-3.5 w-3.5 text-text-muted" />}
                    </div>
                  </div>
                </div>

                {isExpanded && (
                  <div className="px-4 pb-3 pt-1 border-t border-desktop-border">
                    <div className="grid grid-cols-2 gap-3">
                      {/* Original Code */}
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <h4 className="text-[11px] font-medium text-red-400">Original</h4>
                          <button
                            onClick={(e) => { e.stopPropagation(); copyToClipboard(fix.original_code, `original-${index}`) }}
                            className="text-[10px] text-text-muted hover:text-text-primary flex items-center gap-0.5"
                          >
                            {copiedCode.has(`original-${index}`) ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
                            Copy
                          </button>
                        </div>
                        <pre className="text-[11px] text-text-secondary bg-desktop-bg p-2.5 rounded-desktop border border-desktop-border overflow-x-auto whitespace-pre-wrap font-mono">
                          {fix.original_code}
                        </pre>
                      </div>

                      {/* Fixed Code */}
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <h4 className="text-[11px] font-medium text-emerald-400">Fixed</h4>
                          <button
                            onClick={(e) => { e.stopPropagation(); copyToClipboard(fix.fixed_code, `fixed-${index}`) }}
                            className="text-[10px] text-text-muted hover:text-text-primary flex items-center gap-0.5"
                          >
                            {copiedCode.has(`fixed-${index}`) ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
                            Copy
                          </button>
                        </div>
                        <pre className="text-[11px] text-text-secondary bg-desktop-bg p-2.5 rounded-desktop border border-emerald-400/10 overflow-x-auto whitespace-pre-wrap font-mono">
                          {fix.fixed_code}
                        </pre>
                      </div>
                    </div>

                    {/* Notes */}
                    <div className="mt-2.5 p-2.5 bg-blue-500/5 border border-blue-500/10 rounded-desktop">
                      <div className="flex items-start gap-2">
                        <Lightbulb className="h-3.5 w-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                        <div>
                          <p className="text-[11px] text-text-secondary">{fix.explanation}</p>
                          {fix.confidence < 0.8 && (
                            <p className="text-[10px] text-yellow-400 mt-1">⚠ Manual review recommended</p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

export default FixSuggestions
