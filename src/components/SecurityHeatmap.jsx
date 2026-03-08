import React, { useState, useMemo } from 'react'
import {
  FileCode, AlertTriangle, Shield, Bug, Cpu,
  ZoomIn, ZoomOut, Filter, Download, Info
} from 'lucide-react'

const SecurityHeatmap = ({ findings = [], files = [] }) => {
  const [zoomLevel, setZoomLevel] = useState(1)
  const [selectedSeverity, setSelectedSeverity] = useState('all')
  const [selectedType, setSelectedType] = useState('all')
  const [hoveredFile, setHoveredFile] = useState(null)
  const [viewMode, setViewMode] = useState('grid')

  const heatmapData = useMemo(() => {
    const fileMap = new Map()
    files.forEach(file => {
      fileMap.set(file.path, {
        path: file.path, name: file.name || file.path.split('/').pop(),
        directory: file.path.split('/').slice(0, -1).join('/'),
        size: file.size || 1000, findings: [], riskScore: 0,
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 }
      })
    })
    findings.forEach(finding => {
      const f = fileMap.get(finding.file_path)
      if (f) {
        f.findings.push(finding)
        f.severityCounts[finding.severity] += 1
        f.riskScore += ({ critical: 10, high: 7, medium: 4, low: 1 }[finding.severity] || 0)
      }
    })
    return Array.from(fileMap.values())
  }, [findings, files])

  const filteredData = useMemo(() => {
    return heatmapData.filter(file => {
      if (selectedSeverity !== 'all') return file.severityCounts[selectedSeverity] > 0
      if (selectedType !== 'all') return file.findings.some(f => f.type === selectedType)
      return true
    })
  }, [heatmapData, selectedSeverity, selectedType])

  const directoryTree = useMemo(() => {
    const tree = {}
    filteredData.forEach(file => {
      const parts = file.path.split('/')
      let current = tree
      parts.forEach((part, i) => {
        if (!current[part]) current[part] = { name: part, path: parts.slice(0, i + 1).join('/'), isFile: i === parts.length - 1, children: {}, totalRisk: 0, totalFindings: 0 }
        if (i === parts.length - 1) { current[part].fileData = file; current[part].totalRisk = file.riskScore; current[part].totalFindings = file.findings.length }
        else current = current[part].children
      })
    })
    const calc = (n) => { if (n.isFile) return; Object.values(n.children).forEach(c => { calc(c); n.totalRisk += c.totalRisk; n.totalFindings += c.totalFindings }) }
    Object.values(tree).forEach(calc)
    return tree
  }, [filteredData])

  const getRiskColor = (s) => s >= 30 ? 'bg-red-500' : s >= 20 ? 'bg-orange-500' : s >= 10 ? 'bg-yellow-500' : s >= 5 ? 'bg-blue-500' : 'bg-emerald-500'

  const getFileSize = (file) => {
    const maxRisk = Math.max(...heatmapData.map(f => f.riskScore), 1)
    return Math.min(120, 40 * Math.max(0.5, Math.min(2, file.riskScore / maxRisk * 2)) * zoomLevel)
  }

  const exportHeatmap = () => {
    const data = {
      timestamp: new Date().toISOString(), totalFiles: heatmapData.length, totalFindings: findings.length,
      files: heatmapData.map(f => ({ path: f.path, riskScore: f.riskScore, findings: f.findings.length, severityCounts: f.severityCounts }))
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `security-heatmap-${new Date().toISOString().split('T')[0]}.json`; a.click()
    URL.revokeObjectURL(url)
  }

  const renderTreeNode = (node, depth = 0) => {
    if (node.isFile) {
      const file = node.fileData
      return (
        <div key={node.path} className="flex items-center gap-2 p-1.5 rounded-desktop hover:bg-white/[0.02] cursor-pointer transition-colors"
          style={{ paddingLeft: depth * 16 + 8 }}
          onMouseEnter={() => setHoveredFile(file)} onMouseLeave={() => setHoveredFile(null)}>
          <FileCode className="h-3 w-3 text-text-disabled flex-shrink-0" />
          <span className="text-xs text-text-primary truncate">{node.name}</span>
          {file.findings.length > 0 && (
            <span className="text-[10px] px-1 py-0 rounded border border-red-400/15 text-red-400">{file.findings.length}</span>
          )}
          <span className="text-[10px] text-text-disabled ml-auto">R:{file.riskScore}</span>
        </div>
      )
    }
    return (
      <div key={node.path}>
        <div className="flex items-center gap-2 p-1.5 text-text-muted" style={{ paddingLeft: depth * 16 + 8 }}>
          <span className="text-[10px]">📁</span>
          <span className="text-xs font-medium">{node.name}</span>
          {node.totalFindings > 0 && <span className="text-[10px] px-1 py-0 rounded border border-amber-400/15 text-amber-400">{node.totalFindings}</span>}
        </div>
        {Object.values(node.children).map(c => renderTreeNode(c, depth + 1))}
      </div>
    )
  }

  return (
    <div className="desktop-panel">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
        <div>
          <h3 className="text-xs font-semibold text-text-secondary">Security Heatmap</h3>
          <p className="text-[10px] text-text-disabled">{filteredData.length} files · {findings.length} findings</p>
        </div>
        <button onClick={exportHeatmap} className="btn-ghost text-xs px-2 py-1 inline-flex items-center gap-1">
          <Download className="h-3 w-3" /> Export
        </button>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-desktop-border">
        <div className="flex items-center gap-1">
          {['grid', 'tree'].map(m => (
            <button key={m} onClick={() => setViewMode(m)}
              className={`text-[11px] px-2 py-0.5 rounded-desktop transition-colors ${viewMode === m ? 'bg-primary-500/10 text-primary-400' : 'text-text-muted hover:text-text-secondary'}`}>
              {m.charAt(0).toUpperCase() + m.slice(1)}
            </button>
          ))}
        </div>

        {viewMode === 'grid' && (
          <div className="flex items-center gap-1">
            <button onClick={() => setZoomLevel(Math.max(0.5, zoomLevel - 0.25))} className="p-0.5 text-text-muted hover:text-text-primary rounded transition-colors">
              <ZoomOut className="h-3 w-3" />
            </button>
            <span className="text-[10px] text-text-disabled w-8 text-center">{Math.round(zoomLevel * 100)}%</span>
            <button onClick={() => setZoomLevel(Math.min(3, zoomLevel + 0.25))} className="p-0.5 text-text-muted hover:text-text-primary rounded transition-colors">
              <ZoomIn className="h-3 w-3" />
            </button>
          </div>
        )}

        <div className="flex items-center gap-1 ml-auto">
          <Filter className="h-3 w-3 text-text-disabled" />
          <select value={selectedSeverity} onChange={(e) => setSelectedSeverity(e.target.value)} className="input text-[11px] py-0.5 w-auto">
            <option value="all">All Severity</option>
            <option value="critical">Critical</option><option value="high">High</option>
            <option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <select value={selectedType} onChange={(e) => setSelectedType(e.target.value)} className="input text-[11px] py-0.5 w-auto">
            <option value="all">All Types</option>
            <option value="secret">Secrets</option><option value="vulnerability">Vulns</option><option value="ai_pattern">AI</option>
          </select>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 px-4 py-1.5 border-b border-desktop-border">
        <span className="text-[10px] text-text-disabled">Risk:</span>
        {[
          { color: 'bg-emerald-500', label: 'Low' }, { color: 'bg-blue-500', label: 'Med' },
          { color: 'bg-yellow-500', label: 'High' }, { color: 'bg-orange-500', label: 'V.High' },
          { color: 'bg-red-500', label: 'Crit' }
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <div className={`w-2.5 h-2.5 ${color} rounded-sm`} />
            <span className="text-[10px] text-text-muted">{label}</span>
          </div>
        ))}
      </div>

      {/* Content */}
      <div className="p-4">
        {filteredData.length === 0 ? (
          <div className="text-center py-8">
            <Info className="h-5 w-5 text-text-disabled mx-auto mb-1" />
            <p className="text-xs text-text-muted">No files match filters</p>
          </div>
        ) : viewMode === 'grid' ? (
          <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(auto-fill, minmax(${Math.max(60, 120 * zoomLevel)}px, 1fr))` }}>
            {filteredData.map((file) => {
              const size = getFileSize(file)
              const maxRisk = Math.max(...heatmapData.map(f => f.riskScore), 1)
              return (
                <div key={file.path}
                  className={`relative rounded-desktop border border-desktop-border cursor-pointer hover:border-primary-500/20 transition-all ${getRiskColor(file.riskScore)}`}
                  style={{ width: size, height: size, opacity: Math.max(0.15, Math.min(1, file.riskScore / maxRisk)) }}
                  onMouseEnter={() => setHoveredFile(file)} onMouseLeave={() => setHoveredFile(null)}>
                  <div className="absolute inset-0 flex flex-col items-center justify-center p-1">
                    <FileCode className="h-3 w-3 text-white mb-0.5" />
                    <span className="text-[9px] text-white font-medium text-center truncate w-full">{file.name}</span>
                    {file.findings.length > 0 && <span className="text-[9px] text-white font-bold">{file.findings.length}</span>}
                  </div>
                  {file.riskScore >= 20 && <AlertTriangle className="absolute top-0.5 right-0.5 h-2.5 w-2.5 text-white" />}
                </div>
              )
            })}
          </div>
        ) : (
          <div>{Object.values(directoryTree).map(n => renderTreeNode(n))}</div>
        )}
      </div>

      {/* Tooltip */}
      {hoveredFile && (
        <div className="fixed z-50 bg-desktop-panel border border-desktop-border rounded-desktop p-3 shadow-lg pointer-events-none"
          style={{ left: '50%', top: '50%', transform: 'translate(-50%, -50%)' }}>
          <p className="text-xs text-text-primary font-medium mb-0.5">{hoveredFile.name}</p>
          <p className="text-[10px] text-text-disabled mb-2">{hoveredFile.path}</p>
          <div className="space-y-0.5 text-[10px]">
            <div className="flex justify-between gap-4"><span className="text-text-muted">Risk</span><span className="text-text-primary font-medium">{hoveredFile.riskScore}</span></div>
            <div className="flex justify-between gap-4"><span className="text-text-muted">Issues</span><span className="text-text-primary font-medium">{hoveredFile.findings.length}</span></div>
            {Object.entries(hoveredFile.severityCounts).map(([s, c]) => c > 0 && (
              <div key={s} className="flex justify-between gap-4"><span className="text-text-muted capitalize">{s}</span><span className="text-text-primary">{c}</span></div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default SecurityHeatmap
