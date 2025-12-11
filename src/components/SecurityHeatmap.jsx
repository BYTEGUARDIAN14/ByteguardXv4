import React, { useState, useEffect, useMemo } from 'react'
import { motion } from 'framer-motion'
import { 
  FileCode, 
  AlertTriangle, 
  Shield, 
  Bug, 
  Cpu,
  ZoomIn,
  ZoomOut,
  Filter,
  Download,
  Info
} from 'lucide-react'

const SecurityHeatmap = ({ findings = [], files = [] }) => {
  const [zoomLevel, setZoomLevel] = useState(1)
  const [selectedSeverity, setSelectedSeverity] = useState('all')
  const [selectedType, setSelectedType] = useState('all')
  const [hoveredFile, setHoveredFile] = useState(null)
  const [viewMode, setViewMode] = useState('grid') // 'grid' or 'tree'

  // Process data for heatmap
  const heatmapData = useMemo(() => {
    const fileMap = new Map()
    
    // Initialize all files
    files.forEach(file => {
      fileMap.set(file.path, {
        path: file.path,
        name: file.name || file.path.split('/').pop(),
        directory: file.path.split('/').slice(0, -1).join('/'),
        size: file.size || 1000,
        findings: [],
        riskScore: 0,
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 }
      })
    })
    
    // Add findings to files
    findings.forEach(finding => {
      const filePath = finding.file_path
      if (fileMap.has(filePath)) {
        const fileData = fileMap.get(filePath)
        fileData.findings.push(finding)
        fileData.severityCounts[finding.severity] += 1
        
        // Calculate risk score
        const severityWeights = { critical: 10, high: 7, medium: 4, low: 1 }
        fileData.riskScore += severityWeights[finding.severity] || 0
      }
    })
    
    return Array.from(fileMap.values())
  }, [findings, files])

  // Filter data based on selected filters
  const filteredData = useMemo(() => {
    return heatmapData.filter(file => {
      if (selectedSeverity !== 'all') {
        return file.severityCounts[selectedSeverity] > 0
      }
      if (selectedType !== 'all') {
        return file.findings.some(f => f.type === selectedType)
      }
      return true
    })
  }, [heatmapData, selectedSeverity, selectedType])

  // Group files by directory for tree view
  const directoryTree = useMemo(() => {
    const tree = {}
    
    filteredData.forEach(file => {
      const parts = file.path.split('/')
      let current = tree
      
      parts.forEach((part, index) => {
        if (!current[part]) {
          current[part] = {
            name: part,
            path: parts.slice(0, index + 1).join('/'),
            isFile: index === parts.length - 1,
            children: {},
            files: [],
            totalRisk: 0,
            totalFindings: 0
          }
        }
        
        if (index === parts.length - 1) {
          // This is a file
          current[part].fileData = file
          current[part].totalRisk = file.riskScore
          current[part].totalFindings = file.findings.length
        } else {
          // This is a directory
          current = current[part].children
        }
      })
    })
    
    // Calculate directory totals
    const calculateTotals = (node) => {
      if (node.isFile) return
      
      Object.values(node.children).forEach(child => {
        calculateTotals(child)
        node.totalRisk += child.totalRisk
        node.totalFindings += child.totalFindings
      })
    }
    
    Object.values(tree).forEach(calculateTotals)
    
    return tree
  }, [filteredData])

  const getRiskColor = (riskScore) => {
    if (riskScore >= 30) return 'bg-red-500'
    if (riskScore >= 20) return 'bg-orange-500'
    if (riskScore >= 10) return 'bg-yellow-500'
    if (riskScore >= 5) return 'bg-blue-500'
    return 'bg-green-500'
  }

  const getRiskOpacity = (riskScore) => {
    const maxRisk = Math.max(...heatmapData.map(f => f.riskScore), 1)
    return Math.max(0.1, Math.min(1, riskScore / maxRisk))
  }

  const getFileSize = (file) => {
    const baseSize = 40
    const maxSize = 120
    const maxRisk = Math.max(...heatmapData.map(f => f.riskScore), 1)
    const sizeMultiplier = Math.max(0.5, Math.min(2, file.riskScore / maxRisk * 2))
    return Math.min(maxSize, baseSize * sizeMultiplier * zoomLevel)
  }

  const exportHeatmap = () => {
    const data = {
      timestamp: new Date().toISOString(),
      totalFiles: heatmapData.length,
      totalFindings: findings.length,
      riskDistribution: {
        critical: heatmapData.filter(f => f.riskScore >= 30).length,
        high: heatmapData.filter(f => f.riskScore >= 20 && f.riskScore < 30).length,
        medium: heatmapData.filter(f => f.riskScore >= 10 && f.riskScore < 20).length,
        low: heatmapData.filter(f => f.riskScore < 10).length
      },
      files: heatmapData.map(f => ({
        path: f.path,
        riskScore: f.riskScore,
        findings: f.findings.length,
        severityCounts: f.severityCounts
      }))
    }
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-heatmap-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const renderGridView = () => (
    <div 
      className="grid gap-2 p-4"
      style={{
        gridTemplateColumns: `repeat(auto-fill, minmax(${Math.max(60, 120 * zoomLevel)}px, 1fr))`
      }}
    >
      {filteredData.map((file, index) => {
        const size = getFileSize(file)
        const riskColor = getRiskColor(file.riskScore)
        const opacity = getRiskOpacity(file.riskScore)
        
        return (
          <motion.div
            key={file.path}
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: index * 0.01 }}
            className={`
              relative rounded-lg border-2 border-gray-600 cursor-pointer
              hover:border-primary-400 transition-all duration-200
              ${riskColor}
            `}
            style={{
              width: size,
              height: size,
              opacity: opacity
            }}
            onMouseEnter={() => setHoveredFile(file)}
            onMouseLeave={() => setHoveredFile(null)}
          >
            <div className="absolute inset-0 flex flex-col items-center justify-center p-1">
              <FileCode className="h-4 w-4 text-white mb-1" />
              <span className="text-xs text-white font-medium text-center truncate w-full">
                {file.name}
              </span>
              {file.findings.length > 0 && (
                <span className="text-xs text-white font-bold">
                  {file.findings.length}
                </span>
              )}
            </div>
            
            {/* Risk indicator */}
            <div className="absolute top-1 right-1">
              {file.riskScore >= 20 && (
                <AlertTriangle className="h-3 w-3 text-white" />
              )}
            </div>
          </motion.div>
        )
      })}
    </div>
  )

  const renderTreeNode = (node, depth = 0) => {
    if (node.isFile) {
      const file = node.fileData
      const riskColor = getRiskColor(file.riskScore)
      
      return (
        <motion.div
          key={node.path}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className={`
            flex items-center space-x-2 p-2 rounded-lg cursor-pointer
            hover:bg-gray-700 transition-colors duration-200
            ${riskColor} bg-opacity-20 border border-opacity-30
          `}
          style={{ marginLeft: depth * 20 }}
          onMouseEnter={() => setHoveredFile(file)}
          onMouseLeave={() => setHoveredFile(null)}
        >
          <FileCode className="h-4 w-4 text-gray-400" />
          <span className="text-white text-sm">{node.name}</span>
          {file.findings.length > 0 && (
            <span className="bg-red-500 text-white text-xs px-2 py-1 rounded-full">
              {file.findings.length}
            </span>
          )}
        </motion.div>
      )
    }
    
    return (
      <div key={node.path} style={{ marginLeft: depth * 20 }}>
        <div className="flex items-center space-x-2 p-2 text-gray-300">
          <div className="h-4 w-4 text-gray-400">📁</div>
          <span className="text-sm font-medium">{node.name}</span>
          {node.totalFindings > 0 && (
            <span className="bg-orange-500 text-white text-xs px-2 py-1 rounded-full">
              {node.totalFindings}
            </span>
          )}
        </div>
        {Object.values(node.children).map(child => renderTreeNode(child, depth + 1))}
      </div>
    )
  }

  const renderTreeView = () => (
    <div className="p-4">
      {Object.values(directoryTree).map(node => renderTreeNode(node))}
    </div>
  )

  return (
    <div className="card">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-xl font-semibold text-white mb-2">Security Heatmap</h3>
          <p className="text-gray-400 text-sm">
            Visual representation of security risks across your codebase
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button
            onClick={exportHeatmap}
            className="btn-ghost text-sm"
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </button>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-4 mb-6 p-4 bg-gray-800 rounded-lg">
        {/* View Mode */}
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-400">View:</span>
          <button
            onClick={() => setViewMode('grid')}
            className={`px-3 py-1 rounded text-sm ${
              viewMode === 'grid' ? 'bg-primary-500 text-white' : 'bg-gray-700 text-gray-300'
            }`}
          >
            Grid
          </button>
          <button
            onClick={() => setViewMode('tree')}
            className={`px-3 py-1 rounded text-sm ${
              viewMode === 'tree' ? 'bg-primary-500 text-white' : 'bg-gray-700 text-gray-300'
            }`}
          >
            Tree
          </button>
        </div>

        {/* Zoom Controls */}
        {viewMode === 'grid' && (
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">Zoom:</span>
            <button
              onClick={() => setZoomLevel(Math.max(0.5, zoomLevel - 0.25))}
              className="p-1 bg-gray-700 rounded hover:bg-gray-600"
            >
              <ZoomOut className="h-4 w-4 text-gray-300" />
            </button>
            <span className="text-sm text-gray-300 min-w-[3rem] text-center">
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => setZoomLevel(Math.min(3, zoomLevel + 0.25))}
              className="p-1 bg-gray-700 rounded hover:bg-gray-600"
            >
              <ZoomIn className="h-4 w-4 text-gray-300" />
            </button>
          </div>
        )}

        {/* Filters */}
        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-white"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-white"
          >
            <option value="all">All Types</option>
            <option value="secret">Secrets</option>
            <option value="vulnerability">Vulnerabilities</option>
            <option value="ai_pattern">AI Patterns</option>
          </select>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center space-x-6 mb-6 p-3 bg-gray-800 rounded-lg">
        <span className="text-sm text-gray-400">Risk Level:</span>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-green-500 rounded"></div>
            <span className="text-xs text-gray-300">Low (0-5)</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-blue-500 rounded"></div>
            <span className="text-xs text-gray-300">Medium (5-10)</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-yellow-500 rounded"></div>
            <span className="text-xs text-gray-300">High (10-20)</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-orange-500 rounded"></div>
            <span className="text-xs text-gray-300">Very High (20-30)</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-red-500 rounded"></div>
            <span className="text-xs text-gray-300">Critical (30+)</span>
          </div>
        </div>
      </div>

      {/* Heatmap Content */}
      <div className="relative">
        {viewMode === 'grid' ? renderGridView() : renderTreeView()}
        
        {filteredData.length === 0 && (
          <div className="text-center py-12">
            <Info className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-400">No files match the current filters</p>
          </div>
        )}
      </div>

      {/* Hover Tooltip */}
      {hoveredFile && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="fixed z-50 bg-gray-900 border border-gray-600 rounded-lg p-4 shadow-xl pointer-events-none"
          style={{
            left: '50%',
            top: '50%',
            transform: 'translate(-50%, -50%)'
          }}
        >
          <h4 className="text-white font-medium mb-2">{hoveredFile.name}</h4>
          <p className="text-gray-400 text-sm mb-3">{hoveredFile.path}</p>
          
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-400 text-sm">Risk Score:</span>
              <span className="text-white font-medium">{hoveredFile.riskScore}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400 text-sm">Total Issues:</span>
              <span className="text-white font-medium">{hoveredFile.findings.length}</span>
            </div>
            
            {Object.entries(hoveredFile.severityCounts).map(([severity, count]) => (
              count > 0 && (
                <div key={severity} className="flex justify-between">
                  <span className="text-gray-400 text-sm capitalize">{severity}:</span>
                  <span className="text-white font-medium">{count}</span>
                </div>
              )
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}

export default SecurityHeatmap
