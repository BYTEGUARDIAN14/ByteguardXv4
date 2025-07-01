import React, { useState, useEffect, useMemo } from 'react'
import { motion } from 'framer-motion'
import { 
  GitBranch, 
  ArrowRight, 
  AlertTriangle, 
  Shield, 
  Eye,
  ZoomIn,
  ZoomOut,
  Download,
  Filter,
  Play,
  Pause,
  RotateCcw
} from 'lucide-react'

const CodeFlowAnalysis = ({ findings = [], codeStructure = {} }) => {
  const [selectedFlow, setSelectedFlow] = useState(null)
  const [animationSpeed, setAnimationSpeed] = useState(1)
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentStep, setCurrentStep] = useState(0)
  const [zoomLevel, setZoomLevel] = useState(1)
  const [filterSeverity, setFilterSeverity] = useState('all')

  // Process findings to create data flow paths
  const dataFlows = useMemo(() => {
    const flows = []
    
    // Group findings by potential data flow
    const flowMap = new Map()
    
    findings.forEach(finding => {
      if (finding.type === 'ai_pattern' && finding.subtype?.includes('input')) {
        const flowId = `flow_${finding.file_path}_${finding.line_number}`
        
        if (!flowMap.has(flowId)) {
          flowMap.set(flowId, {
            id: flowId,
            source: {
              file: finding.file_path,
              line: finding.line_number,
              type: 'user_input',
              description: 'User Input Entry Point'
            },
            steps: [],
            vulnerabilities: [],
            riskLevel: 'low'
          })
        }
        
        const flow = flowMap.get(flowId)
        flow.vulnerabilities.push(finding)
        
        // Simulate data flow analysis
        flow.steps = this.generateFlowSteps(finding)
        flow.riskLevel = this.calculateFlowRisk(flow.vulnerabilities)
      }
    })
    
    return Array.from(flowMap.values())
  }, [findings])

  const generateFlowSteps = (finding) => {
    // Simulate code flow analysis based on finding context
    const steps = [
      {
        id: 'input',
        type: 'input',
        description: 'User input received',
        file: finding.file_path,
        line: finding.line_number,
        code: finding.context || 'user_input = request.get("data")',
        riskLevel: 'medium'
      }
    ]
    
    // Add processing steps based on finding type
    if (finding.subtype?.includes('sql')) {
      steps.push({
        id: 'processing',
        type: 'processing',
        description: 'Data processing without validation',
        file: finding.file_path,
        line: finding.line_number + 2,
        code: 'query = f"SELECT * FROM users WHERE id = {user_input}"',
        riskLevel: 'high'
      })
      
      steps.push({
        id: 'database',
        type: 'sink',
        description: 'Database query execution',
        file: finding.file_path,
        line: finding.line_number + 3,
        code: 'cursor.execute(query)',
        riskLevel: 'critical'
      })
    } else if (finding.subtype?.includes('command')) {
      steps.push({
        id: 'processing',
        type: 'processing',
        description: 'Command construction',
        file: finding.file_path,
        line: finding.line_number + 1,
        code: 'command = f"ls {user_input}"',
        riskLevel: 'high'
      })
      
      steps.push({
        id: 'execution',
        type: 'sink',
        description: 'System command execution',
        file: finding.file_path,
        line: finding.line_number + 2,
        code: 'os.system(command)',
        riskLevel: 'critical'
      })
    } else {
      steps.push({
        id: 'output',
        type: 'sink',
        description: 'Data output without sanitization',
        file: finding.file_path,
        line: finding.line_number + 1,
        code: 'return user_input',
        riskLevel: 'medium'
      })
    }
    
    return steps
  }

  const calculateFlowRisk = (vulnerabilities) => {
    const severityWeights = { critical: 4, high: 3, medium: 2, low: 1 }
    const totalWeight = vulnerabilities.reduce((sum, vuln) => {
      return sum + (severityWeights[vuln.severity] || 0)
    }, 0)
    
    if (totalWeight >= 10) return 'critical'
    if (totalWeight >= 6) return 'high'
    if (totalWeight >= 3) return 'medium'
    return 'low'
  }

  const filteredFlows = useMemo(() => {
    if (filterSeverity === 'all') return dataFlows
    return dataFlows.filter(flow => flow.riskLevel === filterSeverity)
  }, [dataFlows, filterSeverity])

  const getRiskColor = (riskLevel) => {
    const colors = {
      critical: 'text-red-400 border-red-500',
      high: 'text-orange-400 border-orange-500',
      medium: 'text-yellow-400 border-yellow-500',
      low: 'text-green-400 border-green-500'
    }
    return colors[riskLevel] || colors.low
  }

  const getStepIcon = (stepType) => {
    switch (stepType) {
      case 'input': return '📥'
      case 'processing': return '⚙️'
      case 'sink': return '🎯'
      default: return '📄'
    }
  }

  const startAnimation = () => {
    if (!selectedFlow) return
    
    setIsPlaying(true)
    setCurrentStep(0)
    
    const interval = setInterval(() => {
      setCurrentStep(prev => {
        if (prev >= selectedFlow.steps.length - 1) {
          setIsPlaying(false)
          clearInterval(interval)
          return prev
        }
        return prev + 1
      })
    }, 1000 / animationSpeed)
  }

  const resetAnimation = () => {
    setIsPlaying(false)
    setCurrentStep(0)
  }

  const exportFlowData = () => {
    const exportData = {
      timestamp: new Date().toISOString(),
      totalFlows: dataFlows.length,
      riskDistribution: {
        critical: dataFlows.filter(f => f.riskLevel === 'critical').length,
        high: dataFlows.filter(f => f.riskLevel === 'high').length,
        medium: dataFlows.filter(f => f.riskLevel === 'medium').length,
        low: dataFlows.filter(f => f.riskLevel === 'low').length
      },
      flows: dataFlows.map(flow => ({
        id: flow.id,
        riskLevel: flow.riskLevel,
        vulnerabilityCount: flow.vulnerabilities.length,
        steps: flow.steps.length,
        source: flow.source
      }))
    }
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `code-flow-analysis-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="card">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-xl font-semibold text-white mb-2">Code Flow Analysis</h3>
          <p className="text-gray-400 text-sm">
            Trace data flow paths and identify security vulnerabilities
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button
            onClick={exportFlowData}
            className="btn-ghost text-sm"
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Flow List */}
        <div className="lg:col-span-1">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-lg font-medium text-white">Data Flows</h4>
            <div className="flex items-center space-x-2">
              <Filter className="h-4 w-4 text-gray-400" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-white"
              >
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {filteredFlows.map((flow, index) => (
              <motion.div
                key={flow.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className={`
                  p-3 rounded-lg border-2 cursor-pointer transition-all duration-200
                  ${selectedFlow?.id === flow.id 
                    ? 'border-primary-500 bg-primary-500 bg-opacity-10' 
                    : 'border-gray-600 hover:border-gray-500'
                  }
                `}
                onClick={() => setSelectedFlow(flow)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <GitBranch className="h-4 w-4 text-gray-400" />
                    <span className="text-white text-sm font-medium">
                      Flow {index + 1}
                    </span>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full border ${getRiskColor(flow.riskLevel)}`}>
                    {flow.riskLevel.toUpperCase()}
                  </span>
                </div>
                
                <p className="text-gray-400 text-xs mb-2">
                  {flow.source.file.split('/').pop()}:{flow.source.line}
                </p>
                
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">
                    {flow.steps.length} steps
                  </span>
                  <span className="text-gray-400">
                    {flow.vulnerabilities.length} issues
                  </span>
                </div>
              </motion.div>
            ))}
            
            {filteredFlows.length === 0 && (
              <div className="text-center py-8">
                <GitBranch className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                <p className="text-gray-400 text-sm">No data flows found</p>
              </div>
            )}
          </div>
        </div>

        {/* Flow Visualization */}
        <div className="lg:col-span-2">
          {selectedFlow ? (
            <div>
              {/* Controls */}
              <div className="flex items-center justify-between mb-6 p-3 bg-gray-800 rounded-lg">
                <div className="flex items-center space-x-3">
                  <button
                    onClick={isPlaying ? () => setIsPlaying(false) : startAnimation}
                    className="btn-primary text-sm"
                  >
                    {isPlaying ? (
                      <Pause className="h-4 w-4 mr-2" />
                    ) : (
                      <Play className="h-4 w-4 mr-2" />
                    )}
                    {isPlaying ? 'Pause' : 'Play'}
                  </button>
                  
                  <button
                    onClick={resetAnimation}
                    className="btn-ghost text-sm"
                  >
                    <RotateCcw className="h-4 w-4 mr-2" />
                    Reset
                  </button>
                </div>
                
                <div className="flex items-center space-x-3">
                  <span className="text-sm text-gray-400">Speed:</span>
                  <input
                    type="range"
                    min="0.5"
                    max="3"
                    step="0.5"
                    value={animationSpeed}
                    onChange={(e) => setAnimationSpeed(parseFloat(e.target.value))}
                    className="w-20"
                  />
                  <span className="text-sm text-gray-300">{animationSpeed}x</span>
                </div>
              </div>

              {/* Flow Steps */}
              <div className="space-y-4">
                {selectedFlow.steps.map((step, index) => {
                  const isActive = index <= currentStep
                  const isCurrent = index === currentStep
                  
                  return (
                    <motion.div
                      key={step.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ 
                        opacity: isActive ? 1 : 0.3,
                        y: 0,
                        scale: isCurrent ? 1.02 : 1
                      }}
                      transition={{ duration: 0.3 }}
                      className={`
                        relative p-4 rounded-lg border-2 transition-all duration-300
                        ${isCurrent 
                          ? `border-primary-500 bg-primary-500 bg-opacity-10 shadow-lg` 
                          : isActive
                            ? `border-gray-600 bg-gray-800`
                            : 'border-gray-700 bg-gray-900'
                        }
                      `}
                    >
                      <div className="flex items-start space-x-4">
                        {/* Step Icon */}
                        <div className={`
                          flex items-center justify-center w-10 h-10 rounded-full border-2
                          ${isCurrent 
                            ? 'border-primary-500 bg-primary-500 bg-opacity-20' 
                            : isActive
                              ? 'border-gray-500 bg-gray-700'
                              : 'border-gray-600 bg-gray-800'
                          }
                        `}>
                          <span className="text-lg">{getStepIcon(step.type)}</span>
                        </div>
                        
                        {/* Step Content */}
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-white font-medium">{step.description}</h5>
                            <span className={`text-xs px-2 py-1 rounded-full border ${getRiskColor(step.riskLevel)}`}>
                              {step.riskLevel.toUpperCase()}
                            </span>
                          </div>
                          
                          <p className="text-gray-400 text-sm mb-3">
                            {step.file.split('/').pop()}:{step.line}
                          </p>
                          
                          <div className="code-block">
                            <pre className="text-sm text-gray-300">
                              {step.code}
                            </pre>
                          </div>
                        </div>
                      </div>
                      
                      {/* Arrow to next step */}
                      {index < selectedFlow.steps.length - 1 && (
                        <div className="flex justify-center mt-4">
                          <motion.div
                            animate={{
                              opacity: isActive ? 1 : 0.3,
                              y: isActive ? [0, 5, 0] : 0
                            }}
                            transition={{
                              y: { duration: 1, repeat: Infinity, ease: "easeInOut" }
                            }}
                          >
                            <ArrowRight className="h-5 w-5 text-primary-400" />
                          </motion.div>
                        </div>
                      )}
                    </motion.div>
                  )
                })}
              </div>

              {/* Vulnerabilities Summary */}
              <div className="mt-6 p-4 bg-gray-800 rounded-lg">
                <h5 className="text-white font-medium mb-3">Associated Vulnerabilities</h5>
                <div className="space-y-2">
                  {selectedFlow.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-gray-700 rounded">
                      <div className="flex items-center space-x-2">
                        <AlertTriangle className={`h-4 w-4 ${getRiskColor(vuln.severity).split(' ')[0]}`} />
                        <span className="text-white text-sm">{vuln.description}</span>
                      </div>
                      <span className={`text-xs px-2 py-1 rounded-full border ${getRiskColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-96 border-2 border-dashed border-gray-600 rounded-lg">
              <div className="text-center">
                <Eye className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-400">Select a data flow to visualize</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default CodeFlowAnalysis
