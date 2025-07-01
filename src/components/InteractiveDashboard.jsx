import React, { useState, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  BarChart3, 
  TrendingUp, 
  TrendingDown, 
  Shield, 
  AlertTriangle,
  CheckCircle,
  Clock,
  Users,
  FileText,
  Zap,
  Target,
  Activity,
  Filter,
  RefreshCw,
  Download,
  Settings,
  Maximize2,
  Minimize2
} from 'lucide-react'
import SecurityHeatmap from './SecurityHeatmap'
import CodeFlowAnalysis from './CodeFlowAnalysis'
import RiskMeter from './RiskMeter'

const InteractiveDashboard = ({ 
  scanData = {}, 
  analyticsData = {}, 
  realTimeUpdates = true 
}) => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d')
  const [selectedMetric, setSelectedMetric] = useState('findings')
  const [expandedWidget, setExpandedWidget] = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshInterval, setRefreshInterval] = useState(30) // seconds
  const [customFilters, setCustomFilters] = useState({
    severity: 'all',
    type: 'all',
    status: 'all'
  })

  // Real-time data simulation
  const [liveData, setLiveData] = useState({
    activeScans: 3,
    queuedScans: 7,
    avgScanTime: 45,
    systemLoad: 68,
    lastUpdate: new Date()
  })

  // Auto-refresh effect
  useEffect(() => {
    if (!autoRefresh) return

    const interval = setInterval(() => {
      setLiveData(prev => ({
        ...prev,
        activeScans: Math.max(0, prev.activeScans + Math.floor(Math.random() * 3) - 1),
        queuedScans: Math.max(0, prev.queuedScans + Math.floor(Math.random() * 5) - 2),
        avgScanTime: Math.max(10, prev.avgScanTime + Math.floor(Math.random() * 10) - 5),
        systemLoad: Math.max(0, Math.min(100, prev.systemLoad + Math.floor(Math.random() * 20) - 10)),
        lastUpdate: new Date()
      }))
    }, refreshInterval * 1000)

    return () => clearInterval(interval)
  }, [autoRefresh, refreshInterval])

  // Process analytics data
  const processedData = useMemo(() => {
    const timeRanges = {
      '24h': 1,
      '7d': 7,
      '30d': 30,
      '90d': 90
    }
    
    const days = timeRanges[selectedTimeRange] || 7
    
    // Generate trend data
    const trendData = Array.from({ length: days }, (_, i) => {
      const date = new Date()
      date.setDate(date.getDate() - (days - 1 - i))
      
      return {
        date: date.toISOString().split('T')[0],
        findings: Math.floor(Math.random() * 50) + 10,
        scans: Math.floor(Math.random() * 20) + 5,
        fixes: Math.floor(Math.random() * 30) + 5,
        riskScore: Math.floor(Math.random() * 40) + 30
      }
    })
    
    return {
      trendData,
      totalFindings: scanData.total_findings || 0,
      totalScans: analyticsData.total_scans || 0,
      avgRiskScore: analyticsData.avg_risk_score || 0,
      improvementRate: 15.3 // Mock improvement rate
    }
  }, [selectedTimeRange, scanData, analyticsData])

  const widgets = [
    {
      id: 'overview',
      title: 'Security Overview',
      size: 'large',
      component: OverviewWidget
    },
    {
      id: 'trends',
      title: 'Security Trends',
      size: 'large',
      component: TrendsWidget
    },
    {
      id: 'realtime',
      title: 'Real-time Monitoring',
      size: 'medium',
      component: RealtimeWidget
    },
    {
      id: 'heatmap',
      title: 'Security Heatmap',
      size: 'large',
      component: HeatmapWidget
    },
    {
      id: 'flow',
      title: 'Code Flow Analysis',
      size: 'large',
      component: FlowWidget
    },
    {
      id: 'performance',
      title: 'Performance Metrics',
      size: 'medium',
      component: PerformanceWidget
    }
  ]

  const exportDashboard = () => {
    const dashboardData = {
      timestamp: new Date().toISOString(),
      timeRange: selectedTimeRange,
      filters: customFilters,
      metrics: processedData,
      liveData,
      scanData,
      analyticsData
    }
    
    const blob = new Blob([JSON.stringify(dashboardData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `byteguardx-dashboard-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      {/* Dashboard Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">Security Dashboard</h2>
          <p className="text-gray-400 mt-1">
            Real-time security insights and analytics
          </p>
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Time Range Selector */}
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
          
          {/* Auto-refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`p-2 rounded-lg transition-colors ${
              autoRefresh ? 'bg-green-500 text-white' : 'bg-gray-700 text-gray-300'
            }`}
          >
            <RefreshCw className={`h-4 w-4 ${autoRefresh ? 'animate-spin' : ''}`} />
          </button>
          
          {/* Export Button */}
          <button
            onClick={exportDashboard}
            className="btn-ghost"
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </button>
          
          {/* Settings */}
          <button className="btn-ghost">
            <Settings className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <QuickStatCard
          title="Total Findings"
          value={processedData.totalFindings}
          change={-12.5}
          icon={AlertTriangle}
          color="red"
        />
        <QuickStatCard
          title="Scans Completed"
          value={processedData.totalScans}
          change={8.3}
          icon={Shield}
          color="blue"
        />
        <QuickStatCard
          title="Risk Score"
          value={`${processedData.avgRiskScore}/100`}
          change={-5.2}
          icon={Target}
          color="yellow"
        />
        <QuickStatCard
          title="Improvement Rate"
          value={`${processedData.improvementRate}%`}
          change={2.1}
          icon={TrendingUp}
          color="green"
        />
      </div>

      {/* Widgets Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        <AnimatePresence>
          {widgets.map(widget => {
            const Widget = widget.component
            const isExpanded = expandedWidget === widget.id
            
            return (
              <motion.div
                key={widget.id}
                layout
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ 
                  opacity: 1, 
                  scale: 1,
                  gridColumn: isExpanded ? 'span 3' : widget.size === 'large' ? 'span 2' : 'span 1'
                }}
                exit={{ opacity: 0, scale: 0.9 }}
                className={`
                  card relative
                  ${widget.size === 'large' ? 'lg:col-span-2' : ''}
                  ${isExpanded ? 'xl:col-span-3 lg:col-span-2' : ''}
                `}
              >
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-white">{widget.title}</h3>
                  <button
                    onClick={() => setExpandedWidget(isExpanded ? null : widget.id)}
                    className="p-1 text-gray-400 hover:text-white transition-colors"
                  >
                    {isExpanded ? (
                      <Minimize2 className="h-4 w-4" />
                    ) : (
                      <Maximize2 className="h-4 w-4" />
                    )}
                  </button>
                </div>
                
                <Widget
                  data={processedData}
                  liveData={liveData}
                  scanData={scanData}
                  analyticsData={analyticsData}
                  isExpanded={isExpanded}
                  filters={customFilters}
                />
              </motion.div>
            )
          })}
        </AnimatePresence>
      </div>
    </div>
  )
}

// Quick Stat Card Component
const QuickStatCard = ({ title, value, change, icon: Icon, color }) => {
  const colorClasses = {
    red: 'text-red-400 bg-red-500',
    blue: 'text-blue-400 bg-blue-500',
    yellow: 'text-yellow-400 bg-yellow-500',
    green: 'text-green-400 bg-green-500'
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-400 text-sm">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          <div className="flex items-center mt-2">
            {change > 0 ? (
              <TrendingUp className="h-4 w-4 text-green-400 mr-1" />
            ) : (
              <TrendingDown className="h-4 w-4 text-red-400 mr-1" />
            )}
            <span className={`text-sm ${change > 0 ? 'text-green-400' : 'text-red-400'}`}>
              {Math.abs(change)}%
            </span>
          </div>
        </div>
        <div className={`p-3 rounded-lg bg-opacity-10 ${colorClasses[color]}`}>
          <Icon className={`h-6 w-6 ${colorClasses[color].split(' ')[0]}`} />
        </div>
      </div>
    </motion.div>
  )
}

// Widget Components
const OverviewWidget = ({ data, scanData }) => (
  <div className="space-y-4">
    <RiskMeter findings={scanData.findings || []} />
    <div className="grid grid-cols-2 gap-4 text-center">
      <div>
        <p className="text-2xl font-bold text-white">{data.totalFindings}</p>
        <p className="text-gray-400 text-sm">Total Issues</p>
      </div>
      <div>
        <p className="text-2xl font-bold text-primary-400">{data.totalScans}</p>
        <p className="text-gray-400 text-sm">Scans Run</p>
      </div>
    </div>
  </div>
)

const TrendsWidget = ({ data, isExpanded }) => (
  <div className="space-y-4">
    <div className="h-48">
      {/* Simplified chart - in production would use Chart.js or similar */}
      <div className="flex items-end justify-between h-full space-x-1">
        {data.trendData.slice(-7).map((point, index) => (
          <div
            key={index}
            className="bg-primary-500 rounded-t"
            style={{
              height: `${(point.findings / 50) * 100}%`,
              width: '12%'
            }}
          />
        ))}
      </div>
    </div>
    <div className="text-center">
      <p className="text-gray-400 text-sm">Security findings trend (7 days)</p>
    </div>
  </div>
)

const RealtimeWidget = ({ liveData }) => (
  <div className="space-y-4">
    <div className="grid grid-cols-2 gap-4">
      <div className="text-center">
        <p className="text-xl font-bold text-green-400">{liveData.activeScans}</p>
        <p className="text-gray-400 text-xs">Active Scans</p>
      </div>
      <div className="text-center">
        <p className="text-xl font-bold text-yellow-400">{liveData.queuedScans}</p>
        <p className="text-gray-400 text-xs">Queued</p>
      </div>
    </div>
    
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="text-gray-400">System Load</span>
        <span className="text-white">{liveData.systemLoad}%</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-2">
        <motion.div
          className="bg-primary-500 h-2 rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${liveData.systemLoad}%` }}
          transition={{ duration: 0.5 }}
        />
      </div>
    </div>
    
    <p className="text-gray-400 text-xs text-center">
      Last updated: {liveData.lastUpdate.toLocaleTimeString()}
    </p>
  </div>
)

const HeatmapWidget = ({ scanData, isExpanded }) => (
  <div className={isExpanded ? 'h-96' : 'h-48'}>
    <SecurityHeatmap 
      findings={scanData.findings || []} 
      files={scanData.files || []}
    />
  </div>
)

const FlowWidget = ({ scanData, isExpanded }) => (
  <div className={isExpanded ? 'h-96' : 'h-48'}>
    <CodeFlowAnalysis 
      findings={scanData.findings || []}
      codeStructure={scanData.codeStructure || {}}
    />
  </div>
)

const PerformanceWidget = ({ data, liveData }) => (
  <div className="space-y-4">
    <div className="grid grid-cols-1 gap-3">
      <div className="flex justify-between">
        <span className="text-gray-400 text-sm">Avg Scan Time</span>
        <span className="text-white font-medium">{liveData.avgScanTime}s</span>
      </div>
      <div className="flex justify-between">
        <span className="text-gray-400 text-sm">Throughput</span>
        <span className="text-white font-medium">2.3 scans/min</span>
      </div>
      <div className="flex justify-between">
        <span className="text-gray-400 text-sm">Success Rate</span>
        <span className="text-green-400 font-medium">98.7%</span>
      </div>
    </div>
    
    <div className="pt-2 border-t border-gray-700">
      <div className="flex items-center space-x-2">
        <Activity className="h-4 w-4 text-green-400" />
        <span className="text-green-400 text-sm">System Healthy</span>
      </div>
    </div>
  </div>
)

export default InteractiveDashboard
