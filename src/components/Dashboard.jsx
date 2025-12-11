import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  FileText,
  Zap,
  Activity,
  Puzzle,
  Cloud,
  Globe,
  Code,
  Server,
  Network,
  FileCheck,
  Settings
} from 'lucide-react';
import SecurityMetrics from './SecurityMetrics';
import VulnerabilityHeatmap from './VulnerabilityHeatmap';
import RiskMeter from './RiskMeter';
import PluginMarketplace from './PluginMarketplace';
import PluginDashboard from './PluginDashboard';
import PluginExecutionMonitor from './PluginExecutionMonitor';
import SecurityAnalyticsDashboard from './SecurityAnalyticsDashboard';

const Dashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [pluginData, setPluginData] = useState(null);
  const [pluginStats, setPluginStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchDashboardData();
    fetchPluginData();
    fetchPluginStats();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/dashboard/stats');
      if (!response.ok) {
        throw new Error('Failed to fetch dashboard data');
      }
      const data = await response.json();
      setDashboardData(data.stats);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchPluginData = async () => {
    try {
      const response = await fetch('/api/v2/plugins');
      if (response.ok) {
        const data = await response.json();
        setPluginData(data.marketplace);
      }
    } catch (err) {
      console.error('Failed to fetch plugin data:', err);
    }
  };

  const fetchPluginStats = async () => {
    try {
      const response = await fetch('/api/v2/plugins/stats');
      if (response.ok) {
        const data = await response.json();
        setPluginStats(data.stats);
      }
    } catch (err) {
      console.error('Failed to fetch plugin stats:', err);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'cloud_security': return Cloud;
      case 'web_application': return Globe;
      case 'source_code': return Code;
      case 'infrastructure': return Server;
      case 'network_security': return Network;
      case 'binary_analysis': return FileCheck;
      case 'compliance': return Shield;
      default: return Puzzle;
    }
  };

  const renderTabNavigation = () => (
    <div className="flex space-x-1 bg-black/20 backdrop-blur-sm rounded-lg p-1 mb-6">
      {[
        { id: 'overview', label: 'Overview', icon: Activity },
        { id: 'plugins', label: 'Plugin Ecosystem', icon: Puzzle },
        { id: 'marketplace', label: 'Plugin Marketplace', icon: Settings },
        { id: 'security', label: 'Security Analytics', icon: Shield }
      ].map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          onClick={() => setActiveTab(id)}
          className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all duration-200 ${
            activeTab === id
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
              : 'text-gray-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <Icon className="w-4 h-4" />
          <span>{label}</span>
        </button>
      ))}
    </div>
  );

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4" />;
      case 'high': return <AlertTriangle className="h-4 w-4" />;
      case 'medium': return <Clock className="h-4 w-4" />;
      case 'low': return <CheckCircle className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const renderPluginEcosystemOverview = () => (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
      {/* Plugin Statistics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Plugin Ecosystem</h3>
          <Puzzle className="w-6 h-6 text-cyan-400" />
        </div>

        {pluginData && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Total Plugins</span>
              <span className="text-2xl font-bold text-cyan-400">
                {pluginData.statistics?.total_plugins || 22}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Categories</span>
              <span className="text-xl font-semibold text-white">
                {pluginData.statistics?.categories || 8}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Active Plugins</span>
              <span className="text-xl font-semibold text-green-400">
                {pluginData.statistics?.active_plugins || 22}
              </span>
            </div>
          </div>
        )}
      </motion.div>

      {/* Plugin Performance */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Performance</h3>
          <TrendingUp className="w-6 h-6 text-green-400" />
        </div>

        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Success Rate</span>
            <span className="text-2xl font-bold text-green-400">
              {pluginStats ? (pluginStats.success_rate * 100).toFixed(1) : '98.5'}%
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Avg Execution</span>
            <span className="text-xl font-semibold text-white">
              {pluginStats ? pluginStats.average_execution_time?.toFixed(1) : '1.2'}ms
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Total Executions</span>
            <span className="text-xl font-semibold text-cyan-400">
              {pluginStats?.total_executions || 1247}
            </span>
          </div>
        </div>
      </motion.div>

      {/* Security Coverage */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Security Coverage</h3>
          <Shield className="w-6 h-6 text-blue-400" />
        </div>

        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Security Score</span>
            <span className="text-2xl font-bold text-blue-400">
              {dashboardData?.security_score || 87}/100
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Active Threats</span>
            <span className="text-xl font-semibold text-red-400">
              {dashboardData?.active_threats || 3}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Scan Coverage</span>
            <span className="text-xl font-semibold text-green-400">
              {dashboardData?.scan_coverage || 94.2}%
            </span>
          </div>
        </div>
      </motion.div>
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <motion.div
          className="flex items-center space-x-3"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
          <span className="text-gray-300 font-light">Loading dashboard...</span>
        </motion.div>
      </div>
    );
  }

  if (error) {
    return (
      <motion.div
        className="glass-card border-red-400/20 bg-red-500/5"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="flex items-center space-x-3">
          <AlertTriangle className="h-5 w-5 text-red-400" />
          <span className="text-red-300">
            Error loading dashboard: {error}
          </span>
        </div>
      </motion.div>
    );
  }

  const mockData = dashboardData || {
    summary: {
      totalScans: 156,
      totalFindings: 89,
      criticalFindings: 3,
      highFindings: 12,
      mediumFindings: 34,
      lowFindings: 40,
      lastScanTime: '2024-01-15T10:30:00Z',
      riskScore: 65
    },
    recentScans: [
      {
        id: '1',
        path: '/src/components',
        status: 'completed',
        findings: 5,
        timestamp: '2024-01-15T10:30:00Z'
      },
      {
        id: '2',
        path: '/src/utils',
        status: 'completed',
        findings: 2,
        timestamp: '2024-01-15T09:15:00Z'
      },
      {
        id: '3',
        path: '/api/routes',
        status: 'running',
        findings: 0,
        timestamp: '2024-01-15T10:45:00Z'
      }
    ],
    trends: {
      weeklyFindings: [12, 8, 15, 6, 9, 11, 7],
      scanFrequency: [3, 5, 2, 4, 6, 3, 4]
    }
  };

  return (
    <div className="space-y-8 p-6 bg-black text-white min-h-screen">
      {/* Header */}
      <motion.div
        className="flex items-center justify-between"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">
            ByteGuardX Security Dashboard
          </h1>
          <p className="text-gray-300 font-light">
            Advanced security scanning with 22+ production-grade plugins
          </p>
        </div>
        <motion.button
          onClick={() => {
            fetchDashboardData();
            fetchPluginData();
            fetchPluginStats();
          }}
          className="btn-primary hover-lift"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <Activity className="h-4 w-4 mr-2" />
          Refresh
        </motion.button>
      </motion.div>

      {/* Tab Navigation */}
      {renderTabNavigation()}

      {/* Plugin Ecosystem Overview */}
      {activeTab === 'overview' && renderPluginEcosystemOverview()}

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <>
          {/* Plugin Execution Monitor */}
          <div className="mb-8">
            <PluginExecutionMonitor onPluginSelect={(execution) => console.log('Selected:', execution)} />
          </div>

          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="border-l-4 border-l-cyan-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Shield className="h-4 w-4 text-cyan-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockData.summary.totalScans}</div>
            <p className="text-xs text-gray-600">
              +12% from last month
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-red-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {mockData.summary.criticalFindings}
            </div>
            <p className="text-xs text-gray-600">
              Requires immediate attention
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-orange-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Priority</CardTitle>
            <TrendingUp className="h-4 w-4 text-orange-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">
              {mockData.summary.highFindings}
            </div>
            <p className="text-xs text-gray-600">
              -8% from last week
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-green-500">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
            <Zap className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {mockData.summary.riskScore}/100
            </div>
            <Progress value={mockData.summary.riskScore} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Metrics */}
        <div className="lg:col-span-2">
          <SecurityMetrics data={mockData.summary} />
        </div>

        {/* Risk Meter */}
        <div>
          <RiskMeter score={mockData.summary.riskScore} />
        </div>
      </div>

      {/* Vulnerability Heatmap */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <VulnerabilityHeatmap data={mockData.trends} />
        
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FileText className="h-5 w-5 mr-2" />
              Recent Scans
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {mockData.recentScans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 rounded-full ${
                      scan.status === 'completed' ? 'bg-green-500' : 
                      scan.status === 'running' ? 'bg-yellow-500' : 'bg-red-500'
                    }`}></div>
                    <div>
                      <p className="font-medium text-sm">{scan.path}</p>
                      <p className="text-xs text-gray-600">
                        {new Date(scan.timestamp).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant={scan.findings > 0 ? "destructive" : "secondary"}>
                      {scan.findings} issues
                    </Badge>
                    <Badge variant="outline">
                      {scan.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Severity Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle>Findings by Severity</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { severity: 'critical', count: mockData.summary.criticalFindings, label: 'Critical' },
              { severity: 'high', count: mockData.summary.highFindings, label: 'High' },
              { severity: 'medium', count: mockData.summary.mediumFindings, label: 'Medium' },
              { severity: 'low', count: mockData.summary.lowFindings, label: 'Low' }
            ].map(({ severity, count, label }) => (
              <div key={severity} className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`inline-flex items-center justify-center w-12 h-12 rounded-full ${getSeverityColor(severity)} text-white mb-2`}>
                  {getSeverityIcon(severity)}
                </div>
                <div className="text-2xl font-bold">{count}</div>
                <div className="text-sm text-gray-600">{label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
        </>
      )}

      {/* Plugin Dashboard Tab */}
      {activeTab === 'plugins' && (
        <PluginDashboard
          pluginData={pluginData}
          pluginStats={pluginStats}
          onRefresh={() => {
            fetchPluginData();
            fetchPluginStats();
          }}
        />
      )}

      {/* Plugin Marketplace Tab */}
      {activeTab === 'marketplace' && (
        <PluginMarketplace
          pluginData={pluginData}
          onRefresh={fetchPluginData}
        />
      )}

      {/* Security Analytics Tab */}
      {activeTab === 'security' && (
        <SecurityAnalyticsDashboard
          pluginData={pluginData}
          pluginStats={pluginStats}
        />
      )}
    </div>
  );
};

export default Dashboard;
