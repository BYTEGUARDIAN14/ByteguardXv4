/**
 * Developer Metrics Dashboard
 * Comprehensive analytics for developers including scan metrics, patterns, and plugin usage
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Activity,
  Shield,
  Clock,
  Users,
  Code,
  AlertTriangle,
  CheckCircle,
  Download,
  Filter,
  Calendar,
  Zap,
  Target,
  Layers
} from 'lucide-react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';

const DeveloperMetricsDashboard = ({ timeRange = '30d', userId }) => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedMetric, setSelectedMetric] = useState('scans');

  // Mock data - in production, this would come from API
  const mockMetrics = {
    overview: {
      total_scans: 1247,
      total_vulnerabilities: 89,
      scan_success_rate: 98.4,
      average_scan_time: 285,
      most_used_plugins: ['security-scanner', 'dependency-checker', 'secret-detector'],
      security_score_trend: 'up',
      productivity_score: 87
    },
    scan_metrics: {
      daily_scans: [
        { date: '2024-01-01', scans: 45, vulnerabilities: 3, duration: 280 },
        { date: '2024-01-02', scans: 52, vulnerabilities: 7, duration: 295 },
        { date: '2024-01-03', scans: 38, vulnerabilities: 2, duration: 270 },
        { date: '2024-01-04', scans: 61, vulnerabilities: 8, duration: 310 },
        { date: '2024-01-05', scans: 47, vulnerabilities: 4, duration: 275 },
        { date: '2024-01-06', scans: 55, vulnerabilities: 6, duration: 290 },
        { date: '2024-01-07', scans: 43, vulnerabilities: 3, duration: 265 }
      ],
      vulnerability_types: [
        { name: 'SQL Injection', count: 23, severity: 'high' },
        { name: 'XSS', count: 18, severity: 'medium' },
        { name: 'Secrets Exposed', count: 15, severity: 'critical' },
        { name: 'Dependency Vuln', count: 12, severity: 'medium' },
        { name: 'CSRF', count: 8, severity: 'low' },
        { name: 'Path Traversal', count: 6, severity: 'high' },
        { name: 'Code Injection', count: 4, severity: 'critical' },
        { name: 'Auth Bypass', count: 3, severity: 'critical' }
      ],
      scan_patterns: {
        peak_hours: [9, 10, 11, 14, 15, 16],
        preferred_days: ['Monday', 'Tuesday', 'Wednesday', 'Thursday'],
        scan_frequency: 'daily',
        batch_size_avg: 15.7
      }
    },
    plugin_usage: {
      most_popular: [
        { name: 'Security Scanner', usage: 95, rating: 4.8 },
        { name: 'Dependency Checker', usage: 87, rating: 4.6 },
        { name: 'Secret Detector', usage: 82, rating: 4.9 },
        { name: 'Code Quality', usage: 76, rating: 4.4 },
        { name: 'License Checker', usage: 68, rating: 4.2 }
      ],
      performance_impact: [
        { plugin: 'Security Scanner', avg_time: 45, memory_mb: 128 },
        { plugin: 'Dependency Checker', avg_time: 32, memory_mb: 96 },
        { plugin: 'Secret Detector', avg_time: 28, memory_mb: 64 },
        { plugin: 'Code Quality', avg_time: 67, memory_mb: 156 },
        { plugin: 'License Checker', avg_time: 15, memory_mb: 32 }
      ]
    },
    productivity: {
      time_saved: 156, // hours per month
      issues_prevented: 234,
      false_positive_rate: 3.2,
      developer_satisfaction: 4.6,
      adoption_rate: 89.3,
      workflow_integration: 92.1
    }
  };

  useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setMetrics(mockMetrics);
      setLoading(false);
    }, 1000);
  }, [timeRange, userId]);

  const MetricCard = ({ title, value, change, icon: Icon, color = 'blue' }) => (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className="card p-6"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400 mb-1">{title}</p>
          <p className="text-2xl font-bold text-white">{value}</p>
          {change && (
            <div className={`flex items-center mt-2 text-sm ${
              change.type === 'increase' ? 'text-green-400' : 'text-red-400'
            }`}>
              {change.type === 'increase' ? <TrendingUp className="h-4 w-4 mr-1" /> : <TrendingDown className="h-4 w-4 mr-1" />}
              {change.value}
            </div>
          )}
        </div>
        <div className={`p-3 rounded-lg bg-${color}-500/20`}>
          <Icon className={`h-6 w-6 text-${color}-400`} />
        </div>
      </div>
    </motion.div>
  );

  const VulnerabilityChart = () => {
    const data = metrics?.scan_metrics.daily_scans || [];
    
    return (
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">Scan Activity & Vulnerabilities</h3>
          <div className="flex items-center space-x-2">
            <Calendar className="h-4 w-4 text-gray-400" />
            <span className="text-sm text-gray-400">Last 7 days</span>
          </div>
        </div>
        
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="date" stroke="#9CA3AF" />
            <YAxis stroke="#9CA3AF" />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1F2937', 
                border: '1px solid #374151',
                borderRadius: '8px'
              }}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="scans"
              stackId="1"
              stroke="#3B82F6"
              fill="#3B82F6"
              fillOpacity={0.3}
              name="Scans"
            />
            <Area
              type="monotone"
              dataKey="vulnerabilities"
              stackId="2"
              stroke="#EF4444"
              fill="#EF4444"
              fillOpacity={0.3}
              name="Vulnerabilities"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    );
  };

  const VulnerabilityTypesChart = () => {
    const data = metrics?.scan_metrics.vulnerability_types || [];
    const COLORS = {
      critical: '#DC2626',
      high: '#EA580C',
      medium: '#D97706',
      low: '#65A30D'
    };

    return (
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-white mb-6">Most Flagged Patterns</h3>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                outerRadius={80}
                fill="#8884d8"
                dataKey="count"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[entry.severity]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          
          <div className="space-y-3">
            {data.slice(0, 6).map((item, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div 
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: COLORS[item.severity] }}
                  />
                  <span className="text-sm text-white">{item.name}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-medium text-white">{item.count}</span>
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    item.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    item.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    item.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  }`}>
                    {item.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  const PluginUsageChart = () => {
    const data = metrics?.plugin_usage.most_popular || [];

    return (
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-white mb-6">Most Used Plugins</h3>
        
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={data} layout="horizontal">
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis type="number" stroke="#9CA3AF" />
            <YAxis dataKey="name" type="category" stroke="#9CA3AF" width={120} />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1F2937', 
                border: '1px solid #374151',
                borderRadius: '8px'
              }}
            />
            <Bar dataKey="usage" fill="#10B981" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  };

  const ProductivityMetrics = () => {
    const productivity = metrics?.productivity || {};

    return (
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-white mb-6">Productivity Impact</h3>
        
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-400">{productivity.time_saved}h</div>
            <div className="text-sm text-gray-400">Time Saved</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-400">{productivity.issues_prevented}</div>
            <div className="text-sm text-gray-400">Issues Prevented</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">{productivity.false_positive_rate}%</div>
            <div className="text-sm text-gray-400">False Positive Rate</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-400">{productivity.developer_satisfaction}/5</div>
            <div className="text-sm text-gray-400">Satisfaction Score</div>
          </div>
        </div>
        
        <div className="mt-6 space-y-4">
          <div>
            <div className="flex justify-between text-sm mb-2">
              <span className="text-gray-400">Adoption Rate</span>
              <span className="text-white">{productivity.adoption_rate}%</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="bg-green-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${productivity.adoption_rate}%` }}
              />
            </div>
          </div>
          
          <div>
            <div className="flex justify-between text-sm mb-2">
              <span className="text-gray-400">Workflow Integration</span>
              <span className="text-white">{productivity.workflow_integration}%</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${productivity.workflow_integration}%` }}
              />
            </div>
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Developer Metrics</h2>
          <p className="text-gray-400 mt-1">Comprehensive analytics and insights for your development workflow</p>
        </div>
        
        <div className="flex items-center space-x-4">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white"
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last year</option>
          </select>
          
          <button className="flex items-center space-x-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors">
            <Download className="h-4 w-4" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Scans"
          value={metrics.overview.total_scans.toLocaleString()}
          change={{ type: 'increase', value: '+12.5%' }}
          icon={Activity}
          color="blue"
        />
        <MetricCard
          title="Vulnerabilities Found"
          value={metrics.overview.total_vulnerabilities}
          change={{ type: 'decrease', value: '-8.2%' }}
          icon={Shield}
          color="red"
        />
        <MetricCard
          title="Success Rate"
          value={`${metrics.overview.scan_success_rate}%`}
          change={{ type: 'increase', value: '+2.1%' }}
          icon={CheckCircle}
          color="green"
        />
        <MetricCard
          title="Avg Scan Time"
          value={`${metrics.overview.average_scan_time}s`}
          change={{ type: 'decrease', value: '-15.3%' }}
          icon={Clock}
          color="yellow"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <VulnerabilityChart />
        <VulnerabilityTypesChart />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <PluginUsageChart />
        <ProductivityMetrics />
      </div>
    </div>
  );
};

export default DeveloperMetricsDashboard;
