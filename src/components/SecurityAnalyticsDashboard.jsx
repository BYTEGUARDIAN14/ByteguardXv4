import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Activity,
  BarChart3,
  PieChart,
  Target,
  Zap,
  Clock,
  Users,
  Globe
} from 'lucide-react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart as RechartsPieChart,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';

const SecurityAnalyticsDashboard = ({ pluginData, pluginStats }) => {
  const [timeRange, setTimeRange] = useState('7d');
  const [selectedMetric, setSelectedMetric] = useState('vulnerabilities');

  // Mock data for demonstration
  const vulnerabilityTrends = [
    { date: '2024-01-09', critical: 2, high: 5, medium: 12, low: 8 },
    { date: '2024-01-10', critical: 1, high: 7, medium: 15, low: 10 },
    { date: '2024-01-11', critical: 3, high: 4, medium: 18, low: 12 },
    { date: '2024-01-12', critical: 0, high: 6, medium: 14, low: 9 },
    { date: '2024-01-13', critical: 2, high: 8, medium: 20, low: 15 },
    { date: '2024-01-14', critical: 1, high: 5, medium: 16, low: 11 },
    { date: '2024-01-15', critical: 0, high: 3, medium: 13, low: 7 }
  ];

  const pluginPerformanceData = pluginStats?.plugin_performance?.slice(0, 8).map(plugin => ({
    name: plugin.plugin.split(':')[0].replace(/_/g, ' '),
    executions: plugin.executions,
    successRate: plugin.success_rate * 100,
    avgTime: plugin.avg_time
  })) || [];

  const severityDistribution = [
    { name: 'Critical', value: 12, color: '#ef4444' },
    { name: 'High', value: 38, color: '#f97316' },
    { name: 'Medium', value: 108, color: '#eab308' },
    { name: 'Low', value: 72, color: '#3b82f6' }
  ];

  const categoryBreakdown = pluginData?.categories?.map(cat => ({
    name: cat.display_name,
    plugins: cat.plugin_count,
    findings: Math.floor(Math.random() * 50) + 10
  })) || [];

  const renderMetricCards = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
            <p className="text-2xl font-bold text-white">230</p>
            <p className="text-green-400 text-xs flex items-center mt-1">
              <TrendingUp className="w-3 h-3 mr-1" />
              -12% from last week
            </p>
          </div>
          <div className="p-3 bg-red-500/20 rounded-lg">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-sm">Security Score</p>
            <p className="text-2xl font-bold text-white">87/100</p>
            <p className="text-green-400 text-xs flex items-center mt-1">
              <TrendingUp className="w-3 h-3 mr-1" />
              +5 points
            </p>
          </div>
          <div className="p-3 bg-green-500/20 rounded-lg">
            <Shield className="w-6 h-6 text-green-400" />
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-sm">Plugin Executions</p>
            <p className="text-2xl font-bold text-white">{pluginStats?.total_executions || 1247}</p>
            <p className="text-cyan-400 text-xs flex items-center mt-1">
              <Activity className="w-3 h-3 mr-1" />
              {((pluginStats?.success_rate || 0.985) * 100).toFixed(1)}% success rate
            </p>
          </div>
          <div className="p-3 bg-cyan-500/20 rounded-lg">
            <Zap className="w-6 h-6 text-cyan-400" />
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-sm">Avg Response Time</p>
            <p className="text-2xl font-bold text-white">{(pluginStats?.average_execution_time || 1.2).toFixed(1)}ms</p>
            <p className="text-green-400 text-xs flex items-center mt-1">
              <Clock className="w-3 h-3 mr-1" />
              -0.3ms faster
            </p>
          </div>
          <div className="p-3 bg-blue-500/20 rounded-lg">
            <Target className="w-6 h-6 text-blue-400" />
          </div>
        </div>
      </motion.div>
    </div>
  );

  const renderVulnerabilityTrends = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card mb-8"
    >
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-white flex items-center">
          <TrendingUp className="w-5 h-5 mr-2 text-cyan-400" />
          Vulnerability Trends
        </h3>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="px-3 py-1 bg-black/40 border border-white/10 rounded-md text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
          <option value="90d">Last 90 days</option>
        </select>
      </div>

      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={vulnerabilityTrends}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis 
              dataKey="date" 
              stroke="#9CA3AF"
              fontSize={12}
              tickFormatter={(value) => new Date(value).toLocaleDateString()}
            />
            <YAxis stroke="#9CA3AF" fontSize={12} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1F2937',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#F9FAFB'
              }}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke="#ef4444"
              fill="#ef4444"
              fillOpacity={0.6}
              name="Critical"
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke="#f97316"
              fill="#f97316"
              fillOpacity={0.6}
              name="High"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke="#eab308"
              fill="#eab308"
              fillOpacity={0.6}
              name="Medium"
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke="#3b82f6"
              fill="#3b82f6"
              fillOpacity={0.6}
              name="Low"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );

  const renderPluginPerformance = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card"
      >
        <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
          <BarChart3 className="w-5 h-5 mr-2 text-cyan-400" />
          Plugin Performance
        </h3>
        
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={pluginPerformanceData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis 
                dataKey="name" 
                stroke="#9CA3AF"
                fontSize={10}
                angle={-45}
                textAnchor="end"
                height={80}
              />
              <YAxis stroke="#9CA3AF" fontSize={12} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1F2937',
                  border: '1px solid #374151',
                  borderRadius: '8px',
                  color: '#F9FAFB'
                }}
              />
              <Bar dataKey="executions" fill="#06b6d4" name="Executions" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card"
      >
        <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
          <PieChart className="w-5 h-5 mr-2 text-cyan-400" />
          Severity Distribution
        </h3>
        
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <RechartsPieChart>
              <Pie
                data={severityDistribution}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {severityDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1F2937',
                  border: '1px solid #374151',
                  borderRadius: '8px',
                  color: '#F9FAFB'
                }}
              />
            </RechartsPieChart>
          </ResponsiveContainer>
        </div>
      </motion.div>
    </div>
  );

  const renderCategoryBreakdown = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card"
    >
      <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
        <Globe className="w-5 h-5 mr-2 text-cyan-400" />
        Security Category Breakdown
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {categoryBreakdown.map((category, index) => (
          <div key={index} className="p-4 bg-black/20 rounded-lg border border-white/10">
            <div className="text-center">
              <div className="text-2xl font-bold text-cyan-400 mb-1">
                {category.findings}
              </div>
              <div className="text-sm font-medium text-white mb-1">
                {category.name}
              </div>
              <div className="text-xs text-gray-400">
                {category.plugins} plugins
              </div>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Security Analytics</h2>
          <p className="text-gray-400">
            Comprehensive security insights and plugin performance metrics
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <select
            value={selectedMetric}
            onChange={(e) => setSelectedMetric(e.target.value)}
            className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="vulnerabilities">Vulnerabilities</option>
            <option value="performance">Performance</option>
            <option value="coverage">Coverage</option>
          </select>
        </div>
      </div>

      {renderMetricCards()}
      {renderVulnerabilityTrends()}
      {renderPluginPerformance()}
      {renderCategoryBreakdown()}
    </div>
  );
};

export default SecurityAnalyticsDashboard;
