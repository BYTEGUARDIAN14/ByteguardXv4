import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Puzzle,
  Activity,
  TrendingUp,
  Clock,
  CheckCircle,
  AlertTriangle,
  Play,
  Pause,
  Settings,
  BarChart3,
  Shield,
  Cloud,
  Globe,
  Code,
  Server,
  Network,
  FileCheck,
  TestTube,
  Sliders
} from 'lucide-react';
import PluginConfiguration from './PluginConfiguration';
import PluginTestingInterface from './PluginTestingInterface';

const PluginDashboard = ({ pluginData, pluginStats, onRefresh }) => {
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [pluginExecutions, setPluginExecutions] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');

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

  const getCategoryColor = (category) => {
    switch (category) {
      case 'cloud_security': return 'text-blue-400 bg-blue-500/20';
      case 'web_application': return 'text-green-400 bg-green-500/20';
      case 'source_code': return 'text-purple-400 bg-purple-500/20';
      case 'infrastructure': return 'text-orange-400 bg-orange-500/20';
      case 'network_security': return 'text-cyan-400 bg-cyan-500/20';
      case 'binary_analysis': return 'text-red-400 bg-red-500/20';
      case 'compliance': return 'text-yellow-400 bg-yellow-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const renderTabNavigation = () => (
    <div className="flex space-x-1 bg-black/20 backdrop-blur-sm rounded-lg p-1 mb-6">
      {[
        { id: 'overview', label: 'Overview', icon: Activity },
        { id: 'configuration', label: 'Configuration', icon: Sliders },
        { id: 'testing', label: 'Testing', icon: TestTube }
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

  const renderPluginCategories = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      {pluginData?.categories?.map((category, index) => {
        const Icon = getCategoryIcon(category.name);
        const colorClass = getCategoryColor(category.name);
        
        return (
          <motion.div
            key={category.name}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className={`glass-card cursor-pointer transition-all duration-200 hover:scale-105 ${
              selectedCategory === category.name ? 'ring-2 ring-cyan-500' : ''
            }`}
            onClick={() => setSelectedCategory(category.name)}
          >
            <div className="flex items-center justify-between mb-3">
              <div className={`p-2 rounded-lg ${colorClass}`}>
                <Icon className="w-5 h-5" />
              </div>
              <span className="text-2xl font-bold text-white">
                {category.plugin_count}
              </span>
            </div>
            <h3 className="text-sm font-medium text-gray-300 mb-1">
              {category.display_name}
            </h3>
            <p className="text-xs text-gray-400 line-clamp-2">
              {category.description}
            </p>
          </motion.div>
        );
      })}
    </div>
  );

  const renderPluginPerformance = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      {/* Performance Metrics */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">Performance Metrics</h3>
          <BarChart3 className="w-5 h-5 text-cyan-400" />
        </div>
        
        <div className="space-y-4">
          {pluginStats?.plugin_performance?.slice(0, 5).map((plugin, index) => (
            <div key={plugin.plugin} className="flex items-center justify-between p-3 bg-black/20 rounded-lg">
              <div className="flex-1">
                <div className="text-sm font-medium text-white">
                  {plugin.plugin.split(':')[0]}
                </div>
                <div className="text-xs text-gray-400">
                  {plugin.executions} executions
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm font-semibold text-green-400">
                  {(plugin.success_rate * 100).toFixed(1)}%
                </div>
                <div className="text-xs text-gray-400">
                  {plugin.avg_time.toFixed(1)}ms
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Real-time Activity */}
      <motion.div
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">Real-time Activity</h3>
          <Activity className="w-5 h-5 text-green-400" />
        </div>
        
        <div className="space-y-3">
          {/* Mock real-time plugin executions */}
          {[
            { plugin: 'AWS S3 Scanner', status: 'completed', findings: 2, time: '1.2s' },
            { plugin: 'SSRF Detector', status: 'running', findings: 0, time: '0.8s' },
            { plugin: 'JWT Validator', status: 'completed', findings: 1, time: '0.5s' },
            { plugin: 'Terraform Scanner', status: 'completed', findings: 3, time: '2.1s' },
            { plugin: 'Crypto Detector', status: 'queued', findings: 0, time: '-' }
          ].map((execution, index) => (
            <div key={index} className="flex items-center justify-between p-3 bg-black/20 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className={`w-2 h-2 rounded-full ${
                  execution.status === 'completed' ? 'bg-green-400' :
                  execution.status === 'running' ? 'bg-yellow-400 animate-pulse' :
                  'bg-gray-400'
                }`} />
                <div>
                  <div className="text-sm font-medium text-white">
                    {execution.plugin}
                  </div>
                  <div className="text-xs text-gray-400 capitalize">
                    {execution.status}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm font-semibold text-cyan-400">
                  {execution.findings} findings
                </div>
                <div className="text-xs text-gray-400">
                  {execution.time}
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );

  const renderPluginList = () => {
    const filteredPlugins = selectedCategory === 'all' 
      ? pluginData?.categories?.flatMap(cat => cat.plugins) || []
      : pluginData?.categories?.find(cat => cat.name === selectedCategory)?.plugins || [];

    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">
            {selectedCategory === 'all' ? 'All Plugins' : `${selectedCategory.replace('_', ' ').toUpperCase()} Plugins`}
          </h3>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-3 py-1 rounded-md text-sm transition-colors ${
                selectedCategory === 'all'
                  ? 'bg-cyan-500/20 text-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              All
            </button>
            <button
              onClick={onRefresh}
              className="p-2 text-gray-400 hover:text-white transition-colors"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredPlugins.slice(0, 12).map((plugin, index) => (
            <motion.div
              key={plugin.manifest?.name || index}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.05 }}
              className="bg-black/20 border border-white/10 rounded-lg p-4 hover:bg-black/30 transition-colors"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1">
                  <h4 className="text-sm font-semibold text-white mb-1">
                    {plugin.manifest?.name?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown Plugin'}
                  </h4>
                  <p className="text-xs text-gray-400 line-clamp-2">
                    {plugin.manifest?.description || 'No description available'}
                  </p>
                </div>
                <div className="flex items-center space-x-1 ml-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full" />
                  <span className="text-xs text-green-400">Active</span>
                </div>
              </div>
              
              <div className="flex items-center justify-between text-xs text-gray-400">
                <span>v{plugin.manifest?.version || '1.0.0'}</span>
                <span>{plugin.manifest?.trust_level || 'High'} Trust</span>
              </div>
              
              <div className="mt-3 pt-3 border-t border-white/10">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">Executions:</span>
                  <span className="text-white font-medium">
                    {plugin.stats?.executions || Math.floor(Math.random() * 100)}
                  </span>
                </div>
                <div className="flex items-center justify-between text-xs mt-1">
                  <span className="text-gray-400">Success Rate:</span>
                  <span className="text-green-400 font-medium">
                    {((plugin.stats?.trust_score || 0.95) * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Plugin Ecosystem</h2>
          <p className="text-gray-400">
            Manage and monitor your security scanning plugins
          </p>
        </div>
        <motion.button
          onClick={onRefresh}
          className="btn-primary"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <Activity className="w-4 h-4 mr-2" />
          Refresh
        </motion.button>
      </div>

      {/* Tab Navigation */}
      {renderTabNavigation()}

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <>
          {/* Plugin Categories */}
          {renderPluginCategories()}

          {/* Performance Metrics */}
          {renderPluginPerformance()}

          {/* Plugin List */}
          {renderPluginList()}
        </>
      )}

      {activeTab === 'configuration' && (
        <PluginConfiguration
          pluginData={pluginData}
          onConfigUpdate={onRefresh}
        />
      )}

      {activeTab === 'testing' && (
        <PluginTestingInterface
          pluginData={pluginData}
        />
      )}
    </div>
  );
};

export default PluginDashboard;
