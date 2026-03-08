import React, { useState } from 'react';
import {
  Puzzle, Activity, TrendingUp, Clock, CheckCircle, AlertTriangle,
  Play, Pause, Settings, BarChart3, Shield, Cloud, Globe, Code,
  Server, Network, FileCheck, TestTube, Sliders
} from 'lucide-react';
import PluginConfiguration from './PluginConfiguration';
import PluginTestingInterface from './PluginTestingInterface';

const PluginDashboard = ({ pluginData, pluginStats, onRefresh }) => {
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [activeTab, setActiveTab] = useState('overview');

  const getCategoryIcon = (category) => ({
    cloud_security: Cloud, web_application: Globe, source_code: Code,
    infrastructure: Server, network_security: Network, binary_analysis: FileCheck, compliance: Shield
  }[category] || Puzzle);

  const getCategoryColor = (category) => ({
    cloud_security: 'text-blue-400', web_application: 'text-emerald-400', source_code: 'text-purple-400',
    infrastructure: 'text-amber-400', network_security: 'text-primary-400', binary_analysis: 'text-red-400',
    compliance: 'text-yellow-400'
  }[category] || 'text-text-disabled');

  const filteredPlugins = selectedCategory === 'all'
    ? pluginData?.categories?.flatMap(cat => cat.plugins) || []
    : pluginData?.categories?.find(cat => cat.name === selectedCategory)?.plugins || [];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text-primary">Plugin Ecosystem</h2>
          <p className="text-[11px] text-text-muted">Manage and monitor scanning plugins</p>
        </div>
        <button onClick={onRefresh} className="btn-ghost text-xs px-3 py-1.5 inline-flex items-center gap-1">
          <Activity className="h-3 w-3" /> Refresh
        </button>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 border-b border-desktop-border pb-0">
        {[
          { id: 'overview', label: 'Overview', icon: Activity },
          { id: 'configuration', label: 'Config', icon: Sliders },
          { id: 'testing', label: 'Testing', icon: TestTube }
        ].map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setActiveTab(id)}
            className={`flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium border-b-2 transition-colors ${activeTab === id ? 'border-primary-500 text-primary-400' : 'border-transparent text-text-muted hover:text-text-secondary'
              }`}
          >
            <Icon className="h-3 w-3" /> {label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <>
          {/* Category Cards */}
          <div className="grid grid-cols-4 gap-3">
            {pluginData?.categories?.map((category) => {
              const Icon = getCategoryIcon(category.name);
              const color = getCategoryColor(category.name);
              return (
                <button key={category.name}
                  onClick={() => setSelectedCategory(category.name)}
                  className={`desktop-panel p-2.5 text-left transition-colors ${selectedCategory === category.name ? 'border-primary-500/30' : ''
                    }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <Icon className={`h-3.5 w-3.5 ${color}`} />
                    <span className="text-sm font-semibold text-text-primary">{category.plugin_count}</span>
                  </div>
                  <p className="text-[11px] text-text-primary truncate">{category.display_name}</p>
                  <p className="text-[10px] text-text-disabled truncate">{category.description}</p>
                </button>
              );
            })}
          </div>

          {/* Performance & Activity */}
          <div className="grid grid-cols-2 gap-3">
            <div className="desktop-panel p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold text-text-secondary">Performance</h3>
                <BarChart3 className="h-3.5 w-3.5 text-primary-400" />
              </div>
              <div className="space-y-1">
                {pluginStats?.plugin_performance?.slice(0, 5).map((plugin) => (
                  <div key={plugin.plugin} className="flex items-center justify-between p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                    <div>
                      <p className="text-xs text-text-primary">{plugin.plugin.split(':')[0]}</p>
                      <p className="text-[10px] text-text-disabled">{plugin.executions} runs</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-emerald-400 font-medium">{(plugin.success_rate * 100).toFixed(1)}%</p>
                      <p className="text-[10px] text-text-disabled">{plugin.avg_time.toFixed(1)}ms</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="desktop-panel p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold text-text-secondary">Live Activity</h3>
                <Activity className="h-3.5 w-3.5 text-emerald-400" />
              </div>
              <div className="space-y-1">
                {[
                  { plugin: 'AWS S3 Scanner', status: 'completed', findings: 2, time: '1.2s' },
                  { plugin: 'SSRF Detector', status: 'running', findings: 0, time: '0.8s' },
                  { plugin: 'JWT Validator', status: 'completed', findings: 1, time: '0.5s' },
                  { plugin: 'Terraform Scanner', status: 'completed', findings: 3, time: '2.1s' },
                  { plugin: 'Crypto Detector', status: 'queued', findings: 0, time: '-' }
                ].map((exec, i) => (
                  <div key={i} className="flex items-center justify-between p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                    <div className="flex items-center gap-2">
                      <div className={`w-1.5 h-1.5 rounded-full ${exec.status === 'completed' ? 'bg-emerald-400' :
                          exec.status === 'running' ? 'bg-yellow-400 animate-pulse' : 'bg-text-disabled'
                        }`} />
                      <div>
                        <p className="text-xs text-text-primary">{exec.plugin}</p>
                        <p className="text-[10px] text-text-disabled capitalize">{exec.status}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-primary-400">{exec.findings} findings</p>
                      <p className="text-[10px] text-text-disabled">{exec.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Plugin List */}
          <div className="desktop-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-text-secondary">
                {selectedCategory === 'all' ? 'All Plugins' : selectedCategory.replace(/_/g, ' ').toUpperCase()}
              </h3>
              <div className="flex items-center gap-1">
                <button onClick={() => setSelectedCategory('all')}
                  className={`text-[11px] px-2 py-0.5 rounded transition-colors ${selectedCategory === 'all' ? 'bg-primary-500/10 text-primary-400' : 'text-text-muted hover:text-text-secondary'
                    }`}
                >All</button>
                <button onClick={onRefresh} className="p-1 text-text-muted hover:text-text-primary rounded transition-colors">
                  <Settings className="h-3 w-3" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2">
              {filteredPlugins.slice(0, 12).map((plugin, index) => (
                <div key={plugin.manifest?.name || index} className="p-2.5 bg-desktop-card rounded-desktop border border-desktop-border hover:border-primary-500/15 transition-colors">
                  <div className="flex items-start justify-between mb-1.5">
                    <h4 className="text-xs font-medium text-text-primary truncate flex-1">
                      {plugin.manifest?.name?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown'}
                    </h4>
                    <div className="flex items-center gap-0.5 ml-1">
                      <div className="w-1.5 h-1.5 bg-emerald-400 rounded-full" />
                    </div>
                  </div>
                  <p className="text-[10px] text-text-muted line-clamp-2 mb-1.5">{plugin.manifest?.description || 'No description'}</p>
                  <div className="flex items-center justify-between text-[10px] text-text-disabled pt-1.5 border-t border-desktop-border">
                    <span>v{plugin.manifest?.version || '1.0.0'}</span>
                    <span className="text-emerald-400">{((plugin.stats?.trust_score || 0.95) * 100).toFixed(0)}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {activeTab === 'configuration' && <PluginConfiguration pluginData={pluginData} onConfigUpdate={onRefresh} />}
      {activeTab === 'testing' && <PluginTestingInterface pluginData={pluginData} />}
    </div>
  );
};

export default PluginDashboard;
