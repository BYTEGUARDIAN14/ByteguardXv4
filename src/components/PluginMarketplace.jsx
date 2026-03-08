import React, { useState } from 'react';
import {
  Search,
  Filter,
  Star,
  Download,
  Shield,
  Clock,
  Users,
  TrendingUp,
  Award,
  Zap,
  Cloud,
  Globe,
  Code,
  Server,
  Network,
  FileCheck,
  Puzzle
} from 'lucide-react';

const PluginMarketplace = ({ pluginData, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [sortBy, setSortBy] = useState('featured');

  const getCategoryIcon = (category) => ({
    cloud_security: Cloud, web_application: Globe, source_code: Code,
    infrastructure: Server, network_security: Network, binary_analysis: FileCheck,
    compliance: Shield
  }[category] || Puzzle);

  const getCategoryColor = (category) => ({
    cloud_security: 'text-blue-400', web_application: 'text-emerald-400', source_code: 'text-purple-400',
    infrastructure: 'text-amber-400', network_security: 'text-primary-400', binary_analysis: 'text-red-400',
    compliance: 'text-yellow-400'
  }[category] || 'text-text-disabled');

  return (
    <div className="space-y-4">
      {/* Header + Search */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text-primary">Plugin Marketplace</h2>
          <p className="text-[11px] text-text-muted">Discover and manage security scanning plugins</p>
        </div>
        <button onClick={onRefresh} className="btn-ghost text-xs px-3 py-1.5 inline-flex items-center gap-1">
          <TrendingUp className="h-3 w-3" /> Refresh
        </button>
      </div>

      <div className="flex gap-2">
        <div className="flex-1 relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-disabled" />
          <input type="text" placeholder="Search plugins..." value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)} className="input text-xs py-1.5 pl-8" />
        </div>
        <select value={selectedCategory} onChange={(e) => setSelectedCategory(e.target.value)} className="input text-xs py-1.5 w-auto">
          <option value="all">All Categories</option>
          {pluginData?.categories?.map(c => <option key={c.name} value={c.name}>{c.display_name}</option>)}
        </select>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className="input text-xs py-1.5 w-auto">
          <option value="featured">Featured</option>
          <option value="popular">Popular</option>
          <option value="newest">Newest</option>
          <option value="rating">Rated</option>
        </select>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total', value: pluginData?.statistics?.total_plugins || 22, color: 'text-primary-400' },
          { label: 'Active', value: pluginData?.statistics?.active_plugins || 22, color: 'text-emerald-400' },
          { label: 'Categories', value: pluginData?.statistics?.categories || 8, color: 'text-blue-400' },
          { label: 'Success', value: '98.5%', color: 'text-yellow-400' }
        ].map(({ label, value, color }) => (
          <div key={label} className="desktop-panel p-3 text-center">
            <div className={`text-base font-semibold ${color}`}>{value}</div>
            <div className="text-[10px] text-text-disabled">{label}</div>
          </div>
        ))}
      </div>

      {/* Category Grid */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Filter className="h-3.5 w-3.5 text-primary-400" /> Categories
        </h3>
        <div className="grid grid-cols-4 gap-2">
          {pluginData?.categories?.map((category) => {
            const Icon = getCategoryIcon(category.name);
            const color = getCategoryColor(category.name);
            return (
              <button key={category.name}
                onClick={() => setSelectedCategory(category.name)}
                className={`p-2.5 rounded-desktop text-center transition-colors border ${selectedCategory === category.name ? 'border-primary-500/30 bg-primary-500/5' : 'border-desktop-border hover:bg-white/[0.02]'
                  }`}
              >
                <Icon className={`h-4 w-4 ${color} mx-auto mb-1`} />
                <p className="text-[11px] text-text-primary">{category.display_name}</p>
                <p className="text-[10px] text-text-disabled">{category.plugin_count}</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Featured Plugins */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Award className="h-3.5 w-3.5 text-yellow-400" /> Featured Plugins
        </h3>
        <div className="grid grid-cols-3 gap-3">
          {pluginData?.featured_plugins?.slice(0, 6).map((plugin, index) => {
            const Icon = getCategoryIcon(plugin.manifest?.category);
            const color = getCategoryColor(plugin.manifest?.category);
            return (
              <div key={plugin.manifest?.name || index} className="p-3 bg-desktop-card rounded-desktop border border-desktop-border hover:border-primary-500/20 transition-colors">
                <div className="flex items-start justify-between mb-2">
                  <Icon className={`h-4 w-4 ${color}`} />
                  <div className="flex items-center gap-0.5">
                    <Star className="h-2.5 w-2.5 text-yellow-400 fill-current" />
                    <span className="text-[10px] text-text-secondary">{(plugin.trust_score * 5).toFixed(1)}</span>
                  </div>
                </div>
                <h4 className="text-xs font-medium text-text-primary mb-0.5 truncate">
                  {plugin.manifest?.name?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown'}
                </h4>
                <p className="text-[10px] text-text-muted line-clamp-2 mb-2">{plugin.manifest?.description || 'No description'}</p>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-0.5">
                    <div className="w-1.5 h-1.5 bg-emerald-400 rounded-full" />
                    <span className="text-[10px] text-emerald-400">Active</span>
                  </div>
                  <span className="text-[10px] text-text-disabled">v{plugin.manifest?.version || '1.0.0'}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary mb-3">Quick Actions</h3>
        <div className="grid grid-cols-3 gap-2">
          {[
            { label: 'Run All', icon: Zap, color: 'text-primary-400', bg: 'bg-primary-400/5 border-primary-400/10' },
            { label: 'Security Scan', icon: Shield, color: 'text-emerald-400', bg: 'bg-emerald-400/5 border-emerald-400/10' },
            { label: 'Analytics', icon: TrendingUp, color: 'text-blue-400', bg: 'bg-blue-400/5 border-blue-400/10' }
          ].map(({ label, icon: Icon, color, bg }) => (
            <button key={label} className={`flex items-center justify-center gap-1.5 p-2 rounded-desktop border ${bg} ${color} text-xs hover:brightness-125 transition-all`}>
              <Icon className="h-3.5 w-3.5" /> {label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PluginMarketplace;
