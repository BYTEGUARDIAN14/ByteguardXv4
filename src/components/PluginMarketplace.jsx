import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
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
      case 'cloud_security': return 'from-blue-500 to-blue-600';
      case 'web_application': return 'from-green-500 to-green-600';
      case 'source_code': return 'from-purple-500 to-purple-600';
      case 'infrastructure': return 'from-orange-500 to-orange-600';
      case 'network_security': return 'from-cyan-500 to-cyan-600';
      case 'binary_analysis': return 'from-red-500 to-red-600';
      case 'compliance': return 'from-yellow-500 to-yellow-600';
      default: return 'from-gray-500 to-gray-600';
    }
  };

  const renderMarketplaceHeader = () => (
    <div className="mb-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Plugin Marketplace</h2>
          <p className="text-gray-400">
            Discover and manage security scanning plugins for your organization
          </p>
        </div>
        <motion.button
          onClick={onRefresh}
          className="btn-primary"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <TrendingUp className="w-4 h-4 mr-2" />
          Refresh
        </motion.button>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            placeholder="Search plugins..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-3 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
        
        <select
          value={selectedCategory}
          onChange={(e) => setSelectedCategory(e.target.value)}
          className="px-4 py-3 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="all">All Categories</option>
          {pluginData?.categories?.map(category => (
            <option key={category.name} value={category.name}>
              {category.display_name}
            </option>
          ))}
        </select>

        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="px-4 py-3 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="featured">Featured</option>
          <option value="popular">Most Popular</option>
          <option value="newest">Newest</option>
          <option value="rating">Highest Rated</option>
        </select>
      </div>
    </div>
  );

  const renderFeaturedPlugins = () => (
    <div className="mb-8">
      <h3 className="text-xl font-semibold text-white mb-4 flex items-center">
        <Award className="w-5 h-5 mr-2 text-yellow-400" />
        Featured Plugins
      </h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {pluginData?.featured_plugins?.slice(0, 6).map((plugin, index) => (
          <motion.div
            key={plugin.manifest?.name || index}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="glass-card group hover:scale-105 transition-all duration-300"
          >
            <div className="flex items-start justify-between mb-4">
              <div className={`p-3 rounded-lg bg-gradient-to-r ${getCategoryColor(plugin.manifest?.category)}`}>
                {React.createElement(getCategoryIcon(plugin.manifest?.category), {
                  className: "w-6 h-6 text-white"
                })}
              </div>
              <div className="flex items-center space-x-1">
                <Star className="w-4 h-4 text-yellow-400 fill-current" />
                <span className="text-sm text-white font-medium">
                  {(plugin.trust_score * 5).toFixed(1)}
                </span>
              </div>
            </div>

            <h4 className="text-lg font-semibold text-white mb-2">
              {plugin.manifest?.name?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) || 'Unknown Plugin'}
            </h4>
            
            <p className="text-gray-400 text-sm mb-4 line-clamp-3">
              {plugin.manifest?.description || 'No description available'}
            </p>

            <div className="flex items-center justify-between text-xs text-gray-400 mb-4">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-1">
                  <Download className="w-3 h-3" />
                  <span>{Math.floor(Math.random() * 1000)}+</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Users className="w-3 h-3" />
                  <span>{Math.floor(Math.random() * 100)}+</span>
                </div>
              </div>
              <span className="text-cyan-400 font-medium">
                v{plugin.manifest?.version || '1.0.0'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-400 rounded-full" />
                <span className="text-xs text-green-400">Active</span>
              </div>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-md text-xs font-medium hover:bg-cyan-500/30 transition-colors"
              >
                View Details
              </motion.button>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );

  const renderCategoryGrid = () => (
    <div className="mb-8">
      <h3 className="text-xl font-semibold text-white mb-4 flex items-center">
        <Filter className="w-5 h-5 mr-2 text-cyan-400" />
        Browse by Category
      </h3>
      
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
        {pluginData?.categories?.map((category, index) => {
          const Icon = getCategoryIcon(category.name);
          const gradientClass = getCategoryColor(category.name);
          
          return (
            <motion.div
              key={category.name}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.05 }}
              className={`relative overflow-hidden rounded-xl cursor-pointer group ${
                selectedCategory === category.name ? 'ring-2 ring-cyan-500' : ''
              }`}
              onClick={() => setSelectedCategory(category.name)}
            >
              <div className={`bg-gradient-to-br ${gradientClass} p-6 text-center transition-transform group-hover:scale-105`}>
                <Icon className="w-8 h-8 text-white mx-auto mb-2" />
                <h4 className="text-white font-medium text-sm mb-1">
                  {category.display_name}
                </h4>
                <p className="text-white/80 text-xs">
                  {category.plugin_count} plugins
                </p>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );

  const renderMarketplaceStats = () => (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card text-center"
      >
        <div className="text-3xl font-bold text-cyan-400 mb-2">
          {pluginData?.statistics?.total_plugins || 22}
        </div>
        <div className="text-gray-400 text-sm">Total Plugins</div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card text-center"
      >
        <div className="text-3xl font-bold text-green-400 mb-2">
          {pluginData?.statistics?.active_plugins || 22}
        </div>
        <div className="text-gray-400 text-sm">Active Plugins</div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card text-center"
      >
        <div className="text-3xl font-bold text-blue-400 mb-2">
          {pluginData?.statistics?.categories || 8}
        </div>
        <div className="text-gray-400 text-sm">Categories</div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass-card text-center"
      >
        <div className="text-3xl font-bold text-yellow-400 mb-2">
          98.5%
        </div>
        <div className="text-gray-400 text-sm">Success Rate</div>
      </motion.div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      {renderMarketplaceHeader()}

      {/* Statistics */}
      {renderMarketplaceStats()}

      {/* Category Grid */}
      {renderCategoryGrid()}

      {/* Featured Plugins */}
      {renderFeaturedPlugins()}

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card"
      >
        <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center justify-center space-x-2 p-4 bg-cyan-500/20 text-cyan-400 rounded-lg hover:bg-cyan-500/30 transition-colors">
            <Zap className="w-5 h-5" />
            <span>Run All Plugins</span>
          </button>
          <button className="flex items-center justify-center space-x-2 p-4 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 transition-colors">
            <Shield className="w-5 h-5" />
            <span>Security Scan</span>
          </button>
          <button className="flex items-center justify-center space-x-2 p-4 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 transition-colors">
            <TrendingUp className="w-5 h-5" />
            <span>View Analytics</span>
          </button>
        </div>
      </motion.div>
    </div>
  );
};

export default PluginMarketplace;
