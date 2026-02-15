import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Settings,
  Shield,
  Sliders,
  Toggle,
  Save,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Info,
  Lock,
  Unlock,
  Zap,
  Clock,
  Memory,
  Cpu
} from 'lucide-react';
import tauriAPI from '../services/tauri-api';

const PluginConfiguration = ({ pluginData, onConfigUpdate }) => {
  const [configurations, setConfigurations] = useState({});
  const [globalSettings, setGlobalSettings] = useState({
    enableSandbox: true,
    maxConcurrentPlugins: 10,
    defaultTimeout: 60,
    maxMemoryMB: 512,
    maxCpuPercent: 50,
    trustThreshold: 0.7,
    enableLogging: true,
    enableMetrics: true
  });
  const [selectedPlugin, setSelectedPlugin] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadConfigurations();
  }, []);

  const loadConfigurations = async () => {
    try {
      const data = await tauriAPI.plugins.getConfig();
      if (data) {
        setConfigurations(data.configurations || {});
        setGlobalSettings(data.global_settings || globalSettings);
      }
    } catch (error) {
      console.error('Failed to load configurations:', error);
    }
  };

  const saveConfiguration = async () => {
    setSaving(true);
    try {
      const success = await tauriAPI.plugins.saveConfig({
        configurations,
        global_settings: globalSettings
      });

      if (success) {
        onConfigUpdate && onConfigUpdate();
        // Show success notification
      }
    } catch (error) {
      console.error('Failed to save configuration:', error);
    } finally {
      setSaving(false);
    }
  };

  const updatePluginConfig = (pluginName, key, value) => {
    setConfigurations(prev => ({
      ...prev,
      [pluginName]: {
        ...prev[pluginName],
        [key]: value
      }
    }));
  };

  const updateGlobalSetting = (key, value) => {
    setGlobalSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const renderGlobalSettings = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card mb-6"
    >
      <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
        <Settings className="w-5 h-5 mr-2 text-cyan-400" />
        Global Plugin Settings
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Sandbox Settings */}
        <div className="space-y-4">
          <h4 className="text-sm font-medium text-gray-300 flex items-center">
            <Shield className="w-4 h-4 mr-2" />
            Security & Sandbox
          </h4>

          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400">Enable Sandbox</span>
            <button
              onClick={() => updateGlobalSetting('enableSandbox', !globalSettings.enableSandbox)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${globalSettings.enableSandbox ? 'bg-cyan-600' : 'bg-gray-600'
                }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${globalSettings.enableSandbox ? 'translate-x-6' : 'translate-x-1'
                  }`}
              />
            </button>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2">Trust Threshold</label>
            <input
              type="range"
              min="0.1"
              max="1.0"
              step="0.1"
              value={globalSettings.trustThreshold}
              onChange={(e) => updateGlobalSetting('trustThreshold', parseFloat(e.target.value))}
              className="w-full"
            />
            <div className="text-xs text-gray-500 mt-1">
              {(globalSettings.trustThreshold * 100).toFixed(0)}%
            </div>
          </div>
        </div>

        {/* Performance Settings */}
        <div className="space-y-4">
          <h4 className="text-sm font-medium text-gray-300 flex items-center">
            <Zap className="w-4 h-4 mr-2" />
            Performance Limits
          </h4>

          <div>
            <label className="block text-sm text-gray-400 mb-2">Max Concurrent Plugins</label>
            <input
              type="number"
              min="1"
              max="50"
              value={globalSettings.maxConcurrentPlugins}
              onChange={(e) => updateGlobalSetting('maxConcurrentPlugins', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2 flex items-center">
              <Clock className="w-3 h-3 mr-1" />
              Default Timeout (seconds)
            </label>
            <input
              type="number"
              min="10"
              max="300"
              value={globalSettings.defaultTimeout}
              onChange={(e) => updateGlobalSetting('defaultTimeout', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>

        {/* Resource Settings */}
        <div className="space-y-4">
          <h4 className="text-sm font-medium text-gray-300 flex items-center">
            <Memory className="w-4 h-4 mr-2" />
            Resource Limits
          </h4>

          <div>
            <label className="block text-sm text-gray-400 mb-2">Max Memory (MB)</label>
            <input
              type="number"
              min="64"
              max="2048"
              value={globalSettings.maxMemoryMB}
              onChange={(e) => updateGlobalSetting('maxMemoryMB', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2 flex items-center">
              <Cpu className="w-3 h-3 mr-1" />
              Max CPU (%)
            </label>
            <input
              type="number"
              min="10"
              max="100"
              value={globalSettings.maxCpuPercent}
              onChange={(e) => updateGlobalSetting('maxCpuPercent', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>
      </div>

      <div className="mt-6 pt-6 border-t border-white/10">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={globalSettings.enableLogging}
                onChange={(e) => updateGlobalSetting('enableLogging', e.target.checked)}
                className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
              />
              <span className="text-sm text-gray-400">Enable Logging</span>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={globalSettings.enableMetrics}
                onChange={(e) => updateGlobalSetting('enableMetrics', e.target.checked)}
                className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
              />
              <span className="text-sm text-gray-400">Enable Metrics</span>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );

  const renderPluginList = () => {
    const allPlugins = pluginData?.categories?.flatMap(cat => cat.plugins) || [];

    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card"
      >
        <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
          <Sliders className="w-5 h-5 mr-2 text-cyan-400" />
          Plugin Configuration
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {allPlugins.slice(0, 12).map((plugin, index) => {
            const pluginName = plugin.manifest?.name || `plugin_${index}`;
            const config = configurations[pluginName] || {};
            const isEnabled = config.enabled !== false;

            return (
              <div
                key={pluginName}
                className={`p-4 bg-black/20 border rounded-lg transition-all cursor-pointer ${selectedPlugin === pluginName
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-white/10 hover:border-white/20'
                  }`}
                onClick={() => setSelectedPlugin(selectedPlugin === pluginName ? null : pluginName)}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    <div className={`w-2 h-2 rounded-full ${isEnabled ? 'bg-green-400' : 'bg-gray-400'}`} />
                    <h4 className="text-sm font-medium text-white">
                      {pluginName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </h4>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      updatePluginConfig(pluginName, 'enabled', !isEnabled);
                    }}
                    className={`p-1 rounded ${isEnabled ? 'text-green-400' : 'text-gray-400'}`}
                  >
                    {isEnabled ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                  </button>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Trust Level:</span>
                    <span className="text-white">{plugin.manifest?.trust_level || 'High'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Category:</span>
                    <span className="text-cyan-400">
                      {plugin.manifest?.category?.replace('_', ' ') || 'General'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Version:</span>
                    <span className="text-white">v{plugin.manifest?.version || '1.0.0'}</span>
                  </div>
                </div>

                {selectedPlugin === pluginName && (
                  <div className="mt-4 pt-4 border-t border-white/10 space-y-3">
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Confidence Threshold</label>
                      <input
                        type="range"
                        min="0.1"
                        max="1.0"
                        step="0.1"
                        value={config.confidenceThreshold || 0.6}
                        onChange={(e) => updatePluginConfig(pluginName, 'confidenceThreshold', parseFloat(e.target.value))}
                        className="w-full"
                      />
                      <div className="text-xs text-gray-500">
                        {((config.confidenceThreshold || 0.6) * 100).toFixed(0)}%
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Timeout (seconds)</label>
                      <input
                        type="number"
                        min="10"
                        max="300"
                        value={config.timeout || 60}
                        onChange={(e) => updatePluginConfig(pluginName, 'timeout', parseInt(e.target.value))}
                        className="w-full px-2 py-1 bg-black/40 border border-white/10 rounded text-white text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"
                      />
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </motion.div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Plugin Configuration</h2>
          <p className="text-gray-400">
            Configure global settings and individual plugin parameters
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={loadConfigurations}
            className="flex items-center space-x-2 px-4 py-2 bg-gray-600/20 text-gray-300 rounded-lg hover:bg-gray-600/30 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Reset</span>
          </button>
          <motion.button
            onClick={saveConfiguration}
            disabled={saving}
            className="flex items-center space-x-2 px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-lg hover:from-cyan-600 hover:to-blue-700 transition-all disabled:opacity-50"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {saving ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
          </motion.button>
        </div>
      </div>

      {renderGlobalSettings()}
      {renderPluginList()}
    </div>
  );
};

export default PluginConfiguration;
