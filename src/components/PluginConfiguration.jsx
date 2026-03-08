import React, { useState, useEffect } from 'react';
import {
  Settings, Shield, Sliders, Save, RefreshCw, CheckCircle,
  Lock, Unlock, Zap, Clock, Cpu
} from 'lucide-react';
import tauriAPI from '../services/tauri-api';

const PluginConfiguration = ({ pluginData, onConfigUpdate }) => {
  const [configurations, setConfigurations] = useState({});
  const [globalSettings, setGlobalSettings] = useState({
    enableSandbox: true, maxConcurrentPlugins: 10, defaultTimeout: 60,
    maxMemoryMB: 512, maxCpuPercent: 50, trustThreshold: 0.7,
    enableLogging: true, enableMetrics: true
  });
  const [selectedPlugin, setSelectedPlugin] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => { loadConfigurations(); }, []);

  const loadConfigurations = async () => {
    try {
      const data = await tauriAPI.plugins.getConfig();
      if (data) {
        setConfigurations(data.configurations || {});
        setGlobalSettings(data.global_settings || globalSettings);
      }
    } catch (error) { console.error('Failed to load configurations:', error); }
  };

  const saveConfiguration = async () => {
    setSaving(true);
    try {
      const success = await tauriAPI.plugins.saveConfig({ configurations, global_settings: globalSettings });
      if (success) onConfigUpdate?.();
    } catch (error) { console.error('Failed to save configuration:', error); }
    finally { setSaving(false); }
  };

  const updatePluginConfig = (pluginName, key, value) => {
    setConfigurations(prev => ({ ...prev, [pluginName]: { ...prev[pluginName], [key]: value } }));
  };

  const updateGlobalSetting = (key, value) => {
    setGlobalSettings(prev => ({ ...prev, [key]: value }));
  };

  const allPlugins = pluginData?.categories?.flatMap(cat => cat.plugins) || [];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text-primary">Plugin Configuration</h2>
          <p className="text-[11px] text-text-muted">Global settings and individual plugin parameters</p>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={loadConfigurations} className="btn-ghost text-xs px-2.5 py-1.5 inline-flex items-center gap-1">
            <RefreshCw className="h-3 w-3" /> Reset
          </button>
          <button onClick={saveConfiguration} disabled={saving}
            className="btn-primary text-xs px-3 py-1.5 inline-flex items-center gap-1 disabled:opacity-50"
          >
            {saving ? <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="h-3 w-3" />}
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>

      {/* Global Settings */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Settings className="h-3.5 w-3.5 text-primary-400" /> Global Settings
        </h3>

        <div className="grid grid-cols-3 gap-4">
          {/* Security */}
          <div className="space-y-2.5">
            <h4 className="text-[11px] font-medium text-text-muted flex items-center gap-1">
              <Shield className="h-3 w-3" /> Security
            </h4>
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-text-secondary">Sandbox</span>
              <button onClick={() => updateGlobalSetting('enableSandbox', !globalSettings.enableSandbox)}
                className={`relative inline-flex h-4 w-8 items-center rounded-full transition-colors ${globalSettings.enableSandbox ? 'bg-primary-600' : 'bg-desktop-border'
                  }`}
              >
                <span className={`inline-block h-3 w-3 rounded-full bg-white transition-transform ${globalSettings.enableSandbox ? 'translate-x-4' : 'translate-x-0.5'
                  }`} />
              </button>
            </div>
            <div>
              <label className="text-[11px] text-text-muted mb-0.5 block">Trust: {(globalSettings.trustThreshold * 100).toFixed(0)}%</label>
              <input type="range" min="0.1" max="1.0" step="0.1" value={globalSettings.trustThreshold}
                onChange={(e) => updateGlobalSetting('trustThreshold', parseFloat(e.target.value))}
                className="w-full accent-primary-500" />
            </div>
          </div>

          {/* Performance */}
          <div className="space-y-2.5">
            <h4 className="text-[11px] font-medium text-text-muted flex items-center gap-1">
              <Zap className="h-3 w-3" /> Performance
            </h4>
            <div>
              <label className="text-[11px] text-text-muted mb-0.5 block">Max Concurrent</label>
              <input type="number" min="1" max="50" value={globalSettings.maxConcurrentPlugins}
                onChange={(e) => updateGlobalSetting('maxConcurrentPlugins', parseInt(e.target.value))}
                className="input text-xs py-1" />
            </div>
            <div>
              <label className="text-[11px] text-text-muted mb-0.5 block flex items-center gap-0.5">
                <Clock className="h-2.5 w-2.5" /> Timeout (s)
              </label>
              <input type="number" min="10" max="300" value={globalSettings.defaultTimeout}
                onChange={(e) => updateGlobalSetting('defaultTimeout', parseInt(e.target.value))}
                className="input text-xs py-1" />
            </div>
          </div>

          {/* Resources */}
          <div className="space-y-2.5">
            <h4 className="text-[11px] font-medium text-text-muted flex items-center gap-1">
              <Cpu className="h-3 w-3" /> Resources
            </h4>
            <div>
              <label className="text-[11px] text-text-muted mb-0.5 block">Max Memory (MB)</label>
              <input type="number" min="64" max="2048" value={globalSettings.maxMemoryMB}
                onChange={(e) => updateGlobalSetting('maxMemoryMB', parseInt(e.target.value))}
                className="input text-xs py-1" />
            </div>
            <div>
              <label className="text-[11px] text-text-muted mb-0.5 block">Max CPU (%)</label>
              <input type="number" min="10" max="100" value={globalSettings.maxCpuPercent}
                onChange={(e) => updateGlobalSetting('maxCpuPercent', parseInt(e.target.value))}
                className="input text-xs py-1" />
            </div>
          </div>
        </div>

        <div className="mt-3 pt-3 border-t border-desktop-border flex items-center gap-4">
          {['enableLogging', 'enableMetrics'].map(key => (
            <label key={key} className="flex items-center gap-1.5 cursor-pointer">
              <input type="checkbox" checked={globalSettings[key]}
                onChange={(e) => updateGlobalSetting(key, e.target.checked)}
                className="w-3 h-3 rounded border-desktop-border" />
              <span className="text-xs text-text-secondary">{key === 'enableLogging' ? 'Logging' : 'Metrics'}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Plugin List */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Sliders className="h-3.5 w-3.5 text-primary-400" /> Per-Plugin Config
        </h3>

        <div className="grid grid-cols-3 gap-2">
          {allPlugins.slice(0, 12).map((plugin, index) => {
            const pluginName = plugin.manifest?.name || `plugin_${index}`;
            const config = configurations[pluginName] || {};
            const isEnabled = config.enabled !== false;
            const isSelected = selectedPlugin === pluginName;

            return (
              <div key={pluginName}
                className={`p-2.5 rounded-desktop border cursor-pointer transition-colors ${isSelected ? 'border-primary-500/30 bg-primary-500/5' : 'border-desktop-border bg-desktop-card hover:border-primary-500/15'
                  }`}
                onClick={() => setSelectedPlugin(isSelected ? null : pluginName)}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${isEnabled ? 'bg-emerald-400' : 'bg-text-disabled'}`} />
                    <h4 className="text-xs font-medium text-text-primary truncate">
                      {pluginName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </h4>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); updatePluginConfig(pluginName, 'enabled', !isEnabled); }}
                    className={`p-0.5 rounded ${isEnabled ? 'text-emerald-400' : 'text-text-disabled'}`}
                  >
                    {isEnabled ? <Unlock className="h-3 w-3" /> : <Lock className="h-3 w-3" />}
                  </button>
                </div>

                <div className="text-[10px] text-text-disabled space-y-0.5">
                  <div className="flex justify-between"><span>Trust</span><span>{plugin.manifest?.trust_level || 'High'}</span></div>
                  <div className="flex justify-between"><span>Category</span><span className="text-primary-400">{plugin.manifest?.category?.replace('_', ' ') || 'General'}</span></div>
                  <div className="flex justify-between"><span>Version</span><span>v{plugin.manifest?.version || '1.0.0'}</span></div>
                </div>

                {isSelected && (
                  <div className="mt-2 pt-2 border-t border-desktop-border space-y-1.5">
                    <div>
                      <label className="text-[10px] text-text-muted block">Confidence: {((config.confidenceThreshold || 0.6) * 100).toFixed(0)}%</label>
                      <input type="range" min="0.1" max="1.0" step="0.1" value={config.confidenceThreshold || 0.6}
                        onChange={(e) => updatePluginConfig(pluginName, 'confidenceThreshold', parseFloat(e.target.value))}
                        className="w-full accent-primary-500" />
                    </div>
                    <div>
                      <label className="text-[10px] text-text-muted block">Timeout (s)</label>
                      <input type="number" min="10" max="300" value={config.timeout || 60}
                        onChange={(e) => updatePluginConfig(pluginName, 'timeout', parseInt(e.target.value))}
                        className="input text-xs py-0.5" />
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default PluginConfiguration;
