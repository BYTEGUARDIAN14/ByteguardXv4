import React, { useState, useEffect } from 'react';
import {
  Settings, Shield, Bell, Database, Users, Key, Globe, Zap,
  Save, RefreshCw, AlertTriangle, CheckCircle, Info
} from 'lucide-react';

const SettingsPage = () => {
  const [settings, setSettings] = useState({
    apiUrl: 'http://localhost:5000', maxConcurrentScans: 5, defaultScanTimeout: 300, enableAutoScan: false,
    enableRateLimit: true, rateLimitPerMinute: 60, enableAuditLog: true, sessionTimeout: 3600,
    enableEmailNotifications: false, emailAddress: '', notifyOnCritical: true, notifyOnScanComplete: false,
    enableWorkerPool: true, workerPoolSize: 8, enableIncrementalScan: true, enableCache: true, cacheTimeout: 3600,
    enableSSO: false, enableAnalytics: true, enableCICDIntegrations: true, enableAPIDocumentation: true
  });
  const [saving, setSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState(null);
  const [systemInfo, setSystemInfo] = useState(null);

  useEffect(() => { loadSettings(); loadSystemInfo(); }, []);

  const loadSettings = async () => {
    try { const r = await fetch('/api/settings'); if (r.ok) { const d = await r.json(); setSettings(p => ({ ...p, ...d })); } }
    catch (e) { console.error('Failed to load settings:', e); }
  };

  const loadSystemInfo = async () => {
    try { const r = await fetch('/api/health/complete'); if (r.ok) setSystemInfo(await r.json()); }
    catch (e) { console.error('Failed to load system info:', e); }
  };

  const saveSettings = async () => {
    setSaving(true);
    try {
      const r = await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) });
      if (r.ok) { setLastSaved(new Date()); alert('Settings saved!'); } else throw new Error('Save failed');
    } catch (e) { alert('Failed: ' + e.message); }
    finally { setSaving(false); }
  };

  const resetToDefaults = () => {
    if (confirm('Reset all settings to defaults?')) {
      setSettings({
        apiUrl: 'http://localhost:5000', maxConcurrentScans: 5, defaultScanTimeout: 300, enableAutoScan: false,
        enableRateLimit: true, rateLimitPerMinute: 60, enableAuditLog: true, sessionTimeout: 3600,
        enableEmailNotifications: false, emailAddress: '', notifyOnCritical: true, notifyOnScanComplete: false,
        enableWorkerPool: true, workerPoolSize: 8, enableIncrementalScan: true, enableCache: true, cacheTimeout: 3600,
        enableSSO: false, enableAnalytics: true, enableCICDIntegrations: true, enableAPIDocumentation: true
      });
    }
  };

  const u = (key, value) => setSettings(p => ({ ...p, [key]: value }));

  const Toggle = ({ id, label, checked, onChange, badge }) => (
    <div className="flex items-center justify-between">
      <label htmlFor={id} className="flex items-center gap-1.5 cursor-pointer">
        <input type="checkbox" id={id} checked={checked} onChange={onChange} className="w-3 h-3 rounded border-desktop-border" />
        <span className="text-xs text-text-secondary">{label}</span>
      </label>
      {badge && <span className="text-[10px] text-text-disabled px-1.5 py-0.5 border border-desktop-border rounded-desktop">{badge}</span>}
    </div>
  );

  const Field = ({ label, children }) => (
    <div>
      <label className="block text-[11px] text-text-muted mb-1">{label}</label>
      {children}
    </div>
  );

  return (
    <div className="p-6 space-y-4 overflow-y-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">System Settings</h1>
          <p className="text-xs text-text-muted mt-0.5">Configure ByteGuardX preferences</p>
        </div>
        <div className="flex gap-1.5">
          <button onClick={resetToDefaults} className="btn-ghost text-xs px-2.5 py-1.5 inline-flex items-center gap-1">
            <RefreshCw className="h-3 w-3" /> Reset
          </button>
          <button onClick={saveSettings} disabled={saving} className="btn-primary text-xs px-3 py-1.5 inline-flex items-center gap-1 disabled:opacity-50">
            {saving ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>

      {lastSaved && (
        <div className="p-2 bg-emerald-400/5 border border-emerald-400/10 rounded-desktop flex items-center gap-1.5">
          <CheckCircle className="h-3 w-3 text-emerald-400" />
          <span className="text-[11px] text-emerald-400">Saved at {lastSaved.toLocaleTimeString()}</span>
        </div>
      )}

      {/* General */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Settings className="h-3.5 w-3.5 text-primary-400" /> General
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <Field label="API URL">
            <input type="text" value={settings.apiUrl} onChange={(e) => u('apiUrl', e.target.value)} className="input text-xs py-1" />
          </Field>
          <Field label="Max Concurrent Scans">
            <input type="number" value={settings.maxConcurrentScans} onChange={(e) => u('maxConcurrentScans', parseInt(e.target.value))} min="1" max="20" className="input text-xs py-1" />
          </Field>
          <Field label="Scan Timeout (s)">
            <input type="number" value={settings.defaultScanTimeout} onChange={(e) => u('defaultScanTimeout', parseInt(e.target.value))} min="60" max="3600" className="input text-xs py-1" />
          </Field>
          <div className="flex items-end">
            <Toggle id="enableAutoScan" label="Auto-scan on changes" checked={settings.enableAutoScan} onChange={(e) => u('enableAutoScan', e.target.checked)} />
          </div>
        </div>
      </div>

      {/* Security */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Shield className="h-3.5 w-3.5 text-primary-400" /> Security
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <Toggle id="enableRateLimit" label="Rate Limiting" checked={settings.enableRateLimit} onChange={(e) => u('enableRateLimit', e.target.checked)} />
          <Field label="Rate Limit (req/min)">
            <input type="number" value={settings.rateLimitPerMinute} onChange={(e) => u('rateLimitPerMinute', parseInt(e.target.value))} min="10" max="1000" disabled={!settings.enableRateLimit} className="input text-xs py-1" />
          </Field>
          <Toggle id="enableAuditLog" label="Audit Logging" checked={settings.enableAuditLog} onChange={(e) => u('enableAuditLog', e.target.checked)} />
          <Field label="Session Timeout (s)">
            <input type="number" value={settings.sessionTimeout} onChange={(e) => u('sessionTimeout', parseInt(e.target.value))} min="300" max="86400" className="input text-xs py-1" />
          </Field>
        </div>
      </div>

      {/* Notifications */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Bell className="h-3.5 w-3.5 text-primary-400" /> Notifications
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <Toggle id="enableEmailNotifications" label="Email Notifications" checked={settings.enableEmailNotifications} onChange={(e) => u('enableEmailNotifications', e.target.checked)} />
          <Field label="Email Address">
            <input type="email" value={settings.emailAddress} onChange={(e) => u('emailAddress', e.target.value)} placeholder="admin@company.com" disabled={!settings.enableEmailNotifications} className="input text-xs py-1" />
          </Field>
          <Toggle id="notifyOnCritical" label="On Critical Findings" checked={settings.notifyOnCritical} onChange={(e) => u('notifyOnCritical', e.target.checked)} />
          <Toggle id="notifyOnScanComplete" label="On Scan Complete" checked={settings.notifyOnScanComplete} onChange={(e) => u('notifyOnScanComplete', e.target.checked)} />
        </div>
      </div>

      {/* Performance */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Zap className="h-3.5 w-3.5 text-primary-400" /> Performance
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <Toggle id="enableWorkerPool" label="Worker Pool" checked={settings.enableWorkerPool} onChange={(e) => u('enableWorkerPool', e.target.checked)} />
          <Field label="Worker Pool Size">
            <input type="number" value={settings.workerPoolSize} onChange={(e) => u('workerPoolSize', parseInt(e.target.value))} min="1" max="32" disabled={!settings.enableWorkerPool} className="input text-xs py-1" />
          </Field>
          <Toggle id="enableIncrementalScan" label="Incremental Scan" checked={settings.enableIncrementalScan} onChange={(e) => u('enableIncrementalScan', e.target.checked)} />
          <Toggle id="enableCache" label="Caching" checked={settings.enableCache} onChange={(e) => u('enableCache', e.target.checked)} />
          <Field label="Cache Timeout (s)">
            <input type="number" value={settings.cacheTimeout} onChange={(e) => u('cacheTimeout', parseInt(e.target.value))} min="300" max="86400" disabled={!settings.enableCache} className="input text-xs py-1" />
          </Field>
        </div>
      </div>

      {/* Enterprise */}
      <div className="desktop-panel p-4">
        <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
          <Globe className="h-3.5 w-3.5 text-primary-400" /> Enterprise
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <Toggle id="enableSSO" label="SSO Integration" checked={settings.enableSSO} onChange={(e) => u('enableSSO', e.target.checked)} badge="Enterprise" />
          <Toggle id="enableAnalytics" label="Advanced Analytics" checked={settings.enableAnalytics} onChange={(e) => u('enableAnalytics', e.target.checked)} badge="Pro" />
          <Toggle id="enableCICDIntegrations" label="CI/CD Integrations" checked={settings.enableCICDIntegrations} onChange={(e) => u('enableCICDIntegrations', e.target.checked)} badge="Pro" />
          <Toggle id="enableAPIDocumentation" label="API Documentation" checked={settings.enableAPIDocumentation} onChange={(e) => u('enableAPIDocumentation', e.target.checked)} />
        </div>
      </div>

      {/* System Info */}
      {systemInfo && (
        <div className="desktop-panel p-4">
          <h3 className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 mb-3">
            <Database className="h-3.5 w-3.5 text-primary-400" /> System
          </h3>
          <div className="grid grid-cols-3 gap-3">
            <div><p className="text-[11px] text-text-muted">Status</p><p className={`text-xs font-medium ${systemInfo.overall_status === 'healthy' ? 'text-emerald-400' : 'text-red-400'}`}>{systemInfo.overall_status}</p></div>
            <div><p className="text-[11px] text-text-muted">Uptime</p><p className="text-xs text-text-primary">{Math.floor(systemInfo.uptime_seconds / 3600)}h {Math.floor((systemInfo.uptime_seconds % 3600) / 60)}m</p></div>
            <div><p className="text-[11px] text-text-muted">Version</p><p className="text-xs text-text-primary">v3.0.0</p></div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsPage;
