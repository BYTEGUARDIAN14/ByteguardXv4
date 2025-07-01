import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Alert, AlertDescription } from '../components/ui/alert';
import { 
  Settings, 
  Shield, 
  Bell, 
  Database,
  Users,
  Key,
  Globe,
  Zap,
  Save,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Info
} from 'lucide-react';

const SettingsPage = () => {
  const [settings, setSettings] = useState({
    // General Settings
    apiUrl: 'http://localhost:5000',
    maxConcurrentScans: 5,
    defaultScanTimeout: 300,
    enableAutoScan: false,
    
    // Security Settings
    enableRateLimit: true,
    rateLimitPerMinute: 60,
    enableAuditLog: true,
    sessionTimeout: 3600,
    
    // Notification Settings
    enableEmailNotifications: false,
    emailAddress: '',
    notifyOnCritical: true,
    notifyOnScanComplete: false,
    
    // Performance Settings
    enableWorkerPool: true,
    workerPoolSize: 8,
    enableIncrementalScan: true,
    enableCache: true,
    cacheTimeout: 3600,
    
    // Enterprise Features
    enableSSO: false,
    enableAnalytics: true,
    enableCICDIntegrations: true,
    enableAPIDocumentation: true
  });

  const [saving, setSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState(null);
  const [systemInfo, setSystemInfo] = useState(null);

  useEffect(() => {
    loadSettings();
    loadSystemInfo();
  }, []);

  const loadSettings = async () => {
    try {
      const response = await fetch('/api/settings');
      if (response.ok) {
        const data = await response.json();
        setSettings(prev => ({ ...prev, ...data }));
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  };

  const loadSystemInfo = async () => {
    try {
      const response = await fetch('/api/health/complete');
      if (response.ok) {
        const data = await response.json();
        setSystemInfo(data);
      }
    } catch (error) {
      console.error('Failed to load system info:', error);
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    try {
      const response = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(settings),
      });

      if (response.ok) {
        setLastSaved(new Date());
        alert('Settings saved successfully!');
      } else {
        throw new Error('Failed to save settings');
      }
    } catch (error) {
      console.error('Save failed:', error);
      alert('Failed to save settings: ' + error.message);
    } finally {
      setSaving(false);
    }
  };

  const resetToDefaults = () => {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      setSettings({
        apiUrl: 'http://localhost:5000',
        maxConcurrentScans: 5,
        defaultScanTimeout: 300,
        enableAutoScan: false,
        enableRateLimit: true,
        rateLimitPerMinute: 60,
        enableAuditLog: true,
        sessionTimeout: 3600,
        enableEmailNotifications: false,
        emailAddress: '',
        notifyOnCritical: true,
        notifyOnScanComplete: false,
        enableWorkerPool: true,
        workerPoolSize: 8,
        enableIncrementalScan: true,
        enableCache: true,
        cacheTimeout: 3600,
        enableSSO: false,
        enableAnalytics: true,
        enableCICDIntegrations: true,
        enableAPIDocumentation: true
      });
    }
  };

  const updateSetting = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
          <p className="text-gray-600 mt-1">
            Configure ByteGuardX system settings and preferences
          </p>
        </div>
        <div className="flex space-x-2">
          <Button variant="outline" onClick={resetToDefaults}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Reset to Defaults
          </Button>
          <Button onClick={saveSettings} disabled={saving} className="bg-cyan-600 hover:bg-cyan-700">
            {saving ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save Settings
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Last Saved Info */}
      {lastSaved && (
        <Alert className="border-green-200 bg-green-50">
          <CheckCircle className="h-4 w-4" />
          <AlertDescription className="text-green-800">
            Settings saved successfully at {lastSaved.toLocaleTimeString()}
          </AlertDescription>
        </Alert>
      )}

      {/* General Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Settings className="h-5 w-5 mr-2" />
            General Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                API URL
              </label>
              <Input
                value={settings.apiUrl}
                onChange={(e) => updateSetting('apiUrl', e.target.value)}
                placeholder="http://localhost:5000"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Max Concurrent Scans
              </label>
              <Input
                type="number"
                value={settings.maxConcurrentScans}
                onChange={(e) => updateSetting('maxConcurrentScans', parseInt(e.target.value))}
                min="1"
                max="20"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Default Scan Timeout (seconds)
              </label>
              <Input
                type="number"
                value={settings.defaultScanTimeout}
                onChange={(e) => updateSetting('defaultScanTimeout', parseInt(e.target.value))}
                min="60"
                max="3600"
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableAutoScan"
                checked={settings.enableAutoScan}
                onChange={(e) => updateSetting('enableAutoScan', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableAutoScan" className="text-sm font-medium text-gray-700">
                Enable Auto-scan on File Changes
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Security Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Shield className="h-5 w-5 mr-2" />
            Security Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableRateLimit"
                checked={settings.enableRateLimit}
                onChange={(e) => updateSetting('enableRateLimit', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableRateLimit" className="text-sm font-medium text-gray-700">
                Enable Rate Limiting
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Rate Limit (requests/minute)
              </label>
              <Input
                type="number"
                value={settings.rateLimitPerMinute}
                onChange={(e) => updateSetting('rateLimitPerMinute', parseInt(e.target.value))}
                min="10"
                max="1000"
                disabled={!settings.enableRateLimit}
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableAuditLog"
                checked={settings.enableAuditLog}
                onChange={(e) => updateSetting('enableAuditLog', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableAuditLog" className="text-sm font-medium text-gray-700">
                Enable Audit Logging
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Session Timeout (seconds)
              </label>
              <Input
                type="number"
                value={settings.sessionTimeout}
                onChange={(e) => updateSetting('sessionTimeout', parseInt(e.target.value))}
                min="300"
                max="86400"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Notification Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Bell className="h-5 w-5 mr-2" />
            Notification Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableEmailNotifications"
                checked={settings.enableEmailNotifications}
                onChange={(e) => updateSetting('enableEmailNotifications', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableEmailNotifications" className="text-sm font-medium text-gray-700">
                Enable Email Notifications
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Address
              </label>
              <Input
                type="email"
                value={settings.emailAddress}
                onChange={(e) => updateSetting('emailAddress', e.target.value)}
                placeholder="admin@company.com"
                disabled={!settings.enableEmailNotifications}
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="notifyOnCritical"
                checked={settings.notifyOnCritical}
                onChange={(e) => updateSetting('notifyOnCritical', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="notifyOnCritical" className="text-sm font-medium text-gray-700">
                Notify on Critical Findings
              </label>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="notifyOnScanComplete"
                checked={settings.notifyOnScanComplete}
                onChange={(e) => updateSetting('notifyOnScanComplete', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="notifyOnScanComplete" className="text-sm font-medium text-gray-700">
                Notify on Scan Completion
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Performance Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Zap className="h-5 w-5 mr-2" />
            Performance Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableWorkerPool"
                checked={settings.enableWorkerPool}
                onChange={(e) => updateSetting('enableWorkerPool', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableWorkerPool" className="text-sm font-medium text-gray-700">
                Enable Worker Pool
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Worker Pool Size
              </label>
              <Input
                type="number"
                value={settings.workerPoolSize}
                onChange={(e) => updateSetting('workerPoolSize', parseInt(e.target.value))}
                min="1"
                max="32"
                disabled={!settings.enableWorkerPool}
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableIncrementalScan"
                checked={settings.enableIncrementalScan}
                onChange={(e) => updateSetting('enableIncrementalScan', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableIncrementalScan" className="text-sm font-medium text-gray-700">
                Enable Incremental Scanning
              </label>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableCache"
                checked={settings.enableCache}
                onChange={(e) => updateSetting('enableCache', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableCache" className="text-sm font-medium text-gray-700">
                Enable Caching
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Cache Timeout (seconds)
              </label>
              <Input
                type="number"
                value={settings.cacheTimeout}
                onChange={(e) => updateSetting('cacheTimeout', parseInt(e.target.value))}
                min="300"
                max="86400"
                disabled={!settings.enableCache}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Enterprise Features */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Globe className="h-5 w-5 mr-2" />
            Enterprise Features
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="enableSSO"
                  checked={settings.enableSSO}
                  onChange={(e) => updateSetting('enableSSO', e.target.checked)}
                  className="rounded"
                />
                <label htmlFor="enableSSO" className="text-sm font-medium text-gray-700">
                  Enable SSO Integration
                </label>
              </div>
              <Badge variant="outline">Enterprise</Badge>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="enableAnalytics"
                  checked={settings.enableAnalytics}
                  onChange={(e) => updateSetting('enableAnalytics', e.target.checked)}
                  className="rounded"
                />
                <label htmlFor="enableAnalytics" className="text-sm font-medium text-gray-700">
                  Enable Advanced Analytics
                </label>
              </div>
              <Badge variant="outline">Pro</Badge>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="enableCICDIntegrations"
                  checked={settings.enableCICDIntegrations}
                  onChange={(e) => updateSetting('enableCICDIntegrations', e.target.checked)}
                  className="rounded"
                />
                <label htmlFor="enableCICDIntegrations" className="text-sm font-medium text-gray-700">
                  Enable CI/CD Integrations
                </label>
              </div>
              <Badge variant="outline">Pro</Badge>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enableAPIDocumentation"
                checked={settings.enableAPIDocumentation}
                onChange={(e) => updateSetting('enableAPIDocumentation', e.target.checked)}
                className="rounded"
              />
              <label htmlFor="enableAPIDocumentation" className="text-sm font-medium text-gray-700">
                Enable API Documentation
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* System Information */}
      {systemInfo && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Database className="h-5 w-5 mr-2" />
              System Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div>
                <p className="font-medium text-gray-700">System Status</p>
                <p className={`${systemInfo.overall_status === 'healthy' ? 'text-green-600' : 'text-red-600'}`}>
                  {systemInfo.overall_status}
                </p>
              </div>
              <div>
                <p className="font-medium text-gray-700">Uptime</p>
                <p className="text-gray-600">
                  {Math.floor(systemInfo.uptime_seconds / 3600)}h {Math.floor((systemInfo.uptime_seconds % 3600) / 60)}m
                </p>
              </div>
              <div>
                <p className="font-medium text-gray-700">Version</p>
                <p className="text-gray-600">ByteGuardX v3.0.0</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default SettingsPage;
