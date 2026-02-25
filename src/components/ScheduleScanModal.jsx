import React, { useState } from 'react'
import {
  X,
  Calendar,
  Clock,
  Folder,
  Settings,
  Save,
  AlertCircle
} from 'lucide-react'

const ScheduleScanModal = ({ isOpen, onClose, onSchedule }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    directory_path: '',
    frequency: 'daily',
    cron_expression: '',
    timezone: 'UTC',
    scan_config: {
      include_secrets: true,
      include_dependencies: true,
      include_ai_patterns: true,
      file_extensions: ['.js', '.py', '.java', '.php', '.rb', '.go'],
      exclude_patterns: ['node_modules/', '.git/', 'vendor/']
    }
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const frequencies = [
    { value: 'daily', label: 'Daily', description: 'Run every day at the same time' },
    { value: 'weekly', label: 'Weekly', description: 'Run once per week' },
    { value: 'monthly', label: 'Monthly', description: 'Run once per month' },
    { value: 'custom', label: 'Custom', description: 'Use custom cron expression' }
  ]

  const timezones = [
    'UTC', 'America/New_York', 'America/Los_Angeles',
    'Europe/London', 'Europe/Paris', 'Asia/Tokyo',
    'Asia/Shanghai', 'Australia/Sydney'
  ]

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
    setError('')
  }

  const handleScanConfigChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      scan_config: { ...prev.scan_config, [field]: value }
    }))
  }

  const handleFileExtensionChange = (extensions) => {
    const extensionArray = extensions.split(',').map(ext => ext.trim()).filter(ext => ext)
    handleScanConfigChange('file_extensions', extensionArray)
  }

  const handleExcludePatternsChange = (patterns) => {
    const patternArray = patterns.split(',').map(pattern => pattern.trim()).filter(pattern => pattern)
    handleScanConfigChange('exclude_patterns', patternArray)
  }

  const validateForm = () => {
    if (!formData.name.trim()) { setError('Scan name is required'); return false }
    if (!formData.directory_path.trim()) { setError('Directory path is required'); return false }
    if (formData.frequency === 'custom' && !formData.cron_expression.trim()) {
      setError('Cron expression is required for custom frequency'); return false
    }
    return true
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!validateForm()) return

    setLoading(true)
    setError('')
    try {
      await onSchedule(formData)
      onClose()
      setFormData({
        name: '', description: '', directory_path: '',
        frequency: 'daily', cron_expression: '', timezone: 'UTC',
        scan_config: {
          include_secrets: true, include_dependencies: true, include_ai_patterns: true,
          file_extensions: ['.js', '.py', '.java', '.php', '.rb', '.go'],
          exclude_patterns: ['node_modules/', '.git/', 'vendor/']
        }
      })
    } catch (error) {
      setError(error.message || 'Failed to schedule scan')
    } finally {
      setLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <div
      className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="desktop-panel w-full max-w-xl max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-desktop-border">
          <div className="flex items-center gap-2">
            <Calendar className="h-4 w-4 text-primary-400" />
            <h2 className="text-sm font-semibold text-text-primary">Schedule Security Scan</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-text-muted hover:text-text-primary hover:bg-white/[0.04] rounded transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-5">
          {error && (
            <div className="flex items-center gap-2 p-2.5 bg-red-500/10 border border-red-500/20 rounded-desktop">
              <AlertCircle className="h-3.5 w-3.5 text-red-400 flex-shrink-0" />
              <span className="text-red-400 text-xs">{error}</span>
            </div>
          )}

          {/* Basic Information */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
              <Settings className="h-3.5 w-3.5 text-primary-400" />
              Basic Information
            </h3>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-text-muted mb-1">Scan Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => handleInputChange('name', e.target.value)}
                  placeholder="e.g., Daily Security Scan"
                  className="input text-xs py-1.5"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Directory Path *</label>
                <div className="relative">
                  <Folder className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-disabled" />
                  <input
                    type="text"
                    value={formData.directory_path}
                    onChange={(e) => handleInputChange('directory_path', e.target.value)}
                    placeholder="/path/to/project"
                    className="input text-xs py-1.5 pl-8"
                    required
                  />
                </div>
              </div>
            </div>

            <div>
              <label className="block text-xs text-text-muted mb-1">Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                placeholder="Optional description"
                rows={2}
                className="input text-xs py-1.5 resize-none"
              />
            </div>
          </div>

          {/* Schedule Configuration */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-primary-400" />
              Schedule
            </h3>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-text-muted mb-1">Frequency</label>
                <select
                  value={formData.frequency}
                  onChange={(e) => handleInputChange('frequency', e.target.value)}
                  className="input text-xs py-1.5"
                >
                  {frequencies.map((freq) => (
                    <option key={freq.value} value={freq.value}>{freq.label}</option>
                  ))}
                </select>
                <p className="text-[11px] text-text-disabled mt-0.5">
                  {frequencies.find(f => f.value === formData.frequency)?.description}
                </p>
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Timezone</label>
                <select
                  value={formData.timezone}
                  onChange={(e) => handleInputChange('timezone', e.target.value)}
                  className="input text-xs py-1.5"
                >
                  {timezones.map((tz) => (
                    <option key={tz} value={tz}>{tz}</option>
                  ))}
                </select>
              </div>
            </div>

            {formData.frequency === 'custom' && (
              <div>
                <label className="block text-xs text-text-muted mb-1">Cron Expression *</label>
                <input
                  type="text"
                  value={formData.cron_expression}
                  onChange={(e) => handleInputChange('cron_expression', e.target.value)}
                  placeholder="0 2 * * * (daily at 2 AM)"
                  className="input text-xs py-1.5"
                />
                <p className="text-[11px] text-text-disabled mt-0.5">
                  Format: minute hour day month weekday
                </p>
              </div>
            )}
          </div>

          {/* Scan Configuration */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Scan Settings
            </h3>

            <div className="space-y-2">
              {[
                { field: 'include_secrets', label: 'Secret Scanning' },
                { field: 'include_dependencies', label: 'Dependency Scanning' },
                { field: 'include_ai_patterns', label: 'AI Pattern Detection' }
              ].map(({ field, label }) => (
                <label key={field} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.scan_config[field]}
                    onChange={(e) => handleScanConfigChange(field, e.target.checked)}
                    className="w-3.5 h-3.5 rounded border-desktop-border bg-desktop-card text-primary-500 focus:ring-primary-500/30"
                  />
                  <span className="text-xs text-text-secondary">{label}</span>
                </label>
              ))}
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-text-muted mb-1">File Extensions</label>
                <input
                  type="text"
                  value={formData.scan_config.file_extensions.join(', ')}
                  onChange={(e) => handleFileExtensionChange(e.target.value)}
                  placeholder=".js, .py, .java"
                  className="input text-xs py-1.5"
                />
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Exclude Patterns</label>
                <input
                  type="text"
                  value={formData.scan_config.exclude_patterns.join(', ')}
                  onChange={(e) => handleExcludePatternsChange(e.target.value)}
                  placeholder="node_modules/, .git/"
                  className="input text-xs py-1.5"
                />
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-2 pt-3 border-t border-desktop-border">
            <button
              type="button"
              onClick={onClose}
              className="btn-ghost text-xs px-3 py-1.5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary text-xs px-4 py-1.5 inline-flex items-center gap-1.5"
            >
              {loading ? (
                <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <Save className="h-3.5 w-3.5" />
              )}
              <span>{loading ? 'Scheduling...' : 'Schedule Scan'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default ScheduleScanModal
