import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
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
    'UTC',
    'America/New_York',
    'America/Los_Angeles',
    'Europe/London',
    'Europe/Paris',
    'Asia/Tokyo',
    'Asia/Shanghai',
    'Australia/Sydney'
  ]

  const handleInputChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
    setError('')
  }

  const handleScanConfigChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      scan_config: {
        ...prev.scan_config,
        [field]: value
      }
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
    if (!formData.name.trim()) {
      setError('Scan name is required')
      return false
    }
    
    if (!formData.directory_path.trim()) {
      setError('Directory path is required')
      return false
    }

    if (formData.frequency === 'custom' && !formData.cron_expression.trim()) {
      setError('Cron expression is required for custom frequency')
      return false
    }

    return true
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }

    setLoading(true)
    setError('')

    try {
      await onSchedule(formData)
      onClose()
      // Reset form
      setFormData({
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
    } catch (error) {
      setError(error.message || 'Failed to schedule scan')
    } finally {
      setLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="glass-card w-full max-w-2xl max-h-[90vh] overflow-y-auto"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-6" style={{borderBottom: '1px solid rgba(255, 255, 255, 0.1)'}}>
            <div className="flex items-center space-x-3">
              <Calendar className="h-6 w-6 text-cyan-400" />
              <h2 className="text-xl font-semibold text-white">Schedule Security Scan</h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-white/10"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            {/* Error Message */}
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center space-x-2 p-3 bg-red-500/20 border border-red-500/30 rounded-lg"
              >
                <AlertCircle className="h-4 w-4 text-red-400" />
                <span className="text-red-400 text-sm">{error}</span>
              </motion.div>
            )}

            {/* Basic Information */}
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-white flex items-center space-x-2">
                <Settings className="h-5 w-5 text-cyan-400" />
                <span>Basic Information</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Scan Name *
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => handleInputChange('name', e.target.value)}
                    placeholder="e.g., Daily Security Scan"
                    className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Directory Path *
                  </label>
                  <div className="relative">
                    <Folder className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      value={formData.directory_path}
                      onChange={(e) => handleInputChange('directory_path', e.target.value)}
                      placeholder="/path/to/project"
                      className="w-full pl-10 pr-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Description
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => handleInputChange('description', e.target.value)}
                  placeholder="Optional description for this scheduled scan"
                  rows={3}
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500 resize-none"
                />
              </div>
            </div>

            {/* Schedule Configuration */}
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-white flex items-center space-x-2">
                <Clock className="h-5 w-5 text-cyan-400" />
                <span>Schedule Configuration</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Frequency
                  </label>
                  <select
                    value={formData.frequency}
                    onChange={(e) => handleInputChange('frequency', e.target.value)}
                    className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  >
                    {frequencies.map((freq) => (
                      <option key={freq.value} value={freq.value}>
                        {freq.label}
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-400 mt-1">
                    {frequencies.find(f => f.value === formData.frequency)?.description}
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Timezone
                  </label>
                  <select
                    value={formData.timezone}
                    onChange={(e) => handleInputChange('timezone', e.target.value)}
                    className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  >
                    {timezones.map((tz) => (
                      <option key={tz} value={tz}>
                        {tz}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {formData.frequency === 'custom' && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Cron Expression *
                  </label>
                  <input
                    type="text"
                    value={formData.cron_expression}
                    onChange={(e) => handleInputChange('cron_expression', e.target.value)}
                    placeholder="0 2 * * * (daily at 2 AM)"
                    className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Use standard cron format: minute hour day month weekday
                  </p>
                </div>
              )}
            </div>

            {/* Scan Configuration */}
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-white">Scan Settings</h3>

              <div className="space-y-3">
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={formData.scan_config.include_secrets}
                    onChange={(e) => handleScanConfigChange('include_secrets', e.target.checked)}
                    className="w-4 h-4 text-cyan-500 bg-gray-900 border-gray-600 rounded focus:ring-cyan-500"
                  />
                  <span className="text-white">Include Secret Scanning</span>
                </label>

                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={formData.scan_config.include_dependencies}
                    onChange={(e) => handleScanConfigChange('include_dependencies', e.target.checked)}
                    className="w-4 h-4 text-cyan-500 bg-gray-900 border-gray-600 rounded focus:ring-cyan-500"
                  />
                  <span className="text-white">Include Dependency Scanning</span>
                </label>

                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={formData.scan_config.include_ai_patterns}
                    onChange={(e) => handleScanConfigChange('include_ai_patterns', e.target.checked)}
                    className="w-4 h-4 text-cyan-500 bg-gray-900 border-gray-600 rounded focus:ring-cyan-500"
                  />
                  <span className="text-white">Include AI Pattern Detection</span>
                </label>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    File Extensions
                  </label>
                  <input
                    type="text"
                    value={formData.scan_config.file_extensions.join(', ')}
                    onChange={(e) => handleFileExtensionChange(e.target.value)}
                    placeholder=".js, .py, .java, .php"
                    className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Comma-separated list of file extensions to scan
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Exclude Patterns
                  </label>
                  <input
                    type="text"
                    value={formData.scan_config.exclude_patterns.join(', ')}
                    onChange={(e) => handleExcludePatternsChange(e.target.value)}
                    placeholder="node_modules/, .git/, vendor/"
                    className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Comma-separated list of patterns to exclude
                  </p>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end space-x-3 pt-4" style={{borderTop: '1px solid rgba(255, 255, 255, 0.1)'}}>
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="btn-primary flex items-center space-x-2"
              >
                {loading ? (
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                ) : (
                  <Save className="h-4 w-4" />
                )}
                <span>{loading ? 'Scheduling...' : 'Schedule Scan'}</span>
              </button>
            </div>
          </form>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

export default ScheduleScanModal
