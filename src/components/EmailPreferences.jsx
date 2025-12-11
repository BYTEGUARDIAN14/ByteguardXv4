import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Mail,
  Bell,
  Shield,
  Calendar,
  AlertTriangle,
  CheckCircle,
  Save,
  RefreshCw
} from 'lucide-react'

const EmailPreferences = () => {
  const [preferences, setPreferences] = useState({
    scan_completed: true,
    vulnerabilities_found: true,
    login_alerts: true,
    scheduled_scan_failed: true,
    weekly_summary: false
  })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    fetchPreferences()
  }, [])

  const fetchPreferences = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/user/profile', {
        credentials: 'include'
      })
      
      if (response.ok) {
        const data = await response.json()
        if (data.user && data.user.email_notifications) {
          setPreferences(data.user.email_notifications)
        }
      }
    } catch (error) {
      console.error('Error fetching email preferences:', error)
    } finally {
      setLoading(false)
    }
  }

  const updatePreferences = async () => {
    try {
      setSaving(true)
      setMessage('')
      
      const response = await fetch('/api/user/email-preferences', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ email_notifications: preferences })
      })

      if (response.ok) {
        setMessage('Email preferences updated successfully')
        setTimeout(() => setMessage(''), 3000)
      } else {
        throw new Error('Failed to update preferences')
      }
    } catch (error) {
      setMessage('Failed to update email preferences')
      setTimeout(() => setMessage(''), 3000)
    } finally {
      setSaving(false)
    }
  }

  const handleToggle = (key) => {
    setPreferences(prev => ({
      ...prev,
      [key]: !prev[key]
    }))
  }

  const notificationTypes = [
    {
      key: 'scan_completed',
      title: 'Scan Completed',
      description: 'Receive notifications when security scans finish',
      icon: Shield,
      color: 'text-green-400'
    },
    {
      key: 'vulnerabilities_found',
      title: 'Vulnerabilities Found',
      description: 'Get alerts when critical or high-severity vulnerabilities are detected',
      icon: AlertTriangle,
      color: 'text-red-400'
    },
    {
      key: 'login_alerts',
      title: 'Login Alerts',
      description: 'Security notifications for new login attempts',
      icon: Bell,
      color: 'text-blue-400'
    },
    {
      key: 'scheduled_scan_failed',
      title: 'Scheduled Scan Failures',
      description: 'Notifications when scheduled scans fail to execute',
      icon: Calendar,
      color: 'text-orange-400'
    },
    {
      key: 'weekly_summary',
      title: 'Weekly Summary',
      description: 'Weekly digest of your security activity and findings',
      icon: Mail,
      color: 'text-purple-400'
    }
  ]

  if (loading) {
    return (
      <div className="glass-card p-6">
        <div className="flex items-center space-x-3 mb-6">
          <Mail className="h-6 w-6 text-cyan-400" />
          <h3 className="text-xl font-semibold text-white">Email Notifications</h3>
        </div>
        
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="glass-card p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <Mail className="h-6 w-6 text-cyan-400" />
          <h3 className="text-xl font-semibold text-white">Email Notifications</h3>
        </div>
        
        <button
          onClick={fetchPreferences}
          className="p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-white/10"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Success/Error Message */}
      {message && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className={`
            flex items-center space-x-2 p-3 rounded-lg mb-6
            ${message.includes('success') 
              ? 'bg-green-500/20 border border-green-500/30' 
              : 'bg-red-500/20 border border-red-500/30'
            }
          `}
        >
          {message.includes('success') ? (
            <CheckCircle className="h-4 w-4 text-green-400" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-red-400" />
          )}
          <span className={`text-sm ${message.includes('success') ? 'text-green-400' : 'text-red-400'}`}>
            {message}
          </span>
        </motion.div>
      )}

      {/* Notification Settings */}
      <div className="space-y-4 mb-6">
        {notificationTypes.map((type) => {
          const Icon = type.icon
          const isEnabled = preferences[type.key]
          
          return (
            <motion.div
              key={type.key}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center justify-between p-4 bg-gray-900/30 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors"
            >
              <div className="flex items-center space-x-4">
                <div className={`p-2 rounded-lg bg-gray-800 ${type.color}`}>
                  <Icon className="h-5 w-5" />
                </div>
                
                <div>
                  <h4 className="text-white font-medium">{type.title}</h4>
                  <p className="text-gray-400 text-sm">{type.description}</p>
                </div>
              </div>

              {/* Toggle Switch */}
              <button
                onClick={() => handleToggle(type.key)}
                className={`
                  relative inline-flex h-6 w-11 items-center rounded-full transition-colors
                  ${isEnabled ? 'bg-cyan-500' : 'bg-gray-600'}
                `}
              >
                <span
                  className={`
                    inline-block h-4 w-4 transform rounded-full bg-white transition-transform
                    ${isEnabled ? 'translate-x-6' : 'translate-x-1'}
                  `}
                />
              </button>
            </motion.div>
          )
        })}
      </div>

      {/* Email Frequency Info */}
      <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg mb-6">
        <div className="flex items-start space-x-3">
          <Bell className="h-5 w-5 text-blue-400 mt-0.5" />
          <div>
            <h4 className="text-blue-400 font-medium mb-1">Email Frequency</h4>
            <p className="text-blue-300 text-sm">
              Immediate notifications are sent for critical security events. 
              Non-urgent notifications are batched and sent at most once per hour to avoid spam.
            </p>
          </div>
        </div>
      </div>

      {/* Test Email Section */}
      <div className="p-4 bg-gray-900/30 rounded-lg border border-gray-700 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-white font-medium mb-1">Test Email Notifications</h4>
            <p className="text-gray-400 text-sm">
              Send a test email to verify your notification settings are working correctly.
            </p>
          </div>
          
          <button
            onClick={async () => {
              try {
                const response = await fetch('/api/user/test-email', {
                  method: 'POST',
                  credentials: 'include'
                })
                
                if (response.ok) {
                  setMessage('Test email sent successfully')
                } else {
                  setMessage('Failed to send test email')
                }
                
                setTimeout(() => setMessage(''), 3000)
              } catch (error) {
                setMessage('Failed to send test email')
                setTimeout(() => setMessage(''), 3000)
              }
            }}
            className="btn-secondary text-sm"
          >
            Send Test Email
          </button>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex items-center justify-end space-x-3">
        <button
          onClick={updatePreferences}
          disabled={saving}
          className="btn-primary flex items-center space-x-2"
        >
          {saving ? (
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          ) : (
            <Save className="h-4 w-4" />
          )}
          <span>{saving ? 'Saving...' : 'Save Preferences'}</span>
        </button>
      </div>

      {/* Privacy Notice */}
      <div className="mt-6 p-3 bg-gray-900/20 rounded-lg border border-gray-800">
        <p className="text-gray-400 text-xs">
          <strong>Privacy Notice:</strong> Your email address is only used for security notifications 
          and account-related communications. We never share your email with third parties or send 
          marketing emails. You can disable notifications at any time.
        </p>
      </div>
    </div>
  )
}

export default EmailPreferences
