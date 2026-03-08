import React, { useState, useEffect } from 'react'
import {
  Mail, Bell, Shield, Calendar, AlertTriangle, CheckCircle, Save, RefreshCw
} from 'lucide-react'

const EmailPreferences = () => {
  const [preferences, setPreferences] = useState({
    scan_completed: true, vulnerabilities_found: true, login_alerts: true,
    scheduled_scan_failed: true, weekly_summary: false
  })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => { fetchPreferences() }, [])

  const fetchPreferences = async () => {
    try {
      setLoading(true)
      const r = await fetch('/api/user/profile', { credentials: 'include' })
      if (r.ok) { const d = await r.json(); if (d.user?.email_notifications) setPreferences(d.user.email_notifications) }
    } catch (e) { console.error('Error fetching email preferences:', e) }
    finally { setLoading(false) }
  }

  const updatePreferences = async () => {
    try {
      setSaving(true); setMessage('')
      const r = await fetch('/api/user/email-preferences', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        credentials: 'include', body: JSON.stringify({ email_notifications: preferences })
      })
      setMessage(r.ok ? 'Email preferences updated successfully' : 'Failed to update preferences')
    } catch (e) { setMessage('Failed to update email preferences') }
    finally { setSaving(false); setTimeout(() => setMessage(''), 3000) }
  }

  const handleToggle = (key) => setPreferences(p => ({ ...p, [key]: !p[key] }))

  const notificationTypes = [
    { key: 'scan_completed', title: 'Scan Completed', description: 'When scans finish', icon: Shield, color: 'text-emerald-400' },
    { key: 'vulnerabilities_found', title: 'Vulnerabilities Found', description: 'Critical/high severity alerts', icon: AlertTriangle, color: 'text-red-400' },
    { key: 'login_alerts', title: 'Login Alerts', description: 'New login attempts', icon: Bell, color: 'text-blue-400' },
    { key: 'scheduled_scan_failed', title: 'Scan Failures', description: 'Scheduled scan failures', icon: Calendar, color: 'text-amber-400' },
    { key: 'weekly_summary', title: 'Weekly Summary', description: 'Weekly activity digest', icon: Mail, color: 'text-purple-400' }
  ]

  if (loading) {
    return (
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3 flex items-center gap-1.5">
          <Mail className="h-3.5 w-3.5 text-primary-400" /> Email Notifications
        </h3>
        <div className="flex items-center justify-center py-8">
          <div className="w-5 h-5 border-2 border-primary-500/30 border-t-primary-500 rounded-full animate-spin" />
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-text-primary flex items-center gap-1.5">
          <Mail className="h-3.5 w-3.5 text-primary-400" /> Email Notifications
        </h3>
        <button onClick={fetchPreferences} className="p-1 text-text-muted hover:text-text-primary rounded transition-colors" title="Refresh">
          <RefreshCw className="h-3 w-3" />
        </button>
      </div>

      {message && (
        <div className={`flex items-center gap-1.5 p-2 rounded-desktop mb-3 text-[11px] ${message.includes('success') ? 'bg-emerald-400/5 border border-emerald-400/10 text-emerald-400' : 'bg-red-400/5 border border-red-400/10 text-red-400'
          }`}>
          {message.includes('success') ? <CheckCircle className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
          {message}
        </div>
      )}

      <div className="space-y-1.5 mb-4">
        {notificationTypes.map(({ key, title, description, icon: Icon, color }) => (
          <div key={key} className="flex items-center justify-between p-2.5 bg-white/[0.02] rounded-desktop border border-desktop-border hover:border-primary-500/10 transition-colors">
            <div className="flex items-center gap-2.5">
              <div className={`p-1 rounded-desktop bg-white/[0.04] ${color}`}>
                <Icon className="h-3.5 w-3.5" />
              </div>
              <div>
                <p className="text-xs text-text-primary">{title}</p>
                <p className="text-[10px] text-text-muted">{description}</p>
              </div>
            </div>
            <button onClick={() => handleToggle(key)}
              className={`relative inline-flex h-4 w-8 items-center rounded-full transition-colors ${preferences[key] ? 'bg-primary-600' : 'bg-desktop-border'}`}>
              <span className={`inline-block h-3 w-3 rounded-full bg-white transition-transform ${preferences[key] ? 'translate-x-4' : 'translate-x-0.5'}`} />
            </button>
          </div>
        ))}
      </div>

      <div className="p-2.5 bg-blue-400/5 border border-blue-400/10 rounded-desktop mb-3">
        <div className="flex items-start gap-2">
          <Bell className="h-3 w-3 text-blue-400 mt-0.5 flex-shrink-0" />
          <p className="text-[10px] text-blue-300">
            Critical events sent immediately. Non-urgent batched hourly.
          </p>
        </div>
      </div>

      <div className="flex items-center justify-between p-2.5 bg-white/[0.02] rounded-desktop border border-desktop-border mb-3">
        <div>
          <p className="text-xs text-text-primary">Test Notifications</p>
          <p className="text-[10px] text-text-muted">Send a test email to verify</p>
        </div>
        <button onClick={async () => {
          try {
            const r = await fetch('/api/user/test-email', { method: 'POST', credentials: 'include' })
            setMessage(r.ok ? 'Test email sent successfully' : 'Failed to send test email')
          } catch (e) { setMessage('Failed to send test email') }
          setTimeout(() => setMessage(''), 3000)
        }} className="btn-ghost text-xs px-2.5 py-1">Send Test</button>
      </div>

      <div className="flex justify-end mb-3">
        <button onClick={updatePreferences} disabled={saving} className="btn-primary text-xs px-3 py-1.5 inline-flex items-center gap-1 disabled:opacity-50">
          {saving ? <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="h-3 w-3" />}
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>

      <div className="p-2 bg-white/[0.01] rounded-desktop border border-desktop-border">
        <p className="text-[10px] text-text-disabled">
          <strong>Privacy:</strong> Email used only for security notifications. Never shared. Disable anytime.
        </p>
      </div>
    </div>
  )
}

export default EmailPreferences
