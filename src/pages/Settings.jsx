import React, { useState, useEffect } from 'react'
import {
  User,
  Shield,
  Key,
  Bell,
  Save,
  Eye,
  EyeOff,
  Smartphone,
  AlertTriangle,
  CheckCircle,
  LogOut
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import EmailPreferences from '../components/EmailPreferences'

const Settings = () => {
  const { user, updateProfile, logout, api } = useAuth()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('profile')
  const [isLoading, setIsLoading] = useState(false)
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)

  const [profileData, setProfileData] = useState({
    username: user?.username || '',
    email: user?.email || '',
    firstName: user?.firstName || '',
    lastName: user?.lastName || ''
  })

  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  })

  const [twoFactorData, setTwoFactorData] = useState({
    isEnabled: false,
    qrCode: '',
    manualKey: '',
    verificationCode: '',
    backupCodes: []
  })

  useEffect(() => {
    if (user) {
      setProfileData({
        username: user.username || '',
        email: user.email || '',
        firstName: user.firstName || '',
        lastName: user.lastName || ''
      })
      checkTwoFactorStatus()
    }
  }, [user])

  const checkTwoFactorStatus = async () => {
    try {
      const response = await api.get('/api/auth/2fa/status')
      setTwoFactorData(prev => ({
        ...prev,
        isEnabled: response.data.enabled
      }))
    } catch (error) {
      console.error('Failed to check 2FA status:', error)
    }
  }

  const handleProfileUpdate = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    try {
      const result = await updateProfile(profileData)
      if (result.success) {
        toast.success('Profile updated successfully!')
      }
    } catch (error) {
      toast.error('Failed to update profile')
    } finally {
      setIsLoading(false)
    }
  }

  const handlePasswordChange = async (e) => {
    e.preventDefault()
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast.error('New passwords do not match')
      return
    }
    if (passwordData.newPassword.length < 8) {
      toast.error('Password must be at least 8 characters long')
      return
    }
    setIsLoading(true)
    try {
      const response = await api.post('/api/auth/change-password', {
        current_password: passwordData.currentPassword,
        new_password: passwordData.newPassword
      })
      if (response.status === 200) {
        toast.success('Password changed successfully!')
        setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' })
      }
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to change password')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSetup2FA = async () => {
    setIsLoading(true)
    try {
      const response = await api.post('/api/auth/2fa/setup')
      setTwoFactorData(prev => ({
        ...prev,
        qrCode: response.data.qr_code,
        manualKey: response.data.manual_entry_key,
        backupCodes: response.data.backup_codes
      }))
      toast.success('2FA setup initiated.')
    } catch (error) {
      toast.error('Failed to setup 2FA')
    } finally {
      setIsLoading(false)
    }
  }

  const handleEnable2FA = async () => {
    if (!twoFactorData.verificationCode) {
      toast.error('Please enter the verification code')
      return
    }
    setIsLoading(true)
    try {
      const response = await api.post('/api/auth/2fa/enable', {
        totp_token: twoFactorData.verificationCode
      })
      if (response.status === 200) {
        setTwoFactorData(prev => ({ ...prev, isEnabled: true, verificationCode: '' }))
        toast.success('2FA enabled successfully!')
      }
    } catch (error) {
      toast.error('Invalid verification code')
    } finally {
      setIsLoading(false)
    }
  }

  const handleDisable2FA = async () => {
    if (!confirm('Are you sure you want to disable two-factor authentication?')) return
    setIsLoading(true)
    try {
      const response = await api.post('/api/auth/2fa/disable')
      if (response.status === 200) {
        setTwoFactorData(prev => ({ ...prev, isEnabled: false, qrCode: '', manualKey: '', backupCodes: [] }))
        toast.success('2FA disabled successfully!')
      }
    } catch (error) {
      toast.error('Failed to disable 2FA')
    } finally {
      setIsLoading(false)
    }
  }

  const handleLogout = async () => {
    if (confirm('Are you sure you want to log out?')) {
      await logout()
      navigate('/login')
    }
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: '2fa', label: 'Two-Factor Auth', icon: Smartphone },
    { id: 'notifications', label: 'Notifications', icon: Bell }
  ]

  return (
    <div className="p-6 overflow-y-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Settings</h1>
          <p className="text-xs text-text-muted mt-0.5">Manage your account and preferences</p>
        </div>
        <button
          onClick={handleLogout}
          className="btn-ghost text-red-400 hover:text-red-300 hover:bg-red-500/10 flex items-center gap-2 text-xs px-3 py-1.5"
        >
          <LogOut className="h-3.5 w-3.5" />
          Log Out
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Tab Navigation */}
        <div className="lg:col-span-1">
          <div className="desktop-panel p-3">
            <nav className="space-y-0.5">
              {tabs.map((tab) => {
                const Icon = tab.icon
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-desktop text-xs font-medium transition-colors
                      ${activeTab === tab.id
                        ? 'bg-primary-500/10 text-primary-400'
                        : 'text-text-muted hover:text-text-primary hover:bg-white/[0.03]'
                      }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span>{tab.label}</span>
                  </button>
                )
              })}
            </nav>
          </div>
        </div>

        {/* Content */}
        <div className="lg:col-span-3">
          <div className="desktop-panel p-6">
            {/* Profile Tab */}
            {activeTab === 'profile' && (
              <div>
                <h3 className="text-sm font-semibold text-text-primary mb-5">Profile Information</h3>
                <form onSubmit={handleProfileUpdate} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-text-muted mb-1.5">Username</label>
                      <input
                        type="text"
                        value={profileData.username}
                        onChange={(e) => setProfileData(prev => ({ ...prev, username: e.target.value }))}
                        className="desktop-input"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-text-muted mb-1.5">Email</label>
                      <input
                        type="email"
                        value={profileData.email}
                        onChange={(e) => setProfileData(prev => ({ ...prev, email: e.target.value }))}
                        className="desktop-input"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-text-muted mb-1.5">First Name</label>
                      <input
                        type="text"
                        value={profileData.firstName}
                        onChange={(e) => setProfileData(prev => ({ ...prev, firstName: e.target.value }))}
                        className="desktop-input"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-text-muted mb-1.5">Last Name</label>
                      <input
                        type="text"
                        value={profileData.lastName}
                        onChange={(e) => setProfileData(prev => ({ ...prev, lastName: e.target.value }))}
                        className="desktop-input"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end pt-2">
                    <button type="submit" disabled={isLoading} className="btn-primary flex items-center gap-2 text-xs">
                      <Save className="h-3.5 w-3.5" />
                      {isLoading ? 'Saving...' : 'Save Changes'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <div>
                <h3 className="text-sm font-semibold text-text-primary mb-5">Security Settings</h3>
                <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">Current Password</label>
                    <div className="relative">
                      <input
                        type={showCurrentPassword ? 'text' : 'password'}
                        value={passwordData.currentPassword}
                        onChange={(e) => setPasswordData(prev => ({ ...prev, currentPassword: e.target.value }))}
                        className="desktop-input pr-9"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                        className="absolute inset-y-0 right-0 pr-2.5 flex items-center text-text-disabled hover:text-text-muted"
                      >
                        {showCurrentPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">New Password</label>
                    <div className="relative">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={passwordData.newPassword}
                        onChange={(e) => setPasswordData(prev => ({ ...prev, newPassword: e.target.value }))}
                        className="desktop-input pr-9"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        className="absolute inset-y-0 right-0 pr-2.5 flex items-center text-text-disabled hover:text-text-muted"
                      >
                        {showNewPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">Confirm New Password</label>
                    <input
                      type="password"
                      value={passwordData.confirmPassword}
                      onChange={(e) => setPasswordData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                      className="desktop-input"
                      required
                    />
                  </div>
                  <div className="flex justify-end pt-2">
                    <button type="submit" disabled={isLoading} className="btn-primary flex items-center gap-2 text-xs">
                      <Key className="h-3.5 w-3.5" />
                      {isLoading ? 'Changing...' : 'Change Password'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* 2FA Tab */}
            {activeTab === '2fa' && (
              <div>
                <h3 className="text-sm font-semibold text-text-primary mb-5">Two-Factor Authentication</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 bg-white/[0.02] rounded-desktop border border-desktop-border">
                    <div className="flex items-center gap-3">
                      <div className={`p-1.5 rounded-desktop ${twoFactorData.isEnabled ? 'bg-emerald-500/10' : 'bg-white/[0.04]'}`}>
                        {twoFactorData.isEnabled ? (
                          <CheckCircle className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <AlertTriangle className="h-4 w-4 text-text-disabled" />
                        )}
                      </div>
                      <div>
                        <p className="text-xs font-medium text-text-primary">Two-Factor Authentication</p>
                        <p className="text-[11px] text-text-muted">{twoFactorData.isEnabled ? 'Enabled' : 'Disabled'}</p>
                      </div>
                    </div>

                    {twoFactorData.isEnabled ? (
                      <button
                        onClick={handleDisable2FA}
                        disabled={isLoading}
                        className="btn-danger text-xs px-3 py-1.5"
                      >
                        Disable
                      </button>
                    ) : (
                      <button onClick={handleSetup2FA} disabled={isLoading} className="btn-primary text-xs px-3 py-1.5">
                        Setup 2FA
                      </button>
                    )}
                  </div>

                  {twoFactorData.qrCode && !twoFactorData.isEnabled && (
                    <div className="space-y-4">
                      <div className="p-3 bg-white/[0.02] rounded-desktop border border-desktop-border">
                        <h4 className="text-xs font-medium text-text-primary mb-2">Setup Instructions</h4>
                        <ol className="list-decimal list-inside space-y-1 text-[11px] text-text-muted">
                          <li>Install an authenticator app</li>
                          <li>Scan the QR code or enter the manual key</li>
                          <li>Enter the 6-digit code to verify</li>
                        </ol>
                      </div>

                      <div className="text-center">
                        <img
                          src={`data:image/png;base64,${twoFactorData.qrCode}`}
                          alt="2FA QR Code"
                          className="mx-auto mb-3"
                        />
                        <p className="text-[11px] text-text-muted mb-3">
                          Manual key: <code className="bg-desktop-card px-1.5 py-0.5 rounded text-text-primary text-mono">{twoFactorData.manualKey}</code>
                        </p>
                      </div>

                      <div className="flex gap-3">
                        <input
                          type="text"
                          placeholder="Enter 6-digit code"
                          value={twoFactorData.verificationCode}
                          onChange={(e) => setTwoFactorData(prev => ({ ...prev, verificationCode: e.target.value }))}
                          className="desktop-input flex-1"
                          maxLength="6"
                        />
                        <button
                          onClick={handleEnable2FA}
                          disabled={isLoading || !twoFactorData.verificationCode}
                          className="btn-primary text-xs px-4"
                        >
                          Verify & Enable
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Notifications Tab */}
            {activeTab === 'notifications' && (
              <EmailPreferences />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Settings
