import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  User,
  Mail,
  Shield,
  Key,
  Bell,
  Save,
  Eye,
  EyeOff,
  Smartphone,
  AlertTriangle,
  CheckCircle,
  LogOut,
  Settings as SettingsIcon,
  Lock,
  Globe,
  Download,
  Upload,
  Palette
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import Sidebar from '../components/layout/Sidebar'
import Header from '../components/layout/Header'
import GlassCard from '../components/ui/GlassCard'
import Button from '../components/ui/Button'
import Input from '../components/ui/Input'
import Select from '../components/ui/Select'
import { useNotifications } from '../components/ui/NotificationSystem'
import { staggerContainer, staggerItem, slideUp } from '../utils/animations'
import toast from 'react-hot-toast'
import EmailPreferences from '../components/EmailPreferences'

const Settings = () => {
  const { user, updateProfile, logout, api } = useAuth()
  const navigate = useNavigate()
  const notifications = useNotifications()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
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
      
      // Check 2FA status
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
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        })
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
      toast.success('2FA setup initiated. Scan the QR code with your authenticator app.')
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
        setTwoFactorData(prev => ({
          ...prev,
          isEnabled: true,
          verificationCode: ''
        }))
        toast.success('2FA enabled successfully!')
      }
    } catch (error) {
      toast.error('Invalid verification code')
    } finally {
      setIsLoading(false)
    }
  }

  const handleDisable2FA = async () => {
    if (!confirm('Are you sure you want to disable two-factor authentication?')) {
      return
    }
    
    setIsLoading(true)
    
    try {
      const response = await api.post('/api/auth/2fa/disable')
      if (response.status === 200) {
        setTwoFactorData(prev => ({
          ...prev,
          isEnabled: false,
          qrCode: '',
          manualKey: '',
          backupCodes: []
        }))
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
    <div className="min-h-screen text-white relative">

      {/* Header */}
      <header className="glass-panel" style={{borderBottom: '1px solid rgba(255, 255, 255, 0.1)'}}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => navigate('/dashboard')}
                className="text-gray-400 hover:text-white transition-colors"
              >
                ← Back to Dashboard
              </button>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 text-sm text-gray-300">
                <User className="h-4 w-4" />
                <span>{user?.username}</span>
              </div>
              
              <button
                onClick={handleLogout}
                className="p-2 text-gray-400 hover:text-red-400 transition-colors"
              >
                <LogOut className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="glass-card p-6">
              <h2 className="text-xl font-bold text-white mb-6">Settings</h2>
              <nav className="space-y-2">
                {tabs.map((tab) => {
                  const Icon = tab.icon
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                        activeTab === tab.id
                          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                          : 'text-gray-400 hover:text-white hover:bg-white/5'
                      }`}
                    >
                      <Icon className="h-5 w-5" />
                      <span>{tab.label}</span>
                    </button>
                  )
                })}
              </nav>
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="glass-card p-8"
            >
              {/* Profile Tab */}
              {activeTab === 'profile' && (
                <div>
                  <h3 className="text-2xl font-bold text-white mb-6">Profile Information</h3>
                  <form onSubmit={handleProfileUpdate} className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          Username
                        </label>
                        <input
                          type="text"
                          value={profileData.username}
                          onChange={(e) => setProfileData(prev => ({ ...prev, username: e.target.value }))}
                          className="input"
                          required
                        />
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          Email
                        </label>
                        <input
                          type="email"
                          value={profileData.email}
                          onChange={(e) => setProfileData(prev => ({ ...prev, email: e.target.value }))}
                          className="input"
                          required
                        />
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          First Name
                        </label>
                        <input
                          type="text"
                          value={profileData.firstName}
                          onChange={(e) => setProfileData(prev => ({ ...prev, firstName: e.target.value }))}
                          className="input"
                        />
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          Last Name
                        </label>
                        <input
                          type="text"
                          value={profileData.lastName}
                          onChange={(e) => setProfileData(prev => ({ ...prev, lastName: e.target.value }))}
                          className="input"
                        />
                      </div>
                    </div>
                    
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={isLoading}
                        className="btn-primary flex items-center space-x-2 disabled:opacity-50"
                      >
                        <Save className="h-4 w-4" />
                        <span>{isLoading ? 'Saving...' : 'Save Changes'}</span>
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {/* Security Tab */}
              {activeTab === 'security' && (
                <div>
                  <h3 className="text-2xl font-bold text-white mb-6">Security Settings</h3>
                  <form onSubmit={handlePasswordChange} className="space-y-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Current Password
                      </label>
                      <div className="relative">
                        <input
                          type={showCurrentPassword ? 'text' : 'password'}
                          value={passwordData.currentPassword}
                          onChange={(e) => setPasswordData(prev => ({ ...prev, currentPassword: e.target.value }))}
                          className="input pr-10"
                          required
                        />
                        <button
                          type="button"
                          onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showCurrentPassword ? (
                            <EyeOff className="h-5 w-5 text-gray-400" />
                          ) : (
                            <Eye className="h-5 w-5 text-gray-400" />
                          )}
                        </button>
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        New Password
                      </label>
                      <div className="relative">
                        <input
                          type={showNewPassword ? 'text' : 'password'}
                          value={passwordData.newPassword}
                          onChange={(e) => setPasswordData(prev => ({ ...prev, newPassword: e.target.value }))}
                          className="input pr-10"
                          required
                        />
                        <button
                          type="button"
                          onClick={() => setShowNewPassword(!showNewPassword)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showNewPassword ? (
                            <EyeOff className="h-5 w-5 text-gray-400" />
                          ) : (
                            <Eye className="h-5 w-5 text-gray-400" />
                          )}
                        </button>
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Confirm New Password
                      </label>
                      <input
                        type="password"
                        value={passwordData.confirmPassword}
                        onChange={(e) => setPasswordData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                        className="input"
                        required
                      />
                    </div>
                    
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={isLoading}
                        className="btn-primary flex items-center space-x-2 disabled:opacity-50"
                      >
                        <Key className="h-4 w-4" />
                        <span>{isLoading ? 'Changing...' : 'Change Password'}</span>
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {/* 2FA Tab */}
              {activeTab === '2fa' && (
                <div>
                  <h3 className="text-2xl font-bold text-white mb-6">Two-Factor Authentication</h3>
                  
                  <div className="space-y-6">
                    <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-lg ${twoFactorData.isEnabled ? 'bg-green-500/20' : 'bg-gray-500/20'}`}>
                          {twoFactorData.isEnabled ? (
                            <CheckCircle className="h-5 w-5 text-green-400" />
                          ) : (
                            <AlertTriangle className="h-5 w-5 text-gray-400" />
                          )}
                        </div>
                        <div>
                          <p className="text-white font-medium">
                            Two-Factor Authentication
                          </p>
                          <p className="text-gray-400 text-sm">
                            {twoFactorData.isEnabled ? 'Enabled' : 'Disabled'}
                          </p>
                        </div>
                      </div>
                      
                      {twoFactorData.isEnabled ? (
                        <button
                          onClick={handleDisable2FA}
                          disabled={isLoading}
                          className="px-4 py-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors disabled:opacity-50"
                        >
                          Disable
                        </button>
                      ) : (
                        <button
                          onClick={handleSetup2FA}
                          disabled={isLoading}
                          className="btn-primary"
                        >
                          Setup 2FA
                        </button>
                      )}
                    </div>
                    
                    {twoFactorData.qrCode && !twoFactorData.isEnabled && (
                      <div className="space-y-4">
                        <div className="p-4 bg-white/5 rounded-lg">
                          <h4 className="text-lg font-medium text-white mb-4">Setup Instructions</h4>
                          <ol className="list-decimal list-inside space-y-2 text-gray-300">
                            <li>Install an authenticator app (Google Authenticator, Authy, etc.)</li>
                            <li>Scan the QR code below or enter the manual key</li>
                            <li>Enter the 6-digit code from your app to verify</li>
                          </ol>
                        </div>
                        
                        <div className="text-center">
                          <img 
                            src={`data:image/png;base64,${twoFactorData.qrCode}`}
                            alt="2FA QR Code"
                            className="mx-auto mb-4"
                          />
                          <p className="text-gray-400 text-sm mb-4">
                            Manual entry key: <code className="bg-gray-800 px-2 py-1 rounded">{twoFactorData.manualKey}</code>
                          </p>
                        </div>
                        
                        <div className="flex space-x-4">
                          <input
                            type="text"
                            placeholder="Enter 6-digit code"
                            value={twoFactorData.verificationCode}
                            onChange={(e) => setTwoFactorData(prev => ({ ...prev, verificationCode: e.target.value }))}
                            className="input flex-1"
                            maxLength="6"
                          />
                          <button
                            onClick={handleEnable2FA}
                            disabled={isLoading || !twoFactorData.verificationCode}
                            className="btn-primary disabled:opacity-50"
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
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Settings
