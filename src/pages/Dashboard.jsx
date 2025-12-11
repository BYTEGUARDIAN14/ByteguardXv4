import React, { useState, useEffect, startTransition, useDeferredValue } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield,
  Activity,
  FileText,
  AlertTriangle,
  CheckCircle,
  Clock,
  User,
  Settings,
  LogOut,
  Scan,
  TrendingUp,
  Database,
  Calendar,
  Plus,
  Play,
  Pause,
  BarChart3,
  Zap,
  Bug,
  Lock
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import Sidebar from '../components/layout/Sidebar'
import Header from '../components/layout/Header'
import StatsCard from '../components/dashboard/StatsCard'
import GlassCard from '../components/ui/GlassCard'
import Button from '../components/ui/Button'
import { SkeletonLoader, ScanningLoader } from '../components/ui/LoadingStates'
import { CircularProgress } from '../components/ui/ProgressIndicator'
import { staggerContainer, staggerItem, slideUp } from '../utils/animations'
import ScheduleScanModal from '../components/ScheduleScanModal'

const Dashboard = () => {
  const { user, logout, api } = useAuth()
  const navigate = useNavigate()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [dashboardData, setDashboardData] = useState({
    recentScans: [],
    scanStats: {
      totalScans: 0,
      vulnerabilitiesFound: 0,
      lastScanDate: null,
      criticalIssues: 0,
      resolvedIssues: 0,
      scanTime: 0
    },
    systemHealth: 'healthy',
    securityScore: 85
  })
  const [scheduledScans, setScheduledScans] = useState([])
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [activeScans, setActiveScans] = useState([])

  // Use deferred values to prevent suspension
  const deferredDashboardData = useDeferredValue(dashboardData)
  const deferredScheduledScans = useDeferredValue(scheduledScans)
  const deferredIsLoading = useDeferredValue(isLoading)

  useEffect(() => {
    startTransition(() => {
      fetchDashboardData()
      fetchScheduledScans()
    })
  }, [])

  const fetchDashboardData = async () => {
    try {
      startTransition(() => {
        setIsLoading(true)
      })

      // Fetch user's scan history and stats with timeout
      const fetchWithTimeout = (promise, timeout = 10000) => {
        return Promise.race([
          promise,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout')), timeout)
          )
        ])
      }

      const [scansResponse, statsResponse] = await Promise.allSettled([
        fetchWithTimeout(api.get('/api/scans/recent')),
        fetchWithTimeout(api.get('/api/user/stats'))
      ])

      // Process responses safely
      const scansData = scansResponse.status === 'fulfilled' ? scansResponse.value : null
      const statsData = statsResponse.status === 'fulfilled' ? statsResponse.value : null

      startTransition(() => {
        setDashboardData({
          recentScans: scansData?.scans || [],
          scanStats: statsData?.stats || {
            totalScans: 0,
            vulnerabilitiesFound: 0,
            lastScanDate: null,
            criticalIssues: 0,
            resolvedIssues: 0,
            scanTime: 0
          },
          systemHealth: (scansResponse.status === 'fulfilled' && statsResponse.status === 'fulfilled') ? 'healthy' : 'degraded',
          securityScore: statsData?.stats?.securityScore || 85
        })
      })

      // Log any failed requests
      if (scansResponse.status === 'rejected') {
        console.warn('Failed to fetch recent scans:', scansResponse.reason)
      }
      if (statsResponse.status === 'rejected') {
        console.warn('Failed to fetch user stats:', statsResponse.reason)
      }

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)

      // Set safe default data on error
      startTransition(() => {
        setDashboardData({
          recentScans: [],
          scanStats: {
            totalScans: 0,
            vulnerabilitiesFound: 0,
            lastScanDate: null,
            criticalIssues: 0,
            resolvedIssues: 0,
            scanTime: 0
          },
          systemHealth: 'error',
          securityScore: 0
        })
      })
    } finally {
      startTransition(() => {
        setIsLoading(false)
      })
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const handleStartScan = () => {
    navigate('/scan')
  }

  const fetchScheduledScans = async () => {
    try {
      const response = await fetch('/api/scans/scheduled', {
        credentials: 'include'
      })
      if (response.ok) {
        const data = await response.json()
        startTransition(() => {
          setScheduledScans(data.scheduled_scans || [])
        })
      }
    } catch (error) {
      console.error('Error fetching scheduled scans:', error)
    }
  }

  const handleScheduleScan = async (scanData) => {
    try {
      const response = await fetch('/api/scans/schedule', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(scanData)
      })

      if (response.ok) {
        fetchScheduledScans() // Refresh the list
        startTransition(() => {
          setShowScheduleModal(false)
        })
      } else {
        throw new Error('Failed to schedule scan')
      }
    } catch (error) {
      console.error('Error scheduling scan:', error)
      throw error
    }
  }

  const toggleScheduledScan = async (scanId, isActive) => {
    try {
      const response = await fetch(`/api/scans/scheduled/${scanId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ is_active: !isActive })
      })

      if (response.ok) {
        fetchScheduledScans() // Refresh the list
      }
    } catch (error) {
      console.error('Error toggling scheduled scan:', error)
    }
  }

  const handleViewReports = () => {
    navigate('/reports')
  }

  if (deferredIsLoading) {
    return (
      <div className="min-h-screen bg-black text-white">
        <Sidebar
          isCollapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        />

        <div className={`
          transition-all duration-300 pt-16
          ${sidebarCollapsed ? 'md:ml-20' : 'md:ml-72'}
        `}>
          <div className="p-4 sm:p-6 md:p-8">
            <ScanningLoader text="Loading dashboard..." />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen text-white relative">

      <Sidebar
        isCollapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      <Header
        onMenuToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        sidebarCollapsed={sidebarCollapsed}
      />

      <main className={`
        transition-all duration-300 pt-16
        ${sidebarCollapsed ? 'md:ml-20' : 'md:ml-72'}
      `}>
        <div className="p-4 sm:p-6 md:p-8">
          {/* Welcome Section */}
          <motion.div
            className="mb-8"
            variants={staggerContainer}
            initial="hidden"
            animate="visible"
          >
            <motion.div variants={staggerItem}>
              <h1 className="text-3xl font-bold text-white mb-2">
                Welcome back, {user?.username}!
              </h1>
              <p className="text-gray-400">
                Here's your security overview for today
              </p>
            </motion.div>
          </motion.div>
          {/* Stats Cards */}
          <motion.div
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
            variants={staggerContainer}
            initial="hidden"
            animate="visible"
          >
            <motion.div variants={staggerItem}>
              <StatsCard
                title="Total Scans"
                value={deferredDashboardData.scanStats.totalScans}
                change="+12% from last month"
                changeType="positive"
                icon={Scan}
                color="cyan"
                onClick={() => navigate('/reports')}
              />
            </motion.div>

            <motion.div variants={staggerItem}>
              <StatsCard
                title="Vulnerabilities"
                value={deferredDashboardData.scanStats.vulnerabilitiesFound}
                change="-8% from last month"
                changeType="positive"
                icon={AlertTriangle}
                color="red"
                onClick={() => navigate('/reports')}
              />
            </motion.div>

            <motion.div variants={staggerItem}>
              <StatsCard
                title="Critical Issues"
                value={deferredDashboardData.scanStats.criticalIssues}
                change="2 resolved today"
                changeType="positive"
                icon={Bug}
                color="yellow"
                onClick={() => navigate('/reports')}
              />
            </motion.div>

            <motion.div variants={staggerItem}>
              <StatsCard
                title="Security Score"
                value={`${deferredDashboardData.securityScore}%`}
                change="+5% improvement"
                changeType="positive"
                icon={Shield}
                color="green"
                onClick={() => navigate('/analytics')}
              />
            </motion.div>
          </motion.div>

          {/* Security Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            {/* Security Score Circle */}
            <motion.div variants={slideUp}>
              <GlassCard className="p-6 text-center" hover={false}>
                <h3 className="text-lg font-semibold text-white mb-6">Security Score</h3>
                <div className="flex justify-center mb-4">
                  <CircularProgress
                    progress={deferredDashboardData.securityScore}
                    size={120}
                    color="cyan"
                    animated={true}
                  />
                </div>
                <p className="text-gray-400 text-sm">
                  Your overall security posture
                </p>
              </GlassCard>
            </motion.div>

            {/* Quick Actions */}
            <motion.div variants={slideUp}>
              <GlassCard className="p-6" hover={false}>
                <h3 className="text-lg font-semibold text-white mb-6">Quick Actions</h3>
                <div className="space-y-3">
                  <Button
                    variant="primary"
                    fullWidth
                    icon={Scan}
                    onClick={() => navigate('/scan')}
                  >
                    Start New Scan
                  </Button>

                  <Button
                    variant="secondary"
                    fullWidth
                    icon={FileText}
                    onClick={() => navigate('/reports')}
                  >
                    View Reports
                  </Button>

                  <Button
                    variant="ghost"
                    fullWidth
                    icon={Calendar}
                    onClick={() => startTransition(() => setShowScheduleModal(true))}
                  >
                    Schedule Scan
                  </Button>
                </div>
              </GlassCard>
            </motion.div>

            {/* System Status */}
            <motion.div variants={slideUp}>
              <GlassCard className="p-6" hover={false}>
                <h3 className="text-lg font-semibold text-white mb-6">System Status</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Scanner Engine</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-green-400 text-sm">Online</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">AI Analysis</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-green-400 text-sm">Active</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Database</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-green-400 text-sm">Connected</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Last Update</span>
                    <span className="text-gray-300 text-sm">2 hours ago</span>
                  </div>
                </div>
              </GlassCard>
            </motion.div>
          </div>

          {/* Recent Activity */}
          <motion.div
            className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8"
            variants={staggerContainer}
            initial="hidden"
            animate="visible"
          >
            {/* Recent Scans */}
            <motion.div variants={staggerItem}>
              <GlassCard className="p-6" hover={false}>
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => navigate('/reports')}
                  >
                    View All
                  </Button>
                </div>

                <div className="space-y-4">
                  {deferredDashboardData.recentScans.length > 0 ? (
                    deferredDashboardData.recentScans.slice(0, 5).map((scan, index) => (
                      <motion.div
                        key={scan.id}
                        className="flex items-center justify-between p-3 rounded-lg hover:bg-white/5 transition-colors cursor-pointer"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        onClick={() => navigate(`/report/${scan.id}`)}
                      >
                        <div className="flex items-center space-x-3">
                          <div className={`w-2 h-2 rounded-full ${scan.status === 'completed' ? 'bg-green-400' :
                            scan.status === 'failed' ? 'bg-red-400' :
                              'bg-yellow-400'
                            }`} />
                          <div>
                            <p className="text-white font-medium">{scan.filename || 'Unknown'}</p>
                            <p className="text-gray-400 text-sm">
                              {scan.vulnerabilities_found || 0} issues found
                            </p>
                          </div>
                        </div>
                        <span className="text-gray-400 text-sm">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </span>
                      </motion.div>
                    ))
                  ) : (
                    <div className="text-center py-8">
                      <Scan className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                      <p className="text-gray-400">No scans yet</p>
                      <Button
                        variant="primary"
                        size="sm"
                        className="mt-4"
                        onClick={() => navigate('/scan')}
                      >
                        Start Your First Scan
                      </Button>
                    </div>
                  )}
                </div>
              </GlassCard>
            </motion.div>
            {/* Scheduled Scans */}
            <motion.div variants={staggerItem}>
              <GlassCard className="p-6" hover={false}>
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold text-white">Scheduled Scans</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={Plus}
                    onClick={() => startTransition(() => setShowScheduleModal(true))}
                  >
                    Add New
                  </Button>
                </div>

                <div className="space-y-4">
                  {deferredScheduledScans.length > 0 ? (
                    deferredScheduledScans.slice(0, 5).map((scan, index) => (
                      <motion.div
                        key={scan.id}
                        className="flex items-center justify-between p-3 rounded-lg hover:bg-white/5 transition-colors"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                      >
                        <div className="flex items-center space-x-3">
                          <div className={`w-2 h-2 rounded-full ${scan.is_active ? 'bg-green-400' : 'bg-gray-400'
                            }`} />
                          <div>
                            <p className="text-white font-medium">{scan.name}</p>
                            <p className="text-gray-400 text-sm">
                              {scan.schedule_type} • Next: {new Date(scan.next_run).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toggleScheduledScan(scan.id, scan.is_active)}
                        >
                          {scan.is_active ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                        </Button>
                      </motion.div>
                    ))
                  ) : (
                    <div className="text-center py-8">
                      <Calendar className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                      <p className="text-gray-400">No scheduled scans</p>
                      <Button
                        variant="primary"
                        size="sm"
                        className="mt-4"
                        onClick={() => startTransition(() => setShowScheduleModal(true))}
                      >
                        Schedule Your First Scan
                      </Button>
                    </div>
                  )}
                </div>
              </GlassCard>
            </motion.div>
          </motion.div>
        </div>
      </main>

      {/* Schedule Scan Modal */}
      <AnimatePresence>
        {showScheduleModal && (
          <ScheduleScanModal
            isOpen={showScheduleModal}
            onClose={() => startTransition(() => setShowScheduleModal(false))}
            onSchedule={handleScheduleScan}
          />
        )}
      </AnimatePresence>
    </div>
  )
}

export default Dashboard
