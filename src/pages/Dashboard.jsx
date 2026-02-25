import React, { useState, useEffect, startTransition, useDeferredValue } from 'react'
import {
  Shield,
  AlertTriangle,
  Scan,
  FileText,
  Calendar,
  Plus,
  Play,
  Pause,
  Bug
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import GlassCard from '../components/ui/GlassCard'
import Button from '../components/ui/Button'
import StatsCard from '../components/dashboard/StatsCard'
import { CircularProgress } from '../components/ui/ProgressIndicator'
import ScheduleScanModal from '../components/ScheduleScanModal'

const Dashboard = () => {
  const { user, logout, api } = useAuth()
  const navigate = useNavigate()
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
      startTransition(() => setIsLoading(true))

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

      if (scansResponse.status === 'rejected') {
        console.warn('Failed to fetch recent scans:', scansResponse.reason)
      }
      if (statsResponse.status === 'rejected') {
        console.warn('Failed to fetch user stats:', statsResponse.reason)
      }

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
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
      startTransition(() => setIsLoading(false))
    }
  }

  const fetchScheduledScans = async () => {
    try {
      const response = await fetch('/api/scans/scheduled', {
        credentials: 'include'
      })
      if (response.ok) {
        const data = await response.json()
        startTransition(() => setScheduledScans(data.scheduled_scans || []))
      }
    } catch (error) {
      console.error('Error fetching scheduled scans:', error)
    }
  }

  const handleScheduleScan = async (scanData) => {
    try {
      const response = await fetch('/api/scans/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(scanData)
      })

      if (response.ok) {
        fetchScheduledScans()
        startTransition(() => setShowScheduleModal(false))
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
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ is_active: !isActive })
      })

      if (response.ok) {
        fetchScheduledScans()
      }
    } catch (error) {
      console.error('Error toggling scheduled scan:', error)
    }
  }

  if (deferredIsLoading) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-3">
          <div className="w-4 h-4 border-2 border-primary-600 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-text-muted">Loading dashboard...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6 overflow-y-auto">
      {/* Page Title */}
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Security Dashboard</h1>
        <p className="text-xs text-text-muted mt-0.5">Your local security overview</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Scans"
          value={deferredDashboardData.scanStats.totalScans}
          change="+12% from last month"
          changeType="positive"
          icon={Scan}
          color="cyan"
          onClick={() => navigate('/reports')}
        />
        <StatsCard
          title="Vulnerabilities"
          value={deferredDashboardData.scanStats.vulnerabilitiesFound}
          change="-8% from last month"
          changeType="positive"
          icon={AlertTriangle}
          color="red"
          onClick={() => navigate('/reports')}
        />
        <StatsCard
          title="Critical Issues"
          value={deferredDashboardData.scanStats.criticalIssues}
          change="2 resolved today"
          changeType="positive"
          icon={Bug}
          color="yellow"
          onClick={() => navigate('/reports')}
        />
        <StatsCard
          title="Security Score"
          value={`${deferredDashboardData.securityScore}%`}
          change="+5% improvement"
          changeType="positive"
          icon={Shield}
          color="green"
        />
      </div>

      {/* Middle Row: Score + Quick Actions + System Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Security Score */}
        <GlassCard className="p-5" hover={false}>
          <h3 className="text-sm font-semibold text-text-primary mb-4">Security Score</h3>
          <div className="flex justify-center mb-3">
            <CircularProgress
              progress={deferredDashboardData.securityScore}
              size={100}
              color="cyan"
              animated={true}
            />
          </div>
          <p className="text-xs text-text-muted text-center">Overall security posture</p>
        </GlassCard>

        {/* Quick Actions */}
        <GlassCard className="p-5" hover={false}>
          <h3 className="text-sm font-semibold text-text-primary mb-4">Quick Actions</h3>
          <div className="space-y-2">
            <Button variant="primary" fullWidth icon={Scan} onClick={() => navigate('/scan')}>
              Start New Scan
            </Button>
            <Button variant="secondary" fullWidth icon={FileText} onClick={() => navigate('/reports')}>
              View Reports
            </Button>
            <Button variant="ghost" fullWidth icon={Calendar} onClick={() => startTransition(() => setShowScheduleModal(true))}>
              Schedule Scan
            </Button>
          </div>
        </GlassCard>

        {/* System Status */}
        <GlassCard className="p-5" hover={false}>
          <h3 className="text-sm font-semibold text-text-primary mb-4">System Status</h3>
          <div className="space-y-3">
            {[
              { label: 'Scanner Engine', status: 'Online', online: true },
              { label: 'AI Analysis', status: 'Active', online: true },
              { label: 'Database', status: 'Connected', online: true },
              { label: 'Last Update', status: '2 hours ago', online: null },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between">
                <span className="text-xs text-text-muted">{item.label}</span>
                <div className="flex items-center gap-1.5">
                  {item.online !== null && (
                    <div className={`status-dot ${item.online ? 'status-online' : 'status-error'}`} />
                  )}
                  <span className={`text-xs ${item.online ? 'text-emerald-400' : 'text-text-secondary'}`}>
                    {item.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      {/* Bottom Row: Recent Scans + Scheduled Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Scans */}
        <GlassCard className="p-5" hover={false}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-text-primary">Recent Scans</h3>
            <Button variant="ghost" size="sm" onClick={() => navigate('/reports')}>
              View All
            </Button>
          </div>

          <div className="space-y-1">
            {deferredDashboardData.recentScans.length > 0 ? (
              deferredDashboardData.recentScans.slice(0, 5).map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between px-3 py-2 rounded-desktop hover:bg-white/[0.03] transition-colors cursor-pointer"
                  onClick={() => navigate(`/report/${scan.id}`)}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className={`status-dot ${scan.status === 'completed' ? 'status-online' :
                      scan.status === 'failed' ? 'status-error' : 'status-warning'}`} />
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-text-primary truncate">{scan.filename || 'Unknown'}</p>
                      <p className="text-[11px] text-text-muted">{scan.vulnerabilities_found || 0} issues</p>
                    </div>
                  </div>
                  <span className="text-[11px] text-text-disabled shrink-0 ml-3">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-center py-8">
                <Scan className="h-8 w-8 text-text-disabled mx-auto mb-3" />
                <p className="text-xs text-text-muted mb-3">No scans yet</p>
                <Button variant="primary" size="sm" onClick={() => navigate('/scan')}>
                  Start Your First Scan
                </Button>
              </div>
            )}
          </div>
        </GlassCard>

        {/* Scheduled Scans */}
        <GlassCard className="p-5" hover={false}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-text-primary">Scheduled Scans</h3>
            <Button
              variant="ghost"
              size="sm"
              icon={Plus}
              onClick={() => startTransition(() => setShowScheduleModal(true))}
            >
              Add
            </Button>
          </div>

          <div className="space-y-1">
            {deferredScheduledScans.length > 0 ? (
              deferredScheduledScans.slice(0, 5).map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between px-3 py-2 rounded-desktop hover:bg-white/[0.03] transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className={`status-dot ${scan.is_active ? 'status-online' : 'status-offline'}`} />
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-text-primary truncate">{scan.name}</p>
                      <p className="text-[11px] text-text-muted">
                        {scan.schedule_type} • Next: {new Date(scan.next_run).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => toggleScheduledScan(scan.id, scan.is_active)}
                    className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-white/[0.04] transition-colors"
                  >
                    {scan.is_active ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                  </button>
                </div>
              ))
            ) : (
              <div className="text-center py-8">
                <Calendar className="h-8 w-8 text-text-disabled mx-auto mb-3" />
                <p className="text-xs text-text-muted mb-3">No scheduled scans</p>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => startTransition(() => setShowScheduleModal(true))}
                >
                  Schedule Your First Scan
                </Button>
              </div>
            )}
          </div>
        </GlassCard>
      </div>

      {/* Schedule Scan Modal */}
      {showScheduleModal && (
        <ScheduleScanModal
          isOpen={showScheduleModal}
          onClose={() => startTransition(() => setShowScheduleModal(false))}
          onSchedule={handleScheduleScan}
        />
      )}
    </div>
  )
}

export default Dashboard
