import React, { useState, useEffect } from 'react'
import {
  Users, Shield, Activity, BarChart3, Settings, AlertTriangle,
  CheckCircle, Clock, Search, Filter, Download, Eye, UserCheck, UserX, Crown
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'

const AdminDashboard = () => {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('overview')
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [scans, setScans] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [filters, setFilters] = useState({ userRole: '', userStatus: '', scanStatus: '', logAction: '' })

  useEffect(() => { if (user?.role === 'admin') fetchAdminData() }, [user])

  const fetchAdminData = async () => {
    try {
      setLoading(true)
      const [statsRes, usersRes, scansRes, logsRes] = await Promise.all([
        fetch('/api/admin/stats', { credentials: 'include' }),
        fetch('/api/admin/users?per_page=50', { credentials: 'include' }),
        fetch('/api/admin/scans?per_page=20', { credentials: 'include' }),
        fetch('/api/admin/activity?per_page=30', { credentials: 'include' })
      ])
      if (statsRes.ok) setStats(await statsRes.json())
      if (usersRes.ok) { const d = await usersRes.json(); setUsers(d.users || []) }
      if (scansRes.ok) { const d = await scansRes.json(); setScans(d.scans || []) }
      if (logsRes.ok) { const d = await logsRes.json(); setAuditLogs(d.logs || []) }
    } catch (error) { console.error('Error fetching admin data:', error) }
    finally { setLoading(false) }
  }

  const updateUserRole = async (userId, newRole) => {
    try {
      const r = await fetch(`/api/admin/users/${userId}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        credentials: 'include', body: JSON.stringify({ role: newRole })
      })
      if (r.ok) fetchAdminData()
    } catch (e) { console.error('Error updating user role:', e) }
  }

  const toggleUserStatus = async (userId, currentStatus) => {
    try {
      const r = await fetch(`/api/admin/users/${userId}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        credentials: 'include', body: JSON.stringify({ is_active: !currentStatus })
      })
      if (r.ok) fetchAdminData()
    } catch (e) { console.error('Error updating user status:', e) }
  }

  const filteredUsers = users.filter(u => {
    const matchesSearch = u.email.toLowerCase().includes(searchTerm.toLowerCase()) || u.username.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesRole = !filters.userRole || u.role === filters.userRole
    const matchesStatus = !filters.userStatus || (filters.userStatus === 'active' && u.is_active) || (filters.userStatus === 'inactive' && !u.is_active)
    return matchesSearch && matchesRole && matchesStatus
  })

  const filteredScans = scans.filter(s => {
    const matchesSearch = s.directory_path.toLowerCase().includes(searchTerm.toLowerCase()) || s.user_email.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesSearch && (!filters.scanStatus || s.status === filters.scanStatus)
  })

  const filteredLogs = auditLogs.filter(l => {
    const matchesSearch = l.action.toLowerCase().includes(searchTerm.toLowerCase()) || (l.user_email && l.user_email.toLowerCase().includes(searchTerm.toLowerCase()))
    return matchesSearch && (!filters.logAction || l.action.includes(filters.logAction))
  })

  if (user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="desktop-panel p-6 text-center">
          <div className="text-red-400 text-3xl mb-2">🚫</div>
          <h2 className="text-sm font-semibold text-text-primary mb-1">Access Denied</h2>
          <p className="text-xs text-text-muted">You don't have admin permissions.</p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="desktop-panel p-6 text-center">
          <div className="w-6 h-6 border-2 border-primary-500/30 border-t-primary-500 rounded-full animate-spin mx-auto mb-2" />
          <p className="text-xs text-text-muted">Loading admin data...</p>
        </div>
      </div>
    )
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: BarChart3 },
    { id: 'users', label: 'Users', icon: Users },
    { id: 'scans', label: 'Scans', icon: Shield },
    { id: 'activity', label: 'Activity', icon: Activity }
  ]

  const statusBadge = (status, type = 'scan') => {
    const colors = {
      completed: 'border-emerald-400/15 text-emerald-400', running: 'border-blue-400/15 text-blue-400',
      active: 'border-emerald-400/15 text-emerald-400', inactive: 'border-red-400/15 text-red-400',
      true: 'border-emerald-400/15 text-emerald-400', false: 'border-red-400/15 text-red-400'
    }
    const label = type === 'bool' ? (status ? 'Success' : 'Failed') : status
    const key = type === 'bool' ? String(status) : (status || '')
    return (
      <span className={`text-[10px] px-1.5 py-0.5 rounded-desktop border ${colors[key] || 'border-desktop-border text-text-disabled'}`}>
        {typeof label === 'string' ? label : String(label)}
      </span>
    )
  }

  return (
    <div className="p-6 space-y-4 overflow-y-auto">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Admin Dashboard</h1>
        <p className="text-xs text-text-muted mt-0.5">System administration and monitoring</p>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Users', value: stats.users.total, sub: `${stats.users.active} active`, icon: Users, subColor: 'text-emerald-400' },
            { label: 'Total Scans', value: stats.scans.total, sub: `${stats.scans.this_month} this month`, icon: Shield, subColor: 'text-blue-400' },
            { label: 'Critical', value: stats.findings.critical, sub: `${stats.findings.total} total`, icon: AlertTriangle, subColor: 'text-red-400' },
            { label: 'Recent Logins', value: stats.activity.recent_logins_24h, sub: 'Last 24h', icon: Activity, subColor: 'text-yellow-400' }
          ].map(({ label, value, sub, icon: Icon, subColor }) => (
            <div key={label} className="desktop-panel p-3">
              <div className="flex items-center justify-between mb-1">
                <p className="text-[10px] text-text-disabled">{label}</p>
                <Icon className="h-3.5 w-3.5 text-primary-400" />
              </div>
              <p className="text-lg font-semibold text-text-primary">{value}</p>
              <p className={`text-[10px] ${subColor}`}>{sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tab Nav */}
      <div className="flex gap-1 border-b border-desktop-border">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setActiveTab(id)}
            className={`flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium border-b-2 transition-colors ${activeTab === id ? 'border-primary-500 text-primary-400' : 'border-transparent text-text-muted hover:text-text-secondary'
              }`}
          >
            <Icon className="h-3 w-3" /> {label}
          </button>
        ))}
      </div>

      {/* Search + Filters */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-disabled" />
          <input type="text" placeholder="Search..." value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)} className="input text-xs py-1.5 pl-8" />
        </div>
        {activeTab === 'users' && (
          <>
            <select value={filters.userRole} onChange={(e) => setFilters(p => ({ ...p, userRole: e.target.value }))} className="input text-xs py-1.5 w-auto">
              <option value="">All Roles</option>
              <option value="admin">Admin</option>
              <option value="developer">Developer</option>
              <option value="viewer">Viewer</option>
            </select>
            <select value={filters.userStatus} onChange={(e) => setFilters(p => ({ ...p, userStatus: e.target.value }))} className="input text-xs py-1.5 w-auto">
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </>
        )}
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === 'overview' && (
          <div className="desktop-panel p-4">
            <h3 className="text-xs font-semibold text-text-secondary mb-3">System Overview</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-[11px] font-medium text-text-muted mb-2">Recent Activity</h4>
                <div className="space-y-1">
                  {auditLogs.slice(0, 5).map((log, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                      <Activity className="h-3 w-3 text-primary-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-text-primary truncate">{log.action}</p>
                        <p className="text-[10px] text-text-disabled">{log.user_email} · {new Date(log.timestamp).toLocaleString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="text-[11px] font-medium text-text-muted mb-2">Recent Scans</h4>
                <div className="space-y-1">
                  {scans.slice(0, 5).map((scan, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 bg-desktop-card rounded-desktop border border-desktop-border">
                      <Shield className="h-3 w-3 text-primary-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-text-primary truncate">{scan.directory_path}</p>
                        <p className="text-[10px] text-text-disabled">{scan.user_email} · {scan.total_findings} findings</p>
                      </div>
                      {statusBadge(scan.status)}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="desktop-panel">
            <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
              <h3 className="text-xs font-semibold text-text-secondary">User Management</h3>
              <button className="btn-ghost text-xs px-2.5 py-1 inline-flex items-center gap-1">
                <Download className="h-3 w-3" /> Export
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-desktop-border">
                    {['User', 'Role', 'Status', 'Scans', 'Last Activity', 'Actions'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-[10px] font-medium text-text-disabled uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((u) => (
                    <tr key={u.id} className="border-b border-desktop-border hover:bg-white/[0.02] transition-colors">
                      <td className="py-2 px-3">
                        <p className="text-xs text-text-primary">{u.email}</p>
                        <p className="text-[10px] text-text-disabled">@{u.username}</p>
                      </td>
                      <td className="py-2 px-3">
                        <select value={u.role} onChange={(e) => updateUserRole(u.id, e.target.value)}
                          className="input text-[11px] py-0.5 w-auto">
                          <option value="viewer">Viewer</option>
                          <option value="developer">Developer</option>
                          <option value="admin">Admin</option>
                        </select>
                      </td>
                      <td className="py-2 px-3">{statusBadge(u.is_active ? 'active' : 'inactive')}</td>
                      <td className="py-2 px-3 text-xs text-text-primary">{u.total_scans}</td>
                      <td className="py-2 px-3 text-[10px] text-text-disabled">
                        {u.last_activity ? new Date(u.last_activity).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="py-2 px-3">
                        <div className="flex gap-0.5">
                          <button onClick={() => toggleUserStatus(u.id, u.is_active)}
                            className={`p-1 rounded transition-colors ${u.is_active ? 'text-red-400 hover:bg-red-400/5' : 'text-emerald-400 hover:bg-emerald-400/5'}`}
                            title={u.is_active ? 'Deactivate' : 'Activate'}>
                            {u.is_active ? <UserX className="h-3 w-3" /> : <UserCheck className="h-3 w-3" />}
                          </button>
                          <button className="p-1 rounded text-primary-400 hover:bg-primary-400/5 transition-colors" title="View">
                            <Eye className="h-3 w-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'scans' && (
          <div className="desktop-panel">
            <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
              <h3 className="text-xs font-semibold text-text-secondary">Scan Management</h3>
              <button className="btn-ghost text-xs px-2.5 py-1 inline-flex items-center gap-1">
                <Download className="h-3 w-3" /> Export
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-desktop-border">
                    {['Directory', 'User', 'Status', 'Findings', 'Created', ''].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-[10px] font-medium text-text-disabled uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((s) => (
                    <tr key={s.id} className="border-b border-desktop-border hover:bg-white/[0.02] transition-colors">
                      <td className="py-2 px-3">
                        <p className="text-xs text-text-primary">{s.directory_path}</p>
                        <p className="text-[10px] text-text-disabled">ID: {s.scan_id}</p>
                      </td>
                      <td className="py-2 px-3 text-xs text-text-primary">{s.user_email}</td>
                      <td className="py-2 px-3">{statusBadge(s.status)}</td>
                      <td className="py-2 px-3 text-xs">
                        <span className="text-red-400">{s.critical_findings}</span> / <span className="text-yellow-400">{s.high_findings}</span> / <span className="text-blue-400">{s.medium_findings}</span> / <span className="text-emerald-400">{s.low_findings}</span>
                      </td>
                      <td className="py-2 px-3 text-[10px] text-text-disabled">{new Date(s.created_at).toLocaleDateString()}</td>
                      <td className="py-2 px-3">
                        <button className="p-1 rounded text-primary-400 hover:bg-primary-400/5 transition-colors"><Eye className="h-3 w-3" /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'activity' && (
          <div className="desktop-panel">
            <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
              <h3 className="text-xs font-semibold text-text-secondary">Audit Logs</h3>
              <button className="btn-ghost text-xs px-2.5 py-1 inline-flex items-center gap-1">
                <Download className="h-3 w-3" /> Export
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-desktop-border">
                    {['Action', 'User', 'IP', 'Status', 'Time'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-[10px] font-medium text-text-disabled uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((l) => (
                    <tr key={l.id} className="border-b border-desktop-border hover:bg-white/[0.02] transition-colors">
                      <td className="py-2 px-3">
                        <p className="text-xs text-text-primary">{l.action}</p>
                        <p className="text-[10px] text-text-disabled">{l.resource_type}</p>
                      </td>
                      <td className="py-2 px-3 text-xs text-text-primary">{l.user_email || 'System'}</td>
                      <td className="py-2 px-3 text-[10px] text-text-disabled">{l.ip_address}</td>
                      <td className="py-2 px-3">{statusBadge(l.success, 'bool')}</td>
                      <td className="py-2 px-3 text-[10px] text-text-disabled">{new Date(l.timestamp).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default AdminDashboard
