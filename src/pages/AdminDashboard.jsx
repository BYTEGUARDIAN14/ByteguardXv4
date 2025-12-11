import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Users,
  Shield,
  Activity,
  BarChart3,
  Settings,
  AlertTriangle,
  CheckCircle,
  Clock,
  Search,
  Filter,
  Download,
  Eye,
  UserCheck,
  UserX,
  Crown
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
  const [filters, setFilters] = useState({
    userRole: '',
    userStatus: '',
    scanStatus: '',
    logAction: ''
  })

  useEffect(() => {
    if (user?.role !== 'admin') {
      return
    }
    
    fetchAdminData()
  }, [user])

  const fetchAdminData = async () => {
    try {
      setLoading(true)
      
      // Fetch admin statistics
      const statsResponse = await fetch('/api/admin/stats', {
        credentials: 'include'
      })
      if (statsResponse.ok) {
        const statsData = await statsResponse.json()
        setStats(statsData)
      }

      // Fetch users
      const usersResponse = await fetch('/api/admin/users?per_page=50', {
        credentials: 'include'
      })
      if (usersResponse.ok) {
        const usersData = await usersResponse.json()
        setUsers(usersData.users || [])
      }

      // Fetch scans
      const scansResponse = await fetch('/api/admin/scans?per_page=20', {
        credentials: 'include'
      })
      if (scansResponse.ok) {
        const scansData = await scansResponse.json()
        setScans(scansData.scans || [])
      }

      // Fetch audit logs
      const logsResponse = await fetch('/api/admin/activity?per_page=30', {
        credentials: 'include'
      })
      if (logsResponse.ok) {
        const logsData = await logsResponse.json()
        setAuditLogs(logsData.logs || [])
      }

    } catch (error) {
      console.error('Error fetching admin data:', error)
    } finally {
      setLoading(false)
    }
  }

  const updateUserRole = async (userId, newRole) => {
    try {
      const response = await fetch(`/api/admin/users/${userId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ role: newRole })
      })

      if (response.ok) {
        fetchAdminData() // Refresh data
      }
    } catch (error) {
      console.error('Error updating user role:', error)
    }
  }

  const toggleUserStatus = async (userId, currentStatus) => {
    try {
      const response = await fetch(`/api/admin/users/${userId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ is_active: !currentStatus })
      })

      if (response.ok) {
        fetchAdminData() // Refresh data
      }
    } catch (error) {
      console.error('Error updating user status:', error)
    }
  }

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.username.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesRole = !filters.userRole || user.role === filters.userRole
    const matchesStatus = !filters.userStatus || 
                         (filters.userStatus === 'active' && user.is_active) ||
                         (filters.userStatus === 'inactive' && !user.is_active)
    
    return matchesSearch && matchesRole && matchesStatus
  })

  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.directory_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.user_email.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = !filters.scanStatus || scan.status === filters.scanStatus
    
    return matchesSearch && matchesStatus
  })

  const filteredLogs = auditLogs.filter(log => {
    const matchesSearch = log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (log.user_email && log.user_email.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesAction = !filters.logAction || log.action.includes(filters.logAction)
    
    return matchesSearch && matchesAction
  })

  if (user?.role !== 'admin') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="glass-card text-center p-8">
          <div className="text-red-400 text-6xl mb-4">🚫</div>
          <h2 className="text-2xl font-bold text-white mb-2">Access Denied</h2>
          <p className="text-gray-400">
            You don't have permission to access the admin dashboard.
          </p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="glass-card p-8">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
          <p className="text-white">Loading admin dashboard...</p>
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

  return (
    <div className="min-h-screen bg-black text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold gradient-text mb-2">Admin Dashboard</h1>
        <p className="text-gray-400">System administration and monitoring</p>
      </div>

      {/* Stats Overview */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-6"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Users</p>
                <p className="text-2xl font-bold text-white">{stats.users.total}</p>
                <p className="text-green-400 text-sm">
                  {stats.users.active} active
                </p>
              </div>
              <Users className="h-8 w-8 text-cyan-400" />
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="glass-card p-6"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Scans</p>
                <p className="text-2xl font-bold text-white">{stats.scans.total}</p>
                <p className="text-blue-400 text-sm">
                  {stats.scans.this_month} this month
                </p>
              </div>
              <Shield className="h-8 w-8 text-cyan-400" />
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="glass-card p-6"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Critical Findings</p>
                <p className="text-2xl font-bold text-white">{stats.findings.critical}</p>
                <p className="text-red-400 text-sm">
                  {stats.findings.total} total findings
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-400" />
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="glass-card p-6"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Recent Logins</p>
                <p className="text-2xl font-bold text-white">{stats.activity.recent_logins_24h}</p>
                <p className="text-yellow-400 text-sm">
                  Last 24 hours
                </p>
              </div>
              <Activity className="h-8 w-8 text-cyan-400" />
            </div>
          </motion.div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex space-x-1 mb-8 bg-gray-900/50 p-1 rounded-lg">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                flex items-center space-x-2 px-4 py-2 rounded-md transition-all duration-200
                ${activeTab === tab.id
                  ? 'bg-cyan-500 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }
              `}
            >
              <Icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
          />
        </div>
        
        {activeTab === 'users' && (
          <>
            <select
              value={filters.userRole}
              onChange={(e) => setFilters(prev => ({ ...prev, userRole: e.target.value }))}
              className="px-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Roles</option>
              <option value="admin">Admin</option>
              <option value="developer">Developer</option>
              <option value="viewer">Viewer</option>
            </select>
            
            <select
              value={filters.userStatus}
              onChange={(e) => setFilters(prev => ({ ...prev, userStatus: e.target.value }))}
              className="px-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </>
        )}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.2 }}
        >
          {activeTab === 'overview' && (
            <div className="glass-card p-6">
              <h3 className="text-xl font-semibold text-white mb-4">System Overview</h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-medium text-white mb-3">Recent Activity</h4>
                  <div className="space-y-3">
                    {auditLogs.slice(0, 5).map((log, index) => (
                      <div key={index} className="flex items-center space-x-3 p-3 bg-gray-900/30 rounded-lg">
                        <Activity className="h-4 w-4 text-cyan-400" />
                        <div className="flex-1">
                          <p className="text-white text-sm">{log.action}</p>
                          <p className="text-gray-400 text-xs">
                            {log.user_email} • {new Date(log.timestamp).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div>
                  <h4 className="text-lg font-medium text-white mb-3">Recent Scans</h4>
                  <div className="space-y-3">
                    {scans.slice(0, 5).map((scan, index) => (
                      <div key={index} className="flex items-center space-x-3 p-3 bg-gray-900/30 rounded-lg">
                        <Shield className="h-4 w-4 text-cyan-400" />
                        <div className="flex-1">
                          <p className="text-white text-sm">{scan.directory_path}</p>
                          <p className="text-gray-400 text-xs">
                            {scan.user_email} • {scan.total_findings} findings
                          </p>
                        </div>
                        <span className={`
                          px-2 py-1 rounded-full text-xs
                          ${scan.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                            scan.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                            'bg-red-500/20 text-red-400'}
                        `}>
                          {scan.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'users' && (
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-semibold text-white">User Management</h3>
                <button className="btn-primary">
                  <Download className="h-4 w-4 mr-2" />
                  Export Users
                </button>
              </div>
              
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4 text-gray-400">User</th>
                      <th className="text-left py-3 px-4 text-gray-400">Role</th>
                      <th className="text-left py-3 px-4 text-gray-400">Status</th>
                      <th className="text-left py-3 px-4 text-gray-400">Scans</th>
                      <th className="text-left py-3 px-4 text-gray-400">Last Activity</th>
                      <th className="text-left py-3 px-4 text-gray-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUsers.map((user) => (
                      <tr key={user.id} className="border-b border-gray-800 hover:bg-gray-900/30">
                        <td className="py-3 px-4">
                          <div>
                            <p className="text-white font-medium">{user.email}</p>
                            <p className="text-gray-400 text-sm">@{user.username}</p>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <select
                            value={user.role}
                            onChange={(e) => updateUserRole(user.id, e.target.value)}
                            className="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-white text-sm"
                          >
                            <option value="viewer">Viewer</option>
                            <option value="developer">Developer</option>
                            <option value="admin">Admin</option>
                          </select>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`
                            px-2 py-1 rounded-full text-xs
                            ${user.is_active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}
                          `}>
                            {user.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-white">{user.total_scans}</td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {user.last_activity ? new Date(user.last_activity).toLocaleDateString() : 'Never'}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => toggleUserStatus(user.id, user.is_active)}
                              className={`
                                p-1 rounded transition-colors
                                ${user.is_active 
                                  ? 'text-red-400 hover:bg-red-500/20' 
                                  : 'text-green-400 hover:bg-green-500/20'
                                }
                              `}
                              title={user.is_active ? 'Deactivate User' : 'Activate User'}
                            >
                              {user.is_active ? <UserX className="h-4 w-4" /> : <UserCheck className="h-4 w-4" />}
                            </button>
                            <button
                              className="p-1 rounded text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                              title="View User Details"
                            >
                              <Eye className="h-4 w-4" />
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
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-semibold text-white">Scan Management</h3>
                <button className="btn-primary">
                  <Download className="h-4 w-4 mr-2" />
                  Export Scans
                </button>
              </div>
              
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4 text-gray-400">Directory</th>
                      <th className="text-left py-3 px-4 text-gray-400">User</th>
                      <th className="text-left py-3 px-4 text-gray-400">Status</th>
                      <th className="text-left py-3 px-4 text-gray-400">Findings</th>
                      <th className="text-left py-3 px-4 text-gray-400">Created</th>
                      <th className="text-left py-3 px-4 text-gray-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredScans.map((scan) => (
                      <tr key={scan.id} className="border-b border-gray-800 hover:bg-gray-900/30">
                        <td className="py-3 px-4">
                          <p className="text-white font-medium">{scan.directory_path}</p>
                          <p className="text-gray-400 text-sm">ID: {scan.scan_id}</p>
                        </td>
                        <td className="py-3 px-4">
                          <p className="text-white">{scan.user_email}</p>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`
                            px-2 py-1 rounded-full text-xs
                            ${scan.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                              scan.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                              'bg-red-500/20 text-red-400'}
                          `}>
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-white">
                            <span className="text-red-400">{scan.critical_findings}</span> / 
                            <span className="text-yellow-400">{scan.high_findings}</span> / 
                            <span className="text-blue-400">{scan.medium_findings}</span> / 
                            <span className="text-green-400">{scan.low_findings}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-3 px-4">
                          <button
                            className="p-1 rounded text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                            title="View Scan Details"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'activity' && (
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-semibold text-white">Audit Logs</h3>
                <button className="btn-primary">
                  <Download className="h-4 w-4 mr-2" />
                  Export Logs
                </button>
              </div>
              
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4 text-gray-400">Action</th>
                      <th className="text-left py-3 px-4 text-gray-400">User</th>
                      <th className="text-left py-3 px-4 text-gray-400">IP Address</th>
                      <th className="text-left py-3 px-4 text-gray-400">Status</th>
                      <th className="text-left py-3 px-4 text-gray-400">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((log) => (
                      <tr key={log.id} className="border-b border-gray-800 hover:bg-gray-900/30">
                        <td className="py-3 px-4">
                          <p className="text-white font-medium">{log.action}</p>
                          <p className="text-gray-400 text-sm">{log.resource_type}</p>
                        </td>
                        <td className="py-3 px-4 text-white">
                          {log.user_email || 'System'}
                        </td>
                        <td className="py-3 px-4 text-gray-400">
                          {log.ip_address}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`
                            px-2 py-1 rounded-full text-xs
                            ${log.success ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}
                          `}>
                            {log.success ? 'Success' : 'Failed'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

export default AdminDashboard
