import React, { useState } from 'react'
import { Search, Bell, User, ChevronRight } from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext'
import { useNavigate, useLocation } from 'react-router-dom'

const Header = ({ sidebarCollapsed }) => {
  const { user } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [searchQuery, setSearchQuery] = useState('')
  const [showNotifications, setShowNotifications] = useState(false)

  const notifications = [
    {
      id: 1,
      title: 'Scan Complete',
      message: '3 vulnerabilities found',
      time: '2 min ago',
      unread: true
    },
    {
      id: 2,
      title: 'Plugin Update',
      message: 'ESLint Security Plugin v2.1.0',
      time: '1 hour ago',
      unread: true
    },
    {
      id: 3,
      title: 'System Update',
      message: 'ByteGuardX v2.0.0 installed',
      time: '3 hours ago',
      unread: false
    }
  ]

  const unreadCount = notifications.filter(n => n.unread).length

  // Get breadcrumb from current path
  const getBreadcrumb = () => {
    const path = location.pathname
    if (path === '/' || path === '/dashboard') return 'Dashboard'
    if (path === '/scan') return 'Security Scanner'
    if (path === '/reports') return 'Reports'
    if (path.startsWith('/report/')) return 'Report Details'
    if (path === '/plugins') return 'Plugins'
    if (path === '/settings') return 'Settings'
    if (path === '/admin') return 'Administration'
    return 'ByteGuardX'
  }

  const handleSearch = (e) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      console.log('Searching for:', searchQuery)
    }
  }

  return (
    <header
      className={`
        fixed top-0 right-0 h-[44px] z-30
        bg-desktop-sidebar border-b border-desktop-border
        transition-all duration-200 ease-in-out
        ${sidebarCollapsed ? 'left-[56px]' : 'left-[240px]'}
      `}
    >
      <div className="flex items-center justify-between h-full px-4">
        {/* Left: Breadcrumb */}
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[13px] font-medium text-text-primary truncate">
            {getBreadcrumb()}
          </span>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2">
          {/* Search */}
          <form onSubmit={handleSearch} className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-text-disabled" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search..."
              className="w-48 pl-8 pr-3 py-1.5 bg-desktop-input border border-desktop-border rounded-desktop
                         text-xs text-text-primary placeholder-text-disabled
                         focus:outline-none focus:border-primary-600 focus:ring-1 focus:ring-primary-600/30
                         transition-colors duration-150"
            />
          </form>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-1.5 rounded-desktop text-text-muted hover:text-text-primary hover:bg-white/[0.04] transition-colors duration-150"
            >
              <Bell className="h-4 w-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 h-3.5 w-3.5 bg-danger text-white text-[9px] font-bold rounded-full flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </button>

            {showNotifications && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setShowNotifications(false)} />
                <div className="absolute right-0 top-full mt-1 w-72 bg-desktop-elevated border border-desktop-border rounded-desktop shadow-xl z-50">
                  <div className="px-3 py-2 border-b border-desktop-border">
                    <span className="text-xs font-semibold text-text-primary">Notifications</span>
                  </div>

                  <div className="max-h-56 overflow-y-auto">
                    {notifications.map((notification) => (
                      <div
                        key={notification.id}
                        className={`px-3 py-2.5 border-b border-desktop-border/50 hover:bg-white/[0.02] transition-colors cursor-pointer
                          ${notification.unread ? 'bg-primary-500/[0.03]' : ''}`}
                      >
                        <div className="flex items-start gap-2">
                          <div className={`mt-1.5 status-dot shrink-0 ${notification.unread ? 'status-online' : 'status-offline'}`} />
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-medium text-text-primary truncate">{notification.title}</p>
                            <p className="text-[11px] text-text-muted mt-0.5">{notification.message}</p>
                            <p className="text-[10px] text-text-disabled mt-1">{notification.time}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* User */}
          <div className="flex items-center gap-2 pl-2 border-l border-desktop-border ml-1">
            <div className="w-6 h-6 rounded-full bg-primary-700 flex items-center justify-center">
              <span className="text-[10px] font-semibold text-white">
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            {user?.username && (
              <span className="text-xs text-text-secondary font-medium hidden lg:block">
                {user.username}
              </span>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header
