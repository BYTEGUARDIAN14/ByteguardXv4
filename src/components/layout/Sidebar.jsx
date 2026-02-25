import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Shield,
  Home,
  Scan,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Puzzle,
  BarChart3,
  PanelLeftClose,
  PanelLeft
} from 'lucide-react'

const Sidebar = ({ isCollapsed, onToggle }) => {
  const location = useLocation()
  const [hoveredItem, setHoveredItem] = useState(null)

  const navigationItems = [
    { name: 'Dashboard', href: '/', icon: Home },
    { name: 'Dashboard', href: '/dashboard', icon: Home, hidden: true },
    { name: 'Scan', href: '/scan', icon: Scan },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Plugins', href: '/plugins', icon: Puzzle },
  ]

  const bottomItems = [
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  const isActive = (href) => {
    if (href === '/') return location.pathname === '/' || location.pathname === '/dashboard'
    return location.pathname.startsWith(href)
  }

  return (
    <aside
      className={`
        fixed left-0 top-0 h-full z-40
        bg-desktop-sidebar border-r border-desktop-border
        transition-all duration-200 ease-in-out flex flex-col
        ${isCollapsed ? 'w-[56px]' : 'w-[240px]'}
      `}
    >
      {/* App Logo */}
      <div className={`flex items-center h-[44px] border-b border-desktop-border ${isCollapsed ? 'px-3 justify-center' : 'px-4'}`}>
        <div className="flex items-center gap-2.5 min-w-0">
          <Shield className="h-5 w-5 text-primary-400 shrink-0" />
          {!isCollapsed && (
            <div className="min-w-0">
              <span className="text-sm font-semibold text-text-primary tracking-tight">ByteGuardX</span>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 px-2 space-y-0.5 overflow-y-auto">
        {navigationItems.filter(item => !item.hidden).map((item) => {
          const Icon = item.icon
          const active = isActive(item.href)

          return (
            <div key={item.name} className="relative">
              <Link
                to={item.href}
                className={`
                  group relative flex items-center gap-3 h-8 rounded-desktop transition-colors duration-150
                  ${isCollapsed ? 'justify-center px-0' : 'px-3'}
                  ${active
                    ? 'bg-primary-500/10 text-primary-400'
                    : 'text-text-secondary hover:text-text-primary hover:bg-white/[0.04]'
                  }
                `}
                onMouseEnter={() => setHoveredItem(item.name)}
                onMouseLeave={() => setHoveredItem(null)}
              >
                {/* Active indicator bar */}
                {active && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 bg-primary-400 rounded-r-full" />
                )}

                <Icon className="h-4 w-4 shrink-0" />

                {!isCollapsed && (
                  <span className="text-[13px] font-medium truncate">{item.name}</span>
                )}
              </Link>

              {/* Tooltip for collapsed state */}
              {isCollapsed && hoveredItem === item.name && (
                <div className="absolute left-full ml-2 top-1/2 -translate-y-1/2 z-50 px-2.5 py-1.5 bg-desktop-elevated border border-desktop-border rounded-desktop shadow-lg whitespace-nowrap">
                  <span className="text-xs text-text-primary font-medium">{item.name}</span>
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* Bottom Section */}
      <div className="py-2 px-2 border-t border-desktop-border space-y-0.5">
        {bottomItems.map((item) => {
          const Icon = item.icon
          const active = isActive(item.href)

          return (
            <Link
              key={item.name}
              to={item.href}
              className={`
                flex items-center gap-3 h-8 rounded-desktop transition-colors duration-150
                ${isCollapsed ? 'justify-center px-0' : 'px-3'}
                ${active
                  ? 'bg-primary-500/10 text-primary-400'
                  : 'text-text-secondary hover:text-text-primary hover:bg-white/[0.04]'
                }
              `}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!isCollapsed && (
                <span className="text-[13px] font-medium">{item.name}</span>
              )}
            </Link>
          )
        })}

        {/* Collapse Toggle */}
        <button
          onClick={onToggle}
          className={`
            flex items-center gap-3 h-8 w-full rounded-desktop transition-colors duration-150
            text-text-muted hover:text-text-secondary hover:bg-white/[0.04]
            ${isCollapsed ? 'justify-center px-0' : 'px-3'}
          `}
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <PanelLeft className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          {!isCollapsed && (
            <span className="text-[13px] font-medium">Collapse</span>
          )}
        </button>

        {/* Version */}
        {!isCollapsed && (
          <div className="px-3 py-1">
            <span className="text-xxs text-text-disabled font-mono">v2.0.0</span>
          </div>
        )}
      </div>
    </aside>
  )
}

export default Sidebar
