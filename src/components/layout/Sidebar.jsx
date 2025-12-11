import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Link, useLocation } from 'react-router-dom'
import { 
  Shield, 
  Home, 
  Scan, 
  FileText, 
  Settings, 
  User, 
  LogOut,
  ChevronLeft,
  ChevronRight,
  Activity,
  Puzzle,
  BarChart3
} from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext'

const Sidebar = ({ isCollapsed, onToggle }) => {
  const location = useLocation()
  const { user, logout } = useAuth()
  const [hoveredItem, setHoveredItem] = useState(null)

  const navigationItems = [
    { 
      name: 'Dashboard', 
      href: '/dashboard', 
      icon: Home,
      badge: null
    },
    { 
      name: 'Scan Files', 
      href: '/scan', 
      icon: Scan,
      badge: null
    },
    { 
      name: 'Reports', 
      href: '/reports', 
      icon: FileText,
      badge: '3'
    },
    { 
      name: 'Analytics', 
      href: '/analytics', 
      icon: BarChart3,
      badge: null
    },
    { 
      name: 'Plugins', 
      href: '/plugins', 
      icon: Puzzle,
      badge: 'New'
    },
    { 
      name: 'Activity', 
      href: '/activity', 
      icon: Activity,
      badge: null
    }
  ]

  const bottomItems = [
    { 
      name: 'Settings', 
      href: '/settings', 
      icon: Settings 
    },
    { 
      name: 'Profile', 
      href: '/profile', 
      icon: User 
    }
  ]

  const isActive = (href) => location.pathname === href

  const sidebarVariants = {
    expanded: { width: 280 },
    collapsed: { width: 80 }
  }

  const itemVariants = {
    expanded: { opacity: 1, x: 0 },
    collapsed: { opacity: 0, x: -20 }
  }

  const handleLogout = async () => {
    await logout()
  }

  return (
    <motion.div
      className="fixed left-0 top-0 h-full glass-nav border-r border-white/15 z-40"
      variants={sidebarVariants}
      animate={isCollapsed ? 'collapsed' : 'expanded'}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
    >
      <div className="flex flex-col h-full">
        {/* Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between">
            <motion.div
              className="flex items-center space-x-3"
              animate={{ opacity: isCollapsed ? 0 : 1 }}
              transition={{ duration: 0.2 }}
            >
              <div className="p-2 glass-panel rounded-xl">
                <Shield className="h-6 w-6 text-cyan-400" />
              </div>
              {!isCollapsed && (
                <div>
                  <h1 className="text-xl font-bold gradient-text">ByteGuardX</h1>
                  <p className="text-xs text-gray-400">AI Security Scanner</p>
                </div>
              )}
            </motion.div>

            <motion.button
              onClick={onToggle}
              className="p-2 rounded-lg hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
            >
              {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            </motion.button>
          </div>
        </div>

        {/* User Info */}
        {!isCollapsed && user && (
          <motion.div
            className="p-4 border-b border-white/10"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 flex items-center justify-center">
                <span className="text-white font-semibold text-sm">
                  {user.username?.charAt(0).toUpperCase()}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white truncate">
                  {user.username}
                </p>
                <p className="text-xs text-gray-400 truncate">
                  {user.email}
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {navigationItems.map((item, index) => {
            const Icon = item.icon
            const active = isActive(item.href)

            return (
              <motion.div
                key={item.name}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
              >
                <Link
                  to={item.href}
                  className={`
                    group relative flex items-center px-3 py-3 rounded-xl transition-all duration-200
                    ${active 
                      ? 'bg-cyan-400/20 text-cyan-400 border border-cyan-400/30' 
                      : 'text-gray-300 hover:text-white hover:bg-white/10'
                    }
                  `}
                  onMouseEnter={() => setHoveredItem(item.name)}
                  onMouseLeave={() => setHoveredItem(null)}
                >
                  <Icon className={`h-5 w-5 ${isCollapsed ? 'mx-auto' : 'mr-3'}`} />
                  
                  <AnimatePresence>
                    {!isCollapsed && (
                      <motion.div
                        className="flex items-center justify-between flex-1"
                        variants={itemVariants}
                        initial="collapsed"
                        animate="expanded"
                        exit="collapsed"
                        transition={{ duration: 0.2 }}
                      >
                        <span className="font-medium">{item.name}</span>
                        {item.badge && (
                          <motion.span
                            className={`
                              px-2 py-1 text-xs rounded-full font-medium
                              ${item.badge === 'New' 
                                ? 'bg-green-400/20 text-green-400' 
                                : 'bg-cyan-400/20 text-cyan-400'
                              }
                            `}
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            transition={{ delay: 0.2 }}
                          >
                            {item.badge}
                          </motion.span>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Tooltip for collapsed state */}
                  <AnimatePresence>
                    {isCollapsed && hoveredItem === item.name && (
                      <motion.div
                        className="absolute left-full ml-2 px-3 py-2 glass-card rounded-lg whitespace-nowrap z-50"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -10 }}
                        transition={{ duration: 0.2 }}
                      >
                        <span className="text-sm text-white">{item.name}</span>
                        {item.badge && (
                          <span className="ml-2 px-2 py-1 text-xs rounded-full bg-cyan-400/20 text-cyan-400">
                            {item.badge}
                          </span>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Active indicator */}
                  {active && (
                    <motion.div
                      className="absolute left-0 top-1/2 transform -translate-y-1/2 w-1 h-8 bg-cyan-400 rounded-r-full"
                      layoutId="activeIndicator"
                      transition={{ duration: 0.2 }}
                    />
                  )}
                </Link>
              </motion.div>
            )
          })}
        </nav>

        {/* Bottom Navigation */}
        <div className="p-4 border-t border-white/10 space-y-2">
          {bottomItems.map((item) => {
            const Icon = item.icon
            const active = isActive(item.href)

            return (
              <Link
                key={item.name}
                to={item.href}
                className={`
                  group flex items-center px-3 py-3 rounded-xl transition-all duration-200
                  ${active 
                    ? 'bg-cyan-400/20 text-cyan-400' 
                    : 'text-gray-300 hover:text-white hover:bg-white/10'
                  }
                `}
              >
                <Icon className={`h-5 w-5 ${isCollapsed ? 'mx-auto' : 'mr-3'}`} />
                {!isCollapsed && (
                  <span className="font-medium">{item.name}</span>
                )}
              </Link>
            )
          })}

          {/* Logout Button */}
          <motion.button
            onClick={handleLogout}
            className="w-full flex items-center px-3 py-3 rounded-xl text-gray-300 hover:text-red-400 hover:bg-red-400/10 transition-all duration-200"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            <LogOut className={`h-5 w-5 ${isCollapsed ? 'mx-auto' : 'mr-3'}`} />
            {!isCollapsed && <span className="font-medium">Logout</span>}
          </motion.button>
        </div>
      </div>
    </motion.div>
  )
}

export default Sidebar
