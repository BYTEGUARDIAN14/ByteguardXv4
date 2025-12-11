import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Search, 
  Bell, 
  Settings, 
  User, 
  LogOut, 
  Moon, 
  Sun,
  Menu,
  X,
  Shield
} from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'

const Header = ({ onMenuToggle, sidebarCollapsed }) => {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [searchQuery, setSearchQuery] = useState('')
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const [notifications] = useState([
    {
      id: 1,
      title: 'Scan Complete',
      message: 'Your security scan has finished with 3 vulnerabilities found',
      time: '2 min ago',
      type: 'warning',
      unread: true
    },
    {
      id: 2,
      title: 'New Plugin Available',
      message: 'ESLint Security Plugin v2.1.0 is now available',
      time: '1 hour ago',
      type: 'info',
      unread: true
    },
    {
      id: 3,
      title: 'System Update',
      message: 'ByteGuardX has been updated to v1.2.0',
      time: '3 hours ago',
      type: 'success',
      unread: false
    }
  ])

  const unreadCount = notifications.filter(n => n.unread).length

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const handleSearch = (e) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      // Implement search functionality
      console.log('Searching for:', searchQuery)
    }
  }

  const userMenuVariants = {
    hidden: { opacity: 0, scale: 0.95, y: -10 },
    visible: { opacity: 1, scale: 1, y: 0 },
    exit: { opacity: 0, scale: 0.95, y: -10 }
  }

  const notificationVariants = {
    hidden: { opacity: 0, x: 20 },
    visible: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: 20 }
  }

  return (
    <motion.header
      className={`
        fixed top-0 right-0 h-16 glass-nav border-b border-white/15 z-30 transition-all duration-300
        ${sidebarCollapsed ? 'left-20' : 'left-72'}
      `}
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center justify-between h-full px-6">
        {/* Left Section */}
        <div className="flex items-center space-x-4">
          <motion.button
            onClick={onMenuToggle}
            className="p-2 rounded-lg hover:bg-white/10 text-gray-400 hover:text-white transition-colors lg:hidden"
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
          >
            <Menu className="h-5 w-5" />
          </motion.button>

          {/* Search Bar */}
          <form onSubmit={handleSearch} className="relative">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <motion.input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scans, reports..."
                className="w-64 pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400/50 focus:bg-white/10 transition-all duration-200"
                whileFocus={{ scale: 1.02 }}
              />
            </div>
          </form>
        </div>

        {/* Right Section */}
        <div className="flex items-center space-x-4">
          {/* Quick Actions */}
          <motion.button
            onClick={() => navigate('/scan')}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500/80 to-blue-600/80 text-white rounded-xl font-medium hover:from-cyan-400/90 hover:to-blue-500/90 transition-all duration-200"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Shield className="h-4 w-4 mr-2 inline" />
            Quick Scan
          </motion.button>

          {/* Notifications */}
          <div className="relative">
            <motion.button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 rounded-lg hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
            >
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <motion.span
                  className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                >
                  {unreadCount}
                </motion.span>
              )}
            </motion.button>

            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  className="absolute right-0 top-full mt-2 w-80 glass-card border border-white/20 rounded-2xl shadow-2xl"
                  variants={notificationVariants}
                  initial="hidden"
                  animate="visible"
                  exit="exit"
                  transition={{ duration: 0.2 }}
                >
                  <div className="p-4 border-b border-white/10">
                    <h3 className="text-lg font-semibold text-white">Notifications</h3>
                  </div>
                  
                  <div className="max-h-64 overflow-y-auto">
                    {notifications.map((notification, index) => (
                      <motion.div
                        key={notification.id}
                        className={`p-4 border-b border-white/5 hover:bg-white/5 transition-colors ${
                          notification.unread ? 'bg-cyan-400/5' : ''
                        }`}
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.05 }}
                      >
                        <div className="flex items-start space-x-3">
                          <div className={`w-2 h-2 rounded-full mt-2 ${
                            notification.unread ? 'bg-cyan-400' : 'bg-gray-600'
                          }`} />
                          <div className="flex-1">
                            <h4 className="text-sm font-medium text-white">
                              {notification.title}
                            </h4>
                            <p className="text-xs text-gray-400 mt-1">
                              {notification.message}
                            </p>
                            <p className="text-xs text-gray-500 mt-2">
                              {notification.time}
                            </p>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                  
                  <div className="p-4 border-t border-white/10">
                    <button className="w-full text-center text-sm text-cyan-400 hover:text-cyan-300 transition-colors">
                      View All Notifications
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* User Menu */}
          <div className="relative">
            <motion.button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center space-x-3 p-2 rounded-lg hover:bg-white/10 transition-colors"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <div className="w-8 h-8 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 flex items-center justify-center">
                <span className="text-white font-semibold text-sm">
                  {user?.username?.charAt(0).toUpperCase()}
                </span>
              </div>
              <span className="text-white font-medium hidden md:block">
                {user?.username}
              </span>
            </motion.button>

            <AnimatePresence>
              {showUserMenu && (
                <motion.div
                  className="absolute right-0 top-full mt-2 w-48 glass-card border border-white/20 rounded-2xl shadow-2xl"
                  variants={userMenuVariants}
                  initial="hidden"
                  animate="visible"
                  exit="exit"
                  transition={{ duration: 0.2 }}
                >
                  <div className="p-2">
                    <motion.button
                      onClick={() => navigate('/profile')}
                      className="w-full flex items-center space-x-3 px-3 py-2 rounded-lg hover:bg-white/10 text-gray-300 hover:text-white transition-colors"
                      whileHover={{ x: 4 }}
                    >
                      <User className="h-4 w-4" />
                      <span>Profile</span>
                    </motion.button>
                    
                    <motion.button
                      onClick={() => navigate('/settings')}
                      className="w-full flex items-center space-x-3 px-3 py-2 rounded-lg hover:bg-white/10 text-gray-300 hover:text-white transition-colors"
                      whileHover={{ x: 4 }}
                    >
                      <Settings className="h-4 w-4" />
                      <span>Settings</span>
                    </motion.button>
                    
                    <hr className="my-2 border-white/10" />
                    
                    <motion.button
                      onClick={handleLogout}
                      className="w-full flex items-center space-x-3 px-3 py-2 rounded-lg hover:bg-red-500/20 text-gray-300 hover:text-red-400 transition-colors"
                      whileHover={{ x: 4 }}
                    >
                      <LogOut className="h-4 w-4" />
                      <span>Logout</span>
                    </motion.button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </motion.header>
  )
}

export default Header
