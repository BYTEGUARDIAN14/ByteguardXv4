import React, { createContext, useContext, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react'

const NotificationContext = createContext()

export const useNotifications = () => {
  const context = useContext(NotificationContext)
  if (!context) {
    throw new Error('useNotifications must be used within NotificationProvider')
  }
  return context
}

const NotificationItem = ({ notification, onRemove }) => {
  const icons = {
    success: CheckCircle,
    error: AlertCircle,
    warning: AlertTriangle,
    info: Info
  }

  const colors = {
    success: 'border-green-400/30 bg-green-400/10 text-green-400',
    error: 'border-red-400/30 bg-red-400/10 text-red-400',
    warning: 'border-yellow-400/30 bg-yellow-400/10 text-yellow-400',
    info: 'border-blue-400/30 bg-blue-400/10 text-blue-400'
  }

  const Icon = icons[notification.type]

  return (
    <motion.div
      initial={{ opacity: 0, x: 300, scale: 0.8 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 300, scale: 0.8 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
      className={`
        glass-card p-4 border-l-4 max-w-sm w-full shadow-lg
        ${colors[notification.type]}
      `}
    >
      <div className="flex items-start space-x-3">
        <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />
        
        <div className="flex-1 min-w-0">
          {notification.title && (
            <h4 className="text-sm font-semibold text-white mb-1">
              {notification.title}
            </h4>
          )}
          <p className="text-sm text-gray-300">
            {notification.message}
          </p>
          
          {notification.action && (
            <motion.button
              onClick={notification.action.onClick}
              className="mt-2 text-xs font-medium hover:underline"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              {notification.action.label}
            </motion.button>
          )}
        </div>
        
        <motion.button
          onClick={() => onRemove(notification.id)}
          className="text-gray-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-white/10"
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.9 }}
        >
          <X className="h-4 w-4" />
        </motion.button>
      </div>
      
      {notification.progress !== undefined && (
        <div className="mt-3">
          <div className="w-full bg-gray-700 rounded-full h-1">
            <motion.div
              className="bg-current h-1 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${notification.progress}%` }}
              transition={{ duration: 0.5 }}
            />
          </div>
        </div>
      )}
    </motion.div>
  )
}

export const NotificationProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([])

  const addNotification = useCallback((notification) => {
    const id = Date.now() + Math.random()
    const newNotification = {
      id,
      type: 'info',
      duration: 5000,
      ...notification
    }

    setNotifications(prev => [...prev, newNotification])

    // Auto remove after duration
    if (newNotification.duration > 0) {
      setTimeout(() => {
        removeNotification(id)
      }, newNotification.duration)
    }

    return id
  }, [])

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id))
  }, [])

  const removeAll = useCallback(() => {
    setNotifications([])
  }, [])

  // Convenience methods
  const success = useCallback((message, options = {}) => {
    return addNotification({ ...options, message, type: 'success' })
  }, [addNotification])

  const error = useCallback((message, options = {}) => {
    return addNotification({ ...options, message, type: 'error', duration: 7000 })
  }, [addNotification])

  const warning = useCallback((message, options = {}) => {
    return addNotification({ ...options, message, type: 'warning' })
  }, [addNotification])

  const info = useCallback((message, options = {}) => {
    return addNotification({ ...options, message, type: 'info' })
  }, [addNotification])

  const value = {
    notifications,
    addNotification,
    removeNotification,
    removeAll,
    success,
    error,
    warning,
    info
  }

  return (
    <NotificationContext.Provider value={value}>
      {children}
      
      {/* Notification Container */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        <AnimatePresence>
          {notifications.map(notification => (
            <NotificationItem
              key={notification.id}
              notification={notification}
              onRemove={removeNotification}
            />
          ))}
        </AnimatePresence>
      </div>
    </NotificationContext.Provider>
  )
}

// Toast-style notifications for quick feedback
export const Toast = ({ message, type = 'info', onClose }) => {
  const colors = {
    success: 'bg-green-500',
    error: 'bg-red-500',
    warning: 'bg-yellow-500',
    info: 'bg-blue-500'
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: -50 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -50 }}
      className={`
        fixed top-4 left-1/2 transform -translate-x-1/2 z-50
        px-6 py-3 rounded-full text-white font-medium shadow-lg
        ${colors[type]}
      `}
    >
      {message}
    </motion.div>
  )
}
