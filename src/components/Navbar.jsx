import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Menu, X, Scan, FileText, Home } from 'lucide-react'

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false)
  const location = useLocation()

  const navigation = [
    { name: 'Home', href: '/', icon: Home },
    { name: 'Scan', href: '/scan', icon: Scan },
    { name: 'Reports', href: '/report', icon: FileText },
  ]

  const isActive = (path) => {
    if (path === '/') {
      return location.pathname === '/'
    }
    return location.pathname.startsWith(path)
  }

  return (
    <nav className="sticky top-0 z-50 bg-black bg-opacity-90 backdrop-blur-sm border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2 group">
            <motion.div
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="p-2 bg-primary-500 bg-opacity-10 rounded-lg group-hover:bg-opacity-20 transition-all duration-200"
            >
              <Shield className="h-6 w-6 text-primary-400" />
            </motion.div>
            <div className="flex flex-col">
              <span className="text-xl font-bold gradient-text">ByteGuardX</span>
              <span className="text-xs text-gray-400 -mt-1">AI-Powered Scanner</span>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-1">
            {navigation.map((item) => {
              const Icon = item.icon
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`
                    flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200
                    ${isActive(item.href)
                      ? 'text-primary-400 bg-primary-500 bg-opacity-10'
                      : 'text-gray-300 hover:text-white hover:bg-gray-800'
                    }
                  `}
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.name}</span>
                </Link>
              )
            })}
          </div>

          {/* CTA Button */}
          <div className="hidden md:flex items-center space-x-4">
            <Link
              to="/scan"
              className="btn-primary"
            >
              Start Scan
            </Link>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors duration-200"
            >
              {isOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      <motion.div
        initial={false}
        animate={{
          height: isOpen ? 'auto' : 0,
          opacity: isOpen ? 1 : 0,
        }}
        transition={{ duration: 0.2 }}
        className="md:hidden overflow-hidden bg-gray-900 border-t border-gray-800"
      >
        <div className="px-4 py-2 space-y-1">
          {navigation.map((item) => {
            const Icon = item.icon
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={() => setIsOpen(false)}
                className={`
                  flex items-center space-x-3 px-3 py-3 rounded-lg text-base font-medium transition-all duration-200
                  ${isActive(item.href)
                    ? 'text-primary-400 bg-primary-500 bg-opacity-10'
                    : 'text-gray-300 hover:text-white hover:bg-gray-800'
                  }
                `}
              >
                <Icon className="h-5 w-5" />
                <span>{item.name}</span>
              </Link>
            )
          })}
          
          <div className="pt-4 pb-2">
            <Link
              to="/scan"
              onClick={() => setIsOpen(false)}
              className="btn-primary w-full justify-center"
            >
              Start Scan
            </Link>
          </div>
        </div>
      </motion.div>
    </nav>
  )
}

export default Navbar
