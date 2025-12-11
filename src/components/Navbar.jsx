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
    <nav className="sticky top-0 z-50 glass-nav" style={{borderBottom: '1px solid rgba(255, 255, 255, 0.15)'}}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-3 group">
            <motion.div
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="p-2 glass-panel rounded-xl group-hover:bg-white/10 transition-all duration-300"
            >
              <Shield className="h-6 w-6 text-white group-hover:text-cyan-400 transition-colors duration-300" />
            </motion.div>
            <div className="flex flex-col">
              <span className="text-xl font-bold gradient-text">ByteGuardX</span>
              <span className="text-xs text-gray-300 -mt-1 font-light">AI-Powered Scanner</span>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-2">
            {navigation.map((item) => {
              const Icon = item.icon
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`
                    flex items-center space-x-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-300
                    ${isActive(item.href)
                      ? 'nav-link-active'
                      : 'nav-link'
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
              to="/login"
              className="btn-secondary hover-lift"
            >
              Login
            </Link>
            <Link
              to="/scan"
              className="btn-primary hover-lift"
            >
              Start Scan
            </Link>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="p-2 rounded-xl text-gray-300 hover:text-cyan-400 glass-panel hover:bg-white/10 transition-all duration-300"
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
        transition={{ duration: 0.3, ease: "easeInOut" }}
        className="md:hidden overflow-hidden glass"
        style={{borderTop: '1px solid rgba(255, 255, 255, 0.15)'}}
      >
        <div className="px-4 py-4 space-y-2">
          {navigation.map((item) => {
            const Icon = item.icon
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={() => setIsOpen(false)}
                className={`
                  flex items-center space-x-3 px-4 py-3 rounded-xl text-base font-medium transition-all duration-300
                  ${isActive(item.href)
                    ? 'nav-link-active'
                    : 'nav-link'
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
