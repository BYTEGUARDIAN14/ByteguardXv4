import React from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Home, ArrowLeft, Search, Shield } from 'lucide-react'

const NotFound = () => {
  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="max-w-md w-full text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          {/* 404 Animation */}
          <motion.div
            initial={{ scale: 0.8 }}
            animate={{ scale: 1 }}
            transition={{ 
              duration: 0.8, 
              type: "spring", 
              stiffness: 100 
            }}
            className="mb-8"
          >
            <div className="relative">
              <div className="text-8xl font-bold text-gray-800 mb-4">404</div>
              <motion.div
                animate={{ 
                  rotate: [0, 10, -10, 0],
                  scale: [1, 1.1, 1]
                }}
                transition={{ 
                  duration: 2, 
                  repeat: Infinity,
                  repeatType: "reverse"
                }}
                className="absolute top-4 right-8"
              >
                <Shield className="h-12 w-12 text-primary-400 opacity-50" />
              </motion.div>
            </div>
          </motion.div>

          {/* Error Message */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6 }}
            className="mb-8"
          >
            <h1 className="text-3xl font-bold text-white mb-4">
              Page Not Found
            </h1>
            <p className="text-gray-400 text-lg leading-relaxed">
              The page you're looking for doesn't exist or has been moved. 
              Let's get you back to scanning for security vulnerabilities.
            </p>
          </motion.div>

          {/* Action Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.6 }}
            className="space-y-4"
          >
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                to="/"
                className="btn-primary text-lg px-6 py-3 hover-lift"
              >
                <Home className="h-5 w-5 mr-2" />
                Go Home
              </Link>
              
              <Link
                to="/scan"
                className="btn-secondary text-lg px-6 py-3 hover-lift"
              >
                <Search className="h-5 w-5 mr-2" />
                Start Scan
              </Link>
            </div>

            <button
              onClick={() => window.history.back()}
              className="btn-ghost text-sm px-4 py-2"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Go Back
            </button>
          </motion.div>

          {/* Helpful Links */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.6 }}
            className="mt-12 pt-8 border-t border-gray-800"
          >
            <p className="text-gray-500 text-sm mb-4">
              Looking for something specific?
            </p>
            
            <div className="grid grid-cols-1 gap-3 text-sm">
              <Link
                to="/scan"
                className="text-gray-400 hover:text-primary-400 transition-colors duration-200"
              >
                → Security Scanning
              </Link>
              <Link
                to="/report"
                className="text-gray-400 hover:text-primary-400 transition-colors duration-200"
              >
                → Sample Reports
              </Link>
              <a
                href="https://github.com/byteguardx/byteguardx"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-primary-400 transition-colors duration-200"
              >
                → Documentation
              </a>
            </div>
          </motion.div>

          {/* Background Animation */}
          <motion.div
            animate={{
              scale: [1, 1.2, 1],
              opacity: [0.1, 0.2, 0.1]
            }}
            transition={{
              duration: 4,
              repeat: Infinity,
              repeatType: "reverse"
            }}
            className="absolute inset-0 -z-10"
          >
            <div className="w-full h-full bg-gradient-to-br from-primary-500/5 via-transparent to-transparent rounded-full blur-3xl" />
          </motion.div>
        </motion.div>
      </div>
    </div>
  )
}

export default NotFound
