import React, { useState, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Mail, Lock, Eye, EyeOff, Smartphone } from 'lucide-react'

import { useAuth } from '../contexts/AuthContext'
import Navbar from '../components/Navbar'
import Footer from '../components/Footer'
import Button from '../components/ui/Button'

const Login = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const { login, isAuthenticated, isLoading } = useAuth()

  const [showPassword, setShowPassword] = useState(false)
  const [show2FA, setShow2FA] = useState(false)
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    totpToken: ''
  })
  const [errors, setErrors] = useState({})

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      const from = location.state?.from?.pathname || '/dashboard'
      navigate(from, { replace: true })
    }
  }, [isAuthenticated, navigate, location])

  const handleSubmit = async (e) => {
    e.preventDefault()

    // Clear previous errors
    setErrors({})

    // Basic validation
    if (!formData.email || !formData.password) {
      setErrors({
        general: 'Please fill in all required fields'
      })
      return
    }

    const result = await login(formData.email, formData.password, formData.totpToken)

    if (result.success) {
      const from = location.state?.from?.pathname || '/dashboard'
      navigate(from, { replace: true })
    } else if (result.requires2FA) {
      setShow2FA(true)
      setErrors({})
    } else {
      setErrors({
        general: result.error || 'Login failed'
      })
    }
  }

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value
    }))

    // Clear errors when user starts typing
    if (errors[name] || errors.general) {
      setErrors(prev => ({
        ...prev,
        [name]: '',
        general: ''
      }))
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden">

      <Navbar />
      <div className="flex items-center justify-center min-h-screen">
        <div className="relative z-10 flex items-center justify-center p-4 w-full">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="w-full max-w-md"
          >
            {/* Logo */}
            <div className="text-center mb-8">
              <motion.div
                className="inline-flex items-center space-x-3 mb-6"
                whileHover={{ scale: 1.05 }}
                transition={{ duration: 0.3 }}
              >
                <div className="glass-panel p-4 rounded-2xl">
                  <Shield className="h-8 w-8 text-cyan-400" />
                </div>
                <div className="text-left">
                  <h1 className="text-2xl font-bold gradient-text">ByteGuardX</h1>
                  <p className="text-sm text-gray-400 font-light">AI-Powered Scanner</p>
                </div>
              </motion.div>
              <h2 className="text-xl font-semibold text-white mb-2">Welcome Back</h2>
              <p className="text-gray-300 font-light">Sign in to your security dashboard</p>
            </div>

            {/* Login Form */}
            <motion.div
              className="glass-card"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.6, delay: 0.2 }}
            >
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Error Message */}
                {errors.general && (
                  <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                    <p className="text-red-400 text-sm">{errors.general}</p>
                  </div>
                )}

                {/* Email Field */}
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                    Email Address
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Mail className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      className={`input pl-10 ${errors.email ? 'border-red-500' : ''}`}
                      placeholder="Enter your email"
                      required
                      disabled={isLoading}
                    />
                  </div>
                  {errors.email && (
                    <p className="mt-1 text-sm text-red-400">{errors.email}</p>
                  )}
                </div>

                {/* Password Field */}
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      id="password"
                      name="password"
                      value={formData.password}
                      onChange={handleChange}
                      className={`input pl-10 pr-10 ${errors.password ? 'border-red-500' : ''}`}
                      placeholder="Enter your password"
                      required
                      disabled={isLoading}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowPassword(!showPassword)}
                      disabled={isLoading}
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5 text-gray-400 hover:text-cyan-400 transition-colors" />
                      ) : (
                        <Eye className="h-5 w-5 text-gray-400 hover:text-cyan-400 transition-colors" />
                      )}
                    </button>
                  </div>
                  {errors.password && (
                    <p className="mt-1 text-sm text-red-400">{errors.password}</p>
                  )}
                </div>

                {/* 2FA Field (shown when required) */}
                {show2FA && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    transition={{ duration: 0.3 }}
                  >
                    <label htmlFor="totpToken" className="block text-sm font-medium text-gray-300 mb-2">
                      Two-Factor Authentication Code
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Smartphone className="h-5 w-5 text-gray-400" />
                      </div>
                      <input
                        type="text"
                        id="totpToken"
                        name="totpToken"
                        value={formData.totpToken}
                        onChange={handleChange}
                        className={`input pl-10 ${errors.totpToken ? 'border-red-500' : ''}`}
                        placeholder="Enter 6-digit code"
                        maxLength="6"
                        disabled={isLoading}
                      />
                    </div>
                    {errors.totpToken && (
                      <p className="mt-1 text-sm text-red-400">{errors.totpToken}</p>
                    )}
                    <p className="mt-1 text-xs text-gray-500">
                      Enter the 6-digit code from your authenticator app
                    </p>
                  </motion.div>
                )}

                {/* Remember Me & Forgot Password */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <input
                      id="remember-me"
                      name="remember-me"
                      type="checkbox"
                      className="h-4 w-4 text-cyan-400 focus:ring-cyan-400 border-gray-600 rounded bg-gray-800"
                    />
                    <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-300">
                      Remember me
                    </label>
                  </div>
                  <div className="text-sm">
                    <Link to="/forgot-password" className="text-cyan-400 hover:text-cyan-300 transition-colors">
                      Forgot password?
                    </Link>
                  </div>
                </div>

                {/* Submit Button */}
                <Button
                  type="submit"
                  loading={isLoading}
                  fullWidth
                  variant="primary"
                  size="md"
                  className="mt-6 sm:text-lg"
                >
                  {show2FA ? 'Verify & Sign In' : 'Sign In'}
                </Button>
              </form>

              {/* Sign Up Link */}
              <div className="mt-6 text-center">
                <p className="text-gray-400">
                  Don't have an account?{' '}
                  <Link to="/signup" className="text-cyan-400 hover:text-cyan-300 transition-colors font-medium">
                    Sign up
                  </Link>
                </p>
              </div>
            </motion.div>

            {/* Security Notice */}
            <motion.div
              className="mt-6 text-center"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.6, delay: 0.4 }}
            >
              <p className="text-xs text-gray-500">
                Protected by enterprise-grade security and encryption
              </p>
            </motion.div>
          </motion.div>
        </div>
      </div>
      <Footer />
    </div>
  )
}

export default Login
