import React, { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'
import toast from 'react-hot-toast'

// Create auth context
const AuthContext = createContext()

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Auth provider component
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)

  const API_BASE_URL = import.meta.env.VITE_API_URL ||
    (import.meta.env.PROD ? 'https://your-flask-backend.herokuapp.com' : 'http://localhost:5000')

  // Create axios instance with credentials and enhanced security
  const api = axios.create({
    baseURL: API_BASE_URL,
    withCredentials: true, // Important for cookies
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // CSRF protection
    },
  })

  // Request interceptor for auth tokens
  api.interceptors.request.use(
    (config) => {
      const token = localStorage.getItem('auth_token')
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )

  // Helper function to check if token is expired
  const isTokenExpired = (token) => {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      return Date.now() >= payload.exp * 1000
    } catch {
      return true
    }
  }

  // Helper function to sanitize error messages
  const sanitizeErrorMessage = (message) => {
    if (typeof message !== 'string') return 'An error occurred'
    // Remove HTML tags and limit length
    return message.replace(/<[^>]*>/g, '').substring(0, 200)
  }

  // Response interceptor for handling auth errors with enhanced security
  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config

      if (error.response?.status === 401 && !originalRequest._retry) {
        // Prevent infinite loops by ignoring 401s on login/logout
        if (originalRequest.url.includes('/auth/login') || originalRequest.url.includes('/auth/logout')) {
          return Promise.reject(error)
        }

        originalRequest._retry = true

        try {
          const refreshTokenValue = localStorage.getItem('refresh_token')
          if (refreshTokenValue && !isTokenExpired(refreshTokenValue)) {
            const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
              },
              credentials: 'include',
              body: JSON.stringify({ refresh_token: refreshTokenValue })
            })

            if (response.ok) {
              const data = await response.json()
              localStorage.setItem('auth_token', data.access_token)
              if (data.refresh_token) {
                localStorage.setItem('refresh_token', data.refresh_token)
              }

              // Retry original request with new token
              originalRequest.headers.Authorization = `Bearer ${data.access_token}`
              return api(originalRequest)
            }
          }

          // Refresh failed or token expired, logout user
          await logout()
          toast.error('Session expired. Please login again.')
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError)
          await logout()
          toast.error('Session expired. Please login again.')
        }
      }

      // Sanitize error messages to prevent XSS
      if (error.response?.data?.error) {
        error.response.data.error = sanitizeErrorMessage(error.response.data.error)
      }

      return Promise.reject(error)
    }
  )

  // Check authentication status on app load
  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      setIsLoading(true)
      const response = await api.get('/api/auth/verify')

      if (response.data.valid) {
        setUser(response.data.user)
        setIsAuthenticated(true)
      } else {
        setUser(null)
        setIsAuthenticated(false)

        // In development mode, don't treat auth failures as errors
        if (response.data.development_mode) {
          console.log('Development mode: User not authenticated -', response.data.message || response.data.error)
        }
      }
    } catch (error) {
      setUser(null)
      setIsAuthenticated(false)

      // Don't show auth errors in development mode for 401s
      if (error.response?.status === 401 && import.meta.env.DEV) {
        console.log('Development mode: Authentication check failed (expected if not logged in)')
      } else {
        // Don't show auth errors for 401s (expected behavior)
        if (error.response?.status !== 401) {
          console.error('Auth check failed:', error)
        }
      }
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (email, password, totpToken = '') => {
    try {
      setIsLoading(true)

      const response = await api.post('/api/auth/login', {
        email,
        password,
        totp_token: totpToken
      })

      if (response.data.user) {
        setUser(response.data.user)
        setIsAuthenticated(true)
        toast.success('Login successful!')
        return { success: true }
      }

      return { success: false, error: 'Login failed' }
    } catch (error) {
      console.error('Login failed:', error)

      let errorMessage = 'Login failed. Please try again.'
      if (error.response?.status === 401) {
        if (error.response.data?.requires_2fa) {
          return {
            success: false,
            requires2FA: true,
            error: 'Two-factor authentication required'
          }
        }
        errorMessage = error.response.data?.error || 'Invalid credentials'
      } else if (error.response?.status === 429) {
        errorMessage = 'Too many login attempts. Please try again later.'
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error
      }

      toast.error(errorMessage)
      return { success: false, error: errorMessage }
    } finally {
      setIsLoading(false)
    }
  }

  const signup = async (email, username, password) => {
    try {
      setIsLoading(true)

      const response = await api.post('/api/auth/register', {
        email,
        username,
        password
      })

      if (response.data.user) {
        setUser(response.data.user)
        setIsAuthenticated(true)
        toast.success('Account created successfully!')
        return { success: true }
      }

      return { success: false, error: 'Registration failed' }
    } catch (error) {
      console.error('Signup failed:', error)

      let errorMessage = 'Registration failed. Please try again.'
      if (error.response?.status === 409) {
        errorMessage = error.response.data?.error || 'Email or username already exists'
      } else if (error.response?.status === 400) {
        errorMessage = error.response.data?.error || 'Invalid input data'
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error
      }

      toast.error(errorMessage)
      return { success: false, error: errorMessage }
    } finally {
      setIsLoading(false)
    }
  }

  const logout = async () => {
    try {
      setIsLoading(true)

      // Call logout endpoint to blacklist tokens
      await api.post('/api/auth/logout')

      setUser(null)
      setIsAuthenticated(false)
      toast.success('Logged out successfully')
    } catch (error) {
      if (error.response?.status !== 401) {
        console.error('Logout failed:', error)
      }
      // Even if logout API fails, clear local state
      setUser(null)
      setIsAuthenticated(false)
    } finally {
      setIsLoading(false)
    }
  }

  const refreshToken = async () => {
    try {
      const response = await api.post('/api/auth/refresh')

      if (response.data.message === 'Token refreshed successfully') {
        // Token refreshed successfully, cookies are updated automatically
        return true
      }

      return false
    } catch (error) {
      console.error('Token refresh failed:', error)
      return false
    }
  }

  const updateProfile = async (updates) => {
    try {
      setIsLoading(true)

      const response = await api.put('/api/user/profile', updates)

      if (response.data.user) {
        setUser(response.data.user)
        toast.success('Profile updated successfully!')
        return { success: true }
      }

      return { success: false, error: 'Profile update failed' }
    } catch (error) {
      console.error('Profile update failed:', error)

      const errorMessage = error.response?.data?.error || 'Profile update failed'
      toast.error(errorMessage)
      return { success: false, error: errorMessage }
    } finally {
      setIsLoading(false)
    }
  }

  // Auto-refresh token when it's about to expire
  useEffect(() => {
    if (!isAuthenticated) return

    const checkTokenExpiry = async () => {
      try {
        // Try to refresh token proactively
        await refreshToken()
      } catch (error) {
        console.error('Token refresh check failed:', error)
      }
    }

    // Check token expiry every 30 minutes
    const interval = setInterval(checkTokenExpiry, 30 * 60 * 1000)

    return () => clearInterval(interval)
  }, [isAuthenticated])

  const value = {
    user,
    isAuthenticated,
    isLoading,
    login,
    signup,
    logout,
    refreshToken,
    updateProfile,
    checkAuthStatus,
    api // Expose configured axios instance
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export default AuthContext
