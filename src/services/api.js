import axios from 'axios'
import toast from 'react-hot-toast'

// Create axios instance with default config
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || (import.meta.env.PROD ? 'https://your-flask-backend.herokuapp.com' : 'http://localhost:5000'),
  timeout: 30000, // 30 seconds
  withCredentials: true, // Important for cookies and CORS
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor for auth tokens and CSRF with enhanced security
api.interceptors.request.use(
  async (config) => {
    // Add security headers
    config.headers['X-Requested-With'] = 'XMLHttpRequest'

    // Add auth token if available
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }

    // Add CSRF token for state-changing requests
    if (['post', 'put', 'delete', 'patch'].includes(config.method?.toLowerCase())) {
      try {
        let csrfToken = localStorage.getItem('csrf_token')

        // Validate CSRF token expiry
        const csrfExpiry = localStorage.getItem('csrf_token_expiry')
        if (csrfExpiry && Date.now() > parseInt(csrfExpiry)) {
          localStorage.removeItem('csrf_token')
          localStorage.removeItem('csrf_token_expiry')
          csrfToken = null
        }

        if (csrfToken) {
          config.headers['X-CSRF-Token'] = csrfToken
        } else {
          // Fetch new CSRF token
          const csrfResponse = await fetch(`${config.baseURL}/api/auth/csrf-token`, {
            credentials: 'include'
          })
          if (csrfResponse.ok) {
            const csrfData = await csrfResponse.json()
            localStorage.setItem('csrf_token', csrfData.csrf_token)
            localStorage.setItem('csrf_token_expiry', (Date.now() + 3600000).toString()) // 1 hour
            config.headers['X-CSRF-Token'] = csrfData.csrf_token
          }
        }
      } catch (error) {
        console.warn('Failed to get CSRF token:', error)
      }
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling with enhanced security
api.interceptors.response.use(
  (response) => {
    // Validate response structure
    if (response && response.data) {
      return response.data
    }
    return response
  },
  async (error) => {
    const originalRequest = error.config

    // Handle token refresh for 401 errors
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshToken = localStorage.getItem('refresh_token')
        if (refreshToken) {
          const response = await fetch(`${api.defaults.baseURL}/api/auth/refresh`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ refresh_token: refreshToken })
          })

          if (response.ok) {
            const data = await response.json()
            localStorage.setItem('auth_token', data.access_token)
            if (data.refresh_token) {
              localStorage.setItem('refresh_token', data.refresh_token)
            }

            // Retry original request
            originalRequest.headers.Authorization = `Bearer ${data.access_token}`
            return api(originalRequest)
          }
        }

        // Refresh failed, clear tokens and redirect to login
        localStorage.removeItem('auth_token')
        localStorage.removeItem('refresh_token')
        localStorage.removeItem('user')
        localStorage.removeItem('csrf_token')
        localStorage.removeItem('csrf_token_expiry')

        if (window.location.pathname !== '/login') {
          window.location.href = '/login'
        }
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError)
      }
    }

    // Sanitize error message to prevent XSS
    const message = error.response?.data?.error || error.message || 'An error occurred'
    const sanitizedMessage = message.replace(/<[^>]*>/g, '') // Remove HTML tags

    // Don't show toast for certain errors (let components handle them)
    const silentErrors = [401, 404, 403]
    if (!silentErrors.includes(error.response?.status)) {
      toast.error(sanitizedMessage)
    }

    return Promise.reject(new Error(sanitizedMessage))
  }
)

// Auth service with enhanced security
export const authService = {
  async login(credentials) {
    const response = await api.post('/api/auth/login', credentials)
    if (response.access_token) {
      localStorage.setItem('auth_token', response.access_token)
      localStorage.setItem('user', JSON.stringify(response.user))

      // Store refresh token if provided
      if (response.refresh_token) {
        localStorage.setItem('refresh_token', response.refresh_token)
      }
    }
    return response
  },

  async refreshToken() {
    try {
      const refreshToken = localStorage.getItem('refresh_token')
      if (!refreshToken) {
        throw new Error('No refresh token available')
      }

      const response = await api.post('/api/auth/refresh', {
        refresh_token: refreshToken
      })

      if (response.access_token) {
        localStorage.setItem('auth_token', response.access_token)
        if (response.refresh_token) {
          localStorage.setItem('refresh_token', response.refresh_token)
        }
        return response
      }
    } catch (error) {
      // If refresh fails, logout user
      this.logout()
      throw error
    }
  },

  logout() {
    localStorage.removeItem('auth_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('user')
    localStorage.removeItem('csrf_token')
  },

  getCurrentUser() {
    const user = localStorage.getItem('user')
    return user ? JSON.parse(user) : null
  },

  isAuthenticated() {
    return !!localStorage.getItem('auth_token')
  },

  async verifyToken() {
    try {
      const response = await api.get('/api/auth/verify')
      return response.valid
    } catch (error) {
      return false
    }
  }
}

// Scan service
export const scanService = {
  // Upload files for scanning
  async uploadFiles(formData) {
    const response = await api.post('/scan/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      timeout: 60000, // 1 minute for file uploads
    })
    return response
  },

  // Scan directory path
  async scanDirectory(directoryPath) {
    const response = await api.post('/scan/directory', {
      path: directoryPath
    })
    return response
  },

  // Scan for secrets only
  async scanSecrets(scanId) {
    const response = await api.post('/scan/secrets', {
      scan_id: scanId
    })
    return response
  },

  // Scan for dependencies only
  async scanDependencies(scanId) {
    const response = await api.post('/scan/dependencies', {
      scan_id: scanId
    })
    return response
  },

  // Scan for AI patterns only
  async scanAIPatterns(scanId) {
    const response = await api.post('/scan/ai-patterns', {
      scan_id: scanId
    })
    return response
  },

  // Comprehensive scan (all types)
  async scanAll(scanId) {
    const response = await api.post('/scan/all', {
      scan_id: scanId
    })
    return response
  },

  // Get scan results by ID
  async getScanResults(scanId) {
    const response = await api.get(`/scan/results/${scanId}`)
    return response
  },

  // List all scans
  async listScans() {
    const response = await api.get('/scan/list')
    return response
  }
}

// Fix service
export const fixService = {
  // Generate bulk fixes
  async generateBulkFixes(findings) {
    const response = await api.post('/fix/bulk', {
      findings
    })
    return response
  }
}

// Report service
export const reportService = {
  // Generate PDF report
  async generatePDFReport(scanId) {
    const response = await api.post('/report/pdf', {
      scan_id: scanId
    })
    return response
  },

  // Download report file
  async downloadReport(filename) {
    const response = await api.get(`/report/download/${filename}`, {
      responseType: 'blob'
    })
    return response
  }
}

// Health check
export const healthService = {
  async checkHealth() {
    const response = await api.get('/health')
    return response
  }
}

// Utility functions
export const apiUtils = {
  // Check if API is available
  async isApiAvailable() {
    try {
      await healthService.checkHealth()
      return true
    } catch (error) {
      return false
    }
  },

  // Format file size
  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  },

  // Format date
  formatDate(dateString) {
    return new Date(dateString).toLocaleString()
  },

  // Get severity color
  getSeverityColor(severity) {
    const colors = {
      critical: 'text-red-400',
      high: 'text-orange-400',
      medium: 'text-yellow-400',
      low: 'text-green-400'
    }
    return colors[severity?.toLowerCase()] || 'text-gray-400'
  }
}

// Export combined service
export default {
  auth: authService,
  scan: scanService,
  fix: fixService,
  report: reportService,
  health: healthService,
  utils: apiUtils
}
