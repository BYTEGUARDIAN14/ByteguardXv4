import axios from 'axios'
import toast from 'react-hot-toast'

// Create axios instance with default config
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || (import.meta.env.PROD ? 'https://your-flask-backend.herokuapp.com' : 'http://localhost:5000'),
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
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

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response.data
  },
  (error) => {
    const message = error.response?.data?.error || error.message || 'An error occurred'
    
    // Don't show toast for certain errors (let components handle them)
    const silentErrors = [401, 404]
    if (!silentErrors.includes(error.response?.status)) {
      toast.error(message)
    }
    
    return Promise.reject(new Error(message))
  }
)

// Auth service
export const authService = {
  async login(credentials) {
    const response = await api.post('/auth/login', credentials)
    if (response.access_token) {
      localStorage.setItem('auth_token', response.access_token)
      localStorage.setItem('user', JSON.stringify(response.user))
    }
    return response
  },

  logout() {
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user')
  },

  getCurrentUser() {
    const user = localStorage.getItem('user')
    return user ? JSON.parse(user) : null
  },

  isAuthenticated() {
    return !!localStorage.getItem('auth_token')
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
