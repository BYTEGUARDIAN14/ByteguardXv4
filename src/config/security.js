// Security configuration for ByteGuardX
export const SECURITY_CONFIG = {
  // API Configuration
  API: {
    BASE_URL: import.meta.env.VITE_API_URL || 'http://localhost:5000',
    TIMEOUT: 30000,
    MAX_RETRIES: 3,
    RETRY_DELAY: 1000,
  },

  // File Upload Security
  FILE_UPLOAD: {
    MAX_SIZE: 10 * 1024 * 1024, // 10MB
    ALLOWED_EXTENSIONS: [
      'py', 'js', 'jsx', 'ts', 'tsx', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb',
      'go', 'rs', 'swift', 'kt', 'scala', 'json', 'xml', 'yml', 'yaml', 'txt',
      'md', 'rst', 'dockerfile', 'sh', 'bat', 'ps1', 'sql', 'html', 'css', 'scss'
    ],
    ALLOWED_MIME_TYPES: [
      'text/plain', 'text/javascript', 'text/x-python', 'text/x-java-source',
      'text/x-c', 'text/x-c++', 'text/x-csharp', 'text/x-php', 'text/x-ruby',
      'text/x-go', 'text/x-rust', 'text/x-swift', 'text/x-kotlin', 'text/x-scala',
      'application/json', 'application/xml', 'text/yaml', 'text/html', 'text/css'
    ]
  },

  // Authentication Security
  AUTH: {
    TOKEN_STORAGE_KEY: 'auth_token',
    REFRESH_TOKEN_KEY: 'refresh_token',
    USER_STORAGE_KEY: 'user',
    CSRF_TOKEN_KEY: 'csrf_token',
    CSRF_EXPIRY_KEY: 'csrf_token_expiry',
    SESSION_TIMEOUT: 3600000, // 1 hour
    REFRESH_THRESHOLD: 300000, // 5 minutes before expiry
  },

  // Input Validation
  VALIDATION: {
    EMAIL_REGEX: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    USERNAME_REGEX: /^[a-zA-Z0-9_]{3,20}$/,
    PASSWORD_MIN_LENGTH: 8,
    PASSWORD_REGEX: {
      UPPERCASE: /[A-Z]/,
      LOWERCASE: /[a-z]/,
      DIGIT: /\d/,
      SPECIAL: /[!@#$%^&*(),.?":{}|<>]/
    }
  },

  // Content Security Policy
  CSP: {
    ALLOWED_ORIGINS: [
      'http://localhost:3000',
      'http://localhost:5000',
      'https://your-domain.com'
    ],
    BLOCKED_PATTERNS: [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi
    ]
  },

  // Rate Limiting
  RATE_LIMITS: {
    LOGIN_ATTEMPTS: 5,
    REGISTRATION_ATTEMPTS: 3,
    SCAN_REQUESTS: 10,
    API_REQUESTS: 100,
    TIME_WINDOW: 60000 // 1 minute
  },

  // Error Handling
  ERROR_HANDLING: {
    SENSITIVE_FIELDS: ['password', 'token', 'secret', 'key', 'auth'],
    MAX_ERROR_LENGTH: 500,
    ENABLE_STACK_TRACE: import.meta.env.DEV,
    LOG_ERRORS: true
  }
}

// Security utility functions
export const SecurityUtils = {
  // Sanitize user input
  sanitizeInput: (input) => {
    if (typeof input !== 'string') return input
    
    // Remove HTML tags and dangerous characters
    return input
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/[<>'"&]/g, '') // Remove dangerous characters
      .trim()
  },

  // Validate email format
  validateEmail: (email) => {
    return SECURITY_CONFIG.VALIDATION.EMAIL_REGEX.test(email)
  },

  // Validate password strength
  validatePassword: (password) => {
    const { PASSWORD_MIN_LENGTH, PASSWORD_REGEX } = SECURITY_CONFIG.VALIDATION
    
    if (password.length < PASSWORD_MIN_LENGTH) {
      return { valid: false, message: `Password must be at least ${PASSWORD_MIN_LENGTH} characters long` }
    }
    
    if (!PASSWORD_REGEX.UPPERCASE.test(password)) {
      return { valid: false, message: 'Password must contain at least one uppercase letter' }
    }
    
    if (!PASSWORD_REGEX.LOWERCASE.test(password)) {
      return { valid: false, message: 'Password must contain at least one lowercase letter' }
    }
    
    if (!PASSWORD_REGEX.DIGIT.test(password)) {
      return { valid: false, message: 'Password must contain at least one digit' }
    }
    
    return { valid: true, message: 'Password is valid' }
  },

  // Validate file upload
  validateFile: (file) => {
    const { MAX_SIZE, ALLOWED_EXTENSIONS } = SECURITY_CONFIG.FILE_UPLOAD
    
    // Check file size
    if (file.size > MAX_SIZE) {
      return { valid: false, message: `File size must be less than ${MAX_SIZE / (1024 * 1024)}MB` }
    }
    
    // Check file extension
    const extension = file.name.split('.').pop()?.toLowerCase()
    if (!extension || !ALLOWED_EXTENSIONS.includes(extension)) {
      return { valid: false, message: 'File type not supported' }
    }
    
    return { valid: true, message: 'File is valid' }
  },

  // Generate secure headers
  getSecureHeaders: () => {
    return {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
  },

  // Check if content contains malicious patterns
  containsMaliciousContent: (content) => {
    return SECURITY_CONFIG.CSP.BLOCKED_PATTERNS.some(pattern => pattern.test(content))
  },

  // Generate unique request ID for tracking
  generateRequestId: () => {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  },

  // Sanitize error messages
  sanitizeError: (error) => {
    const { SENSITIVE_FIELDS, MAX_ERROR_LENGTH } = SECURITY_CONFIG.ERROR_HANDLING
    
    let message = error.message || 'An error occurred'
    
    // Remove sensitive information
    SENSITIVE_FIELDS.forEach(field => {
      const regex = new RegExp(`${field}[\\s]*[:=][\\s]*[^\\s]+`, 'gi')
      message = message.replace(regex, `${field}: [REDACTED]`)
    })
    
    // Limit error message length
    if (message.length > MAX_ERROR_LENGTH) {
      message = message.substring(0, MAX_ERROR_LENGTH) + '...'
    }
    
    return message
  },

  // Check if token is expired
  isTokenExpired: (token) => {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      return Date.now() >= payload.exp * 1000
    } catch {
      return true
    }
  },

  // Secure local storage operations
  secureStorage: {
    set: (key, value) => {
      try {
        const encrypted = btoa(JSON.stringify(value))
        localStorage.setItem(key, encrypted)
      } catch (error) {
        console.error('Failed to store data securely:', error)
      }
    },
    
    get: (key) => {
      try {
        const encrypted = localStorage.getItem(key)
        if (!encrypted) return null
        return JSON.parse(atob(encrypted))
      } catch (error) {
        console.error('Failed to retrieve data securely:', error)
        return null
      }
    },
    
    remove: (key) => {
      localStorage.removeItem(key)
    },
    
    clear: () => {
      const { AUTH } = SECURITY_CONFIG
      Object.values(AUTH).forEach(key => {
        if (typeof key === 'string') {
          localStorage.removeItem(key)
        }
      })
    }
  }
}

export default SECURITY_CONFIG
