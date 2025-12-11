// Frontend Security Configuration for ByteGuardX Portal
module.exports = {
  // Content Security Policy
  csp: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Required for Vite dev mode
        "https://vercel.live",
        "https://vitals.vercel-insights.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'", // Required for styled-components/CSS-in-JS
        "https://fonts.googleapis.com"
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "data:"
      ],
      imgSrc: [
        "'self'",
        "data:",
        "https:",
        "blob:"
      ],
      connectSrc: [
        "'self'",
        "https://api.byteguardx.com", // Your API endpoint
        "https://vercel.live",
        "https://vitals.vercel-insights.com",
        "wss://ws.byteguardx.com" // WebSocket if needed
      ],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      manifestSrc: ["'self'"],
      workerSrc: ["'self'", "blob:"],
      upgradeInsecureRequests: []
    }
  },

  // Security Headers
  headers: {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
  },

  // Allowed domains for external resources
  allowedDomains: [
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'api.byteguardx.com',
    'vercel.live',
    'vitals.vercel-insights.com'
  ],

  // File upload restrictions
  upload: {
    maxFileSize: '5MB',
    allowedTypes: ['.jpg', '.jpeg', '.png', '.svg', '.pdf'],
    scanForMalware: true,
    quarantinePath: '/tmp/quarantine'
  },

  // API security settings
  api: {
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100 // limit each IP to 100 requests per windowMs
    },
    cors: {
      origin: [
        'https://byteguardx.com',
        'https://www.byteguardx.com',
        'https://portal.byteguardx.com'
      ],
      credentials: true,
      optionsSuccessStatus: 200
    }
  },

  // Development security settings
  development: {
    allowHotReload: true,
    allowSourceMaps: true,
    logSecurityWarnings: true,
    strictMode: false // More lenient for dev
  },

  // Production security settings
  production: {
    allowHotReload: false,
    allowSourceMaps: false,
    logSecurityWarnings: false,
    strictMode: true,
    minifyOutput: true,
    removeConsole: true
  }
};
