/**
 * Frontend Security Utilities for ByteGuardX Portal
 */

// Input sanitization
export const sanitizeInput = (input: string): string => {
  return input
    .replace(/[<>]/g, '') // Remove potential HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .trim();
};

// XSS Prevention
export const escapeHtml = (unsafe: string): string => {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

// URL validation
export const isValidUrl = (url: string): boolean => {
  try {
    const urlObj = new URL(url);
    return ['http:', 'https:'].includes(urlObj.protocol);
  } catch {
    return false;
  }
};

// Safe external link handler
export const openExternalLink = (url: string): void => {
  if (isValidUrl(url)) {
    const newWindow = window.open();
    if (newWindow) {
      newWindow.opener = null; // Prevent window.opener attacks
      newWindow.location.href = url;
    }
  }
};

// Content Security Policy violation handler
export const handleCSPViolation = (event: SecurityPolicyViolationEvent): void => {
  console.warn('CSP Violation:', {
    blockedURI: event.blockedURI,
    violatedDirective: event.violatedDirective,
    originalPolicy: event.originalPolicy,
    documentURI: event.documentURI
  });
  
  // Report to security monitoring (implement your reporting logic)
  // reportSecurityViolation(event);
};

// File upload security
export const validateFileUpload = (file: File): { valid: boolean; error?: string } => {
  const maxSize = 5 * 1024 * 1024; // 5MB
  const allowedTypes = ['image/jpeg', 'image/png', 'image/svg+xml', 'application/pdf'];
  
  if (file.size > maxSize) {
    return { valid: false, error: 'File size exceeds 5MB limit' };
  }
  
  if (!allowedTypes.includes(file.type)) {
    return { valid: false, error: 'File type not allowed' };
  }
  
  // Check file extension matches MIME type
  const extension = file.name.split('.').pop()?.toLowerCase();
  const mimeToExt: Record<string, string[]> = {
    'image/jpeg': ['jpg', 'jpeg'],
    'image/png': ['png'],
    'image/svg+xml': ['svg'],
    'application/pdf': ['pdf']
  };
  
  const expectedExtensions = mimeToExt[file.type];
  if (!expectedExtensions || !extension || !expectedExtensions.includes(extension)) {
    return { valid: false, error: 'File extension does not match content type' };
  }
  
  return { valid: true };
};

// Local storage security
export const secureStorage = {
  set: (key: string, value: any): void => {
    try {
      const encrypted = btoa(JSON.stringify(value)); // Basic encoding (use proper encryption in production)
      localStorage.setItem(`byteguardx_${key}`, encrypted);
    } catch (error) {
      console.error('Failed to store data securely:', error);
    }
  },
  
  get: (key: string): any => {
    try {
      const encrypted = localStorage.getItem(`byteguardx_${key}`);
      if (!encrypted) return null;
      return JSON.parse(atob(encrypted));
    } catch (error) {
      console.error('Failed to retrieve data securely:', error);
      return null;
    }
  },
  
  remove: (key: string): void => {
    localStorage.removeItem(`byteguardx_${key}`);
  },
  
  clear: (): void => {
    Object.keys(localStorage)
      .filter(key => key.startsWith('byteguardx_'))
      .forEach(key => localStorage.removeItem(key));
  }
};

// API request security
export const secureApiRequest = async (url: string, options: RequestInit = {}): Promise<Response> => {
  // Add security headers
  const secureOptions: RequestInit = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...options.headers
    },
    credentials: 'same-origin' // Prevent CSRF
  };
  
  // Validate URL
  if (!isValidUrl(url)) {
    throw new Error('Invalid URL provided');
  }
  
  return fetch(url, secureOptions);
};

// Rate limiting for client-side actions
class RateLimiter {
  private attempts: Map<string, number[]> = new Map();
  
  isAllowed(key: string, maxAttempts: number = 5, windowMs: number = 60000): boolean {
    const now = Date.now();
    const attempts = this.attempts.get(key) || [];
    
    // Remove old attempts outside the window
    const validAttempts = attempts.filter(time => now - time < windowMs);
    
    if (validAttempts.length >= maxAttempts) {
      return false;
    }
    
    validAttempts.push(now);
    this.attempts.set(key, validAttempts);
    return true;
  }
  
  reset(key: string): void {
    this.attempts.delete(key);
  }
}

export const rateLimiter = new RateLimiter();

// Initialize security measures
export const initializeSecurity = (): void => {
  // Add CSP violation listener
  document.addEventListener('securitypolicyviolation', handleCSPViolation);
  
  // Disable right-click in production (optional)
  if (process.env.NODE_ENV === 'production') {
    document.addEventListener('contextmenu', (e) => e.preventDefault());
  }
  
  // Clear sensitive data on page unload
  window.addEventListener('beforeunload', () => {
    // Clear any sensitive data from memory
    secureStorage.clear();
  });
  
  console.log('🔒 ByteGuardX Security measures initialized');
};
