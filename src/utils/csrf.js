/**
 * CSRF Token Management Utility
 * Handles CSRF token retrieval and inclusion in requests
 */

class CSRFManager {
  constructor() {
    this.token = null;
    this.tokenExpiry = null;
  }

  /**
   * Get CSRF token from cookie
   */
  getTokenFromCookie() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  /**
   * Fetch CSRF token from server
   */
  async fetchToken() {
    try {
      const response = await fetch('/api/csrf-token', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
        }
      });

      if (response.ok) {
        const data = await response.json();
        this.token = data.csrf_token;
        this.tokenExpiry = Date.now() + (55 * 60 * 1000); // 55 minutes
        
        console.log('CSRF token fetched successfully');
        return this.token;
      } else {
        console.error('Failed to fetch CSRF token:', response.status);
        return null;
      }
    } catch (error) {
      console.error('Error fetching CSRF token:', error);
      return null;
    }
  }

  /**
   * Get valid CSRF token (fetch if needed)
   */
  async getToken() {
    // Check if we have a valid cached token
    if (this.token && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      return this.token;
    }

    // Try to get token from cookie first
    const cookieToken = this.getTokenFromCookie();
    if (cookieToken) {
      this.token = cookieToken;
      this.tokenExpiry = Date.now() + (55 * 60 * 1000);
      return cookieToken;
    }

    // Fetch new token from server
    return await this.fetchToken();
  }

  /**
   * Add CSRF token to request headers
   */
  async addTokenToHeaders(headers = {}) {
    const token = await this.getToken();
    if (token) {
      headers['X-CSRFToken'] = token;
      headers['X-CSRF-Token'] = token; // Alternative header name
    }
    return headers;
  }

  /**
   * Add CSRF token to form data
   */
  async addTokenToFormData(formData) {
    const token = await this.getToken();
    if (token) {
      if (formData instanceof FormData) {
        formData.append('csrf_token', token);
      } else if (typeof formData === 'object') {
        formData.csrf_token = token;
      }
    }
    return formData;
  }

  /**
   * Create a fetch wrapper with automatic CSRF token inclusion
   */
  async fetch(url, options = {}) {
    // Ensure credentials are included
    options.credentials = options.credentials || 'include';

    // Add CSRF token to headers for non-GET requests
    if (!options.method || options.method.toUpperCase() !== 'GET') {
      options.headers = await this.addTokenToHeaders(options.headers || {});
    }

    // If body is FormData or URLSearchParams, add token there too
    if (options.body) {
      if (options.body instanceof FormData) {
        await this.addTokenToFormData(options.body);
      } else if (options.body instanceof URLSearchParams) {
        const token = await this.getToken();
        if (token) {
          options.body.append('csrf_token', token);
        }
      } else if (typeof options.body === 'string') {
        try {
          const bodyData = JSON.parse(options.body);
          const token = await this.getToken();
          if (token) {
            bodyData.csrf_token = token;
            options.body = JSON.stringify(bodyData);
          }
        } catch (e) {
          // Body is not JSON, skip token addition
        }
      }
    }

    return fetch(url, options);
  }

  /**
   * Initialize CSRF protection for the application
   */
  async initialize() {
    try {
      // Fetch initial token
      await this.getToken();
      
      // Set up automatic token refresh
      setInterval(async () => {
        if (this.tokenExpiry && Date.now() > (this.tokenExpiry - 5 * 60 * 1000)) {
          console.log('Refreshing CSRF token...');
          await this.fetchToken();
        }
      }, 5 * 60 * 1000); // Check every 5 minutes

      console.log('CSRF protection initialized');
      return true;
    } catch (error) {
      console.error('Failed to initialize CSRF protection:', error);
      return false;
    }
  }

  /**
   * Clear cached token (useful for logout)
   */
  clearToken() {
    this.token = null;
    this.tokenExpiry = null;
    
    // Clear cookie
    document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  }
}

// Create global instance
const csrfManager = new CSRFManager();

// Export for use in other modules
export default csrfManager;

// Also export the class for custom instances
export { CSRFManager };

// Utility functions for easy use
export const getCSRFToken = () => csrfManager.getToken();
export const csrfFetch = (url, options) => csrfManager.fetch(url, options);
export const addCSRFToHeaders = (headers) => csrfManager.addTokenToHeaders(headers);
export const addCSRFToFormData = (formData) => csrfManager.addTokenToFormData(formData);

// Auto-initialize when module is loaded
if (typeof window !== 'undefined') {
  // Initialize after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      csrfManager.initialize();
    });
  } else {
    csrfManager.initialize();
  }
}

// Intercept form submissions to add CSRF tokens
if (typeof window !== 'undefined') {
  document.addEventListener('submit', async (event) => {
    const form = event.target;
    
    // Skip if form already has CSRF token
    if (form.querySelector('input[name="csrf_token"]')) {
      return;
    }

    // Add CSRF token to form
    const token = await csrfManager.getToken();
    if (token) {
      const tokenInput = document.createElement('input');
      tokenInput.type = 'hidden';
      tokenInput.name = 'csrf_token';
      tokenInput.value = token;
      form.appendChild(tokenInput);
    }
  });
}

// Intercept XMLHttpRequest to add CSRF tokens
if (typeof window !== 'undefined') {
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._method = method;
    this._url = url;
    return originalOpen.call(this, method, url, ...args);
  };

  XMLHttpRequest.prototype.send = async function(data) {
    // Add CSRF token for non-GET requests
    if (this._method && this._method.toUpperCase() !== 'GET') {
      const token = await csrfManager.getToken();
      if (token) {
        this.setRequestHeader('X-CSRFToken', token);
      }
    }
    
    return originalSend.call(this, data);
  };
}
