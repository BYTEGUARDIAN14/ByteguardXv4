/**
 * ByteGuardX API Client
 * 
 * Main client class for interacting with the ByteGuardX API.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const FormData = require('form-data');

const { ScanConfig, ScanResult, ScanStatus, Vulnerability } = require('./models');
const {
  ByteGuardXError,
  AuthenticationError,
  ScanError,
  ConfigurationError,
  APIError
} = require('./exceptions');

/**
 * Main client for interacting with ByteGuardX API.
 * 
 * This client provides methods for scanning code, managing scans,
 * and retrieving security reports.
 */
class ByteGuardXClient {
  /**
   * Initialize the ByteGuardX client.
   * 
   * @param {Object} options - Configuration options
   * @param {string} [options.apiKey] - Your ByteGuardX API key (or set BYTEGUARDX_API_KEY env var)
   * @param {string} [options.apiUrl='https://api.byteguardx.com'] - ByteGuardX API base URL
   * @param {number} [options.timeout=30000] - Request timeout in milliseconds
   * @param {number} [options.maxRetries=3] - Maximum number of retry attempts
   * @param {boolean} [options.verifySsl=true] - Whether to verify SSL certificates
   */
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.BYTEGUARDX_API_KEY;
    if (!this.apiKey) {
      throw new ConfigurationError(
        'API key is required. Set BYTEGUARDX_API_KEY environment variable ' +
        'or pass apiKey in options.'
      );
    }
    
    this.apiUrl = (options.apiUrl || 'https://api.byteguardx.com').replace(/\/$/, '');
    this.timeout = options.timeout || 30000;
    this.maxRetries = options.maxRetries || 3;
    this.verifySsl = options.verifySsl !== false;
    
    // Parse API URL
    this.apiUrlParsed = new URL(this.apiUrl);
    this.isHttps = this.apiUrlParsed.protocol === 'https:';
    
    // Default headers
    this.defaultHeaders = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': 'ByteGuardX-JavaScript-SDK/1.0.0'
    };
  }
  
  /**
   * Make an HTTP request to the API.
   * 
   * @private
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint
   * @param {Object} [data] - Request data
   * @param {Object} [files] - Files to upload
   * @param {Object} [params] - Query parameters
   * @returns {Promise<Object>} Response data
   */
  async _makeRequest(method, endpoint, data = null, files = null, params = null) {
    const url = new URL(endpoint.replace(/^\//, ''), this.apiUrl);
    
    // Add query parameters
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== null && params[key] !== undefined) {
          url.searchParams.append(key, params[key]);
        }
      });
    }
    
    const options = {
      hostname: url.hostname,
      port: url.port || (this.isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: method.toUpperCase(),
      headers: { ...this.defaultHeaders },
      timeout: this.timeout,
      rejectUnauthorized: this.verifySsl
    };
    
    let requestData = null;
    
    if (files) {
      // Handle file uploads with FormData
      const form = new FormData();
      
      // Add regular data fields
      if (data) {
        Object.keys(data).forEach(key => {
          form.append(key, data[key]);
        });
      }
      
      // Add files
      Object.keys(files).forEach(key => {
        const file = files[key];
        if (typeof file === 'string') {
          // File path
          form.append(key, fs.createReadStream(file), path.basename(file));
        } else if (file.path && file.name) {
          // File object with path and name
          form.append(key, fs.createReadStream(file.path), file.name);
        } else {
          // Buffer or stream
          form.append(key, file);
        }
      });
      
      requestData = form;
      options.headers = {
        ...options.headers,
        ...form.getHeaders()
      };
      delete options.headers['Content-Type']; // Let FormData set it
    } else if (data) {
      requestData = JSON.stringify(data);
      options.headers['Content-Length'] = Buffer.byteLength(requestData);
    }
    
    return new Promise((resolve, reject) => {
      const httpModule = this.isHttps ? https : http;
      
      const req = httpModule.request(options, (res) => {
        let responseData = '';
        
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        
        res.on('end', () => {
          try {
            // Handle different response status codes
            if (res.statusCode === 401) {
              reject(new AuthenticationError('Invalid API key or authentication failed'));
              return;
            } else if (res.statusCode === 403) {
              reject(new AuthenticationError('Access forbidden - check your permissions'));
              return;
            } else if (res.statusCode === 429) {
              reject(new APIError('Rate limit exceeded - please try again later'));
              return;
            } else if (res.statusCode >= 400) {
              let errorMessage;
              try {
                const errorData = JSON.parse(responseData);
                errorMessage = errorData.error || `HTTP ${res.statusCode}`;
              } catch {
                errorMessage = `HTTP ${res.statusCode}: ${responseData}`;
              }
              reject(new APIError(errorMessage));
              return;
            }
            
            // Parse response
            const result = responseData ? JSON.parse(responseData) : {};
            resolve(result);
          } catch (error) {
            reject(new APIError(`Failed to parse response: ${error.message}`));
          }
        });
      });
      
      req.on('error', (error) => {
        if (error.code === 'ECONNREFUSED') {
          reject(new APIError(`Failed to connect to ${this.apiUrl}`));
        } else if (error.code === 'ETIMEDOUT') {
          reject(new APIError(`Request timeout after ${this.timeout}ms`));
        } else {
          reject(new APIError(`Request failed: ${error.message}`));
        }
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new APIError(`Request timeout after ${this.timeout}ms`));
      });
      
      // Send request data
      if (requestData) {
        if (requestData.pipe) {
          // Stream (FormData)
          requestData.pipe(req);
        } else {
          // String or Buffer
          req.write(requestData);
          req.end();
        }
      } else {
        req.end();
      }
    });
  }
  
  /**
   * Scan a directory for security vulnerabilities.
   * 
   * @param {string} directoryPath - Path to the directory to scan
   * @param {ScanConfig} [config] - Scan configuration options
   * @param {boolean} [waitForCompletion=true] - Whether to wait for scan completion
   * @returns {Promise<ScanResult>} ScanResult with the security findings
   */
  async scanDirectory(directoryPath, config = null, waitForCompletion = true) {
    if (!fs.existsSync(directoryPath)) {
      throw new ScanError(`Directory does not exist: ${directoryPath}`);
    }
    
    const stats = fs.statSync(directoryPath);
    if (!stats.isDirectory()) {
      throw new ScanError(`Path is not a directory: ${directoryPath}`);
    }
    
    // Create scan configuration
    if (!config) {
      config = new ScanConfig();
    }
    
    const scanData = {
      scan_type: 'directory',
      target_path: path.resolve(directoryPath),
      config: config.toDict()
    };
    
    // Start the scan
    const response = await this._makeRequest('POST', '/api/scans', scanData);
    const scanId = response.scan_id;
    
    if (waitForCompletion) {
      return await this._waitForScanCompletion(scanId);
    } else {
      return new ScanResult({ scanId, status: ScanStatus.RUNNING });
    }
  }
  
  /**
   * Scan a single file for security vulnerabilities.
   * 
   * @param {string} filePath - Path to the file to scan
   * @param {ScanConfig} [config] - Scan configuration options
   * @param {boolean} [waitForCompletion=true] - Whether to wait for scan completion
   * @returns {Promise<ScanResult>} ScanResult with the security findings
   */
  async scanFile(filePath, config = null, waitForCompletion = true) {
    if (!fs.existsSync(filePath)) {
      throw new ScanError(`File does not exist: ${filePath}`);
    }
    
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) {
      throw new ScanError(`Path is not a file: ${filePath}`);
    }
    
    // Upload and scan file
    const files = {
      file: filePath
    };
    
    const scanData = {
      scan_type: 'file',
      config: JSON.stringify(config ? config.toDict() : {})
    };
    
    const response = await this._makeRequest(
      'POST', '/api/scans/upload',
      scanData, files
    );
    
    const scanId = response.scan_id;
    
    if (waitForCompletion) {
      return await this._waitForScanCompletion(scanId);
    } else {
      return new ScanResult({ scanId, status: ScanStatus.RUNNING });
    }
  }
  
  /**
   * Perform a quick security scan with default settings.
   * 
   * @param {string} targetPath - Path to file or directory to scan
   * @param {Object} [options] - Additional scan options
   * @returns {Promise<ScanResult>} ScanResult with the security findings
   */
  async quickScan(targetPath, options = {}) {
    const config = new ScanConfig({
      scanSecrets: true,
      scanVulnerabilities: true,
      scanDependencies: false,
      maxFileSizeMb: 10
    });
    
    const stats = fs.statSync(targetPath);
    if (stats.isDirectory()) {
      return await this.scanDirectory(targetPath, config, options.waitForCompletion);
    } else {
      return await this.scanFile(targetPath, config, options.waitForCompletion);
    }
  }
  
  /**
   * Get the current status of a scan.
   * 
   * @param {string} scanId - Scan ID
   * @returns {Promise<ScanStatus>} Current scan status
   */
  async getScanStatus(scanId) {
    const response = await this._makeRequest('GET', `/api/scans/${scanId}/status`);
    return new ScanStatus(response.status);
  }
  
  /**
   * Get the complete results of a scan.
   * 
   * @param {string} scanId - Scan ID
   * @returns {Promise<ScanResult>} Complete scan results
   */
  async getScanResult(scanId) {
    const response = await this._makeRequest('GET', `/api/scans/${scanId}`);
    return ScanResult.fromDict(response);
  }
  
  /**
   * List recent scans.
   * 
   * @param {Object} [options] - List options
   * @param {number} [options.limit=50] - Maximum number of scans to return
   * @param {number} [options.offset=0] - Number of scans to skip
   * @param {ScanStatus} [options.status] - Filter by scan status
   * @returns {Promise<Array>} List of scan summaries
   */
  async listScans(options = {}) {
    const params = {
      limit: options.limit || 50,
      offset: options.offset || 0
    };
    
    if (options.status) {
      params.status = options.status.value || options.status;
    }
    
    const response = await this._makeRequest('GET', '/api/scans', null, null, params);
    return response.scans;
  }
  
  /**
   * Delete a scan and its results.
   * 
   * @param {string} scanId - Scan ID
   * @returns {Promise<boolean>} True if successful
   */
  async deleteScan(scanId) {
    await this._makeRequest('DELETE', `/api/scans/${scanId}`);
    return true;
  }
  
  /**
   * Export a scan report in the specified format.
   * 
   * @param {string} scanId - ID of the scan to export
   * @param {string} [format='json'] - Report format ('json', 'pdf', 'html', 'csv')
   * @param {boolean} [includeDetails=true] - Whether to include detailed vulnerability information
   * @returns {Promise<Buffer>} Report data as Buffer
   */
  async exportReport(scanId, format = 'json', includeDetails = true) {
    const params = {
      format,
      include_details: includeDetails
    };
    
    // This would need special handling for binary responses
    // For now, return the response as-is
    const response = await this._makeRequest(
      'GET', `/api/scans/${scanId}/export`,
      null, null, params
    );
    
    return Buffer.from(JSON.stringify(response));
  }
  
  /**
   * Wait for a scan to complete and return the results.
   * 
   * @private
   * @param {string} scanId - Scan ID
   * @param {number} [pollInterval=5000] - Polling interval in milliseconds
   * @param {number} [maxWaitTime=3600000] - Maximum wait time in milliseconds
   * @returns {Promise<ScanResult>} Complete scan results
   */
  async _waitForScanCompletion(scanId, pollInterval = 5000, maxWaitTime = 3600000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      const status = await this.getScanStatus(scanId);
      
      if ([ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED].includes(status)) {
        return await this.getScanResult(scanId);
      }
      
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
    
    throw new ScanError(`Scan ${scanId} did not complete within ${maxWaitTime}ms`);
  }
  
  /**
   * Check the health of the ByteGuardX API.
   * 
   * @returns {Promise<Object>} Health check response
   */
  async healthCheck() {
    return await this._makeRequest('GET', '/health');
  }
  
  /**
   * Get information about your ByteGuardX account.
   * 
   * @returns {Promise<Object>} Account information
   */
  async getAccountInfo() {
    return await this._makeRequest('GET', '/api/account');
  }
  
  /**
   * Close any open connections.
   */
  close() {
    // No persistent connections to close in this implementation
  }
}

module.exports = ByteGuardXClient;
