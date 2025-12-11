/**
 * ByteGuardX JavaScript SDK
 * 
 * A comprehensive JavaScript/Node.js SDK for integrating ByteGuardX 
 * security scanning capabilities into your applications and CI/CD pipelines.
 */

const ByteGuardXClient = require('./client');
const SecurityScanner = require('./scanner');
const {
  ScanConfig,
  ScanResult,
  Vulnerability,
  SecurityIssue,
  ScanStatus,
  SeverityLevel
} = require('./models');
const {
  ByteGuardXError,
  AuthenticationError,
  ScanError,
  ConfigurationError,
  APIError
} = require('./exceptions');

// Package metadata
const packageInfo = require('../package.json');

// Default configuration
const DEFAULT_API_URL = 'https://api.byteguardx.com';
const DEFAULT_TIMEOUT = 30000;
const DEFAULT_MAX_RETRIES = 3;

/**
 * Create a ByteGuardX client with the given API key.
 * 
 * @param {string} apiKey - Your ByteGuardX API key
 * @param {string} [apiUrl] - Optional custom API URL (defaults to production)
 * @param {Object} [options] - Additional client configuration options
 * @returns {ByteGuardXClient} Configured ByteGuardXClient instance
 * 
 * @example
 * const byteguardx = require('byteguardx-sdk');
 * const client = byteguardx.createClient('your-api-key');
 * const result = await client.scanDirectory('/path/to/code');
 */
function createClient(apiKey, apiUrl = null, options = {}) {
  return new ByteGuardXClient({
    apiKey,
    apiUrl: apiUrl || DEFAULT_API_URL,
    timeout: DEFAULT_TIMEOUT,
    maxRetries: DEFAULT_MAX_RETRIES,
    ...options
  });
}

/**
 * Perform a quick security scan on the specified path.
 * 
 * @param {string} path - Path to file or directory to scan
 * @param {string} [apiKey] - ByteGuardX API key (can also be set via environment variable)
 * @param {Object} [options] - Additional scan configuration options
 * @returns {Promise<ScanResult>} ScanResult containing the security findings
 * 
 * @example
 * const byteguardx = require('byteguardx-sdk');
 * const result = await byteguardx.quickScan('/path/to/code', 'your-api-key');
 * console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
 */
async function quickScan(path, apiKey = null, options = {}) {
  const client = createClient(apiKey);
  try {
    return await client.quickScan(path, options);
  } finally {
    client.close();
  }
}

/**
 * Check the current SDK version and compare with latest available.
 * 
 * @returns {Promise<Object>} Object with version information
 */
async function checkVersion() {
  try {
    const https = require('https');
    const url = 'https://registry.npmjs.org/byteguardx-sdk/latest';
    
    return new Promise((resolve) => {
      https.get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try {
            const packageData = JSON.parse(data);
            const latestVersion = packageData.version;
            resolve({
              current: packageInfo.version,
              latest: latestVersion,
              updateAvailable: packageInfo.version !== latestVersion
            });
          } catch (error) {
            resolve({
              current: packageInfo.version,
              latest: 'unknown',
              updateAvailable: false
            });
          }
        });
      }).on('error', () => {
        resolve({
          current: packageInfo.version,
          latest: 'unknown',
          updateAvailable: false
        });
      });
    });
  } catch (error) {
    return {
      current: packageInfo.version,
      latest: 'unknown',
      updateAvailable: false
    };
  }
}

// Main exports
module.exports = {
  // Main classes
  ByteGuardXClient,
  SecurityScanner,
  Client: ByteGuardXClient, // Alias
  Scanner: SecurityScanner, // Alias
  
  // Models
  ScanConfig,
  ScanResult,
  Vulnerability,
  SecurityIssue,
  ScanStatus,
  SeverityLevel,
  
  // Exceptions
  ByteGuardXError,
  AuthenticationError,
  ScanError,
  ConfigurationError,
  APIError,
  
  // Utility functions
  createClient,
  quickScan,
  checkVersion,
  
  // Constants
  DEFAULT_API_URL,
  DEFAULT_TIMEOUT,
  DEFAULT_MAX_RETRIES,
  
  // Metadata
  version: packageInfo.version,
  author: packageInfo.author,
  homepage: packageInfo.homepage
};

// ES6 module compatibility
module.exports.default = module.exports;
