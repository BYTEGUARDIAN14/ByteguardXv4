/**
 * ByteGuardX - Tauri API Service
 * 
 * This module provides a unified API interface that works in both
 * Tauri desktop mode and web/Electron fallback mode.
 * 
 * In Tauri mode, it uses the Tauri invoke() API for IPC.
 * In web mode, it falls back to HTTP requests.
 */

// Check if running in Tauri
const isTauri = typeof window !== 'undefined' && window.__TAURI__ !== undefined;

// Dynamic import for Tauri APIs (only loads in Tauri environment)
let invoke = null;
let dialog = null;
let event = null;
let path = null;

if (isTauri) {
    import('@tauri-apps/api/tauri').then(mod => { invoke = mod.invoke; });
    import('@tauri-apps/api/dialog').then(mod => { dialog = mod; });
    import('@tauri-apps/api/event').then(mod => { event = mod; });
    import('@tauri-apps/api/path').then(mod => { path = mod; });
}

/**
 * Platform detection utilities
 */
export const platform = {
    isTauri: () => isTauri,
    isWeb: () => !isTauri,
    isDesktop: () => isTauri,

    async getOS() {
        if (isTauri && path) {
            const os = await import('@tauri-apps/api/os');
            return os.type();
        }
        return navigator.platform;
    }
};

/**
 * Scan service - handles vulnerability scanning
 */
export const scanService = {
    /**
     * Start a new scan on the specified path
     * @param {string} scanPath - Path to scan
     * @param {Object} options - Scan options
     * @returns {Promise<Object>} Scan result
     */
    async runScan(scanPath, options = {}) {
        if (isTauri && invoke) {
            return await invoke('run_scan', {
                path: scanPath,
                options: {
                    scan_secrets: options.scanSecrets ?? true,
                    scan_dependencies: options.scanDependencies ?? true,
                    scan_ai_patterns: options.scanAiPatterns ?? true,
                    max_file_size: options.maxFileSize ?? 10 * 1024 * 1024,
                    excluded_paths: options.excludedPaths ?? []
                }
            });
        }

        // Fallback to HTTP API
        const response = await fetch('/api/scan/directory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: scanPath, ...options })
        });
        return response.json();
    },

    /**
     * Get scan status
     * @param {string} scanId - Scan ID
     * @returns {Promise<string>} Status
     */
    async getScanStatus(scanId) {
        if (isTauri && invoke) {
            return await invoke('get_scan_status', { scanId });
        }

        const response = await fetch(`/api/scan/status/${scanId}`);
        return response.json();
    },

    /**
     * Cancel a running scan
     * @param {string} scanId - Scan ID
     * @returns {Promise<boolean>} Success
     */
    async cancelScan(scanId) {
        if (isTauri && invoke) {
            return await invoke('cancel_scan', { scanId });
        }

        const response = await fetch(`/api/scan/cancel/${scanId}`, { method: 'POST' });
        return response.json();
    },

    /**
     * Get scan results
     * @param {string} scanId - Scan ID
     * @returns {Promise<Object>} Scan results
     */
    async getScanResults(scanId) {
        if (isTauri && invoke) {
            return await invoke('get_scan_results', { scanId });
        }

        const response = await fetch(`/api/scan/results/${scanId}`);
        return response.json();
    },

    /**
     * List recent scans
     * @param {number} limit - Max number of scans to return
     * @returns {Promise<Array>} Scan list
     */
    async listScans(limit = 50) {
        if (isTauri && invoke) {
            return await invoke('list_scans', { limit });
        }

        const response = await fetch('/api/scan/list');
        return response.json();
    }
};

/**
 * Settings service - manages application settings
 */
export const settingsService = {
    /**
     * Get a setting by key
     * @param {string} key - Setting key
     * @returns {Promise<any>} Setting value
     */
    async get(key) {
        if (isTauri && invoke) {
            try {
                return await invoke('get_setting', { key });
            } catch (e) {
                console.warn(`Setting '${key}' not found, using default`);
                return null;
            }
        }

        // Fallback to localStorage
        const value = localStorage.getItem(`byteguardx.${key}`);
        return value ? JSON.parse(value) : null;
    },

    /**
     * Set a setting
     * @param {string} key - Setting key
     * @param {any} value - Setting value
     */
    async set(key, value) {
        if (isTauri && invoke) {
            return await invoke('set_setting', { key, value });
        }

        // Fallback to localStorage
        localStorage.setItem(`byteguardx.${key}`, JSON.stringify(value));
    },

    /**
     * Get all settings
     * @returns {Promise<Object>} All settings
     */
    async getAll() {
        if (isTauri && invoke) {
            return await invoke('get_all_settings');
        }

        // Fallback: return defaults
        return {
            allowUpdateCheck: false,
            allowTelemetry: false,
            scanSecrets: true,
            scanDependencies: true,
            scanAiPatterns: true,
            theme: 'dark',
            showNotifications: true
        };
    },

    /**
     * Reset settings to defaults
     */
    async reset() {
        if (isTauri && invoke) {
            return await invoke('reset_settings');
        }

        // Clear localStorage settings
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith('byteguardx.')) {
                localStorage.removeItem(key);
            }
        });
    }
};

/**
 * Plugin service - manages plugins
 */
export const pluginService = {
    /**
     * List installed plugins
     * @returns {Promise<Array>} Plugin list
     */
    async list() {
        if (isTauri && invoke) {
            return await invoke('list_plugins');
        }

        const response = await fetch('/api/plugins/list');
        return response.json();
    },

    /**
     * Install a plugin from local file
     * @param {string} path - Path to plugin file
     * @returns {Promise<Object>} Installed plugin info
     */
    async installLocal(path) {
        if (isTauri && invoke) {
            return await invoke('install_plugin_local', { path });
        }

        throw new Error('Local plugin installation only available in desktop mode');
    },

    /**
     * Uninstall a plugin
     * @param {string} pluginId - Plugin ID
     * @returns {Promise<boolean>} Success
     */
    async uninstall(pluginId) {
        if (isTauri && invoke) {
            return await invoke('uninstall_plugin', { pluginId });
        }

        const response = await fetch(`/api/plugins/${pluginId}`, { method: 'DELETE' });
        return response.ok;
    },

    /**
     * Verify plugin checksum
     * @param {string} path - Plugin file path
     * @param {string} expectedHash - Expected SHA-256 hash
     * @returns {Promise<boolean>} Verification result
     */
    async verifyChecksum(path, expectedHash) {
        if (isTauri && invoke) {
            return await invoke('verify_plugin_checksum', { path, expectedHash });
        }

        throw new Error('Checksum verification only available in desktop mode');
    },

    /**
     * Get plugin statistics
     * @returns {Promise<Object>} Plugin stats
     */
    async getStats() {
        if (isTauri && invoke) {
            return await invoke('get_plugin_stats');
        }

        // Fallback for web mode
        return {
            total_executions: 0,
            success_rate: 0,
            average_execution_time: 0
        };
    },

    /**
     * Get plugin configuration
     * @returns {Promise<Object>} Plugin configuration
     */
    async getConfig() {
        if (isTauri && invoke) {
            try {
                return await invoke('get_plugin_config');
            } catch (e) {
                console.warn('get_plugin_config not implemented, using mock');
            }
        }

        // Mock data
        return {
            configurations: {},
            global_settings: {
                enableSandbox: true,
                maxConcurrentPlugins: 10,
                defaultTimeout: 60,
                maxMemoryMB: 512,
                maxCpuPercent: 50,
                trustThreshold: 0.7,
                enableLogging: true,
                enableMetrics: true
            }
        };
    },

    /**
     * Save plugin configuration
     * @param {Object} config - Configuration object
     * @returns {Promise<boolean>} Success
     */
    async saveConfig(config) {
        if (isTauri && invoke) {
            try {
                return await invoke('save_plugin_config', { config });
            } catch (e) {
                console.warn('save_plugin_config not implemented, using mock');
            }
        }

        // Mock success
        return true;
    },

    /**
     * Execute a plugin (test mode)
     * @param {string} pluginId - Plugin ID
     * @param {Object} params - Execution parameters
     * @returns {Promise<Object>} Execution result
     */
    async execute(pluginId, params) {
        if (isTauri && invoke) {
            try {
                return await invoke('execute_plugin', { pluginId, params });
            } catch (e) {
                console.warn('execute_plugin not implemented, using mock');
            }
        }

        // Mock result
        return {
            result: {
                status: 'completed',
                findings: [],
                execution_time_ms: 150
            }
        };
    }
};

/**
 * Report service - manages reports
 */
export const reportService = {
    /**
     * Export scan results to a file
     * @param {string} scanId - Scan ID
     * @param {string} format - Output format (pdf, html, json, csv)
     * @param {string} outputPath - Output file path
     * @returns {Promise<string>} Output path
     */
    async export(scanId, format, outputPath) {
        if (isTauri && invoke) {
            return await invoke('export_report', { scanId, format, outputPath });
        }

        // In web mode, download via HTTP
        const response = await fetch(`/api/report/generate/${scanId}?format=${format}`);
        const blob = await response.blob();

        // Trigger download
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `byteguardx-report-${scanId}.${format}`;
        a.click();
        URL.revokeObjectURL(url);

        return `byteguardx-report-${scanId}.${format}`;
    },

    /**
     * Get available report formats
     * @returns {Promise<Array<string>>} Format list
     */
    async getFormats() {
        if (isTauri && invoke) {
            return await invoke('get_report_formats');
        }

        return ['pdf', 'html', 'json', 'csv'];
    }
};

/**
 * Dialog service - native file dialogs
 */
export const dialogService = {
    /**
     * Open a directory picker
     * @param {Object} options - Dialog options
     * @returns {Promise<string|null>} Selected path or null
     */
    async selectDirectory(options = {}) {
        if (isTauri && dialog) {
            const result = await dialog.open({
                directory: true,
                multiple: false,
                title: options.title ?? 'Select Directory',
                ...options
            });
            return result;
        }

        // Fallback: use input element (limited functionality)
        return new Promise((resolve) => {
            const input = document.createElement('input');
            input.type = 'file';
            input.webkitdirectory = true;
            input.onchange = () => {
                if (input.files.length > 0) {
                    resolve(input.files[0].webkitRelativePath.split('/')[0]);
                } else {
                    resolve(null);
                }
            };
            input.click();
        });
    },

    /**
     * Open a file picker
     * @param {Object} options - Dialog options
     * @returns {Promise<string[]|null>} Selected paths or null
     */
    async selectFiles(options = {}) {
        if (isTauri && dialog) {
            const result = await dialog.open({
                directory: false,
                multiple: options.multiple ?? true,
                title: options.title ?? 'Select Files',
                filters: options.filters ?? [],
                ...options
            });
            return Array.isArray(result) ? result : (result ? [result] : null);
        }

        // Fallback: use input element
        return new Promise((resolve) => {
            const input = document.createElement('input');
            input.type = 'file';
            input.multiple = options.multiple ?? true;
            input.accept = options.accept ?? '*';
            input.onchange = () => {
                if (input.files.length > 0) {
                    resolve(Array.from(input.files).map(f => f.name));
                } else {
                    resolve(null);
                }
            };
            input.click();
        });
    },

    /**
     * Open a save dialog
     * @param {Object} options - Dialog options
     * @returns {Promise<string|null>} Save path or null
     */
    async saveFile(options = {}) {
        if (isTauri && dialog) {
            return await dialog.save({
                title: options.title ?? 'Save File',
                defaultPath: options.defaultPath,
                filters: options.filters ?? [],
                ...options
            });
        }

        // No fallback for save dialog in web mode
        console.warn('Save dialog not available in web mode');
        return options.defaultPath ?? 'download';
    },

    /**
     * Show a message dialog
     * @param {string} message - Message to display
     * @param {Object} options - Dialog options
     */
    async message(message, options = {}) {
        if (isTauri && dialog) {
            await dialog.message(message, {
                title: options.title ?? 'ByteGuardX',
                type: options.type ?? 'info',
                ...options
            });
            return;
        }

        // Fallback: use browser alert
        alert(message);
    },

    /**
     * Show a confirmation dialog
     * @param {string} message - Message to display
     * @param {Object} options - Dialog options
     * @returns {Promise<boolean>} User response
     */
    async confirm(message, options = {}) {
        if (isTauri && dialog) {
            return await dialog.ask(message, {
                title: options.title ?? 'Confirm',
                type: 'warning',
                ...options
            });
        }

        // Fallback: use browser confirm
        return window.confirm(message);
    }
};

/**
 * System service - system information and health
 */
export const systemService = {
    /**
     * Get application version
     * @returns {Promise<string>} Version string
     */
    async getVersion() {
        if (isTauri && invoke) {
            return await invoke('get_app_version');
        }

        return '1.0.0';
    },

    /**
     * Get system information
     * @returns {Promise<Object>} System info
     */
    async getSystemInfo() {
        if (isTauri && invoke) {
            return await invoke('get_system_info');
        }

        return {
            os: navigator.platform,
            arch: 'unknown',
            version: '1.0.0',
            python_available: false,
            python_version: null
        };
    },

    /**
     * Check if Python is available
     * @returns {Promise<boolean>} Python available
     */
    async checkPython() {
        if (isTauri && invoke) {
            return await invoke('check_python_available');
        }

        return false;
    },

    /**
     * Get health status
     * @returns {Promise<Object>} Health status
     */
    async getHealthStatus() {
        if (isTauri && invoke) {
            return await invoke('get_health_status');
        }

        const response = await fetch('/api/health');
        return response.json();
    }
};

/**
 * Event service - menu and system events
 */
export const eventService = {
    /**
     * Listen for a menu event
     * @param {string} eventName - Event name
     * @param {Function} callback - Callback function
     * @returns {Promise<Function>} Unlisten function
     */
    async onMenuEvent(eventName, callback) {
        if (isTauri && event) {
            return await event.listen(eventName, (e) => callback(e.payload));
        }

        // Fallback: no-op
        return () => { };
    },

    /**
     * Listen for menu-new-scan event
     */
    onNewScan(callback) {
        return this.onMenuEvent('menu-new-scan', callback);
    },

    /**
     * Listen for menu-open-project event
     */
    onOpenProject(callback) {
        return this.onMenuEvent('menu-open-project', callback);
    },

    /**
     * Listen for menu-export-report event
     */
    onExportReport(callback) {
        return this.onMenuEvent('menu-export-report', callback);
    },

    /**
     * Listen for menu-settings event
     */
    onSettings(callback) {
        return this.onMenuEvent('menu-settings', callback);
    }
};


/**
 * Dashboard service - manages dashboard data
 */
export const dashboardService = {
    /**
     * Get dashboard statistics
     * @returns {Promise<Object>} Dashboard stats
     */
    async getStats() {
        if (isTauri && invoke) {
            return await invoke('get_dashboard_stats');
        }

        // Fallback or mock for web mode if needed
        return null;
    }
};

// Default export with all services
export default {
    platform,
    scan: scanService,
    settings: settingsService,
    plugins: pluginService,
    reports: reportService,
    dialog: dialogService,
    system: systemService,
    events: eventService,
    dashboard: dashboardService
};
