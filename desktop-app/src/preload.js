const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // App info
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  
  // Settings
  getSetting: (key) => ipcRenderer.invoke('get-setting', key),
  setSetting: (key, value) => ipcRenderer.invoke('set-setting', key, value),
  
  // File dialogs
  showSaveDialog: (options) => ipcRenderer.invoke('show-save-dialog', options),
  showOpenDialog: (options) => ipcRenderer.invoke('show-open-dialog', options),
  
  // Menu events
  onMenuNewScan: (callback) => ipcRenderer.on('menu-new-scan', callback),
  onMenuOpenProject: (callback) => ipcRenderer.on('menu-open-project', callback),
  onMenuExportReport: (callback) => ipcRenderer.on('menu-export-report', callback),
  onMenuQuickScan: (callback) => ipcRenderer.on('menu-quick-scan', callback),
  onMenuDeepScan: (callback) => ipcRenderer.on('menu-deep-scan', callback),
  onMenuScanSettings: (callback) => ipcRenderer.on('menu-scan-settings', callback),
  onMenuSecurityDashboard: (callback) => ipcRenderer.on('menu-security-dashboard', callback),
  onMenuVulnerabilityDb: (callback) => ipcRenderer.on('menu-vulnerability-db', callback),
  onMenuPreferences: (callback) => ipcRenderer.on('menu-preferences', callback),
  
  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
  
  // Platform info
  platform: process.platform,
  
  // Node.js APIs (limited exposure)
  path: {
    join: (...args) => require('path').join(...args),
    dirname: (path) => require('path').dirname(path),
    basename: (path) => require('path').basename(path),
    extname: (path) => require('path').extname(path)
  }
});

// Desktop-specific enhancements for the web app
contextBridge.exposeInMainWorld('desktopEnhancements', {
  // Check if running in desktop mode
  isDesktop: true,
  
  // Desktop-specific features
  features: {
    fileSystemAccess: true,
    nativeMenus: true,
    autoUpdater: true,
    systemNotifications: true,
    offlineMode: true
  },
  
  // Enhanced file operations
  fileOperations: {
    selectDirectory: async () => {
      const result = await ipcRenderer.invoke('show-open-dialog', {
        properties: ['openDirectory'],
        title: 'Select Directory to Scan'
      });
      return result.canceled ? null : result.filePaths[0];
    },
    
    selectFiles: async (filters = []) => {
      const result = await ipcRenderer.invoke('show-open-dialog', {
        properties: ['openFile', 'multiSelections'],
        title: 'Select Files to Scan',
        filters: filters
      });
      return result.canceled ? [] : result.filePaths;
    },
    
    saveReport: async (defaultName = 'security-report') => {
      const result = await ipcRenderer.invoke('show-save-dialog', {
        title: 'Save Security Report',
        defaultPath: defaultName,
        filters: [
          { name: 'PDF Files', extensions: ['pdf'] },
          { name: 'JSON Files', extensions: ['json'] },
          { name: 'HTML Files', extensions: ['html'] },
          { name: 'All Files', extensions: ['*'] }
        ]
      });
      return result.canceled ? null : result.filePath;
    }
  },
  
  // Desktop notifications
  notifications: {
    show: (title, body, options = {}) => {
      new Notification(title, { body, ...options });
    }
  },
  
  // System integration
  system: {
    openExternal: (url) => {
      // This would need to be implemented via IPC for security
      console.log('Open external:', url);
    }
  }
});

// Enhanced error handling for desktop
window.addEventListener('error', (event) => {
  console.error('Desktop App Error:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('Desktop App Unhandled Rejection:', event.reason);
});

// Desktop-specific styling hints
document.addEventListener('DOMContentLoaded', () => {
  document.body.classList.add('desktop-app');
  
  // Add platform-specific classes
  document.body.classList.add(`platform-${process.platform}`);
  
  // Add desktop-specific CSS variables
  document.documentElement.style.setProperty('--is-desktop', '1');
  document.documentElement.style.setProperty('--platform', process.platform);
});
