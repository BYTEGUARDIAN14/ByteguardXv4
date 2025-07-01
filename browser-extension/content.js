/**
 * ByteGuardX Browser Extension - Content Script
 * Scans code in web-based editors for security vulnerabilities
 */

class ByteGuardXScanner {
  constructor() {
    this.apiUrl = 'http://localhost:5000'
    this.isEnabled = true
    this.scanResults = new Map()
    this.observers = []
    this.scanTimeout = null
    this.lastScanTime = 0
    this.scanDelay = 2000 // 2 seconds delay after typing stops
    
    this.init()
  }

  async init() {
    console.log('ByteGuardX: Initializing scanner...')
    
    // Load settings
    await this.loadSettings()
    
    // Detect platform and setup scanners
    this.detectPlatform()
    this.setupCodeEditorWatchers()
    this.createUI()
    
    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse)
    })
    
    console.log('ByteGuardX: Scanner initialized')
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.sync.get({
        enabled: true,
        apiUrl: 'http://localhost:5000',
        autoScan: true,
        showInlineWarnings: true,
        minimumSeverity: 'medium'
      })
      
      this.isEnabled = result.enabled
      this.apiUrl = result.apiUrl
      this.autoScan = result.autoScan
      this.showInlineWarnings = result.showInlineWarnings
      this.minimumSeverity = result.minimumSeverity
    } catch (error) {
      console.error('ByteGuardX: Failed to load settings:', error)
    }
  }

  detectPlatform() {
    const hostname = window.location.hostname
    
    if (hostname.includes('github.com')) {
      this.platform = 'github'
    } else if (hostname.includes('gitlab.com')) {
      this.platform = 'gitlab'
    } else if (hostname.includes('codepen.io')) {
      this.platform = 'codepen'
    } else if (hostname.includes('codesandbox.io')) {
      this.platform = 'codesandbox'
    } else if (hostname.includes('replit.com')) {
      this.platform = 'replit'
    } else if (hostname.includes('stackblitz.com')) {
      this.platform = 'stackblitz'
    } else {
      this.platform = 'unknown'
    }
    
    console.log(`ByteGuardX: Detected platform: ${this.platform}`)
  }

  setupCodeEditorWatchers() {
    if (!this.isEnabled) return

    // Platform-specific selectors for code editors
    const editorSelectors = {
      github: [
        '.CodeMirror',
        '.monaco-editor',
        'textarea[data-testid="file-editor-text-area"]',
        '.ace_editor'
      ],
      gitlab: [
        '.monaco-editor',
        '.ace_editor',
        '#editor'
      ],
      codepen: [
        '.CodeMirror',
        '.ace_editor'
      ],
      codesandbox: [
        '.monaco-editor',
        '.cm-editor'
      ],
      replit: [
        '.monaco-editor',
        '.cm-editor'
      ],
      stackblitz: [
        '.monaco-editor'
      ]
    }

    const selectors = editorSelectors[this.platform] || [
      '.CodeMirror',
      '.monaco-editor',
      '.ace_editor',
      'textarea',
      'pre[contenteditable]'
    ]

    // Watch for editor elements
    selectors.forEach(selector => {
      this.watchForElements(selector, (element) => {
        this.attachToEditor(element)
      })
    })

    // Watch for dynamic content changes
    this.setupMutationObserver()
  }

  watchForElements(selector, callback) {
    // Check existing elements
    document.querySelectorAll(selector).forEach(callback)

    // Watch for new elements
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.matches && node.matches(selector)) {
              callback(node)
            }
            node.querySelectorAll && node.querySelectorAll(selector).forEach(callback)
          }
        })
      })
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true
    })

    this.observers.push(observer)
  }

  attachToEditor(editorElement) {
    if (editorElement.dataset.byteguardxAttached) return
    editorElement.dataset.byteguardxAttached = 'true'

    console.log('ByteGuardX: Attached to editor:', editorElement)

    // Handle different editor types
    if (editorElement.classList.contains('CodeMirror')) {
      this.attachToCodeMirror(editorElement)
    } else if (editorElement.classList.contains('monaco-editor')) {
      this.attachToMonaco(editorElement)
    } else if (editorElement.classList.contains('ace_editor')) {
      this.attachToAce(editorElement)
    } else if (editorElement.tagName === 'TEXTAREA') {
      this.attachToTextarea(editorElement)
    }
  }

  attachToCodeMirror(element) {
    const cm = element.CodeMirror
    if (!cm) return

    cm.on('change', () => {
      this.scheduleCodeScan(cm.getValue(), this.getLanguageFromEditor(element))
    })
  }

  attachToMonaco(element) {
    // Monaco editor detection is more complex
    // We'll use a polling approach to detect the editor instance
    const checkForMonaco = () => {
      if (window.monaco && window.monaco.editor) {
        const editors = window.monaco.editor.getEditors()
        editors.forEach(editor => {
          if (!editor._byteguardxAttached) {
            editor._byteguardxAttached = true
            editor.onDidChangeModelContent(() => {
              const model = editor.getModel()
              if (model) {
                const code = model.getValue()
                const language = model.getLanguageId()
                this.scheduleCodeScan(code, language)
              }
            })
          }
        })
      }
    }

    // Check periodically for Monaco editors
    setTimeout(checkForMonaco, 1000)
    setInterval(checkForMonaco, 5000)
  }

  attachToAce(element) {
    // Ace editor detection
    if (window.ace) {
      const editor = window.ace.edit(element)
      if (editor) {
        editor.on('change', () => {
          const code = editor.getValue()
          const language = editor.session.getMode().$id.split('/').pop()
          this.scheduleCodeScan(code, language)
        })
      }
    }
  }

  attachToTextarea(element) {
    element.addEventListener('input', () => {
      const code = element.value
      const language = this.detectLanguageFromContent(code) || 'text'
      this.scheduleCodeScan(code, language)
    })
  }

  scheduleCodeScan(code, language) {
    if (!this.autoScan || !code.trim()) return

    // Clear previous timeout
    if (this.scanTimeout) {
      clearTimeout(this.scanTimeout)
    }

    // Schedule new scan
    this.scanTimeout = setTimeout(() => {
      this.scanCode(code, language)
    }, this.scanDelay)
  }

  async scanCode(code, language) {
    if (!code || code.length < 50) return // Skip very short code snippets

    try {
      console.log(`ByteGuardX: Scanning ${language} code...`)
      
      const response = await fetch(`${this.apiUrl}/scan/text`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code: code,
          language: language,
          source: 'browser_extension'
        })
      })

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }

      const results = await response.json()
      this.processScanResults(results, code)
      
    } catch (error) {
      console.error('ByteGuardX: Scan failed:', error)
      this.showNotification('Scan failed. Check if ByteGuardX API is running.', 'error')
    }
  }

  processScanResults(results, code) {
    const findings = results.findings || []
    
    // Filter by minimum severity
    const filteredFindings = findings.filter(finding => {
      const severityLevels = { low: 1, medium: 2, high: 3, critical: 4 }
      const findingSeverity = severityLevels[finding.severity] || 0
      const minSeverity = severityLevels[this.minimumSeverity] || 0
      return findingSeverity >= minSeverity
    })

    // Store results
    const scanId = Date.now().toString()
    this.scanResults.set(scanId, {
      findings: filteredFindings,
      code: code,
      timestamp: new Date()
    })

    // Update UI
    this.updateSecurityIndicator(filteredFindings)
    
    if (this.showInlineWarnings) {
      this.showInlineWarnings(filteredFindings)
    }

    // Show notification for critical issues
    const criticalFindings = filteredFindings.filter(f => f.severity === 'critical')
    if (criticalFindings.length > 0) {
      this.showNotification(
        `Found ${criticalFindings.length} critical security issue(s)!`,
        'critical'
      )
    }

    console.log(`ByteGuardX: Found ${filteredFindings.length} security issues`)
  }

  createUI() {
    // Create floating security indicator
    this.securityIndicator = document.createElement('div')
    this.securityIndicator.id = 'byteguardx-indicator'
    this.securityIndicator.className = 'byteguardx-indicator'
    this.securityIndicator.innerHTML = `
      <div class="byteguardx-icon">🛡️</div>
      <div class="byteguardx-badge" id="byteguardx-badge">0</div>
    `
    
    this.securityIndicator.addEventListener('click', () => {
      this.showResultsPanel()
    })

    document.body.appendChild(this.securityIndicator)

    // Create results panel
    this.createResultsPanel()
  }

  createResultsPanel() {
    this.resultsPanel = document.createElement('div')
    this.resultsPanel.id = 'byteguardx-panel'
    this.resultsPanel.className = 'byteguardx-panel byteguardx-hidden'
    this.resultsPanel.innerHTML = `
      <div class="byteguardx-panel-header">
        <h3>🛡️ ByteGuardX Security Scan</h3>
        <button id="byteguardx-close" class="byteguardx-close">×</button>
      </div>
      <div class="byteguardx-panel-content" id="byteguardx-content">
        <p>No security issues found.</p>
      </div>
    `

    document.body.appendChild(this.resultsPanel)

    // Close button
    document.getElementById('byteguardx-close').addEventListener('click', () => {
      this.hideResultsPanel()
    })

    // Click outside to close
    this.resultsPanel.addEventListener('click', (e) => {
      if (e.target === this.resultsPanel) {
        this.hideResultsPanel()
      }
    })
  }

  updateSecurityIndicator(findings) {
    const badge = document.getElementById('byteguardx-badge')
    if (badge) {
      badge.textContent = findings.length
      
      // Update color based on severity
      const criticalCount = findings.filter(f => f.severity === 'critical').length
      const highCount = findings.filter(f => f.severity === 'high').length
      
      if (criticalCount > 0) {
        badge.className = 'byteguardx-badge critical'
      } else if (highCount > 0) {
        badge.className = 'byteguardx-badge high'
      } else if (findings.length > 0) {
        badge.className = 'byteguardx-badge medium'
      } else {
        badge.className = 'byteguardx-badge safe'
      }
    }
  }

  showResultsPanel() {
    const content = document.getElementById('byteguardx-content')
    const latestResults = Array.from(this.scanResults.values()).pop()
    
    if (!latestResults || latestResults.findings.length === 0) {
      content.innerHTML = '<p class="byteguardx-no-issues">✅ No security issues found!</p>'
    } else {
      const findings = latestResults.findings
      content.innerHTML = `
        <div class="byteguardx-summary">
          <p><strong>Found ${findings.length} security issue(s)</strong></p>
        </div>
        <div class="byteguardx-findings">
          ${findings.map(finding => this.renderFinding(finding)).join('')}
        </div>
      `
    }

    this.resultsPanel.classList.remove('byteguardx-hidden')
  }

  hideResultsPanel() {
    this.resultsPanel.classList.add('byteguardx-hidden')
  }

  renderFinding(finding) {
    const severityClass = `severity-${finding.severity}`
    return `
      <div class="byteguardx-finding ${severityClass}">
        <div class="finding-header">
          <span class="severity-badge ${severityClass}">${finding.severity.toUpperCase()}</span>
          <span class="finding-type">${finding.type}</span>
        </div>
        <div class="finding-description">${finding.description}</div>
        ${finding.recommendation ? `<div class="finding-recommendation">💡 ${finding.recommendation}</div>` : ''}
        ${finding.line_number ? `<div class="finding-location">📍 Line ${finding.line_number}</div>` : ''}
      </div>
    `
  }

  showInlineWarnings(findings) {
    // Remove existing warnings
    document.querySelectorAll('.byteguardx-inline-warning').forEach(el => el.remove())

    // Add new warnings (simplified implementation)
    findings.forEach(finding => {
      if (finding.line_number) {
        this.addInlineWarning(finding)
      }
    })
  }

  addInlineWarning(finding) {
    // This is a simplified implementation
    // In practice, would need to map to specific editor line elements
    const warning = document.createElement('div')
    warning.className = `byteguardx-inline-warning severity-${finding.severity}`
    warning.innerHTML = `
      <span class="warning-icon">⚠️</span>
      <span class="warning-text">${finding.description}</span>
    `
    
    // Try to find the appropriate location to insert the warning
    // This would need to be customized for each platform
    const codeLines = document.querySelectorAll('.blob-code-inner, .line')
    if (codeLines[finding.line_number - 1]) {
      const targetLine = codeLines[finding.line_number - 1]
      targetLine.appendChild(warning)
    }
  }

  showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div')
    notification.className = `byteguardx-notification ${type}`
    notification.innerHTML = `
      <div class="notification-content">
        <span class="notification-icon">${type === 'critical' ? '🚨' : type === 'error' ? '❌' : 'ℹ️'}</span>
        <span class="notification-message">${message}</span>
      </div>
    `

    document.body.appendChild(notification)

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification)
      }
    }, 5000)
  }

  getLanguageFromEditor(element) {
    // Try to detect language from various sources
    const url = window.location.href
    
    // GitHub file detection
    if (url.includes('github.com') && url.includes('/blob/')) {
      const pathMatch = url.match(/\/blob\/[^/]+\/(.+)/)
      if (pathMatch) {
        const filename = pathMatch[1]
        return this.detectLanguageFromFilename(filename)
      }
    }

    // GitLab file detection
    if (url.includes('gitlab.com') && url.includes('/-/blob/')) {
      const pathMatch = url.match(/\/-\/blob\/[^/]+\/(.+)/)
      if (pathMatch) {
        const filename = pathMatch[1]
        return this.detectLanguageFromFilename(filename)
      }
    }

    return 'text'
  }

  detectLanguageFromFilename(filename) {
    const ext = filename.split('.').pop().toLowerCase()
    const languageMap = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'java': 'java',
      'cpp': 'cpp',
      'c': 'c',
      'cs': 'csharp',
      'php': 'php',
      'rb': 'ruby',
      'go': 'go',
      'rs': 'rust',
      'sh': 'bash',
      'sql': 'sql',
      'html': 'html',
      'css': 'css',
      'json': 'json',
      'xml': 'xml',
      'yaml': 'yaml',
      'yml': 'yaml'
    }
    
    return languageMap[ext] || 'text'
  }

  detectLanguageFromContent(code) {
    // Simple content-based language detection
    if (code.includes('def ') && code.includes(':')) return 'python'
    if (code.includes('function ') || code.includes('=>')) return 'javascript'
    if (code.includes('public class ')) return 'java'
    if (code.includes('<?php')) return 'php'
    if (code.includes('#include')) return 'c'
    
    return null
  }

  setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        // Re-scan when page content changes significantly
        if (mutation.addedNodes.length > 0) {
          setTimeout(() => {
            this.setupCodeEditorWatchers()
          }, 1000)
        }
      })
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true
    })

    this.observers.push(observer)
  }

  handleMessage(request, sender, sendResponse) {
    switch (request.action) {
      case 'scan':
        this.manualScan()
        sendResponse({ success: true })
        break
      case 'toggle':
        this.isEnabled = !this.isEnabled
        sendResponse({ enabled: this.isEnabled })
        break
      case 'getResults':
        const latestResults = Array.from(this.scanResults.values()).pop()
        sendResponse({ results: latestResults })
        break
      default:
        sendResponse({ error: 'Unknown action' })
    }
  }

  manualScan() {
    // Trigger manual scan of all visible code
    const editors = document.querySelectorAll('.CodeMirror, .monaco-editor, .ace_editor, textarea')
    editors.forEach(editor => {
      let code = ''
      let language = 'text'

      if (editor.CodeMirror) {
        code = editor.CodeMirror.getValue()
      } else if (editor.tagName === 'TEXTAREA') {
        code = editor.value
      }

      if (code) {
        language = this.getLanguageFromEditor(editor)
        this.scanCode(code, language)
      }
    })
  }

  destroy() {
    // Clean up observers and UI elements
    this.observers.forEach(observer => observer.disconnect())
    
    if (this.securityIndicator) {
      this.securityIndicator.remove()
    }
    
    if (this.resultsPanel) {
      this.resultsPanel.remove()
    }
    
    if (this.scanTimeout) {
      clearTimeout(this.scanTimeout)
    }
  }
}

// Initialize scanner when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new ByteGuardXScanner()
  })
} else {
  new ByteGuardXScanner()
}
