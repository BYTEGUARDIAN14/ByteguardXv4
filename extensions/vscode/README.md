# ByteGuardX VS Code Extension

AI-powered security vulnerability scanner for Visual Studio Code.

## Features

- **Real-time Security Scanning**: Scan files and workspaces for security vulnerabilities
- **AI-Powered Fix Suggestions**: Get intelligent fix recommendations for security issues
- **Inline Diagnostics**: See security issues highlighted directly in your code
- **Multiple Severity Levels**: Critical, High, Medium, and Low severity classifications
- **Comprehensive Coverage**: Detects secrets, dependency vulnerabilities, and code patterns
- **Auto-scan on Save**: Optionally scan files automatically when saved

## Installation

1. Install the ByteGuardX extension from the VS Code marketplace
2. Make sure ByteGuardX API is running (default: http://localhost:5000)
3. Configure your API key in settings (optional for local development)

## Configuration

Open VS Code settings and configure ByteGuardX:

- `byteguardx.apiUrl`: ByteGuardX API URL (default: http://localhost:5000)
- `byteguardx.apiKey`: API key for authentication
- `byteguardx.autoScan`: Automatically scan files on save
- `byteguardx.showInlineDecorations`: Show inline security issue decorations
- `byteguardx.severityFilter`: Severity levels to show

## Usage

### Scan Current File
- Right-click in editor → "ByteGuardX: Scan Current File"
- Command Palette → "ByteGuardX: Scan Current File"
- Keyboard shortcut: `Ctrl+Shift+P` → type "scan file"

### Scan Workspace
- Command Palette → "ByteGuardX: Scan Workspace"
- This will scan all files in your workspace

### View Results
- Open the ByteGuardX panel in the Explorer sidebar
- Results are grouped by severity level
- Click on any finding to jump to the code location

### Fix Security Issues
- Right-click on a highlighted security issue → "ByteGuardX: Fix Security Issue"
- Command Palette → "ByteGuardX: Fix Security Issue" (when cursor is on an issue)
- Use the lightbulb quick fix menu

## Commands

- `byteguardx.scanFile`: Scan the current file
- `byteguardx.scanWorkspace`: Scan the entire workspace
- `byteguardx.showResults`: Show scan results panel
- `byteguardx.fixIssue`: Get AI-powered fix suggestions
- `byteguardx.openSettings`: Open ByteGuardX settings

## Security Issue Types

The extension detects various types of security vulnerabilities:

### Secrets Detection
- API keys and tokens
- Database credentials
- Private keys and certificates
- Cloud service credentials

### Dependency Vulnerabilities
- Known vulnerable packages
- Outdated dependencies
- License compliance issues

### Code Pattern Analysis
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Path traversal issues
- Insecure cryptographic practices

## Severity Levels

- **🔴 Critical**: Immediate security threats requiring urgent attention
- **🟠 High**: Serious security issues that should be fixed soon
- **🟡 Medium**: Moderate security concerns
- **🔵 Low**: Minor security improvements

## Requirements

- Visual Studio Code 1.74.0 or higher
- ByteGuardX API server running (local or remote)
- Node.js 16+ (for development)

## Development

To develop this extension:

1. Clone the repository
2. Run `npm install` to install dependencies
3. Open in VS Code and press F5 to launch Extension Development Host
4. Make changes and reload the window to test

### Building

```bash
npm run compile
npm run package
```

## Support

For issues and feature requests, please visit:
- GitHub: https://github.com/byteguardx/vscode-extension
- Documentation: https://byteguardx.com/docs
- Support: support@byteguardx.com

## License

Commercial License - see LICENSE file for details.
