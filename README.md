# ByteGuardX

**AI-Powered Vulnerability Scanner for Developers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-focused-green.svg)](https://github.com/byteguardx/byteguardx)

ByteGuardX is a comprehensive, offline-first security vulnerability scanner designed for developers, security teams, and privacy-conscious users. It combines traditional static analysis with AI-powered pattern detection to identify security issues in your codebase.

## 🚀 Features

### 🔐 **Secret Detection**
- Hardcoded API keys, tokens, and credentials
- High-entropy string analysis
- Context-aware pattern matching
- Support for 50+ secret types

### 📦 **Dependency Vulnerability Scanning**
- CVE database matching for Python, Node.js, Rust, Go, Java, PHP
- Version range analysis
- Offline vulnerability database
- Fix version recommendations

### 🧠 **AI Pattern Analysis**
- Unsafe AI-generated code patterns
- Input validation issues
- Authentication bypasses
- Cryptographic weaknesses
- Error handling anti-patterns

### 🔧 **Intelligent Fix Suggestions**
- Automated fix generation from templates
- Code transformation suggestions
- Best practice recommendations
- Environment variable migration

### 📄 **Professional Reporting**
- PDF report generation with CVSS v3.1 scoring
- HTML reports with styling
- Severity-based grouping
- Executive summaries
- CVSS vulnerability scoring and breakdown

### 🛠️ **Multiple Interfaces**
- **CLI Tool**: Full-featured command-line interface
- **REST API**: Flask-based API for integrations
- **Web UI**: React frontend with admin dashboard
- **Git Hooks**: Pre-commit security scanning
- **Plugin Marketplace**: Extensible plugin system

### ⏰ **Enterprise Features**
- **Scheduled Scans**: Automated recurring security scans
- **Admin Dashboard**: User and system management interface
- **Email Notifications**: Configurable security alerts
- **Self-Hosted Deployment**: Docker-based deployment wizard
- **Plugin System**: Extensible architecture with marketplace

## 🏗️ **Offline-First Architecture**

ByteGuardX works completely offline with no external dependencies:
- ✅ No internet connection required
- ✅ No data sent to external services
- ✅ Complete privacy and security
- ✅ Fast local processing

## 📦 Installation

### Using pip (Recommended)

```bash
pip install byteguardx
```

### From Source

```bash
git clone https://github.com/byteguardx/byteguardx.git
cd byteguardx
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/byteguardx/byteguardx.git
cd byteguardx
pip install -e ".[dev]"
```

## ⚡ One-Click Setup

**Linux/macOS:** `./scripts/bootstrap.sh && byteguardx init`
**Windows:** `.\scripts\bootstrap.ps1; byteguardx init`
**Manual:** `pip install -r requirements.txt && byteguardx scan /path/to/project`

## 🚀 Quick Start

### CLI Usage

```bash
# Scan a directory
byteguardx scan /path/to/your/project

# Scan with PDF report
byteguardx scan /path/to/project --pdf

# Scan with fix suggestions
byteguardx scan /path/to/project --fix

# Scan specific types only
byteguardx scan /path/to/project --secrets-only
byteguardx scan /path/to/project --deps-only
byteguardx scan /path/to/project --ai-only

# Save results to file
byteguardx scan /path/to/project --output results.json

# Verbose output
byteguardx scan /path/to/project --verbose
```

### API Usage

```bash
# Start the API server
python -m byteguardx.api.app

# Or using Flask
export FLASK_APP=byteguardx.api.app
flask run
```

### Git Hook Installation

```bash
# Install pre-commit hook
python -m byteguardx.pre_commit --install

# Configure hook settings
cat > .byteguardx-precommit.json << EOF
{
  "enabled": true,
  "block_on_critical": true,
  "block_on_high": false,
  "scan_secrets": true,
  "scan_dependencies": true,
  "scan_ai_patterns": false
}
EOF
```

## 🔧 Configuration

### CLI Configuration

```bash
# Create configuration file
byteguardx init-config .byteguardx.json
```

### Environment Variables

```bash
# API Configuration
export SECRET_KEY="your-secret-key"
export JWT_SECRET_KEY="your-jwt-secret"
export ALLOWED_ORIGINS="http://localhost:3000"

# Database paths (optional)
export BYTEGUARDX_SECRET_PATTERNS="/path/to/secret_patterns.json"
export BYTEGUARDX_VULN_DB="/path/to/vulnerable_packages.json"
export BYTEGUARDX_FIX_TEMPLATES="/path/to/fix_templates.json"
```

## 📊 Example Output

```
ByteGuardX Security Scanner
AI-Powered Vulnerability Detection

✅ Processed 45 files

┏━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━┓
┃ Category       ┃ Total ┃ Critical ┃ High ┃ Medium ┃ Low  ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━┩
│ Secrets        │    12 │        3 │    5 │      4 │    0 │
│ Dependencies   │     8 │        1 │    2 │      3 │    2 │
│ Ai_patterns    │    15 │        0 │    4 │      8 │    3 │
└────────────────┴───────┴──────────┴──────┴────────┴──────┘

🔧 Generated 25 fix suggestions

📄 PDF report generated: byteguardx_report_20231201_143022.pdf
```

## 🏢 Business Model

ByteGuardX follows a freemium SaaS model:

| Plan | Features |
|------|----------|
| **Free** | ✅ 5 scans/month<br>✅ Secrets + CVE detection<br>✅ Basic PDF reports |
| **Pro** | 🚀 Unlimited scans<br>🧠 AI pattern analysis<br>🔐 Git hooks<br>📄 Advanced reporting<br>🔁 Full CLI + API access |

## 🛡️ Security Features

- **Path Traversal Protection**: Secure file handling
- **Input Validation**: Comprehensive input sanitization
- **File Size Limits**: Prevent DoS attacks
- **MIME Type Validation**: Safe file processing
- **CSP Headers**: Content Security Policy
- **No Eval/Exec**: No dynamic code execution

## 🧪 Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=byteguardx

# Run specific test categories
pytest tests/test_scanners.py
pytest tests/test_api.py
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/byteguardx/byteguardx.git
cd byteguardx
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### Code Quality

```bash
# Format code
black byteguardx/

# Lint code
flake8 byteguardx/

# Type checking
mypy byteguardx/
```

## 📚 Documentation

- [API Documentation](docs/api.md)
- [CLI Reference](docs/cli.md)
- [Configuration Guide](docs/configuration.md)
- [Integration Examples](docs/integrations.md)

## 🐛 Bug Reports

Please report bugs on our [GitHub Issues](https://github.com/byteguardx/byteguardx/issues) page.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [WeasyPrint](https://weasyprint.org/) for PDF generation
- [Flask](https://flask.palletsprojects.com/) for the API framework
- [Rich](https://rich.readthedocs.io/) for beautiful CLI output
- [Click](https://click.palletsprojects.com/) for CLI framework

## 🔗 Links

- **Website**: [https://byteguardx.com](https://byteguardx.com)
- **Documentation**: [https://docs.byteguardx.com](https://docs.byteguardx.com)
- **GitHub**: [https://github.com/byteguardx/byteguardx](https://github.com/byteguardx/byteguardx)
- **Discord**: [https://discord.gg/byteguardx](https://discord.gg/byteguardx)

---

**Built with ❤️ for developers and security teams**
