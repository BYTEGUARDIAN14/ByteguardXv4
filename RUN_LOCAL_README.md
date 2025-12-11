# ByteGuardX - Run Locally Guide

## Quick Start (Single Command)

### Windows
```bash
run_local.bat
```

### Linux/Mac
```bash
chmod +x run_local.sh
./run_local.sh
```

### Cross-Platform (Python)
```bash
python run_byteguardx_local.py
```

## What This Does

The local runner will automatically:

1. ✅ **Check System Requirements**
   - Python 3.8+ compatibility
   - Node.js availability

2. ✅ **Install Dependencies**
   - Python packages from `requirements.txt`
   - Optional ML packages for enhanced scanning
   - Node.js packages from `package.json`

3. ✅ **Setup Environment**
   - Configure development environment variables
   - Create necessary directories (`data`, `logs`, `reports`, `temp`)

4. ✅ **Start Backend Server**
   - Flask API server on `http://localhost:5000`
   - Health check endpoint at `/health`
   - Enhanced scanning API at `/api/v2/scan/unified`

5. ✅ **Start Frontend Server**
   - React development server on `http://localhost:3000`
   - Hot reload enabled for development

6. ✅ **Monitor & Manage**
   - Automatic process monitoring
   - Graceful shutdown with Ctrl+C
   - Error handling and recovery

## Access Points

Once running, you can access:

### 🌐 Main Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **Health Check**: http://localhost:5000/health
- **API Docs**: http://localhost:5000/api/docs

### 🧪 Test Pages
- **Connection Test**: http://localhost:3000/test-connection.html
- **Authentication**: http://localhost:3000/test-signup.html
- **Complete Workflow**: http://localhost:3000/test-dashboard-complete.html
- **File Scan Test**: http://localhost:3000/test-file-scan.html

### 🔧 Enhanced Scanning Features
- **Unified Scanner**: `POST /api/v2/scan/unified`
- **Result Verification**: Built-in accuracy validation
- **Plugin Trust Scoring**: Reliability assessment
- **Cross-Validation**: Multi-scanner verification
- **Explainable AI**: Confidence breakdowns and explanations

## System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **Node.js**: 14.0 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space

### Optional Dependencies
- **ML Features**: numpy, scikit-learn, pandas (auto-installed)
- **Database**: SQLite (included) or PostgreSQL/MySQL
- **Redis**: For advanced caching (optional)

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Kill processes on ports 3000 and 5000
   # Windows:
   netstat -ano | findstr :3000
   taskkill /PID <PID> /F
   
   # Linux/Mac:
   lsof -ti:3000 | xargs kill -9
   lsof -ti:5000 | xargs kill -9
   ```

2. **Python Dependencies Failed**
   ```bash
   # Upgrade pip and try again
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Node Dependencies Failed**
   ```bash
   # Clear npm cache and reinstall
   npm cache clean --force
   rm -rf node_modules package-lock.json
   npm install
   ```

4. **Backend Won't Start**
   ```bash
   # Check Python path and modules
   python -c "import byteguardx; print('OK')"
   
   # Run backend directly for debugging
   python -m byteguardx.api.app
   ```

5. **Frontend Won't Start**
   ```bash
   # Run frontend directly for debugging
   npm run dev
   ```

### Debug Mode

For detailed logging, set environment variable:
```bash
export BYTEGUARDX_DEBUG=true
python run_byteguardx_local.py
```

### Manual Setup (Alternative)

If the automated script fails, you can run manually:

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install Node dependencies
npm install

# 3. Start backend (Terminal 1)
python -m byteguardx.api.app

# 4. Start frontend (Terminal 2)
npm run dev
```

## Development Features

### Hot Reload
- Frontend: Automatic reload on file changes
- Backend: Manual restart required for Python changes

### Environment Variables
```bash
FLASK_ENV=development
NODE_ENV=development
BYTEGUARDX_ENV=development
PYTHONPATH=<project_root>
```

### File Structure
```
ByteguardX/
├── byteguardx/           # Python backend
├── src/                  # React frontend
├── data/                 # Runtime data
├── logs/                 # Application logs
├── reports/              # Scan reports
├── temp/                 # Temporary files
└── run_byteguardx_local.py  # Startup script
```

## Production Deployment

For production deployment, see:
- `DEPLOYMENT_GUIDE.md`
- `docker-compose.yml`
- `k8s/` directory for Kubernetes

## Support

If you encounter issues:

1. Check the logs in the `logs/` directory
2. Verify system requirements
3. Try the manual setup steps
4. Check GitHub issues or create a new one

## Enhanced Scanning System

This local setup includes the new enhanced scanning features:

- **Unified Scanner**: Orchestrates all scanning components
- **Result Verification**: Cross-validates findings for accuracy
- **Plugin Trust Scoring**: Evaluates plugin reliability
- **Explainable AI**: Provides confidence breakdowns and explanations
- **Performance Optimization**: Caching and parallel processing

Access these features through the new API endpoint:
```bash
curl -X POST http://localhost:5000/api/v2/scan/unified \
  -H "Content-Type: application/json" \
  -d '{
    "content": "api_key = \"sk-1234567890abcdef\"",
    "file_path": "config.py",
    "scan_mode": "comprehensive",
    "enable_verification": true,
    "enable_explanations": true
  }'
```
