# ByteGuardX Marketing Portal - Local Development Setup

This guide will help you set up the ByteGuardX Marketing Portal for local development, including both backend and frontend components.

## Prerequisites

- **Python 3.8+**
- **Node.js 18+**
- **Git**

## 1. Clone the Repository

```powershell
git clone https://github.com/byteguardx/byteguardx.git
cd byteguardx
```

## 2. Backend Setup (Flask API)

### Create and activate a virtual environment

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux/macOS
python -m venv .venv
source .venv/bin/activate
```

### Install Python dependencies

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### Create a .env.local file for backend

Create a file named `.env.local` in the project root with the following content:

```
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=1
BYTEGUARDX_DEBUG=true

# Server Configuration
PORT=5000

# CORS Configuration (for frontend dev servers)
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://localhost:3002,http://127.0.0.1:3002

# Security (Development Keys Only - DO NOT USE IN PRODUCTION)
SECRET_KEY=dev-secret-key-change-in-production
JWT_SECRET_KEY=dev-jwt-secret-key-change-in-production
ENABLE_2FA=False
ENABLE_AUDIT_LOGGING=True
ENABLE_RATE_LIMITING=True
ENABLE_ENCRYPTION=True

# Database Configuration (SQLite for local development)
DATABASE_URL=sqlite:///data/byteguardx.db

# Email Configuration (Optional - for testing email features)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USERNAME=test
SMTP_PASSWORD=test
EMAIL_FROM=no-reply@byteguardx.local

# Sandbox API Keys (Safe for development)
SANDBOX_API_KEY=sk_test_byteguardx1234567890
SANDBOX_STRIPE_KEY=pk_test_stripe1234567890
SANDBOX_GITHUB_TOKEN=github_pat_test1234567890

# Logging
LOG_LEVEL=DEBUG
LOG_FILE=logs/byteguardx-dev.log
```

### Create necessary directories

```powershell
# Windows (PowerShell)
mkdir -Force data, logs, reports, temp

# Linux/macOS
mkdir -p data logs reports temp
```

### Start the backend server

```powershell
# Option 1: Using Python module directly
python -m byteguardx.api.app

# Option 2: Using run_server.py
python run_server.py

# Option 3: Using Flask CLI
$env:FLASK_APP = "byteguardx.api.app"
$env:FLASK_ENV = "development"
flask run --host=0.0.0.0 --port=5000
```

The backend server will start on http://localhost:5000

## 3. Frontend Setup (byteguardx-portal)

### Navigate to the portal directory

```powershell
cd byteguardx-portal
```

### Install Node.js dependencies

```powershell
npm install
```

### Create a .env.local file for frontend

Create a file named `.env.local` in the `byteguardx-portal` directory with the following content:

```
# API Configuration
VITE_API_BASE_URL=http://localhost:5000
VITE_API_URL=http://localhost:5000

# Development Mode
NODE_ENV=development

# Feature Flags
VITE_SHOW_PERF=true
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_DEBUG_TOOLS=true

# Optional HTTPS for Vite (requires certificates)
VITE_HTTPS=false
```

### Start the frontend development server

```powershell
npm run dev
```

The frontend server will start on http://localhost:3002 with hot-reload enabled.

## 4. Verify Integration

### Test Backend API Endpoints

Open a browser or use curl/Postman to verify the backend is running:

```
GET http://localhost:5000/health
```

You should receive a JSON response with status "healthy".

### Test Frontend-Backend Integration

1. Open http://localhost:3002 in your browser
2. The frontend should load and connect to the backend API
3. Check the browser console for any CORS or connection errors
4. Test the contact form submission and analytics tracking

## 5. Debugging

### Backend Debugging

- Check logs in the `logs` directory
- Enable verbose logging by setting `BYTEGUARDX_DEBUG=true` in `.env.local`
- Use a tool like Postman to test API endpoints directly

### Frontend Debugging

- Use browser developer tools (F12) to check for console errors
- Monitor network requests to verify API calls
- Use React DevTools for component debugging

## 6. Stopping and Restarting

### Stop the servers

Press `Ctrl+C` in each terminal window to stop the servers.

### Restart the servers

```powershell
# Backend (from project root)
python -m byteguardx.api.app

# Frontend (from byteguardx-portal directory)
npm run dev
```

## 7. Alternative: All-in-One Startup

For convenience, you can use the provided startup script:

```powershell
# Windows (PowerShell)
node start-byteguardx.js

# Linux/macOS
node start-byteguardx.js
```

This script will start both backend and frontend servers and open the application in your default browser.

## Troubleshooting

### Port Already in Use

```powershell
# Windows (PowerShell)
netstat -ano | findstr :5000
taskkill /PID <PID> /F

netstat -ano | findstr :3002
taskkill /PID <PID> /F

# Linux/macOS
lsof -ti:5000 | xargs kill -9
lsof -ti:3002 | xargs kill -9
```

### CORS Issues

Verify that your backend CORS configuration includes your frontend origin:
- Check that `ALLOWED_ORIGINS` in `.env.local` includes `http://localhost:3002`
- Verify the proxy settings in `byteguardx-portal/vite.config.ts`

### Database Issues

If you encounter database errors:
```powershell
# Create a fresh database
rm data/byteguardx.db
python -c "from byteguardx.database.connection_pool import init_db; init_db('sqlite:///data/byteguardx.db')"
```
