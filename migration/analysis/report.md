# ByteGuardX Codebase Analysis Report

> **Generated**: February 6, 2026  
> **Purpose**: Comprehensive analysis for Electron-to-Tauri migration

---

## 1. File Inventory

### Top-Level Directories

| Directory | Description | Children |
|-----------|-------------|----------|
| `desktop-app/` | Electron desktop application | 3 files (main.js, preload.js, package.json) |
| `frontend/` | Vite + React frontend (alternative) | 20 items |
| `src/` | Main React frontend | 90 items (components, pages, services) |
| `byteguardx/` | Python backend (Flask) | 194 items (API, plugins, security, ML) |
| `.github/workflows/` | CI/CD pipelines | 5 workflows |
| `plugins/` | Plugin storage directory | Empty (runtime populated) |
| `data/` | Application data | 6 items |
| `docs/` | Documentation | 7 files |
| `k8s/` | Kubernetes configs | 5 files |
| `extensions/` | IDE extensions | 7 items |
| `mobile-app/` | React Native mobile app | 10 items |
| `sdks/` | SDK implementations | 4 items |

### Key Configuration Files

| File | Purpose |
|------|---------|
| `package.json` | Root Node.js config (Vite frontend) |
| `desktop-app/package.json` | Electron desktop config |
| `requirements.txt` | Python dependencies (82 lines) |
| `.env.example` | Frontend env template |
| `.env.backend.example` | Backend env template (283 lines) |
| `docker-compose.yml` | Container orchestration |
| `vercel.json` | Vercel deployment config |

---

## 2. Dependency Map

### Electron Desktop Dependencies

```json
{
  "dependencies": {
    "electron-updater": "^6.1.4",
    "electron-store": "^8.1.0",
    "axios": "^1.5.0",
    "express": "^4.18.2",
    "cors": "^2.8.5"
  },
  "devDependencies": {
    "electron": "^27.0.0",
    "electron-builder": "^24.6.4",
    "concurrently": "^8.2.2"
  }
}
```

### Frontend Dependencies (Node)

| Package | Version | Purpose |
|---------|---------|---------|
| react | 18.2.0 | UI framework |
| axios | 1.5.0 | HTTP client |
| react-router-dom | 6.16.0 | Routing |
| framer-motion | 10.16.4 | Animations |
| recharts | 3.5.1 | Data visualization |
| lucide-react | 0.288.0 | Icons |

### Backend Dependencies (Python)

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 2.3.3 | Web framework |
| Flask-CORS | 4.0.0 | Cross-origin support |
| Flask-JWT-Extended | 4.5.3 | JWT authentication |
| Flask-SocketIO | 5.3.6 | WebSocket support |
| SQLAlchemy | 2.0.23 | ORM |
| cryptography | 41.0.7 | Encryption |
| PyJWT | 2.8.0 | JWT tokens |
| pyotp | 2.9.0 | 2FA TOTP |
| psutil | 5.9.6 | System monitoring |

---

## 3. Network Surface Analysis

### Outbound Network Calls

| Location | Type | Required Offline? | Action |
|----------|------|-------------------|--------|
| `api.js:6` | API baseURL | **YES** (local) | Convert to local IPC |
| `api.js:43-51` | CSRF token fetch | Optional | Local token generation |
| `api.js:84` | Token refresh | Optional | Local-only auth |
| `main.js:330` | Auto-updater check | **NO** | Disable by default |
| `main.js:213-220` | shell.openExternal (docs/issues) | **NO** | Remove or make opt-in |
| `.env.backend.example:125` | Plugin marketplace URL | **NO** | Local cache + manual update |
| `.env.backend.example:86-87` | OpenAI/HuggingFace APIs | Optional | Local ML fallback |
| `.env.backend.example:99-102` | GitHub OAuth | **NO** | Disable in offline mode |
| `analytics_routes.py` | Analytics collection | **NO** | Local-only with toggle |

### Network Categories

- **Required for core function**: 0 (scanning is local)
- **Optional (update/telemetry)**: 6 endpoints
- **Must be disabled/flagged**: Auto-updater, OAuth, cloud marketplace

---

## 4. Frontend-Backend Coupling

### API Endpoints Used by Frontend

```
src/services/api.js exports:
├── authService
│   ├── POST /api/auth/login
│   ├── POST /api/auth/refresh
│   ├── GET /api/auth/verify
│   └── GET /api/auth/csrf-token
├── scanService
│   ├── POST /scan/upload
│   ├── POST /scan/directory
│   ├── POST /scan/secrets
│   ├── POST /scan/dependencies
│   ├── POST /scan/ai-patterns
│   ├── POST /scan/all
│   ├── GET /scan/results/:id
│   └── GET /scan/list
├── fixService
│   └── POST /fix/bulk
├── reportService
│   ├── POST /report/pdf
│   └── GET /report/download/:filename
└── healthService
    └── GET /health
```

### WebSocket Usage

- **Flask-SocketIO** configured in backend
- `websocket_handler.py` (11KB) - real-time scan progress
- Must migrate to Tauri event system or maintain as opt-in

### Local Files/DB

| Resource | Location | Usage |
|----------|----------|-------|
| SQLite DB | `byteguardx.db` | Primary data store |
| Audit logs | `data/audit_logs/` | Security logging |
| Plugins | `data/plugins/` | Installed plugins |
| Reports | `reports/` | Generated reports |
| Backups | `data/backups/` | Database backups |

---

## 5. Electron-Specific APIs Used

### main.js (401 lines)

```javascript
// Core Electron modules
const { app, BrowserWindow, Menu, ipcMain, dialog, shell } = require('electron');
const { autoUpdater } = require('electron-updater');
const Store = require('electron-store');

// IPC Handlers
ipcMain.handle('get-app-version', ...)
ipcMain.handle('get-setting', ...)
ipcMain.handle('set-setting', ...)
ipcMain.handle('show-save-dialog', ...)
ipcMain.handle('show-open-dialog', ...)

// Features
- BrowserWindow with contextIsolation: true ✓
- Native menus (File, Edit, View, Scan, Tools, Help)
- autoUpdater.checkForUpdatesAndNotify()
- Backend process spawn (Python)
- Local Express server fallback
```

### preload.js (127 lines)

```javascript
contextBridge.exposeInMainWorld('electronAPI', {
  getAppVersion,
  getSetting, setSetting,
  showSaveDialog, showOpenDialog,
  onMenuNewScan, onMenuOpenProject, etc.
  platform, path utilities
});

contextBridge.exposeInMainWorld('desktopEnhancements', {
  isDesktop: true,
  features: { fileSystemAccess, nativeMenus, autoUpdater, offlineMode },
  fileOperations: { selectDirectory, selectFiles, saveReport },
  notifications: { show },
  system: { openExternal }
});
```

---

## 6. Build Scripts & CI

### Package.json Scripts

```json
{
  "start": "electron .",
  "dev": "concurrently start-backend start-frontend electron",
  "build": "npm run build:frontend && npm run build:electron",
  "build:electron": "electron-builder",
  "build:linux": "electron-builder --linux",
  "build:win32": "electron-builder --win",
  "build:darwin": "electron-builder --mac"
}
```

### CI Workflows

| File | Purpose |
|------|---------|
| `main-ci.yml` | Tests + Docker builds |
| `release.yml` | Cross-platform Electron builds |
| `security-ci.yml` | Security scanning |
| `security-scan.yml` | Vulnerability detection |
| `security-validation.yml` | Security validation |

### Electron-Builder Config

- AppImage, DEB, RPM for Linux
- NSIS, Portable for Windows
- DMG, ZIP for macOS
- Code signing placeholders present

---

## 7. Security Risks Identified

### High Priority

| Risk | Location | Severity | Mitigation |
|------|----------|----------|------------|
| Local HTTP server | `main.js:270-286` | **HIGH** | Remove in Tauri, use Tauri commands |
| Token in localStorage | `api.js:21-23` | **MEDIUM** | Migrate to OS keychain via Tauri |
| CSRF in localStorage | `api.js:29, 48` | **MEDIUM** | Use Rust-side token management |
| Auto-update without signature | `main.js:330` | **HIGH** | Disable or require signed updates |

### Medium Priority

| Risk | Details |
|------|---------|
| `shell.openExternal` unrestricted | `main.js:77-80` - opens any URL |
| Express CORS enabled | `main.js:276` - `app.use(cors())` |
| console.log in production | Multiple locations |

### Low Priority

| Risk | Details |
|------|---------|
| process.platform exposed | `preload.js:32` |
| path utilities exposed | `preload.js:34-40` |

---

## 8. Plugin System Analysis

### Components (in `byteguardx/plugins/`)

| File | Size | Purpose |
|------|------|---------|
| `base_plugin.py` | 16KB | Plugin base class |
| `plugin_manager.py` | 19KB | Plugin lifecycle |
| `plugin_registry.py` | 20KB | Plugin registration |
| `plugin_versioning.py` | 18KB | Version management |
| `signature_verification.py` | 13KB | Plugin signatures |
| `sandbox.py` | 18KB | Process isolation |
| `hardened_sandbox.py` | 21KB | Enhanced sandbox |
| `docker_sandbox.py` | 11KB | Container-based sandbox |
| `marketplace_manager.py` | 18KB | Marketplace integration |
| `enhanced_marketplace.py` | 23KB | Enhanced marketplace |

### Sandboxing Capabilities

- Docker-based (requires Docker runtime)
- Process-level with resource limits
- Signature verification present
- Permission manifest system exists

---

## 9. ML/AI Components

### Location: `byteguardx/ml/`

- 8 files for machine learning
- Optional dependencies (commented in requirements.txt)
- OPENAI_API_KEY, HUGGINGFACE_API_KEY in env
- Local fallback available (`ENABLE_ML_FALLBACK=true`)

---

## 10. Summary Statistics

| Component | Count |
|-----------|-------|
| Python files | ~200 |
| React components | 57 |
| API endpoints | ~50 |
| Security modules | 52 |
| CI workflows | 5 |
| Test files | 11 |
| Documentation files | 20+ |

### Migration Complexity Assessment

| Area | Complexity | Notes |
|------|------------|-------|
| Electron to Tauri shell | **MEDIUM** | Well-structured, contextIsolation already enabled |
| IPC migration | **LOW** | Clear ipcMain handlers to convert |
| Backend integration | **HIGH** | Large Flask app needs IPC wrapper |
| Plugin sandboxing | **HIGH** | Need platform-specific solutions |
| Offline-first | **MEDIUM** | Network calls identified, toggles exist |
| Packaging | **LOW** | Tauri has similar cross-platform support |
