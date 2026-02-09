# ByteGuardX Electron-to-Tauri Migration Plan

> **Version**: 1.0  
> **Status**: Draft for Review  
> **Target**: Fully offline, native desktop application powered by Tauri

---

## Executive Summary

This migration converts ByteGuardX from an Electron-based hybrid web app to a Tauri-powered native desktop application with:
- **Offline-first design** - no network required for core functionality
- **Enhanced security** - minimal permissions, plugin sandboxing, no local HTTP server
- **Smaller bundle size** - Tauri uses native WebView (~50MB vs ~200MB Electron)
- **Full feature preservation** - all existing capabilities maintained

---

## Phase Overview

| Phase | Name | Duration | Status |
|-------|------|----------|--------|
| 0 | Preparation | 0.5 day | Pending |
| 1 | Tauri Scaffold | 1.5 days | Pending |
| 2 | Backend IPC | 3 days | Pending |
| 3 | IPC Migration | 2 days | Pending |
| 4 | Storage Migration | 1 day | Pending |
| 5 | Menu & Tray | 1 day | Pending |
| 6 | Plugin Sandboxing | 4 days | Pending |
| 7 | Offline-First | 2 days | Pending |
| 8 | Packaging & CI | 2 days | Pending |

**Total Estimated Duration**: ~20 days (1 senior developer)

---

## Phase 0 — Preparation

### Git Branch Strategy
```bash
git checkout -b tauri-migration
git tag electron-legacy-v1.0 main
git push origin electron-legacy-v1.0
```

### Files to Create/Modify
- `.tauri-ignore` - Tauri build exclusions
- `.gitignore` - Add Tauri artifacts

---

## Phase 1 — Tauri Scaffold

### New Directory Structure
```
src-tauri/
├── Cargo.toml
├── Cargo.lock
├── tauri.conf.json
├── build.rs
├── icons/
└── src/
    ├── main.rs
    ├── commands.rs
    ├── python_bridge.rs
    ├── storage.rs
    ├── menu.rs
    └── sandbox.rs
```

### Key Configuration
- Minimal permissions (fs, dialog, process spawn only)
- CSP enforcement
- Auto-updater disabled by default

---

## Phase 2 — Backend Decoupling

### Option A: Pure Python Engine (RECOMMENDED)

New `engine/cli.py` accepting JSON-RPC-style commands on stdin:
```json
{"cmd": "scan", "args": {"path": "/project", "options": {}}}
```

Response format:
```json
{"success": true, "data": {...}, "error": null}
```

Rust spawns Python process and manages IPC via stdin/stdout.

### Option B: Flask Localhost (Quick Migration)

Keep Flask temporarily with hardening:
- Bind to 127.0.0.1 only
- Ephemeral port selection
- Strict CORS for tauri://localhost
- Migrate to Option A later

---

## Phase 3 — IPC Migration

### Electron → Tauri Mapping

| Electron | Tauri |
|----------|-------|
| `ipcRenderer.send()` | `invoke()` |
| `ipcMain.handle()` | `#[tauri::command]` |
| `electron-store` | Custom file storage |
| `shell.openExternal()` | `shell::open()` (restricted) |
| `dialog.showOpenDialog()` | `dialog::open()` |

### Files Changed
- `src/services/api.js` → `src/services/tauri-api.js`
- New `src/utils/platform.js` for feature detection

---

## Phase 4 — Storage Migration

### Migration Script
One-time conversion from `electron-store` format to Tauri app data.

### New Storage Location
- Windows: `%APPDATA%\com.byteguardx.desktop\`
- macOS: `~/Library/Application Support/com.byteguardx.desktop/`
- Linux: `~/.config/com.byteguardx.desktop/`

---

## Phase 5 — Menu & Tray

Native menus matching Electron implementation:
- File (New Scan, Open Project, Export, Quit)
- Edit (Undo, Redo, Cut, Copy, Paste)
- View (Reload, DevTools, Zoom)
- Scan (Quick, Deep, Settings)
- Tools (Dashboard, Vuln DB, Preferences)
- Help (Docs, Report Issue, About)

---

## Phase 6 — Plugin Sandboxing

### Platform-Specific Approach

| Platform | Technique |
|----------|-----------|
| Linux | unshare + prlimit + seccomp |
| macOS | sandbox-exec profiles |
| Windows | Job Objects + restricted tokens |

### Plugin Verification
- SHA-256 checksum validation
- Manifest permission declarations
- Version compatibility checks

---

## Phase 7 — Offline-First Adaptations

### Network Calls Converted

| Original | Offline Equivalent |
|----------|-------------------|
| Auto-updater | Manual download + verify |
| Plugin marketplace | Local cache + manual install |
| Telemetry | Disabled by default |
| OAuth login | Local-only auth |
| Vuln DB sync | Manual signed pack import |

### New Settings
- "Allow check for updates" (off by default)
- "Allow anonymous telemetry" (off by default)

---

## Phase 8 — Packaging & CI

### Build Targets

| Platform | Format |
|----------|--------|
| Windows | MSI, NSIS installer |
| macOS | DMG, notarization ready |
| Linux | AppImage, DEB, RPM |

### GitHub Actions Workflow
- Cross-platform matrix build
- Rust toolchain setup
- Frontend build
- Tauri bundle creation
- Artifact upload

---

## Security Hardening

- [x] No embedded secrets (use .env)
- [x] CSP enforcement
- [x] Minimal Tauri allowlist
- [x] Plugin sandboxing
- [x] SHA-256 artifact verification
- [x] No auto-update without signature
- [x] No local HTTP server exposure
- [x] Input validation in Rust handlers

---

## Rollback Procedure

1. Checkout `electron-legacy-v1.0` tag
2. Run `npm run build:electron`
3. Distribute Electron build
4. Optional: `migration/scripts/rollback-storage.js`

---

## Dependencies

### Build Requirements
- Rust 1.70+
- Node.js 18+
- Python 3.9+
- Platform-specific: GTK3/WebKit2 (Linux), Xcode (macOS)

---

## See Also

- [Analysis Report](./analysis/report.md) - Detailed codebase analysis
- [Acceptance Criteria](./acceptance.md) - Verification checklist
