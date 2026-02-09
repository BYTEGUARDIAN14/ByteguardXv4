# ByteGuardX Electron-to-Tauri Migration Changelog

## [1.0.0] - Migration Release

### Added
- **Tauri Framework** - Replaced Electron with Tauri v1.5 for native desktop experience
- **Rust Backend** - New command handlers in `src-tauri/src/commands.rs`
- **Python Engine CLI** - JSON-RPC style interface in `engine/cli.py`
- **Plugin Sandboxing** - Platform-specific isolation (Linux namespaces, macOS sandbox-exec, Windows Job Objects)
- **Offline-First Settings** - Updates and telemetry disabled by default
- **Unified API Layer** - `src/services/tauri-api.js` with web fallbacks
- **GitHub Actions CI** - Cross-platform build workflow

### Changed
- **IPC System** - Electron `ipcRenderer` → Tauri `invoke()`
- **Settings Storage** - `electron-store` → JSON files in app data directory
- **Native Menus** - Electron `Menu` → Tauri Rust menus
- **File Dialogs** - Electron `dialog` → Tauri dialog API
- **Bundle Size** - ~200MB → ~50-70MB

### Removed
- Electron dependencies (`electron`, `electron-builder`, `electron-updater`, `electron-store`)
- Local HTTP server fallback
- Auto-updater (disabled by default for offline mode)

### Security
- Strict CSP enforcement in `tauri.conf.json`
- Minimal allowlist (only required permissions)
- Plugin checksum verification
- Input validation in all Rust command handlers
- Sandboxed plugin execution

---

## Migration Notes

### For Users
1. Your settings will be reset after the migration
2. The app no longer requires network connectivity for core features
3. Update and telemetry features are opt-in (off by default)

### For Developers
1. Clone the `tauri-migration` branch
2. Install Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
3. Install dependencies: `npm install`
4. Run development: `npm run tauri:dev`
5. Build production: `npm run tauri:build`

### Rollback Procedure
If you need to revert to the Electron version:
```bash
git checkout electron-legacy-v1.0
cd desktop-app
npm install
npm run build
```

---

## File Structure After Migration

```
ByteguardX/
├── src-tauri/                 # NEW: Tauri Rust backend
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   └── src/
│       ├── main.rs
│       ├── commands.rs
│       ├── storage.rs
│       ├── python_bridge.rs
│       ├── menu.rs
│       └── sandbox.rs
├── engine/                    # NEW: Python engine CLI
│   ├── __init__.py
│   └── cli.py
├── src/
│   ├── services/
│   │   └── tauri-api.js      # NEW: Unified API wrapper
│   └── ...
├── desktop-app/               # DEPRECATED: Electron (kept for rollback)
├── .github/workflows/
│   └── tauri-build.yml       # NEW: CI for Tauri builds
└── migration/
    ├── plan.md
    ├── acceptance.md
    ├── CHANGELOG.md          # This file
    └── analysis/
        └── report.md
```
