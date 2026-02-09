# ByteGuardX Cleanup - Electron Removal Plan

> **Generated:** 2026-02-06  
> **Purpose:** Safely isolate and remove Electron-specific code

---

## Electron Components Identified

### `desktop-app/` Directory Structure

```
desktop-app/
├── package.json          # Electron dependencies
├── src/
│   ├── main.js          # Electron main process
│   └── preload.js       # Electron preload script
└── (node_modules/, etc.)
```

---

## File-by-File Analysis

### 1. `desktop-app/package.json`

| Aspect | Value |
|--------|-------|
| **Path** | `desktop-app/package.json` |
| **Size** | 2924 bytes |
| **Action** | **REMOVE IMMEDIATELY** |
| **Reason** | Replaced by root `package.json` + `src-tauri/Cargo.toml` |
| **References** | None in main codebase |
| **Rollback** | Available via `git checkout electron-legacy-v1.0` |

### 2. `desktop-app/src/main.js`

| Aspect | Value |
|--------|-------|
| **Path** | `desktop-app/src/main.js` |
| **Size** | ~15KB |
| **Action** | **REMOVE IMMEDIATELY** |
| **Reason** | Replaced by `src-tauri/src/main.rs` |
| **References** | None - only loaded by Electron |
| **Contains** | BrowserWindow, autoUpdater, electron-store, IPC handlers |

### 3. `desktop-app/src/preload.js`

| Aspect | Value |
|--------|-------|
| **Path** | `desktop-app/src/preload.js` |
| **Size** | ~4KB |
| **Action** | **REMOVE IMMEDIATELY** |
| **Reason** | Replaced by `src/services/tauri-api.js` |
| **References** | None - only loaded by Electron |
| **Contains** | electronAPI, desktopEnhancements exposed to renderer |

---

## Mapping: Electron → Tauri Replacements

| Electron Component | Tauri Replacement | Status |
|--------------------|-------------------|--------|
| `main.js` | `src-tauri/src/main.rs` | ✅ Created |
| `preload.js` | `src/services/tauri-api.js` | ✅ Created |
| `electron-store` | `src-tauri/src/storage.rs` | ✅ Created |
| `ipcMain.handle()` | `#[tauri::command]` | ✅ Created |
| `ipcRenderer.invoke()` | `invoke()` from `@tauri-apps/api` | ✅ Created |
| `BrowserWindow` | `tauri.conf.json` windows config | ✅ Created |
| `autoUpdater` | Disabled (offline-first) | ✅ Configured |
| `shell.openExternal` | Tauri shell (restricted) | ✅ Configured |
| `dialog.showOpenDialog` | Tauri dialog API | ✅ Created |
| `Menu` | `src-tauri/src/menu.rs` | ✅ Created |

---

## Removal Action

### Status: **SAFE TO DELETE ENTIRE FOLDER**

```bash
# Verify no imports reference desktop-app
grep -r "desktop-app" --include="*.js" --include="*.jsx" --include="*.py" src/ byteguardx/
# Expected: No results (already verified)

# Delete Electron folder
rm -rf desktop-app/
```

---

## Remaining Electron References to Clean

### In Frontend (Already Handled)

| File | Reference | Status |
|------|-----------|--------|
| `src/services/tauri-api.js` | `window.__TAURI__` check | ✅ Correct (detection) |

### In CI/CD Workflows

| File | Reference | Action |
|------|-----------|--------|
| `.github/workflows/release.yml` | Electron build steps | **REMOVE** or update |
| `.github/workflows/main-ci.yml` | May reference electron | **REVIEW** |

### In Documentation

| File | Reference | Action |
|------|-----------|--------|
| `README.md` | May mention Electron | **UPDATE** |
| Various `*.md` docs | May reference desktop-app | **UPDATE** later |

---

## Rollback Procedure

If removal causes issues:

```bash
# Restore from legacy tag
git checkout electron-legacy-v1.0 -- desktop-app/

# Or cherry-pick specific files
git checkout electron-legacy-v1.0 -- desktop-app/src/main.js
```

---

## Summary

| Item | Action | Risk |
|------|--------|------|
| `desktop-app/` folder | **DELETE** | Low (fully replaced) |
| Root `package.json` | Already clean | None |
| CI workflows | Update later | Low |
| Documentation | Update later | Low |
