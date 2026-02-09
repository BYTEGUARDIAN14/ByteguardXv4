# ByteGuardX Cleanup - Dependency Analysis

> **Generated:** 2026-02-06  
> **Purpose:** Identify removable dependencies for offline-first Tauri migration

---

## Node.js Dependencies (Root `package.json`)

### Current Production Dependencies

| Package | Version | Used Offline? | Status | Notes |
|---------|---------|---------------|--------|-------|
| `@tauri-apps/api` | ^1.5.3 | ✅ Yes | **KEEP** | Tauri IPC |
| `axios` | 1.5.0 | ✅ Yes | **KEEP** | API calls (local backend) |
| `dompurify` | 3.0.5 | ✅ Yes | **KEEP** | XSS sanitization |
| `framer-motion` | 10.16.4 | ✅ Yes | **KEEP** | UI animations |
| `js-cookie` | 3.0.5 | ⚠️ Maybe | **REVIEW** | May be unused now |
| `lucide-react` | 0.288.0 | ✅ Yes | **KEEP** | Icons |
| `ogl` | ^1.0.11 | ✅ Yes | **KEEP** | 3D graphics |
| `react` | 18.2.0 | ✅ Yes | **KEEP** | Core framework |
| `react-dom` | 18.2.0 | ✅ Yes | **KEEP** | Core framework |
| `react-dropzone` | 14.2.3 | ✅ Yes | **KEEP** | File upload |
| `react-helmet-async` | ^2.0.5 | ⚠️ Maybe | **REVIEW** | SEO - less needed for desktop |
| `react-hot-toast` | 2.4.1 | ✅ Yes | **KEEP** | Notifications |
| `react-router-dom` | 6.16.0 | ✅ Yes | **KEEP** | Routing |
| `recharts` | ^3.5.1 | ✅ Yes | **KEEP** | Charts |

### Current Dev Dependencies

| Package | Version | Status | Notes |
|---------|---------|--------|-------|
| `@tauri-apps/cli` | ^1.5.11 | **KEEP** | Tauri build CLI |
| `@types/react*` | 18.2.* | **KEEP** | TypeScript types |
| `@vitejs/plugin-react` | 4.0.3 | **KEEP** | Vite config |
| `autoprefixer` | 10.4.16 | **KEEP** | CSS processing |
| `eslint*` | 8.* | **KEEP** | Linting |
| `postcss` | 8.4.31 | **KEEP** | CSS processing |
| `prettier` | 3.0.3 | **KEEP** | Formatting |
| `tailwindcss` | 3.3.5 | **KEEP** | Styling |
| `vite` | 4.4.5 | **KEEP** | Build tool |

### ✅ Root package.json is CLEAN

No Electron dependencies in root. Tauri dependencies already added.

---

## Electron Dependencies (`desktop-app/package.json`)

### ENTIRE FILE SHOULD BE DELETED

| Package | Type | Status | Reason |
|---------|------|--------|--------|
| `electron` | dev | **REMOVE** | Replaced by Tauri |
| `electron-builder` | dev | **REMOVE** | Replaced by Tauri |
| `concurrently` | dev | **REMOVE** | Build helper |
| `wait-on` | dev | **REMOVE** | Build helper |
| `jest` | dev | **REMOVE** | Can use root tests |
| `eslint` | dev | **REMOVE** | Duplicate of root |
| `electron-updater` | prod | **REMOVE** | Replaced by Tauri |
| `electron-store` | prod | **REMOVE** | Replaced by Rust storage |
| `axios` | prod | **REMOVE** | Duplicate |
| `express` | prod | **REMOVE** | Local server (removed) |
| `cors` | prod | **REMOVE** | Not needed |

**Action:** Delete entire `desktop-app/` folder.

---

## Python Dependencies (`requirements.txt`)

### Production Dependencies (KEEP)

| Package | Used Offline? | Status | Notes |
|---------|---------------|--------|-------|
| `Flask` | ✅ Yes | **KEEP** | Core API |
| `Flask-CORS` | ✅ Yes | **KEEP** | CORS handling |
| `Flask-JWT-Extended` | ✅ Yes | **KEEP** | JWT tokens |
| `Flask-SocketIO` | ✅ Yes | **KEEP** | Real-time updates |
| `Werkzeug` | ✅ Yes | **KEEP** | Flask dependency |
| `SQLAlchemy` | ✅ Yes | **KEEP** | Database ORM |
| `bcrypt` | ✅ Yes | **KEEP** | Password hashing |
| `Flask-Limiter` | ✅ Yes | **KEEP** | Rate limiting |
| `Flask-Talisman` | ⚠️ Maybe | **REVIEW** | Security headers (web-focused) |
| `cryptography` | ✅ Yes | **KEEP** | Encryption |
| `python-magic` | ✅ Yes | **KEEP** | File type detection |
| `validators` | ✅ Yes | **KEEP** | Input validation |
| `PyJWT` | ✅ Yes | **KEEP** | JWT handling |
| `pyotp` | ✅ Yes | **KEEP** | 2FA |
| `passlib` | ✅ Yes | **KEEP** | Password utilities |
| `email-validator` | ✅ Yes | **KEEP** | Email validation |
| `pathvalidate` | ✅ Yes | **KEEP** | Path validation |
| `psutil` | ✅ Yes | **KEEP** | System monitoring |
| `click` | ✅ Yes | **KEEP** | CLI |
| `rich` | ✅ Yes | **KEEP** | CLI output |
| `httpx` | ⚠️ Maybe | **REVIEW** | HTTP client (cloud calls?) |
| `pyyaml` | ✅ Yes | **KEEP** | Config parsing |
| `jsonschema` | ✅ Yes | **KEEP** | Schema validation |
| `python-dotenv` | ✅ Yes | **KEEP** | Env loading |
| `bleach` | ✅ Yes | **KEEP** | Sanitization |

### Optional Dependencies (Already Commented Out)

These are already commented out in requirements.txt - no action needed.

---

## Summary

### Immediate Actions

| Action | Target | Impact |
|--------|--------|--------|
| **DELETE** | `desktop-app/package.json` | Remove Electron deps |
| **DELETE** | `desktop-app/` folder | Remove entire Electron app |
| **REVIEW** | `js-cookie` | May be unused |
| **REVIEW** | `react-helmet-async` | SEO less relevant for desktop |
| **REVIEW** | `httpx` | Check if used for cloud calls only |
| **REVIEW** | `Flask-Talisman` | Security headers for web |

### Already Clean

- ✅ Root `package.json` has no Electron deps
- ✅ Tauri deps already added
- ✅ Python `requirements.txt` is minimal

---

## Removal Commands

```bash
# Delete Electron app entirely
rm -rf desktop-app/

# Check for unused npm packages
npx depcheck

# Audit npm for vulnerabilities
npm audit

# Check Python for unused packages
pip install pip-autoremove
pip-autoremove --list
```
