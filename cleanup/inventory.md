# ByteGuardX Codebase Cleanup - File Inventory

> **Generated:** 2026-02-06  
> **Purpose:** Identify files for removal/deprecation during Tauri offline-first migration  
> **Safety Rule:** Never delete scanning, ML, plugin, or file processing code

---

## Categories

| Category | Description | Action |
|----------|-------------|--------|
| **A** | Core Offline Code | DO NOT TOUCH |
| **B** | Legacy / Online-Only | CANDIDATE FOR REMOVAL |
| **C** | Transitional Code | KEEP TEMPORARILY |
| **D** | Dead / Unreferenced | SAFE TO DELETE |

---

## A. Core Offline Code (DO NOT TOUCH)

### Scanners (`byteguardx/scanners/`)
| File | Reason |
|------|--------|
| `secret_scanner.py` | Core scanning logic |
| `dependency_scanner.py` | CVE detection |
| `code_analyzer.py` | AST analysis |
| All files in `scanners/` | Core functionality |

### ML/AI (`byteguardx/ml/`)
| File | Reason |
|------|--------|
| All files | AI pattern detection |

### Plugins (`byteguardx/plugins/`)
| File | Reason |
|------|--------|
| All 37 files | Plugin ecosystem |

### Core (`byteguardx/core/`)
| File | Reason |
|------|--------|
| `file_processor.py` | File handling |
| All files | Core processing |

### Reports (`byteguardx/reports/`, `byteguardx/reporting/`)
| File | Reason |
|------|--------|
| All files | Report generation |

### Security (`byteguardx/security/`)
| File | Reason |
|------|--------|
| All 52 files | Security analysis logic |

### Database (`byteguardx/database/`, `byteguardx/offline_db/`)
| File | Reason |
|------|--------|
| All files | Local storage |

### Tauri Backend (`src-tauri/`)
| File | Reason |
|------|--------|
| All files | New Tauri implementation |

### Engine CLI (`engine/`)
| File | Reason |
|------|--------|
| `cli.py`, `__init__.py` | Tauri IPC bridge |

---

## B. Legacy / Online-Only Code (CANDIDATE FOR REMOVAL)

### Electron Desktop App (`desktop-app/`)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `desktop-app/package.json` | B | SAFE | Replaced by Tauri |
| `desktop-app/src/main.js` | B | SAFE | Electron main process |
| `desktop-app/src/preload.js` | B | SAFE | Electron preload |
| **Entire folder** | B | **SAFE TO DELETE** | Replaced by `src-tauri/` |

### Dockerfiles (SaaS Deployment)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `Dockerfile.backend` | B | NEEDS REVIEW | May be useful for dev |
| `Dockerfile.frontend` | B | NEEDS REVIEW | May be useful for dev |
| `Dockerfile.security` | B | SAFE | Security hardened container |
| `docker-compose.yml` | B | NEEDS REVIEW | Development utility |
| `docker-compose.scale.yml` | B | SAFE | SaaS scaling only |

### SaaS/Cloud Deployment
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `k8s/` (entire folder) | B | SAFE | Kubernetes configs |
| `vercel.json` | B | SAFE | Vercel deployment |
| `DEPLOYMENT_GUIDE.md` | B | SAFE | Cloud deployment docs |

### Analytics Backend (`byteguardx/analytics/`)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `analytics_routes.py` | B | NEEDS REVIEW | Cloud analytics |
| `byteguardx/api/analytics_routes.py` | B | NEEDS REVIEW | Web analytics |

### Web Portals
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `byteguardx-portal/` (entire folder) | B | SAFE | Web-only portal |
| `portal/` (entire folder) | B | SAFE | Marketing portal |
| `frontend/` (entire folder) | B | NEEDS REVIEW | May be duplicate of `src/` |

### Mobile Apps (Not Offline Desktop)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `mobile-app/` (entire folder) | B | SAFE | Mobile-only |
| `mobile/` (entire folder) | B | SAFE | Mobile-only |

---

## C. Transitional Code (KEEP TEMPORARILY)

### Auth Compatibility Wrappers
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `src/components/ProtectedRoute.jsx` | C | KEEP | No-op wrapper, still imported |
| `src/contexts/AuthContext.jsx` | C | KEEP | Mock user for offline |

### API Compatibility
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `src/services/api.js` | C | KEEP | Still used as fallback |
| `src/services/tauri-api.js` | A | KEEP | New Tauri API |

### Backend API (Still Needed Offline)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `byteguardx/api/app.py` | C | KEEP | Core API, called by engine |
| `byteguardx/auth/` | C | KEEP | Auth decorators still used |

---

## D. Dead / Unreferenced Code (SAFE TO DELETE)

### Test HTML Files (Debug Only)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `src/test-signup.html` | D | **SAFE** | Debug file, not imported |
| `src/test-frontend-scan.html` | D | **SAFE** | Debug file |
| `src/test-file-scan.html` | D | **SAFE** | Debug file |
| `src/test-dashboard-complete.html` | D | **SAFE** | Debug file |
| `src/test-csrf.html` | D | **SAFE** | Debug file |
| `src/test-connection.html` | D | **SAFE** | Debug file |
| `src/test-complete-scan-workflow.html` | D | **SAFE** | Debug file |
| `src/test-auth-and-scan.html` | D | **SAFE** | Debug file |
| `debug_black_overlay.html` | D | **SAFE** | Debug file |
| `test_overlay_fix.html` | D | **SAFE** | Debug file |

### Root-Level Test/Debug Python Scripts
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `debug_model.py` | D | **SAFE** | Debug script |
| `debug_register.py` | D | **SAFE** | Debug script |
| `debug_server_startup.py` | D | **SAFE** | Debug script |
| `debug-scan.js` | D | **SAFE** | Debug script |
| `test_*.py` (22 files) | D | **SAFE** | Ad-hoc test files |
| `test-*.js` (3 files) | D | **SAFE** | Debug scripts |
| `check_db.py` | D | **SAFE** | Debug script |
| `inspect_db.py` | D | **SAFE** | Debug script |
| `quick_analysis.py` | D | **SAFE** | Debug script |
| `quick_test.py` | D | **SAFE** | Debug script |

### Unused Fix/Utility Scripts
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `clean_plugin_imports.py` | D | **SAFE** | One-time fix |
| `fix_all_plugin_imports.py` | D | **SAFE** | One-time fix |
| `fix_plugin_imports.py` | D | **SAFE** | One-time fix |
| `fix_database.py` | D | **SAFE** | One-time fix |
| `update_plugin_imports.py` | D | **SAFE** | One-time fix |
| `analyze_and_fix_all_issues.py` | D | **SAFE** | One-time utility |

### Duplicate/Clean Pages
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `src/pages/Scan_clean.jsx` | D | **SAFE** | Duplicate of Scan.jsx |
| `src/pages/PluginMarketplace_clean.jsx` | D | **SAFE** | Duplicate |

### Log/Temp Files
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `error.log` | D | **SAFE** | Log file |
| `error_log.txt` | D | **SAFE** | Log file |
| `error_log_6.txt` | D | **SAFE** | Log file |
| `security_validation_report.txt` | D | **SAFE** | Report output |
| `*.db-shm`, `*.db-wal` | D | **SAFE** | SQLite temp files |
| `ci_security_results.json` | D | **SAFE** | CI output |
| `security_report.json` | D | **SAFE** | Report output |
| `security_validation_results.json` | D | **SAFE** | Report output |
| `test_login.json` | D | **SAFE** | Test fixture |

### Old Markdown Docs (Superseded)
| File | Category | Status | Reason |
|------|----------|--------|--------|
| `AUTH_IMPLEMENTATION.md` | D | NEEDS REVIEW | May be referenced |
| `PURE_BLACK_THEME_APPLIED.md` | D | **SAFE** | Theme change log |
| `ENHANCED_UI_UX_IMPLEMENTATION.md` | D | NEEDS REVIEW | May be useful |
| `PRIORITY_*_IMPLEMENTATION.md` | D | NEEDS REVIEW | Feature docs |

---

## Summary Counts

| Category | Count | Action |
|----------|-------|--------|
| A - Core | ~100+ files | Keep |
| B - Online-Only | ~50 files | Review/Remove |
| C - Transitional | ~10 files | Keep temporarily |
| D - Dead Code | **~60 files** | Safe to delete |

---

## Next Steps

1. Review `cleanup/dependencies.md` for package cleanup
2. Review `cleanup/electron-removal-plan.md` for Electron isolation
3. Review `cleanup/auth-cleanup.md` for auth pruning
4. Execute deletions in atomic commits
