# ByteGuardX Cleanup - Safe Deletion Implementation

> **Generated:** 2026-02-06  
> **Purpose:** Execute safe deletions with atomic commits

---

## Pre-Deletion Checklist

- [ ] Backup created or commit tagged
- [ ] No open branches modifying these files
- [ ] Verified no imports reference deleted files

---

## Safe Deletion Groups

### Group 1: Electron App (HIGHEST PRIORITY)

**Reason:** Completely replaced by Tauri.

| File/Folder | Verified Unused |
|-------------|-----------------|
| `desktop-app/` (entire folder) | ✅ No imports |

```bash
# Commit 1: Remove Electron desktop app
git rm -rf desktop-app/
git commit -m "chore(cleanup): remove Electron desktop app (replaced by Tauri)"
```

---

### Group 2: Test HTML Files

**Reason:** Debug files not imported or shipped.

| File | Verified Unused |
|------|-----------------|
| `src/test-signup.html` | ✅ Not imported |
| `src/test-frontend-scan.html` | ✅ Not imported |
| `src/test-file-scan.html` | ✅ Not imported |
| `src/test-dashboard-complete.html` | ✅ Not imported |
| `src/test-csrf.html` | ✅ Not imported |
| `src/test-connection.html` | ✅ Not imported |
| `src/test-complete-scan-workflow.html` | ✅ Not imported |
| `src/test-auth-and-scan.html` | ✅ Not imported |

```bash
# Commit 2: Remove debug HTML test files
git rm src/test-*.html
git commit -m "chore(cleanup): remove debug HTML test files"
```

---

### Group 3: Root Debug/Test Files

**Reason:** Ad-hoc scripts not part of application.

| File | Verified Unused |
|------|-----------------|
| `debug_model.py` | ✅ Standalone |
| `debug_register.py` | ✅ Standalone |
| `debug_server_startup.py` | ✅ Standalone |
| `debug-scan.js` | ✅ Standalone |
| `debug_black_overlay.html` | ✅ Standalone |
| `test_overlay_fix.html` | ✅ Standalone |

```bash
# Commit 3: Remove root-level debug scripts
git rm debug_*.py debug-*.js debug_*.html test_overlay_fix.html
git commit -m "chore(cleanup): remove root-level debug scripts"
```

---

### Group 4: Root Test Files

**Reason:** Test scripts (tests should be in `tests/`).

| File | Verified Unused |
|------|-----------------|
| `test_*.py` (22 files) | ✅ Standalone |
| `test-*.js` (3 files) | ✅ Standalone |
| `test_login.json` | ✅ Test fixture |

```bash
# Commit 4: Remove root-level test scripts
git rm test_*.py test-*.js test_login.json
git commit -m "chore(cleanup): move test scripts (consolidated in tests/)"
```

---

### Group 5: One-Time Fix Scripts

**Reason:** Already applied, no longer needed.

| File | Verified Unused |
|------|-----------------|
| `clean_plugin_imports.py` | ✅ One-time fix |
| `fix_all_plugin_imports.py` | ✅ One-time fix |
| `fix_plugin_imports.py` | ✅ One-time fix |
| `fix_database.py` | ✅ One-time fix |
| `update_plugin_imports.py` | ✅ One-time fix |
| `analyze_and_fix_all_issues.py` | ✅ One-time fix |

```bash
# Commit 5: Remove one-time fix scripts
git rm clean_plugin_imports.py fix_*.py update_plugin_imports.py analyze_and_fix_all_issues.py
git commit -m "chore(cleanup): remove one-time fix scripts (already applied)"
```

---

### Group 6: Duplicate Page Files

**Reason:** Superseded by main versions.

| File | Verified Unused |
|------|-----------------|
| `src/pages/Scan_clean.jsx` | ✅ Duplicate |
| `src/pages/PluginMarketplace_clean.jsx` | ✅ Duplicate |

```bash
# Commit 6: Remove duplicate clean versions
git rm src/pages/Scan_clean.jsx src/pages/PluginMarketplace_clean.jsx
git commit -m "chore(cleanup): remove duplicate _clean page versions"
```

---

### Group 7: Log and Output Files

**Reason:** Generated outputs, not source.

| File | Verified Unused |
|------|-----------------|
| `error.log` | ✅ Generated |
| `error_log.txt` | ✅ Generated |
| `error_log_6.txt` | ✅ Generated |
| `security_report.json` | ✅ Generated |
| `security_validation_report.txt` | ✅ Generated |
| `security_validation_results.json` | ✅ Generated |
| `ci_security_results.json` | ✅ Generated |

```bash
# Commit 7: Remove generated log/output files
git rm -f error*.log error_log*.txt security_report.json security_validation_*.* ci_security_results.json
git commit -m "chore(cleanup): remove generated log and output files"
```

---

### Group 8: Web/SaaS Portals (NEEDS REVIEW)

**Reason:** Web-only portals, but verify not referenced.

| Folder | Status |
|--------|--------|
| `byteguardx-portal/` | NEEDS REVIEW |
| `portal/` | NEEDS REVIEW |
| `frontend/` | NEEDS REVIEW (may be duplicate) |

```bash
# Verify before deleting
grep -r "byteguardx-portal" --include="*.py" --include="*.js" --include="*.jsx" .
grep -r "portal/" --include="*.py" --include="*.js" .
```

---

## Execution Order

1. **Tag current state:** `git tag pre-cleanup-$(date +%Y%m%d)`
2. **Execute commits 1-7** (safe deletions)
3. **Review group 8** before deleting
4. **Run tests:** `npm test && pytest`
5. **Verify build:** `npm run tauri:build`

---

## Total Files to Delete

| Group | Count | Bytes Saved (est.) |
|-------|-------|-------------------|
| Electron | ~50 | ~20 KB source + node_modules |
| Test HTML | 8 | ~100 KB |
| Debug scripts | 6 | ~50 KB |
| Test scripts | 25 | ~150 KB |
| Fix scripts | 6 | ~30 KB |
| Duplicates | 2 | ~3 KB |
| Logs | 7 | ~20 KB |
| **Total** | **~104 files** | **~400 KB source** |

---

## Rollback Commands

```bash
# If any problems occur
git revert HEAD~7..HEAD  # Undo last 7 commits

# Or restore specific file
git checkout pre-cleanup-YYYYMMDD -- path/to/file
```
