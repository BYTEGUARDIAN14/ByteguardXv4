# ByteGuardX Migration Acceptance Criteria

---

## Build Verification

### ✅ Must Pass

| Criteria | Platform | Test Command |
|----------|----------|--------------|
| Tauri app builds successfully | Linux (ubuntu-22.04) | `npm run tauri build` |
| Tauri app builds successfully | Windows (latest) | `npm run tauri build` |
| Tauri app builds successfully | macOS (latest) | `npm run tauri build` |
| Installers produced | All | Check `src-tauri/target/release/bundle/` |
| Bundle size < 100MB | All | `du -sh bundle/*` |

---

## Offline Functionality

### ✅ Must Pass

| Criteria | Steps | Expected |
|----------|-------|----------|
| App launches offline | Disconnect network, launch app | Dashboard loads |
| No network errors on start | Check console/logs | Zero network-related errors |
| Local scan works | Run scan on local directory | Results displayed |
| Report export works | Generate PDF report | File saved to disk |
| Settings persist | Change settings, restart | Settings retained |

---

## Feature Parity

### ✅ Must Pass

| Feature | Status | Notes |
|---------|--------|-------|
| File scanning | Must work | Single and batch |
| Directory scanning | Must work | Recursive |
| Secret detection | Must work | API keys, passwords |
| Dependency scanning | Must work | CVE detection |
| AI pattern scanning | Must work | Local ML only |
| Report generation | Must work | PDF, JSON, HTML |
| Plugin loading | Must work | Local plugins |
| Custom menus | Must work | All menu items |
| File dialogs | Must work | Open/Save |

---

## IPC Verification

### ✅ Must Pass

| Command | Test | Expected |
|---------|------|----------|
| `run_scan` | Invoke from UI | Returns scan results |
| `get_scan_status` | Poll during scan | Progress updates |
| `list_plugins` | Open plugin page | Plugin list displayed |
| `get_setting` | Check settings | Value returned |
| `set_setting` | Change setting | Persisted correctly |
| `verify_checksum` | Verify test file | Hash matches |

---

## Network Isolation

### ✅ Must Pass

| Test | Tool | Expected |
|------|------|----------|
| Full scan network capture | Wireshark/tcpdump | Zero external requests |
| DNS query check | During scan | No DNS queries |
| Update check disabled | Check network | No update server contact |
| Telemetry disabled | Check network | No analytics requests |

### Command
```bash
# Linux/macOS
sudo tcpdump -i any -c 100 'not host localhost' &
npm run tauri dev
# Run full scan
# Expect: 0 packets captured for external traffic
```

---

## Plugin Sandbox

### ✅ Must Pass

| Test | Setup | Expected |
|------|-------|----------|
| File access denied | Plugin reads `/etc/passwd` (Linux) | Access denied |
| File access denied | Plugin reads `C:\Windows\System32` (Win) | Access denied |
| Network denied | Plugin attempts HTTP request | Connection refused |
| CPU limit enforced | Plugin infinite loop | Process killed |
| Memory limit enforced | Plugin allocates 500MB | OOM killed |

---

## Security Requirements

### ✅ Must Pass

| Requirement | Verification |
|-------------|--------------|
| No secrets in code | `grep -r "API_KEY\|SECRET" src/` returns empty |
| CSP enforced | DevTools → no inline script execution |
| Input validated | Fuzz test command parameters |
| No eval/Function | `grep -r "eval\|new Function" src/` |
| Permissions minimal | Check tauri.conf.json allowlist |

---

## CI Pipeline

### ✅ Must Pass

| Stage | Expected |
|-------|----------|
| Checkout | Success |
| Install Node | Success |
| Install Rust | Success |
| Install deps | Success |
| Build frontend | Success |
| Build Tauri (all platforms) | Success |
| Upload artifacts | 3 platform bundles |

---

## Documentation

### ✅ Must Complete

| Document | Location | Status |
|----------|----------|--------|
| README updated | `/README.md` | Pending |
| Run locally guide | `/docs/run-locally.md` | Pending |
| Packaging guide | `/docs/packaging.md` | Pending |
| Migration notes | `/migration/CHANGELOG.md` | Pending |
| API documentation | `/docs/api.md` | Pending |

---

## Rollback Verification

### ✅ Must Pass

| Test | Steps | Expected |
|------|-------|----------|
| Rollback works | Checkout electron-legacy tag, build | Electron build succeeds |
| Data compatible | Use migrated data with Electron | No data loss |

---

## Performance Benchmarks

### ✅ Should Meet

| Metric | Target | Measurement |
|--------|--------|-------------|
| Cold start time | < 3s | Stopwatch from click to UI |
| Scan start latency | < 500ms | Time to first progress update |
| Memory usage (idle) | < 200MB | Task Manager / Activity Monitor |
| Bundle size | < 100MB | Installer file size |

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| QA | | | |
| Security | | | |
| Product | | | |
