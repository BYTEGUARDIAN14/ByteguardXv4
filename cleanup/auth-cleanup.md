# ByteGuardX Cleanup - Authentication & Online Feature Pruning

> **Generated:** 2026-02-06  
> **Purpose:** Prune online-only auth flows while preserving offline compatibility

---

## Current Auth State

### Already Converted to Offline-First ✅

| Component | File | Status |
|-----------|------|--------|
| AuthContext | `src/contexts/AuthContext.jsx` | ✅ Mock user (always authenticated) |
| ProtectedRoute | `src/components/ProtectedRoute.jsx` | ✅ No-op passthrough |

### AuthContext.jsx (Current Implementation)

```jsx
// Already offline-first:
const user = {
  id: 'local-user',
  username: 'Local User',
  email: 'local@byteguardx.app',
  role: 'admin' // Full access in offline mode
}

// No-op functions for compatibility
const login = async () => ({ success: true })
const signup = async () => ({ success: true })
const logout = async () => { }
```

**Action:** KEEP as transitional code - provides interface compatibility.

---

## Frontend Auth Components

| File | Purpose | Status | Action |
|------|---------|--------|--------|
| `src/contexts/AuthContext.jsx` | Auth provider | Offline mock | **KEEP** (C) |
| `src/components/ProtectedRoute.jsx` | Route guard | Passthrough | **KEEP** (C) |

### No Login/Signup Pages Found

The frontend does not have dedicated login/signup pages - auth was likely handled via modals or external redirect. No pages to remove.

---

## Backend Auth Components

### `byteguardx/auth/` Directory

| File | Purpose | Status | Action |
|------|---------|--------|--------|
| `__init__.py` | Package init | Required | **KEEP** |
| `decorators.py` | Auth decorators | Used by API | **KEEP** |
| `models.py` | User/token models | Used by DB | **KEEP** |
| `two_factor.py` | 2FA logic | May be unused offline | **REVIEW** |

### `byteguardx/api/app.py` Auth Routes

| Endpoint | Purpose | Offline Status | Action |
|----------|---------|----------------|--------|
| `/api/auth/login` | User login | Not needed offline | **DISABLE** or no-op |
| `/api/auth/register` | User signup | Not needed offline | **DISABLE** or no-op |
| `/api/auth/logout` | Logout | No-op is fine | **KEEP** |
| `/api/auth/refresh` | Token refresh | Not needed offline | **DISABLE** or no-op |
| `/api/auth/me` | Get current user | Return mock user | **MODIFY** |

### Recommended API Modifications

For offline-first, auth endpoints should return mock success:

```python
# In byteguardx/api/app.py - Add offline mode check
OFFLINE_MODE = os.getenv('BYTEGUARDX_OFFLINE', 'true').lower() == 'true'

@app.route('/api/auth/login', methods=['POST'])
def login():
    if OFFLINE_MODE:
        return jsonify({
            'success': True,
            'user': {'id': 'local-user', 'role': 'admin'},
            'access_token': 'offline-token'
        })
    # ... original login logic
```

---

## OAuth Flows

### External OAuth Not Found in Frontend

No OAuth redirect handlers or OAuth library imports detected in `src/`.

### Backend OAuth (If Present)

| Component | Action |
|-----------|--------|
| GitHub OAuth routes | **DISABLE** in offline mode |
| Google OAuth routes | **DISABLE** in offline mode |
| OAuth callback handlers | **DISABLE** in offline mode |

---

## Cloud-Only Features

| Feature | File/Component | Action |
|---------|----------------|--------|
| Cloud sharing | Various | **DISABLE** |
| Telemetry | `byteguardx/analytics/` | **DISABLE** by default |
| Remote marketplace | Plugin fetch | **DISABLE** |
| Auto-updater | Already disabled | ✅ Done |

---

## Summary Actions

### Already Done ✅
- [x] AuthContext converted to mock user
- [x] ProtectedRoute converted to passthrough
- [x] Auto-updater disabled in Tauri config

### Recommended (No Breaking Changes)
- [ ] Add `OFFLINE_MODE` env check to backend auth routes
- [ ] Return mock user from `/api/auth/me` in offline mode
- [ ] Keep auth infrastructure for potential future use

### DO NOT Delete
- `AuthContext.jsx` - Interface compatibility
- `ProtectedRoute.jsx` - Routing compatibility  
- `byteguardx/auth/` - Backend decorators still used

---

## Conclusion

**Auth is already offline-compatible.** No immediate deletions required. The mock user pattern ensures all components work without actual authentication.
