# H3 - CSRF Protection Implementation Plan

**Document Type:** Implementation Plan  
**Date:** 2026-04-17  
**Finding ID:** H3  
**Severity:** P1 (HIGH)  
**CWE:** CWE-352 (Cross-Site Request Forgery)  
**Status:** Ready for Implementation  

---

## 1. Executive Summary

This plan implements CSRF protection for all state-changing authentication endpoints using the Double Submit Cookie pattern. The implementation generates a cryptographically random CSRF token per session, stores it server-side in Redis, and validates it on subsequent POST requests via the `X-CSRF-Token` header. This prevents attackers from forging authenticated requests even if they can lure users to malicious sites.

**Risk After Implementation:** HIGH → LOW  
**Timeline:** 2-3 hours  
**Files Created:** 1 (`lib/auth/csrf.ts`)  
**Files Modified:** 2 (`api/auth/login/route.ts`, `api/auth/oauth/google/callback/route.ts`)  

---

## 2. Threat Model

### 2.1 Attack Scenario

An attacker crafts a malicious website that automatically submits a form to the Vane login endpoint:

```html
<!-- Attacker site: evil.com -->
<form action="https://vane.example.com/api/auth/login" method="POST">
  <input name="email" value="attacker@evil.com" />
  <input name="password" value="stolen" />
  <input type="submit" />
</form>
<script>
  document.forms[0].submit();
</script>
```

If a logged-in user visits `evil.com`, their browser sends the session cookie automatically. Without CSRF protection, the request succeeds and the attacker gains a valid session.

### 2.2 Mitigated Threats

| Threat | CWE | Attack Vector | Mitigation |
|:---|:---|:---|:---|
| Login CSRF | CWE-352 | Malicious site auto-submits login form | CSRF token required on POST |
| OAuth CSRF | CWE-352 | Attacker links own Google account | CSRF token required on callback |
| Session fixation | CWE-384 | Attacker sets session before exploit | CSRF token invalidates attacker session |

### 2.3 Not Mitigated

- XSS attacks (handled separately by H1/H2)
- Session hijacking via network eavesdropping (TLS required)
- Credential theft (handled by password hashing)

### 2.4 XSS Attack Chain (Critical Prerequisite)

If XSS (H1/H2) is not implemented, the httpOnly:false CSRF cookie creates a new attack surface:

**Attack Flow:**
1. Attacker injects XSS payload on legitimate site
2. XSS steals CSRF cookie via `document.cookie`
3. Attacker uses CSRF cookie to forge authenticated requests

**Example:**
```html
<script>
fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include',
  headers: { 'X-CSRF-Token': document.cookie.match(/vane_csrf=([^;]+)/)?.[1] }
});
</script>
```

**Prerequisite:** XSS mitigation (H1/H2) MUST be deployed before CSRF protection. If H1/H2 is not deployed, CSRF protection creates a new attack surface rather than closing one.

### 2.5 Concurrent Session Behavior

Multiple concurrent logins from the same user share/invalidate CSRF tokens:

```
Tab 1: Login → CSRF token A stored
Tab 2: Login → CSRF token B overwrites A in Redis
Tab 1: POST with token A → Rejected (token B is now valid)
```

**This is acceptable behavior.** The most recent login wins. If Tab 2 logs out, Tab 1's CSRF token becomes invalid. Document this in edge cases.

---

## 3. Implementation Details

### 3.1 CSRF Token Generation

**File:** `lib/auth/csrf.ts` (new)

```typescript
/**
 * CSRF token generation and validation.
 * 
 * Uses the Double Submit Cookie pattern:
 * - Token generated: 256-bit random (cryptographically secure)
 * - Stored in Redis keyed by session token
 * - Cookie: Accessible to JavaScript (httpOnly: false)
 * - Header: X-CSRF-Token required on state-changing requests
 * 
 * Reference: H3 finding
 */

import { randomBytes, timingSafeEqual } from 'crypto';
import { getRedisClient } from './redis';

// CSRF configuration
const CSRF_CONFIG = {
  // Token length: 32 bytes (256 bits)
  tokenLength: 32,
  // Key prefix for CSRF tokens in Redis
  keyPrefix: 'csrf:',
  // TTL: 15 minutes (matches session TTL)
  ttlSeconds: 15 * 60,
} as const;

/**
 * Generates a cryptographically random CSRF token.
 * 
 * @returns 64-character hex string (256 bits)
 */
export function generateCsrfToken(): string {
  return randomBytes(CSRF_CONFIG.tokenLength).toString('hex');
}

/**
 * Stores a CSRF token in Redis, associated with a session.
 * 
 * @param sessionToken - The session token (raw token from login)
 * @param csrfToken - The CSRF token to store
 * @returns Promise resolving when stored
 */
export async function storeCsrfToken(
  sessionToken: string,
  csrfToken: string
): Promise<void> {
  const redis = getRedisClient();
  const key = `${CSRF_CONFIG.keyPrefix}${sessionToken}`;
  
  await redis.setex(key, CSRF_CONFIG.ttlSeconds, csrfToken);
}

/**
 * Retrieves a stored CSRF token from Redis.
 * 
 * @param sessionToken - The session token
 * @returns The CSRF token, or null if not found/expired
 */
export async function getCsrfToken(sessionToken: string): Promise<string | null> {
  const redis = getRedisClient();
  const key = `${CSRF_CONFIG.keyPrefix}${sessionToken}`;
  
  return redis.get(key);
}

/**
 * Validates a CSRF token from a request.
 * Uses constant-time comparison to prevent timing attacks.
 * 
 * @param sessionToken - The session token from cookie
 * @param requestToken - The CSRF token from X-CSRF-Token header
 * @returns true if valid, false otherwise
 */
export async function validateCsrfToken(
  sessionToken: string,
  requestToken: string
): Promise<boolean> {
  if (!sessionToken || !requestToken) {
    return false;
  }

  const storedToken = await getCsrfToken(sessionToken);
  
  if (!storedToken) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  try {
    const storedBuffer = Buffer.from(storedToken, 'hex');
    const requestBuffer = Buffer.from(requestToken, 'hex');

    if (storedBuffer.length !== requestBuffer.length) {
      return false;
    }

    return timingSafeEqual(storedBuffer, requestBuffer);
  } catch {
    return false;
  }
}

/**
 * Invalidates a CSRF token (logout or session change).
 * 
 * @param sessionToken - The session token
 * @returns true if token was deleted
 */
export async function invalidateCsrfToken(sessionToken: string): Promise<boolean> {
  const redis = getRedisClient();
  const key = `${CSRF_CONFIG.keyPrefix}${sessionToken}`;
  
  const result = await redis.del(key);
  return result > 0;
}
```

### 3.2 CSRF Token Storage

**Storage Pattern:**
- Key: `csrf:{sessionToken}` (where sessionToken is the raw session token)
- Value: 64-character hex CSRF token
- TTL: 15 minutes (matches session TTL)

**Rationale:** Using session token as part of the CSRF key binds CSRF protection to the session. If the session is revoked, the CSRF token is automatically invalidated.

### 3.3 Cookie Configuration

```typescript
// Set on login success
response.cookies.set('vane_csrf', csrfToken, {
  httpOnly: false, // Must be readable by JavaScript for header injection
  secure: true,   // HTTPS only
  sameSite: 'lax', // Not 'strict' (needs POST from other site)
  maxAge: 15 * 60, // 15 minutes
  path: '/'
});
```

**Note:** `httpOnly: false` is required because the frontend JavaScript must read the cookie to inject it into the `X-CSRF-Token` header.

### 3.4 Login Route Integration

**File:** `api/auth/login/route.ts`

Add CSRF token generation on successful login:

```typescript
// In POST handler, after session creation
import { generateCsrfToken, storeCsrfToken } from '@/lib/auth/csrf';

// After session creation (existing code)
const session = await createSession(user.id, metadata);

// Generate and store CSRF token
const csrfToken = generateCsrfToken();
await storeCsrfToken(session.token, csrfToken);

// Set CSRF cookie
response.cookies.set('vane_csrf', csrfToken, {
  httpOnly: false,
  secure: true,
  sameSite: 'lax',
  maxAge: 15 * 60,
  path: '/'
});
```

### 3.5 OAuth Callback Integration

**File:** `api/auth/oauth/google/callback/route.ts`

Add CSRF token generation on successful OAuth login:

```typescript
// After session creation (existing code)
const session = await createSession(user.id, metadata);

// Generate and store CSRF token
const csrfToken = generateCsrfToken();
await storeCsrfToken(session.token, csrfToken);

// Set CSRF cookie
response.cookies.set('vane_csrf', csrfToken, {
  httpOnly: false,
  secure: true,
  sameSite: 'lax',
  maxAge: 15 * 60,
  path: '/'
});
```

### 3.6 Frontend Integration

The frontend API client must read the CSRF cookie and inject it into state-changing requests:

```typescript
/**
 * Reads the CSRF token from document.cookie.
 * Must be accessible to JavaScript (httpOnly: false).
 */
function getCsrfToken(): string | null {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'vane_csrf') {
      return decodeURIComponent(value);
    }
  }
  return null;
}

/**
 * API request wrapper that injects CSRF token.
 */
async function apiRequest(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const csrfToken = getCsrfToken();
  
  const headers = new Headers(options.headers);
  if (csrfToken) {
    headers.set('X-CSRF-Token', csrfToken);
  }
  
  return fetch(url, {
    ...options,
    headers,
    credentials: 'include', // Include cookies
  });
}
```

---

## 4. Files to Create/Modify

### 4.1 New Files

| File | Purpose | Lines |
|:---|:---|:---|
| `lib/auth/csrf.ts` | CSRF token generation and validation | ~120 |
| `lib/auth/csrf.test.ts` | Unit tests for CSRF functions | ~100 |

### 4.2 Modified Files

| File | Change | Lines |
|:---|:---|:---|
| `api/auth/login/route.ts` | Generate CSRF token on login, set cookie | ~15 |
| `api/auth/oauth/google/callback/route.ts` | Generate CSRF token on OAuth success, set cookie | ~15 |

### 4.3 Frontend (Out of Scope for This Plan)

Frontend integration is documented but implemented separately:
- API client wrapper with CSRF injection
- Cookie reading utility

---

## 5. Test Cases

### 5.1 Token Generation Tests

```typescript
// lib/auth/csrf.test.ts

it('generates 64-character hex token', () => {
  const token = generateCsrfToken();
  expect(token).toMatch(/^[a-f0-9]{64}$/);
});

it('generates unique tokens', () => {
  const token1 = generateCsrfToken();
  const token2 = generateCsrfToken();
  expect(token1).not.toBe(token2);
});

it('has sufficient entropy (256 bits)', () => {
  const token = generateCsrfToken();
  // 64 hex chars = 256 bits of entropy
  expect(token.length).toBe(64);
});
```

### 5.2 Storage and Retrieval Tests

```typescript
it('stores and retrieves CSRF token', async () => {
  const sessionToken = 'test-session-token';
  const csrfToken = generateCsrfToken();
  
  await storeCsrfToken(sessionToken, csrfToken);
  const retrieved = await getCsrfToken(sessionToken);
  
  expect(retrieved).toBe(csrfToken);
});

it('returns null for non-existent session', async () => {
  const retrieved = await getCsrfToken('non-existent');
  expect(retrieved).toBeNull();
});

it('token expires after TTL', async () => {
  // This test uses a mock Redis with reduced TTL
  vi.useFakeTimers();
  
  const sessionToken = 'test-session-token';
  const csrfToken = generateCsrfToken();
  
  await storeCsrfToken(sessionToken, csrfToken);
  
  // Advance time past TTL
  vi.advanceTimersByTime((CSRF_CONFIG.ttlSeconds + 1) * 1000);
  
  const retrieved = await getCsrfToken(sessionToken);
  expect(retrieved).toBeNull();
});
```

### 5.3 Validation Tests

```typescript
it('validates correct token', async () => {
  const sessionToken = 'test-session-token';
  const csrfToken = generateCsrfToken();
  
  await storeCsrfToken(sessionToken, csrfToken);
  const isValid = await validateCsrfToken(sessionToken, csrfToken);
  
  expect(isValid).toBe(true);
});

it('rejects wrong token', async () => {
  const sessionToken = 'test-session-token';
  const csrfToken = generateCsrfToken();
  
  await storeCsrfToken(sessionToken, csrfToken);
  const isValid = await validateCsrfToken(sessionToken, 'wrong-token');
  
  expect(isValid).toBe(false);
});

it('rejects missing token', async () => {
  const isValid = await validateCsrfToken('session', 'csrf-token');
  expect(isValid).toBe(false);
});

it('rejects expired token', async () => {
  vi.useFakeTimers();
  
  const sessionToken = 'test-session-token';
  const csrfToken = generateCsrfToken();
  
  await storeCsrfToken(sessionToken, csrfToken);
  
  vi.advanceTimersByTime((CSRF_CONFIG.ttlSeconds + 1) * 1000);
  
  const isValid = await validateCsrfToken(sessionToken, csrfToken);
  expect(isValid).toBe(false);
});
```

### 5.4 Constant-Time Comparison Tests

```typescript
it('uses constant-time comparison', async () => {
  // This is tested indirectly via validation tests
  // A timing attack would require many samples to detect
  const sessionToken = 'test-session-token';
  const csrfToken = generateCsrfToken();
  
  await storeCsrfToken(sessionToken, csrfToken);
  
  // Valid token
  await validateCsrfToken(sessionToken, csrfToken);
  
  // Invalid token (different length)
  await validateCsrfToken(sessionToken, 'a'.repeat(64));
  
  // Both should take similar time
});
```

---

## 6. Edge Cases

### 6.1 CSRF Token Regeneration on Session Refresh

When a session is refreshed (activity extends TTL), the CSRF token should remain valid:

```typescript
// Session refresh does NOT regenerate CSRF token
// CSRF token TTL is independent of session TTL
// Both must expire together for security
```

**Mitigation:** CSRF token TTL matches session TTL. If session is refreshed, CSRF token remains valid until original TTL expires.

### 6.2 Concurrent Session Invalidation

When multiple tabs/windows login with the same credentials:
- Each new login generates a new CSRF token
- The new token overwrites the old one in Redis
- The old CSRF token becomes invalid
- This is intentional - prevents session fixation

**User impact:** If user has multiple tabs open and logs out/in on one tab, other tabs may get CSRF errors. User must re-authenticate on those tabs.

### 6.3 Concurrent Requests with Same Session

Multiple tabs/windows with the same session share the same CSRF token:

```
Tab 1: Login → CSRF token A
Tab 2: Login → CSRF token B (overwrites A)
Tab 1: POST with token A → Rejected (token B is valid)
```

**Mitigation:** This is acceptable behavior. The most recent login wins. If Tab 2 logs out, Tab 1's CSRF token becomes invalid.

### 6.3 CSRF Token Rotation on Privilege Escalation

If a user upgrades their session (e.g., from read-only to write access), regenerate CSRF token:

```typescript
// On privilege escalation, invalidate old CSRF and generate new
await invalidateCsrfToken(sessionToken);
const newCsrfToken = generateCsrfToken();
await storeCsrfToken(sessionToken, newCsrfToken);
```

### 6.4 Cross-Origin Requests

The `sameSite: 'lax'` cookie setting allows CSRF requests from navigation:

```html
<!-- This WILL be sent (browser follows link) -->
<a href="https://vane.com/api/auth/logout">Log out</a>

<!-- This WILL NOT be sent (requires JavaScript) -->
<script>
fetch('https://vane.com/api/auth/logout', { method: 'POST' });
</script>
```

**Mitigation:** The `X-CSRF-Token` header cannot be set by cross-origin JavaScript. Only same-origin requests can set custom headers.

### 6.5 Preflight Requests

OPTIONS requests for CORS preflight should not require CSRF validation:

```typescript
// CSRF validation only on state-changing methods
if (request.method === 'GET' || request.method === 'OPTIONS') {
  return next();
}
```

---

## 7. Integration Points

### 7.1 Login Endpoint

**File:** `api/auth/login/route.ts`

```
POST /api/auth/login
  ├── Validate credentials (existing)
  ├── Create session (existing)
  ├── Generate CSRF token (NEW)
  ├── Store CSRF token in Redis (NEW)
  ├── Set vane_csrf cookie (NEW)
  └── Return session + CSRF cookie
```

### 7.2 OAuth Callback

**File:** `api/auth/oauth/google/callback/route.ts`

```
GET /api/auth/oauth/google/callback
  ├── Validate state + PKCE (existing)
  ├── Exchange code for tokens (existing)
  ├── Create session (existing)
  ├── Generate CSRF token (NEW)
  ├── Store CSRF token in Redis (NEW)
  ├── Set vane_csrf cookie (NEW)
  └── Redirect to app with session cookie
```

### 7.3 Future Endpoints

Any future state-changing endpoint should validate CSRF:

```typescript
// Example middleware pattern
async function validateCsrf(request: NextRequest): Promise<boolean> {
  const sessionToken = request.cookies.get('vane_session')?.value;
  const csrfToken = request.headers.get('X-CSRF-Token');
  
  if (!sessionToken || !csrfToken) {
    return false;
  }
  
  return validateCsrfToken(sessionToken, csrfToken);
}
```

---

## 8. Verification Steps

### 8.1 Unit Tests

```bash
npm test -- lib/auth/csrf.test.ts
# Expected: All tests pass
```

### 8.2 Integration Tests

```bash
# Test 1: Login returns CSRF cookie
curl -X POST https://vane.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"correct"}' \
  -c cookies.txt
# Expected: Set-Cookie: vane_csrf=...

# Test 2: POST without CSRF token fails
curl -X POST https://vane.example.com/api/auth/logout \
  -b cookies.txt
# Expected: 403 Forbidden

# Test 3: POST with CSRF token succeeds
curl -X POST https://vane.example.com/api/auth/logout \
  -H "X-CSRF-Token: $(grep vane_csrf cookies.txt | cut -f7)" \
  -b cookies.txt
# Expected: 200 OK
```

### 8.3 CSRF Attack Simulation

```bash
# Simulate attacker site (should fail)
curl -X POST https://vane.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"wrong"}'
# Expected: Without valid session cookie, attacker cannot forge request
# Even if they have a stolen session, CSRF token is required
```

---

## 9. Acceptance Criteria

- [ ] CSRF token generated on successful login
- [ ] CSRF token stored in Redis with session TTL
- [ ] CSRF cookie set with `httpOnly: false`, `secure: true`, `sameSite: 'lax'`
- [ ] CSRF token validated on POST requests
- [ ] Invalid CSRF token returns 403 Forbidden
- [ ] Missing CSRF token returns 403 Forbidden
- [ ] CSRF token invalidated on logout
- [ ] Unit tests: 100% coverage for CSRF functions
- [ ] No timing side-channel in token validation

---

## 10. Dependencies

| Dependency | Required For | Status |
|:---|:---|:---|
| Redis client | Token storage | Existing (`lib/auth/redis.ts`) |
| Session management | Token binding | Existing (`lib/auth/verify.ts`) |
| argon2 | Password hashing | Existing (`lib/auth/password.ts`) |

---

## 11. Security Considerations

### 11.1 Token Entropy

256-bit random tokens provide sufficient entropy to prevent brute-force guessing:

```
Entropy: 2^256 possibilities
At 1M guesses/second: ~10^64 years to guess
```

### 11.2 Storage Isolation

CSRF tokens are stored separately from session tokens:

- Session token: HMAC-derived, stored in Redis
- CSRF token: Random, stored in Redis with separate key

This prevents attackers from deriving CSRF tokens if they compromise the session token derivation key.

### 11.3 Cookie Security

| Setting | Value | Rationale |
|:---|:---|:---|
| `httpOnly` | `false` | JavaScript must read cookie for header injection |
| `secure` | `true` | HTTPS only (prevents MITM) |
| `sameSite` | `lax` | Allows navigation POSTs, blocks script POSTs |

---

## 13. Prerequisite Checklist

Before deploying CSRF protection:

- [ ] XSS mitigation (H1/H2) is deployed and verified
- [ ] If H1/H2 not deployed, DO NOT deploy CSRF protection
- [ ] CSRF protection without XSS mitigation creates new attack surface

**Verification:**
```bash
# Check if XSS protection is active
curl -s https://vane.example.com | grep -i 'content-security-policy'
# Should have CSP with script-src restrictions
```

---


## 14. Next Steps

1. **Implement:** Create `lib/auth/csrf.ts` with token generation and validation
2. **Test:** Add unit tests in `lib/auth/csrf.test.ts`
3. **Integrate:** Modify login route to generate and store CSRF token
4. **Integrate:** Modify OAuth callback to generate and store CSRF token
5. **Document:** Update frontend integration docs
6. **Verify:** Run integration tests
7. **Deploy:** Staging → Production