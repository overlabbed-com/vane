# STRIDE Security Review — Google OAuth Implementation

**Review date**: 2026-04-17
**Reviewer**: Pi (Ralph Wiggum multi-model review)
**Files reviewed**:
- `lib/auth/oauth/google.ts` — Core OAuth logic
- `api/auth/oauth/google/route.ts` — Auth initiation (GET `/api/auth/oauth/google`)
- `api/auth/oauth/google/callback/route.ts` — OAuth callback (GET `/api/auth/oauth/google/callback`)
- `lib/database/users.ts` — User storage (MOCK in-memory Map)
- `lib/auth/verify.ts` — Session management
- `lib/auth/redis.ts` — Redis session store
- `lib/auth/tokens.ts` — HMAC token derivation
- `lib/auth/audit.ts` — Audit logging

**Overall assessment**: Multiple critical and high severity findings. The implementation has solid foundations (HMAC token derivation, Redis nonce, session versioning) but has critical gaps in id_token validation, session token delivery, and race condition handling that must be addressed before production deployment.

---

## 1. SPOOFING (Identity Fraud)

### S-01: No id_token JWT Validation — CRITICAL
**File**: `lib/auth/oauth/google.ts`
**Lines**: 130-145 (`exchangeCodeForTokens`), 147-160 (`getGoogleUserInfo`)

**Finding**: The `exchangeCodeForTokens()` function retrieves an `id_token` from Google but it is never validated. The `getGoogleUserInfo()` call fetches user profile data separately via `/oauth2/v3/userinfo`, which is a different endpoint with different security properties.

**Risk**: Without id_token validation:
- An attacker with a valid authorization code could receive tokens from a malicious endpoint masquerading as Google
- The identity claims (`sub`, `email`) are never cryptographically verified against Google's signing key
- Token substitution attack is possible if the authorization code is intercepted

**Remediation**:
```typescript
// In exchangeCodeForTokens(), validate id_token after receiving it
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

async function validateIdToken(idToken: string): Promise<GoogleUserInfo> {
  const { payload } = await jwtVerify(idToken, JWKS, {
    issuer: 'https://accounts.google.com',
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  return payload as unknown as GoogleUserInfo;
}
```

**Effort**: Medium — requires `jose` package (~5KB), adds ~20 lines

---

### S-02: Session Token in URL Query Parameter — CRITICAL
**File**: `api/auth/oauth/google/callback/route.ts`
**Lines**: 185-191

```typescript
const redirectUrl = new URL(APP_REDIRECT_URL, request.url);
redirectUrl.searchParams.set('token', session.token);
redirectUrl.searchParams.set('expiresAt', session.expiresAt.toISOString());
```

**Finding**: The session token is transmitted as a URL query parameter.

**Exposure points**:
- Server access logs (token appears in plaintext)
- Browser history (token stored in URL)
- Referer header (token leaked to external sites when clicking external links)
- Browser tabs/favorites (token in saved URLs)
- Screen sharing / screenshots

**Remediation**: Use an HTTP-only, Secure, SameSite=Strict cookie instead:
```typescript
const response = NextResponse.redirect(redirectUrl.toString());
response.cookies.set('session_token', session.token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 15 * 60, // 15 minutes
  path: '/',
});
// Do NOT include token in URL
```

**Effort**: Low — ~10 lines change, but requires frontend update to read from cookie instead of URL param

---

### S-03: APP_REDIRECT_URL No Open Redirect Validation — HIGH
**File**: `api/auth/oauth/google/callback/route.ts`
**Line**: 32

```typescript
const APP_REDIRECT_URL = process.env.OAUTH_SUCCESS_REDIRECT_URL || '/';
```

**Finding**: The redirect URL is taken from an environment variable without validation.

**Risk**: If the env var is compromised or misconfigured, attackers could redirect users to a phishing site after successful authentication.

**Remediation**:
```typescript
const APP_REDIRECT_URL = process.env.OAUTH_SUCCESS_REDIRECT_URL || '/';

// Validate redirect URL
function isValidRedirectUrl(url: string): boolean {
  // Must be relative path OR must match allowed domains
  if (url.startsWith('/')) return true; // Relative is safe
  try {
    const parsed = new URL(url);
    const allowedDomains = (process.env.ALLOWED_REDIRECT_DOMAINS || '').split(',');
    return allowedDomains.includes(parsed.hostname);
  } catch {
    return false;
  }
}

if (!isValidRedirectUrl(APP_REDIRECT_URL)) {
  throw new Error('Invalid OAUTH_SUCCESS_REDIRECT_URL configuration');
}
```

**Effort**: Low — ~15 lines, env var validation at startup

---

### S-04: No Binding Between Authorization Code and State Nonce — MEDIUM
**File**: `api/auth/oauth/google/callback/route.ts`
**Lines**: 62-180

**Finding**: The state nonce validates CSRF but does not bind to the authorization code. An attacker with a valid state cookie could potentially pair it with a different authorization code.

**Remediation**: Include a hash of the expected authorization code in the state:
```typescript
// In route.ts GET handler
const codeChallenge = createHash('sha256').update(code).digest('hex').substring(0, 16);
const state = `${nonceBytes.toString('base64url')}.${codeChallenge}`;

// In callback/route.ts GET handler
const [stateNonce, expectedCodeChallenge] = state.split('.');
const codeChallenge = createHash('sha256').update(code).digest('hex').substring(0, 16);
if (codeChallenge !== expectedCodeChallenge) {
  return NextResponse.json({ error: 'INVALID_STATE' }, { status: 400 });
}
```

**Effort**: Medium — requires changes to both initiation and callback

---

## 2. TAMPERING (Data Modification)

### T-01: Race Condition in User Linking — CRITICAL
**File**: `api/auth/oauth/google/callback/route.ts`
**Lines**: 150-169

```typescript
let user = await getUserByGoogleId(googleUser.sub);

if (!user) {
  const existingUser = await getUserByEmail(googleUser.email);
  
  if (existingUser) {
    await linkGoogleAccount(existingUser.id, googleUser.sub, googleUser.email);
    user = await getUserByGoogleId(googleUser.sub);
  } else {
    user = await createUserWithGoogle({...});
  }
}
```

**Finding**: Classic TOCTOU (Time-of-Check-Time-of-Use) race condition:
1. Request A: `getUserByGoogleId(googleUser.sub)` → null
2. Request B: `getUserByGoogleId(googleUser.sub)` → null
3. Request A: `getUserByEmail(googleUser.email)` → null
4. Request B: `getUserByEmail(googleUser.email)` → null
5. Request A: `createUserWithGoogle()` → user created
6. Request B: `createUserWithGoogle()` → DUPLICATE USER

**Risk**: Duplicate user accounts, account takeover via linking race

**Remediation**: Use database-level atomic operation with unique constraint:
```typescript
// In users.ts - atomic upsert with unique constraint
async function findOrCreateUserByGoogle(data: {
  googleId: string;
  googleEmail: string;
  name?: string;
}): Promise<User> {
  // Try to create with unique constraint
  try {
    return await createUserWithGoogle(data);
  } catch (error) {
    // If unique constraint violation, user already exists - fetch and return
    if (error.code === '23505') { // PostgreSQL unique violation
      return await getUserByGoogleId(data.googleId);
    }
    throw error;
  }
}
```

Or use Redis distributed lock:
```typescript
async function findOrCreateUserWithLock(data: {...}): Promise<User> {
  const lockKey = `lock:google:${data.googleId}`;
  const redis = getRedisClient();
  const lockAcquired = await redis.set(lockKey, '1', 'NX', 'EX', 10);
  
  if (!lockAcquired) {
    // Wait and retry
    await new Promise(r => setTimeout(r, 100));
    return getUserByGoogleId(data.googleId);
  }
  
  try {
    // Check again under lock
    const existing = await getUserByGoogleId(data.googleId);
    if (existing) return existing;
    return createUserWithGoogle(data);
  } finally {
    await redis.del(lockKey);
  }
}
```

**Effort**: Medium — requires DB unique constraint or Redis locking

---

### T-02: MOCK Database No Atomicity — HIGH
**File**: `lib/database/users.ts`
**Lines**: 1-130 (entire file)

**Finding**: The MOCK database uses an in-memory `Map` with no transaction support, no unique constraints, and no atomic operations.

**Current implementation**:
```typescript
const users = new Map<string, User>();
const googleIdIndex = new Map<string, string>();

// Non-atomic: two operations that can race
users.set(userId, user);
googleIdIndex.set(data.googleId, userId);
```

**Risk**: In production, this pattern will cause race conditions and data inconsistency.

**Remediation**: Replace with PostgreSQL transaction:
```typescript
// In production users.ts
async function createUserWithGoogleTransactional(data: {...}): Promise<User> {
  return withTransaction(async (client) => {
    // Check if exists under row lock
    const existing = await client.query(
      'SELECT * FROM users WHERE google_id = $1 FOR UPDATE',
      [data.googleId]
    );
    if (existing.rows[0]) return existing.rows[0];
    
    // Insert new user
    const result = await client.query(
      'INSERT INTO users (google_id, google_email, name, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING *',
      [data.googleId, data.googleEmail, data.name]
    );
    return result.rows[0];
  });
}
```

**Effort**: High — requires PostgreSQL schema, transaction wrapper, unique constraints

---

### T-03: HMAC Integrity Checked in Redis But Session Binding Optional — MEDIUM
**File**: `lib/auth/redis.ts`
**Lines**: 180-230 (`verifySession`)

**Finding**: HMAC integrity signatures are computed and verified in `redis.ts`, but session binding validation (IP/UA) is optional and can be disabled via `SESSION_BINDING_CONFIG.enabled: false`.

**Current**:
```typescript
async function validateSessionBinding(...): Promise<{ valid: boolean }> {
  if (!SESSION_BINDING_CONFIG.enabled) {
    return { valid: true }; // Can be disabled!
  }
  // ...
}
```

**Remediation**: Enable session binding by default, don't make it configurable:
```typescript
const SESSION_BINDING_CONFIG = {
  enabled: true, // Always enabled in production
  ipSubnetBits: 24,
  uaMatchThreshold: 0.7,
} as const;
```

**Effort**: Low — one-line change

---

## 3. INFORMATION DISCLOSURE

### I-01: Session Token Logged in Error Handler — HIGH
**File**: `api/auth/oauth/google/callback/route.ts`
**Lines**: 192-205

```typescript
console.error(
  JSON.stringify({
    event: 'auth.google.callback_error',
    error: error instanceof Error ? error.message : 'Unknown error',
    ip_hash: clientIp.replace(/./g, 'x'), // Good - hashed
    timestamp: new Date().toISOString(),
  })
);
```

**Finding**: The error handler correctly hashes the IP, but the error message itself may contain sensitive data if the error includes request context.

**Risk**: If `error.message` contains the session token or other auth context, it would be written to logs.

**Remediation**:
```typescript
console.error(
  JSON.stringify({
    event: 'auth.google.callback_error',
    error: error instanceof Error ? error.message.substring(0, 100) : 'Unknown error',
    ip_hash: clientIp.replace(/./g, 'x'),
    timestamp: new Date().toISOString(),
  })
);
```

**Effort**: Low — truncate error message

---

### I-02: No id_token Validation Exposes Identity to Separate Endpoint — MEDIUM
**File**: `lib/auth/oauth/google.ts`
**Lines**: 147-160

**Finding**: Instead of validating the `id_token` (which contains verified identity claims), the code calls `/oauth2/v3/userinfo` which is a UserInfo endpoint that returns claims without cryptographic verification.

**Risk**: The UserInfo endpoint could be compromised or return stale data. The `id_token` contains the authoritative identity.

**Remediation**: Validate `id_token` and use its claims directly:
```typescript
// Use claims from validated id_token instead of calling userinfo endpoint
const userInfo = await validateIdToken(tokenResponse.id_token!);
```

**Effort**: Medium — requires jose package

---

### I-03: Audit Logs IP Hash But Not Fully Masked — LOW
**File**: `lib/auth/audit.ts`
**Lines**: 40-50

```typescript
export function hashIpAddress(ipAddress: string | undefined): string {
  // ...
  return createHash('sha256').update(normalized).digest('hex');
}
```

**Finding**: IP addresses are hashed but the full hash is stored. While not reversible, if the hash is leaked alongside other data, it could be correlated.

**Remediation**: Use HMAC with a secret key:
```typescript
const hmacKey = process.env.AUDIT_LOG_HMAC_KEY;
export function hashIpAddress(ipAddress: string | undefined): string {
  if (!ipAddress) return 'unknown';
  const normalized = ipAddress.toLowerCase().trim();
  return createHmac('sha256', hmacKey!).update(normalized).digest('hex');
}
```

**Effort**: Low — add HMAC key env var

---

## 4. DENIAL OF SERVICE

### D-01: No Rate Limiting on OAuth Initiation — HIGH
**File**: `api/auth/oauth/google/route.ts`
**Lines**: 47-75

```typescript
export async function GET(request: NextRequest) {
  // Generate state nonce for CSRF protection
  const { state, nonce } = await generateStateNonce();
  // ...
}
```

**Finding**: No rate limiting on the OAuth initiation endpoint.

**Risk**: An attacker could rapidly generate state nonces, exhausting Redis storage. Each nonce is 32 bytes + key overhead (~100 bytes), so 10M requests = ~1GB Redis storage.

**Remediation**:
```typescript
import { rateLimit } from '@/lib/rate-limit';

const ratelimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 10, // 10 OAuth initiations per window
});

export async function GET(request: NextRequest) {
  const { success, remaining, reset } = await ratelimit.check(request);
  if (!success) {
    return NextResponse.json(
      { error: 'RATE_LIMITED', retryAfter: reset },
      { status: 429 }
    );
  }
  // ...
}
```

**Effort**: Low — integrate existing rate-limit utility

---

### D-02: No Rate Limiting on OAuth Callback — HIGH
**File**: `api/auth/oauth/google/callback/route.ts`
**Lines**: 62-180

**Finding**: No rate limiting on the callback endpoint.

**Risk**: An attacker could repeatedly send callback requests with invalid codes, causing:
- Redis operations (state validation)
- Token exchange attempts (external API calls)
- User lookup operations

**Remediation**: Same as D-01, apply rate limiting to callback:
```typescript
const ratelimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 30, // Higher limit for callback since it includes user interaction
});
```

**Effort**: Low — integrate existing rate-limit utility

---

### D-03: State Nonce TTL Too Long for Attack Mitigation — MEDIUM
**File**: `lib/auth/oauth/google.ts`
**Line**: 26

```typescript
stateTtlSeconds: 10 * 60, // 10 minutes
```

**Finding**: State nonces expire after 10 minutes, which is reasonable for usability but means a nonce can be reused within that window.

**Risk**: If an attacker obtains a valid state+nonce within the 10-minute window, they could complete the OAuth flow.

**Remediation**: Reduce TTL to 5 minutes and add rate limiting:
```typescript
stateTtlSeconds: 5 * 60, // 5 minutes - sufficient for normal users
```

**Effort**: Low — one-line change

---

### D-04: No Account Lockout — MEDIUM
**File**: `lib/auth/audit.ts` (existing audit) + `lib/database/users.ts`

**Finding**: Failed login attempts are logged but not rate-limited. No account lockout after repeated failures.

**Risk**: An attacker could repeatedly attempt OAuth flows to enumerate valid users or cause account lockout (if implemented later).

**Remediation**: Track failed attempts in Redis:
```typescript
const FAILED_LOGIN_KEY = 'failed:login:';
async function checkFailedLoginLimit(ipHash: string): Promise<boolean> {
  const redis = getRedisClient();
  const key = `${FAILED_LOGIN_KEY}${ipHash}`;
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, 15 * 60);
  }
  return count > 10; // Block after 10 failures in 15 minutes
}
```

**Effort**: Medium — requires Redis-based attempt tracking

---

## 5. PRIVILEGE ESCALATION

### E-01: Race Condition Allows Duplicate User Creation — CRITICAL
**File**: `api/auth/oauth/google/callback/route.ts`
**Lines**: 150-169

**Finding**: Same as T-01 but considered here as privilege escalation: two concurrent requests could create two accounts for the same Google user, then link one to an existing email account.

**Risk**: Privilege escalation if an attacker can create multiple accounts and link them to the same email.

**Remediation**: Same as T-01 — atomic upsert with unique constraint

---

### E-02: Email Verification Relies Only on Google — MEDIUM
**File**: `api/auth/oauth/google/callback/route.ts`
**Line**: 113

```typescript
if (!googleUser.email_verified) {
  // ...
  return NextResponse.json(
    { error: 'GOOGLE_AUTH_FAILED', message: 'Email not verified by Google' },
    { status: 401 }
  );
}
```

**Finding**: Email verification status is taken directly from Google's response without additional validation.

**Risk**: Google's `email_verified` could be misconfigured in edge cases, or an attacker could use a Google account with an unverified email that somehow passes verification.

**Remediation**: Require email verification AND send a confirmation email for sensitive operations:
```typescript
if (!googleUser.email_verified) {
  // Require email confirmation for unverified emails
  await sendEmailVerification(user.id, googleUser.email);
  return NextResponse.json(
    { error: 'EMAIL_NOT_VERIFIED', message: 'Please verify your email' },
    { status: 403 }
  );
}
```

**Effort**: Medium — requires email sending infrastructure

---

### E-03: No PKCE Implementation — HIGH
**File**: `lib/auth/oauth/google.ts`
**Lines**: 75-95 (`getGoogleAuthUrl`)

**Finding**: The OAuth flow does not implement PKCE (Proof Key for Code Exchange), which protects against authorization code interception attacks.

**Risk**: On public clients (mobile apps, SPAs), the authorization code could be intercepted via URI schemes, proxy servers, or browser history.

**Remediation**:
```typescript
import { createHash, randomBytes } from 'crypto';

function generatePkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// In getGoogleAuthUrl
const pkce = generatePkce();
const params = new URLSearchParams({
  // ...
  code_challenge: pkce.challenge,
  code_challenge_method: 'S256',
});

// Store verifier in cookie for callback verification
response.cookies.set('pkce_verifier', pkce.verifier, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 600,
});

// In exchangeCodeForTokens
const pkceVerifier = request.cookies.get('pkce_verifier');
body.append('code_verifier', pkceVerifier);
```

**Effort**: Medium — adds ~30 lines, requires cookie storage

---

### E-04: State Nonce Entropy Reduction — LOW
**File**: `lib/auth/oauth/google.ts`
**Lines**: 70-85

```typescript
const nonceBytes = randomBytes(32);
const nonce = nonceBytes.toString('hex'); // 64 chars
const state = nonceBytes.toString('base64url'); // ~43 chars
```

**Finding**: The state is base64url-encoded (43 chars from 32 bytes), reducing effective entropy slightly due to encoding overhead. However, 32 bytes = 256 bits of entropy is still very strong.

**Risk**: Minimal — 256 bits of entropy is beyond brute-force feasibility.

**Remediation**: None required, but document the encoding:
```typescript
// Note: base64url encoding reduces 32 bytes to ~43 characters
// Effective entropy remains 256 bits (32 * 8) which is sufficient
```

**Effort**: None — informational only

---

## Summary Table

| ID | STRIDE | Severity | Finding | File | Lines |
|----|-------|---------|---------|------|-------|
| S-01 | Spoofing | CRITICAL | No id_token JWT validation | google.ts | 130-145 |
| S-02 | Spoofing | CRITICAL | Session token in URL query param | callback/route.ts | 185-191 |
| S-03 | Spoofing | HIGH | APP_REDIRECT_URL no open redirect validation | callback/route.ts | 32 |
| S-04 | Spoofing | MEDIUM | No binding between code and state | callback/route.ts | 62-180 |
| T-01 | Tampering | CRITICAL | Race condition in user linking | callback/route.ts | 150-169 |
| T-02 | Tampering | HIGH | MOCK database no atomicity | users.ts | 1-130 |
| T-03 | Tampering | MEDIUM | Session binding can be disabled | redis.ts | 180-230 |
| I-01 | Info Disclosure | HIGH | Error message may log sensitive data | callback/route.ts | 192-205 |
| I-02 | Info Disclosure | MEDIUM | id_token not validated, userinfo used | google.ts | 147-160 |
| I-03 | Info Disclosure | LOW | IP hash not HMAC-protected | audit.ts | 40-50 |
| D-01 | DoS | HIGH | No rate limiting on initiation | route.ts | 47-75 |
| D-02 | DoS | HIGH | No rate limiting on callback | callback/route.ts | 62-180 |
| D-03 | DoS | MEDIUM | State nonce TTL too long | google.ts | 26 |
| D-04 | DoS | MEDIUM | No account lockout | users.ts | - |
| E-01 | Priv Esc | CRITICAL | Duplicate user creation race | callback/route.ts | 150-169 |
| E-02 | Priv Esc | MEDIUM | Email verification relies only on Google | callback/route.ts | 113 |
| E-03 | Priv Esc | HIGH | No PKCE implementation | google.ts | 75-95 |
| E-04 | Priv Esc | LOW | State nonce entropy encoding | google.ts | 70-85 |

---

## Priority Remediations (Before Production)

1. **S-01 + E-03** (CRITICAL + HIGH): Add id_token validation AND PKCE — these are the most critical OAuth security gaps
2. **S-02** (CRITICAL): Move session token from URL to HTTP-only cookie
3. **T-01 + E-01** (CRITICAL): Fix race condition with atomic user creation
4. **D-01 + D-02** (HIGH): Add rate limiting to both OAuth endpoints
5. **S-03** (HIGH): Validate redirect URL against allowed domains
6. **T-02** (HIGH): Replace MOCK database with PostgreSQL transactions

---

## Positive Security Findings

The implementation has several strong security features:

- **HMAC-SHA256 token derivation** (`tokens.ts`): Raw token never stored, only HMAC-derived token — excellent pattern
- **Session versioning** (`verify.ts`): Enables atomic concurrent logout
- **Redis nonce for CSRF** (`google.ts`): One-time use state validation with TTL
- **IP hashing in audit logs** (`audit.ts`): No PII stored
- **Constant-time comparison** (`tokens.ts`): `timingSafeEqual` prevents timing attacks
- **Session binding (IP/UA)** (`verify.ts`): Can detect session theft (when enabled)
- **HMAC integrity on session data** (`redis.ts`): Detects tampering of stored sessions