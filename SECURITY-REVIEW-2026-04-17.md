# Security Review: Vane Login Endpoint

**Date:** 2026-04-17
**Reviewers:** scout, worker, reviewer (parallel review)
**Files Reviewed:**
- `vane/api/auth/login/route.ts`
- `vane/lib/auth/verify.ts`
- `vane/lib/database/users.ts`

---

## Executive Summary

The login endpoint at `vane/api/auth/login/route.ts` contains a **critical authentication bypass vulnerability**. The endpoint accepts email or userId and immediately creates a session without verifying any credentials. Any attacker who can guess or enumerate a valid userId or email can obtain a fully authenticated session.

---

## Findings

### Finding 1: CRITICAL — Authentication Bypass

**Severity:** CRITICAL
**File:** `vane/api/auth/login/route.ts`
**Lines:** 35-38

**Rationale:**
The POST handler retrieves a user by email or userId, then immediately calls `createSession(user.id)` without verifying the provided password or API key. The credential verification code is commented out.

**Impact:**
An attacker with a valid email or userId can authenticate without knowing the password. This grants full access to the authenticated session, enabling:
- Data exfiltration of all user data
- Privilege escalation if role-based access control depends on sessions
- Lateral movement if other services trust the Vane session token

**Exploit Scenario:**
```bash
curl -X POST https://vane.example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"userId": "admin"}'
# Response: { "success": true, "session": { "token": "..." }, "user": { "id": "admin", "email": "admin@example.com" } }
```

**Mitigation:**
Implement mandatory credential verification before session creation:

```typescript
// vane/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { getUserByEmail, getUserByUserId } from '@/lib/database/users';
import { createSession } from '@/lib/auth/verify';
import { verifyPassword } from '@/lib/auth/crypto';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, userId, password, apiKey } = body;

    if (!email && !userId) {
      return NextResponse.json({ error: 'INVALID_REQUEST' }, { status: 400 });
    }

    let user;
    if (email) user = await getUserByEmail(email);
    else if (userId) user = await getUserByUserId(userId);

    if (!user) {
      // Return same error for both missing user AND invalid credentials
      // to prevent user enumeration
      return NextResponse.json({ error: 'INVALID_CREDENTIALS' }, { status: 401 });
    }

    // Verify password (required for password-based auth)
    if (password) {
      const isPasswordValid = await verifyPassword(password, user.passwordHash);
      if (!isPasswordValid) {
        return NextResponse.json({ error: 'INVALID_CREDENTIALS' }, { status: 401 });
      }
    }
    // Verify API key (required for API key-based auth)
    else if (apiKey) {
      const isApiKeyValid = await verifyApiKey(apiKey, user.apiKeyHash);
      if (!isApiKeyValid) {
        return NextResponse.json({ error: 'INVALID_CREDENTIALS' }, { status: 401 });
      }
    }
    // Reject if neither credential type provided
    else {
      return NextResponse.json({ error: 'INVALID_CREDENTIALS' }, { status: 401 });
    }

    const session = await createSession(user.id);
    return NextResponse.json({ success: true, session, user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json({ error: 'INTERNAL_ERROR' }, { status: 500 });
  }
}
```

**Required Dependencies:**
```typescript
// vane/lib/auth/crypto.ts
import * as argon2 from 'argon2';

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export async function verifyApiKey(apiKey: string, hash: string): Promise<boolean> {
  // API keys are typically raw tokens, so use timing-safe comparison
  const crypto = await import('crypto');
  const hashBuffer = Buffer.from(hash, 'hex');
  const apiKeyBuffer = Buffer.from(apiKey, 'utf8');
  if (hashBuffer.length !== apiKeyBuffer.length) return false;
  return crypto.timingSafeEqual(hashBuffer, apiKeyBuffer);
}
```

---

### Finding 2: HIGH — User Enumeration via Error Messages

**Severity:** HIGH
**File:** `vane/api/auth/login/route.ts`
**Lines:** 24-28

**Rationale:**
The endpoint returns `INVALID_USER` when the user does not exist and `INVALID_CREDENTIALS` when the user exists but credentials are wrong. This allows an attacker to enumerate valid email/userId values.

**Impact:**
An attacker can build a list of valid users via targeted probing:
```bash
# Probe for valid userIds
curl -X POST https://vane.example.com/api/auth/login -d '{"userId": "admin"}'
# → { "error": "INVALID_USER" } or { "error": "INVALID_CREDENTIALS" }

# The difference reveals whether "admin" exists
```

**Mitigation:**
Return the same error for both cases. Do not reveal whether the user exists:

```typescript
// Replace the separate user-not-found check with unified error
if (!user) {
  return NextResponse.json({ error: 'INVALID_CREDENTIALS' }, { status: 401 });
}
```

---

### Finding 3: MEDIUM — Plaintext Session Tokens

**Severity:** MEDIUM
**File:** `vane/lib/auth/verify.ts`
**Lines:** 18-22

**Rationale:**
The session token is stored raw in the sessions Map. If the session store is compromised (memory dump, database breach), the attacker can use tokens directly.

**Impact:**
Compromise of session store yields immediate session hijacking for all active users.

**Mitigation:**
Store a HMAC of the token, not the raw token. Return the raw token to the client only once at login:

```typescript
// vane/lib/auth/verify.ts
import { randomBytes, createHmac } from 'crypto';

const sessions = new Map<string, Session>(); // key = HMAC(token)
const tokenIndex = new Map<string, string>(); // raw token -> hmac key lookup

export async function createSession(userId: string): Promise<Session> {
  const token = randomBytes(32).toString('hex');
  const tokenHmac = createHmac('sha256', process.env.SESSION_SECRET!)
    .update(token)
    .digest('hex');

  const session: Session = {
    token: tokenHmac, // Store HMAC, not raw token
    userId,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    revoked: false,
  };

  sessions.set(tokenHmac, session);
  tokenIndex.set(tokenHmac, token); // For verification: lookup raw token by HMAC

  return { ...session, token }; // Return raw token to client
}
```

**Note:** For production, migrate session storage to Redis with TTL support instead of in-memory Map.

---

### Finding 4: MEDIUM — No Rate Limiting

**Severity:** MEDIUM
**File:** `vane/api/auth/login/route.ts`

**Rationale:**
The endpoint has no rate limiting or brute-force protection. An attacker can attempt unlimited credential guesses.

**Impact:**
Enables offline password cracking if token storage is leaked, or online brute-force if credentials are weak.

**Mitigation:**
Implement rate limiting middleware:
```typescript
// vane/middleware/rateLimit.ts
const attempts = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(options: { windowMs: number; maxAttempts: number }) {
  return (request: NextRequest) => {
    const ip = request.headers.get('x-forwarded-for') ?? 'unknown';
    const now = Date.now();
    const record = attempts.get(ip);

    if (!record || now > record.resetAt) {
      attempts.set(ip, { count: 1, resetAt: now + options.windowMs });
      return { allowed: true, remaining: options.maxAttempts - 1 };
    }

    if (record.count >= options.maxAttempts) {
      return { allowed: false, remaining: 0, retryAfter: record.resetAt - now };
    }

    record.count++;
    return { allowed: true, remaining: options.maxAttempts - record.count };
  };
}
```

---

### Finding 5: LOW — In-Memory Session Store

**Severity:** LOW
**File:** `vane/lib/auth/verify.ts`

**Rationale:**
Sessions are stored in a Node.js Map, which is not persistent across restarts and does not scale horizontally.

**Impact:**
Users are logged out on restart. Sessions are not shared across multiple server instances.

**Mitigation:**
Migrate to Redis for production deployment. This is a production readiness issue, not a security vulnerability.

---

## Priority Remediation Plan

| Priority | Finding | Effort | Timeline |
|----------|---------|--------|----------|
| P0 | Authentication Bypass | Low | Immediate |
| P1 | User Enumeration | Low | Immediate |
| P2 | Rate Limiting | Medium | 1-2 days |
| P3 | Plaintext Tokens | Medium | 1 week |
| P4 | In-Memory Sessions | Medium | 1 week |

---

## Conclusion

The login endpoint is currently **unusable in production** due to the critical authentication bypass. Fix Finding 1 and Finding 2 before any deployment. The remaining findings are important but can be addressed in a phased approach.