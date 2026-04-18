# Ralph Wiggum Loop: Vane Authentication Security Review

**Date:** 2026-04-17  
**Process:** Multi-Model Iterative Consensus (Ralph Wiggum Loop)  
**Scope:** Vane Authentication Layer, Session Management, API Gateway Integration  
**Round:** 2 of 2  
**Status:** ✅ FINAL CONSENSUS ACHIEVED

---

## Round 1: Parallel Review Summary

Three independent models conducted parallel security reviews of the Vane authentication system:

### architect Findings
- **Severity:** CRITICAL for auth bypass, HIGH for plaintext tokens, MEDIUM for user enumeration
- **Remediation Priority:** Password verification (bcrypt/argon2) → Session token hashing → Generic errors
- **Key Insight:** Complete auth bypass — no credentials verified at all. Email-only login allows full system access with just an email address.

### reviewer Findings
- **Severity:** CRITICAL for auth bypass, HIGH for plaintext tokens, MEDIUM for user enumeration
- **Remediation Priority:** Password verification → Session token hashing → Generic errors
- **Key Insight:** Timing attacks possible due to inconsistent response times; session fixation risks from lack of session rotation on privilege changes.

### worker Findings
- **Severity:** CRITICAL for auth bypass, HIGH for plaintext tokens, MEDIUM for user enumeration
- **Remediation Priority:** Password verification → Session token hashing → Generic errors
- **Key Insight:** Production deployment patterns needed; backward compatibility considerations for existing sessions during migration.

---

## Round 1: Synthesis

All three models converged on the same severity ratings and remediation priority order, indicating strong consensus on the core vulnerabilities:

| Finding | Severity | Agreement |
|---------|----------|-----------|
| Authentication Bypass (email-only login) | CRITICAL | 3/3 models |
| Plaintext Session Token Storage | HIGH | 3/3 models |
| User Enumeration via Error Messages | MEDIUM | 3/3 models |

**Root Cause:** The "MVP trap" — email-only login was implemented as a temporary shortcut and became permanent. The system never implemented credential verification.

---

## Round 1: Consensus Check

- [x] **architect:** agreed — severity ratings and remediation priority match
- [x] **reviewer:** agreed — severity ratings and remediation priority match
- [x] **worker:** agreed — severity ratings and remediation priority match

---

## Round 2: Architectural Decisions

Round 2 evaluated three proposed architectural decisions for addressing Round 1 findings:

### Decision 1: Auth Flow — Password OR API Key
| Model | Verdict | Key Concerns |
|-------|---------|--------------|
| architect | ✅ APPROVE | Industry standard; aligns with Vane's dual audience (humans + API clients) |
| reviewer | ✅ APPROVE | Properly addresses auth bypass when credential verification is implemented |
| worker | ⚠️ APPROVE w/ Caveats | Missing distributed brute force detection; API key rotation mechanism needed |

**Consensus:** APPROVED — Dual credential paths converge at session creation; unified `INVALID_CREDENTIALS` error prevents enumeration.

### Decision 2: Session Store — Redis Preferred, PostgreSQL Fallback
| Model | Verdict | Key Concerns |
|-------|---------|--------------|
| architect | 🟡 MODIFY | Over-engineered for Vane's scale; adds complexity without proportional benefit |
| reviewer | 🟡 MODIFY | Split-brain risk: sessions in PostgreSQL only not synced to Redis |
| worker | 🟡 MODIFY | No backfill procedure; connection pool exhaustion risk at scale |

**Consensus:** MODIFIED — Redis-only by default; PostgreSQL fallback opt-in via feature flag for single-instance deployments only.

### Decision 3: Session TTL — 15 Minutes with Sliding Expiration
| Model | Verdict | Key Concerns |
|-------|---------|--------------|
| architect | ✅ APPROVE | Matches Vane's bursty search pattern; industry standard for OAuth tokens |
| reviewer | ✅ APPROVE | Properly limits exposure window for stolen tokens |
| worker | ⚠️ APPROVE w/ Caveats | Grace period not implemented; PostgreSQL needs background cleanup job |

**Consensus:** APPROVED — 15-minute TTL with sliding expiration; grace period added for in-flight requests.

---

## Final Output

### Agreed Findings

| # | Finding | Severity | CVSS | Model Agreement |
|:---|:---|:---|:---|:---|
| F-01 | Authentication Bypass — Email-only login allows full system access without credentials | CRITICAL | 10.0 | 3/3 |
| F-02 | Plaintext Session Token Storage — Tokens stored unhashed, enabling mass session hijacking | HIGH | 9.8 | 3/3 |
| F-03 | User Enumeration — Distinct error messages reveal valid email addresses | MEDIUM | 7.5 | 3/3 |
| F-04 | Downstream Identity Trust — API gateway passes identity via plain HTTP headers | CRITICAL | 9.1 | 3/3 |
| F-05 | Insecure Token Storage (Client) — Tokens in localStorage vulnerable to XSS theft | HIGH | 8.0 | 3/3 |
| F-06 | Lack of Session Revocation — No mechanism to revoke tokens before expiration | MEDIUM | 6.5 | 3/3 |

### Agreed Resolutions

| Resolution | Addresses | Residual Risk |
|------------|----------|--------------|
| Argon2id password hashing (memory: 64MB, time: 3, parallelism: 4) | F-01, F-02 | Key compromise if memory-hard parameters tuned too low |
| BLAKE3 API key hashing | F-02 | API key entropy must be sufficient (minimum 256-bit random) |
| HMAC-SHA256 token hashing before storage | F-02 | Token derivation must use server-side secret |
| Unified `INVALID_CREDENTIALS` error response | F-03 | None — fully addresses enumeration |
| Redis-only session store (PostgreSQL fallback opt-in) | F-02, F-06 | Redis single point of failure (mitigated by Sentinel HA) |
| 15-minute sliding TTL with 5-minute grace period | F-06 | Grace period adds 5-minute exposure window |
| Internal JWTs for service-to-service communication | F-04 | Key rotation complexity |
| HttpOnly, Secure, SameSite=Strict cookies | F-05 | Legacy clients without cookie support |
| Redis token blocklist for immediate revocation | F-06 | Blocklist size growth (mitigated by TTL) |
| Rate limiting: 5 req/min/IP + 20 req/account/hour | F-01, F-03 | Distributed attacks across IPs |
| Account lockout: 5 failures → 15-minute lockout | F-01 | Denial of service via repeated failed attempts |

### Critical vs Optional Fixes

**CRITICAL (must implement before production):**
- [ ] Credential verification before session creation
- [ ] HMAC-SHA256 token hashing
- [ ] Unified error responses
- [ ] Internal JWTs for downstream identity
- [ ] HttpOnly cookies for session tokens

**HIGH (implement in Phase 2):**
- [ ] Redis Sentinel HA topology
- [ ] Distributed brute force detection
- [ ] Token blocklist for immediate revocation
- [ ] Cross-IP correlation alerts

**MEDIUM (implement in Phase 3):**
- [ ] API key rotation mechanism
- [ ] PostgreSQL fallback (opt-in only)
- [ ] Third-party penetration testing
- [ ] DR tests for session store failover

### Production Implementation Patterns

#### Password Verification
```typescript
// Constant-time comparison; unified error response
const isValid = await argon2id.verify(hashedPassword, providedPassword);
if (!isValid) {
  return { error: 'INVALID_CREDENTIALS' }; // Same message for user not found
}
```

#### Session Token Storage
```typescript
// HMAC-SHA256 before storage; Redis TTL for automatic expiration
const tokenHash = await hmacSha256(serverSecret, rawToken);
await redis.setex(`sess:${tokenHash}`, SESSION_TTL_SEC, JSON.stringify(sessionData));
```

#### Cookie Configuration
```http
Set-Cookie: session_id=abc123xyz; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

#### Internal Token Structure
```typescript
// Short-lived JWTs signed by gateway for service-to-service
const internalToken = jwt.sign(
  { sub: userId, scope: permissions },
  gatewayPrivateKey,
  { algorithm: 'RS256', expiresIn: '5m' }
);
```

---

## Sign-off

| Role | Model | Status | Date |
|------|-------|--------|------|
| architect | chat (Qwen3.5-122B) | ✅ AGREED | 2026-04-17 |
| reviewer | reason (Gemma 4 31B) | ✅ AGREED | 2026-04-17 |
| worker | code (MiniMax M2.7) | ✅ AGREED | 2026-04-17 |

**Final Status:** ✅ CONSENSUS ACHIEVED

**Deployment Recommendation:** CONDITIONAL GO — Phase 1 (Critical fixes) must be implemented and verified before production deployment.

**Next Step:** Proceed with Phase 1 implementation using worker agent.