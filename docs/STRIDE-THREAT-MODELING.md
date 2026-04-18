# STRIDE Threat Model: Vane Authentication System

## 1. Executive Summary
The Vane Authentication System provides secure user access via traditional password-based login and high-entropy API keys. The architecture is designed around a "zero-plaintext" storage principle, utilizing Argon2id for password/API key hashing and HMAC-SHA256 for session token derivation.

### Architecture Overview
- **Authentication Entry**: Next.js API routes handling login requests.
- **Identity Verification**: Argon2id verification of passwords and API keys.
- **Session Management**: Statefully managed sessions stored in Redis.
- **Token Strategy**: 256-bit random raw tokens are issued to clients; only the HMAC-SHA256 derivative is stored in Redis.
- **Invalidation**: Session versioning allows for atomic "logout everywhere" functionality.

## 2. Trust Boundaries
The system defines three primary trust boundaries:
1. **Client $\leftrightarrow$ API Gateway**: Untrusted input. All data crossing this boundary is treated as malicious.
2. **API Gateway $\leftrightarrow$ Redis**: Trusted internal network, but currently lacks transport encryption (TLS) and strong authentication in the code implementation.
3. **API Gateway $\leftrightarrow$ Database**: Trusted internal network for user identity retrieval.

## 3. STRIDE Analysis

### 3.1 Login Endpoint (`vane/api/auth/login/route.ts`)
| ID | Threat | Category | Description | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|:---|:---|
| L-01 | User Enumeration | Information Disclosure | Attacker determines if a user exists via response timing or error messages. | Low | Low | Low | Constant-time error responses and dummy hash verification for non-existent users. |
| L-02 | Brute Force / Credential Stuffing | Spoofing | Automated attempts to guess passwords or API keys. | High | High | High | In-memory rate limiting implemented; needs migration to distributed Redis-backed limiting. |
| L-03 | Argon2id DoS | Denial of Service | Large numbers of concurrent login requests exhaust CPU/Memory due to Argon2id cost. | Medium | High | High | Fixed cost parameters; needs global concurrency limits/request queuing. |
| L-04 | Log Injection | Tampering | Malicious input in email/userId fields corrupts logs. | Medium | Low | Low | Input sanitization for logs (removing newlines/null bytes). |

### 3.2 Session Creation & Verification (`vane/lib/auth/verify.ts`)
| ID | Threat | Category | Description | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|:---|:---|
| V-01 | Session Fixation | Spoofing | Attacker forces a session token on a user. | Low | High | Medium | New session token generated on every successful login. |
| V-02 | Version Bypass | Tampering | Attacker modifies session version to bypass "logout everywhere". | Low | Medium | Low | Version is stored server-side in Redis and verified on every request. |
| V-03 | Session Hijacking | Spoofing | Attacker steals a raw session token. | Medium | High | High | Short TTL (15m) and sliding window; metadata (IP/UA) collected but not yet enforced. |

### 3.3 Token Generation (`vane/lib/auth/tokens.ts`)
| ID | Threat | Category | Description | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|:---|:---|
| T-01 | Token Predictability | Spoofing | Weak PRNG allows attackers to predict session tokens. | Low | Critical | Low | Uses `crypto.randomBytes` for 256-bit entropy. |
| T-02 | Secret Leakage | Information Disclosure | `SESSION_SECRET` leaked, allowing attackers to derive stored tokens from raw tokens. | Low | Critical | High | Secret managed via environment variables; rotation logic implemented via dual-key support. |
| T-03 | Token Forgery | Tampering | Attacker creates a valid stored token without the secret. | Low | Critical | Low | HMAC-SHA256 provides strong integrity and authenticity. |

### 3.4 Password Hashing (`vane/lib/auth/password.ts`)
| ID | Threat | Category | Description | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|:---|:---|
| P-01 | GPU Cracking | Information Disclosure | Leaked database allows fast offline cracking of passwords. | Medium | High | Medium | Argon2id used with memory-hard parameters (64MB). |
| P-02 | Memory Exhaustion | Denial of Service | Extremely long passwords cause excessive memory allocation during hashing. | Medium | Medium | Medium | Enforced `MAX_PASSWORD_LENGTH` (1024 chars). |

### 3.5 Session Storage (`vane/lib/auth/redis.ts`)
| ID | Threat | Category | Description | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|:---|:---|
| R-01 | Redis Cleartext Access | Information Disclosure | Unauthenticated access to Redis allows reading all session metadata. | Medium | High | High | No Redis AUTH or TLS configured in code; relies on network isolation. |
| R-02 | Session Data Tampering | Tampering | Attacker modifies session data (e.g., `userId`) directly in Redis. | Low | Critical | High | No integrity protection (HMAC) on the stored JSON session object. |
| R-03 | Redis DoS | Denial of Service | Redis memory exhaustion via session flooding. | Medium | Medium | Medium | Strict TTLs enforced on all session and activity keys. |

### 3.6 API Key Verification (`vane/lib/auth/api-key.ts`)
| ID | Threat | Category | Description | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|:---|:---|
| A-01 | API Key Leakage | Information Disclosure | API keys stored in plaintext in client-side configs or logs. | High | High | High | Keys are hashed with Argon2id; raw keys shown only once to the user. |
| A-02 | Timing Attack | Information Disclosure | Difference in verification time reveals key prefixes. | Low | Low | Low | `argon2.verify` uses constant-time comparison. |

## 4. Cross-Component Threat Analysis

### Critical/High Risk Path: The Redis Vulnerability Chain
The most significant architectural risk is the **Redis Trust Assumption**. 
- **The Chain**: Lack of Redis AUTH $\rightarrow$ Lack of TLS $\rightarrow$ Lack of Session Data Integrity.
- **Impact**: If the internal network is breached, an attacker can not only steal all active session tokens (by reading the stored HMACs and attempting to reverse them or simply replacing them) but can also perform **Privilege Escalation** by modifying the `userId` in the session JSON directly in Redis.

### High Risk Path: Resource Exhaustion
- **The Chain**: Public Login Endpoint $\rightarrow$ Argon2id (CPU/Mem intensive) $\rightarrow$ In-memory Rate Limiting.
- **Impact**: A distributed attack can bypass the in-memory rate limiter (since it's not shared across pods/instances) and trigger a CPU-based DoS by forcing the server to perform thousands of Argon2id hashes simultaneously.

## 5. Mitigation Roadmap

### Phase 1: Immediate Hardening (High Priority)
- [ ] **Redis Security**: Implement Redis AUTH and TLS.
- [ ] **Distributed Rate Limiting**: Move `rateLimitStore` from `Map` to Redis using a sliding window algorithm.
- [ ] **Session Integrity**: Add a digital signature (HMAC) to the session JSON object stored in Redis to prevent tampering.

### Phase 2: Resilience & Monitoring (Medium Priority)
- [ ] **Concurrency Control**: Implement a semaphore or request queue for Argon2id operations to prevent CPU exhaustion.
- [ ] **Session Binding**: Enforce `ipAddress` and `userAgent` validation during `verifySession` to mitigate token theft.
- [ ] **Audit Logging**: Implement structured security events (e.g., `auth.session.tamper_detected`) sent to a centralized SIEM.

### Phase 3: Lifecycle Management (Low Priority)
- [ ] **Automated Secret Rotation**: Implement a cron-based rotation for `SESSION_SECRET`.
- [ ] **Adaptive Hashing**: Implement logic to automatically upgrade Argon2id cost parameters as hardware evolves.

## 6. Security Assumptions
1. **Environment Integrity**: The `SESSION_SECRET` is stored securely in the environment and not committed to version control.
2. **Network Isolation**: The Redis instance is not exposed to the public internet.
3. **OS Entropy**: The underlying operating system provides a cryptographically secure source of randomness for `crypto.randomBytes`.

## 7. Threat Model Limitations
- This model does not cover the Database layer (PostgreSQL/etc.) security, assuming the DB is secured via standard IAM/Network policies.
- This model does not cover the frontend (Next.js) XSS/CSRF protections, focusing exclusively on the authentication backend.
- It assumes the `argon2` library implementation is correct and free of side-channel vulnerabilities.

## 8. Review Checklist
- [ ] Does every STRIDE category have at least one entry per component?
- [ ] Are the risk levels consistent with the impact and likelihood?
- [ ] Is there a clear path from threat $\rightarrow$ mitigation?
- [ ] Are the trust boundaries clearly defined?
- [ ] Does the roadmap address the "Critical" risks first?

## 9. Appendix

### Attack Surface Summary
- **Public Endpoints**: `/api/auth/login` (POST)
- **Internal Dependencies**: Redis (Port 6379), User Database.
- **Sensitive Data**: `SESSION_SECRET`, User Passwords (Hashed), API Keys (Hashed), Session Tokens (HMACed).

### Security Controls Matrix
| Control | Implementation | STRIDE Category |
|:---|:---|:---|
| Argon2id | `lib/auth/password.ts`, `lib/auth/api-key.ts` | Information Disclosure |
| HMAC-SHA256 | `lib/auth/tokens.ts` | Tampering / Spoofing |
| Session Versioning | `lib/auth/verify.ts` | Spoofing |
| Constant-Time Errors | `api/auth/login/route.ts` | Information Disclosure |
| Input Sanitization | `api/auth/login/route.ts` | Tampering |
| TTL / Expiration | `lib/auth/redis.ts` | Denial of Service |
