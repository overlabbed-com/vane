# Vane Deployment Runbook

## Prerequisites

- Node.js 18+
- Redis 6+ (or Redis Cloud/Upstash)
- PostgreSQL 14+
- Google Cloud Console project

---

## 1. Google OAuth Setup

### 1.1 Create OAuth Credentials

1. Go to [Google Cloud Console > APIs & Services > Credentials](https://console.cloud.google.com/apincredentials)
2. Click **Create Credentials** > **OAuth client ID**
3. Application type: **Web application**
4. Add authorized redirect URI:
   ```
   https://your-domain.com/api/auth/oauth/google/callback
   ```
5. Copy **Client ID** and **Client Secret**

### 1.2 Enable Required APIs

1. Go to [Google Cloud Console > APIs & Services > Library](https://console.cloud.google.com/apilibrary)
2. Enable **People API** (for user profile)

---

## 2. Database Setup

### 2.1 Run Migration

```sql
-- Users table: add social login fields
ALTER TABLE users ADD COLUMN google_id VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN google_email VARCHAR(255);

-- Auth events table (for audit logging)
CREATE TABLE IF NOT EXISTS auth_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type VARCHAR(50) NOT NULL,
  user_id VARCHAR(100),
  ip_hash VARCHAR(64) NOT NULL,
  user_agent TEXT,
  reason VARCHAR(100),
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_events_user_id ON auth_events(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_hash ON auth_events(ip_hash);
CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at);
```

### 2.2 Verify Migration

```sql
-- Check columns exist
\d users
-- Should show: google_id, google_email

-- Check events table
\d auth_events
-- Should show: id, event_type, user_id, ip_hash, user_agent, reason, metadata, created_at
```

---

## 3. Environment Variables

### 3.1 Required Variables

```bash
# Application
NODE_ENV=production
PORT=3000
NEXT_PUBLIC_API_URL=https://your-domain.com

# Database
DATABASE_URL=postgresql://user:password@host:5432/database

# Redis
REDIS_URL=redis://host:6379
REDIS_AUTH_SECRET=your-redis-password  # if Redis AUTH enabled

# Session
SESSION_SECRET=your-session-secret-at-least-32-chars

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://your-domain.com/api/auth/oauth/google/callback
```

### 3.2 Optional Variables

```bash
# Rate limiting (defaults shown)
RATE_LIMIT_BASELINE=5           # requests per minute per IP
RATE_LIMIT_BURST=15             # burst allowance
RATE_LIMIT_BURST_WINDOW=10      # burst window in seconds

# Session (defaults shown)
SESSION_TTL_MINUTES=15         # session TTL
MAX_SESSIONS_PER_IP=3          # NAT exemption

# Semaphore (defaults shown)
ARGON2_SEMAPHORE_LIMIT=10       # max concurrent Argon2id ops
ARGON2_QUEUE_TIMEOUT_MS=30000  # max wait for semaphore
```

### 3.3 Generate Secrets

```bash
# Session secret (must be 32+ chars)
openssl rand -hex 32

# Redis AUTH secret
openssl rand -hex 32
```

---

## 4. Build & Deploy

### 4.1 Build

```bash
npm install
npm run build
```

### 4.2 Start

```bash
# Production
npm start

# Or with PM2
pm2 start npm --name "vane" -- start
```

### 4.3 Health Check

```bash
curl https://your-domain.com/api/health
# Expected: {"status":"ok"}
```

---

## 5. Verification

### 5.1 OAuth Flow Test

1. Open browser to `https://your-domain.com/api/auth/oauth/google`
2. Should redirect to Google consent screen
3. Click "Sign in with Google" and authorize
4. Should redirect back with session token
5. Use token in API requests

### 5.2 Test Login Flow

```bash
# 1. Start OAuth flow
curl -s -c cookies.txt -b cookies.txt \
  -L -o /dev/null -w "%{url_effective}\n" \
  "https://your-domain.com/api/auth/oauth/google"

# 2. Check redirect to Google
# Expected: https://accounts.google.com/o/oauth2/v2/auth?...

# 3. After manual auth, check callback
# Should land on: https://your-domain.com/welcome?token=xxx
```

### 5.3 Test Session Validation

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://your-domain.com/api/auth/session
# Expected: {"user": {...}, "session": {...}}
```

### 5.4 Test Rate Limiting

```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://your-domain.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
done
# Expected: 200,200,200,200,200,429
```

---

## 6. Monitoring

### 6.1 Key Metrics

| Metric | Alert Threshold | Query |
|--------|---------------|-------|
| Login success rate | < 50% | `rate(auth.login.success) / rate(auth.login.attempt) < 0.5` |
| Auth latency p99 | > 2s | `histogram_quantile(0.99, auth_password_hash_duration) > 2` |
| Rate limit hits | > 100/min | `rate(rate_limit.exceeded) > 100` |
| Session tampered | > 0 | `count({event="auth.session.tamper_detected"}) > 0` |

### 6.2 Audit Log Queries

```sql
-- Recent failed logins
SELECT * FROM auth_events 
WHERE event_type = 'login_failure' 
ORDER BY created_at DESC LIMIT 10;

-- User login history
SELECT * FROM auth_events 
WHERE user_id = 'user123' 
ORDER BY created_at DESC;

-- Suspicious activity (many failures from same IP)
SELECT ip_hash, COUNT(*) as failures 
FROM auth_events 
WHERE event_type = 'login_failure' 
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_hash 
HAVING COUNT(*) > 5;
```

---

## 7. Rollback

### 7.1 Disable Google OAuth

```bash
# Remove Google env vars and restart
unset GOOGLE_CLIENT_ID
unset GOOGLE_CLIENT_SECRET
pm2 restart vane
```

### 7.2 Revoke All Sessions

```bash
# In Redis CLI
redis-cli KEYS "vane:sess:*" | xargs redis-cli DEL
```

### 7.3 Database Rollback

```sql
-- Remove Google fields (careful - this breaks linked accounts)
ALTER TABLE users DROP COLUMN IF EXISTS google_id;
ALTER TABLE users DROP COLUMN IF EXISTS google_email;
```

---

## 8. Troubleshooting

### 8.1 "redirect_uri_mismatch" Error

**Cause:** Redirect URI in Google Console doesn't match `GOOGLE_REDIRECT_URI`

**Fix:** Update Google Console or check env var matches exactly

### 8.2 "Email not verified" Error

**Cause:** User's Google email isn't verified

**Fix:** Currently rejected. User must use a verified email.

### 8.3 Session Not Validating

**Cause:** `SESSION_SECRET` mismatch or Redis connection issue

**Fix:** 
```bash
# Check Redis
redis-cli ping
# Should return: PONG

# Check session secret matches
echo $SESSION_SECRET | wc -c
# Should be 33+ characters
```

### 8.4 Rate Limiting Too Aggressive

**Fix:** Adjust environment variables:
```bash
RATE_LIMIT_BASELINE=10  # Increase to 10/min
RATE_LIMIT_BURST=30     # Increase burst
```

---

## 9. Security Checklist

- [ ] `SESSION_SECRET` is 32+ characters, randomly generated
- [ ] `GOOGLE_CLIENT_SECRET` stored in secrets manager, not in code
- [ ] Redis AUTH enabled in production
- [ ] Database SSL/TLS enabled
- [ ] Rate limiting configured appropriately
- [ ] Audit log retention policy set (recommend 90 days)
- [ ] Google OAuth redirect URI uses HTTPS
- [ ] No `*` in Google authorized redirect URIs