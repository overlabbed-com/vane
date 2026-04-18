/**
 * Login endpoint with secure authentication.
 * 
 * Security features:
 * - Password OR API key required (no email-only login)
 * - Constant-time error responses (no enumeration)
 * - Argon2id password hashing
 * - HMAC-SHA256 session tokens
 * - Redis session store with TTL refresh
 * - Session versioning for concurrent logout
 * - Distributed Redis-backed rate limiting (sliding window)
 * - NAT exemption for concurrent sessions
 * - No PII in logs
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 * STRIDE: Mitigates CWE-306 (authentication bypass), CWE-204 (enumeration), L-02 (brute force)
 */

import { NextRequest, NextResponse } from 'next/server';
import { getUserByEmail, getUserByUserId } from '@/lib/database/users';
import { verifyPassword } from '@/lib/auth/password';
import { verifyApiKey } from '@/lib/auth/api-key';
import { createSession } from '@/lib/auth/verify';
import { checkRateLimit, trackConcurrentSession } from '@/lib/auth/rate-limit';
import { logLoginAttempt, logLoginSuccess, logLoginFailure } from '@/lib/auth/audit';
import { generateCsrfToken, storeCsrfToken, validateCsrfToken } from '@/lib/auth/csrf';
import { addJitter } from '@/lib/auth/timing';

// Standardized error responses (no enumeration)
// All authentication failures return the same response to prevent user enumeration
const ERROR_MESSAGES = {
  INVALID_REQUEST: 'Invalid request',
  INVALID_CREDENTIALS: 'Invalid credentials',
  INTERNAL_ERROR: 'An internal error occurred',
  RATE_LIMITED: 'Too many requests',
} as const;

// Dummy hash for timing oracle mitigation (valid Argon2id hash of random data)
// Used when user not found to ensure consistent response timing
const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$VHVzdFJhbmRvbVBhc3N3b3JkMTIzNDU2$8xJrhKLDhPQv1xJJrm8K1B5Vx8xJJrm8K1B5Vx8xJJ';

// Maximum login body size: 1KB - sufficient for credentials
const MAX_LOGIN_BODY_SIZE = 1024;

interface LoginBody {
  email?: string;
  userId?: string;
  password?: string;
  apiKey?: string;
}

/**
 * Extracts client metadata for session creation.
 */
function getClientMetadata(request: NextRequest): { ipAddress?: string; userAgent?: string } {
  // Get IP (handle proxies)
  const forwardedFor = request.headers.get('x-forwarded-for');
  const ipAddress = forwardedFor ? forwardedFor.split(',')[0].trim() : undefined;

  // Get user agent
  const userAgent = request.headers.get('user-agent') || undefined;

  return { ipAddress, userAgent };
}

/**
 * Validates that credentials are provided.
 * Requires password OR API key (not both required, not neither).
 */
function validateCredentials(body: LoginBody): { valid: boolean; error?: string } {
  const hasPassword = body.password && body.password.length > 0;
  const hasApiKey = body.apiKey && body.apiKey.length > 0;

  if (!hasPassword && !hasApiKey) {
    return { valid: false, error: 'Password or API key is required' };
  }

  return { valid: true };
}

/**
 * Sanitizes input to prevent log injection.
 * Removes newlines and null bytes that could corrupt log parsing.
 */
function sanitizeForLog(input: string | undefined): string {
  if (!input) {
    return 'undefined';
  }
  // Remove newlines, null bytes, and truncate
  return input.replace(/[\n\r\0]/g, '').substring(0, 100);
}

/**
 * Validates CSRF token for state-changing requests.
 */
async function validateCsrf(request: NextRequest): Promise<boolean> {
  const sessionToken = request.cookies.get('vane_session')?.value;
  const csrfToken = request.headers.get('X-CSRF-Token');
  
  if (!sessionToken || !csrfToken) {
    return false;
  }
  
  return validateCsrfToken(sessionToken, csrfToken);
}

export async function POST(request: NextRequest) {
  // Validate CSRF token for state-changing requests
  const csrfValid = await validateCsrf(request);
  if (!csrfValid) {
    await addJitter();
    return NextResponse.json(
      { error: 'CSRF_INVALID', message: 'Invalid CSRF token' },
      { status: 403 }
    );
  }
  // Get client IP for rate limiting
  const forwardedFor = request.headers.get('x-forwarded-for');
  const clientIp = forwardedFor ? forwardedFor.split(',')[0].trim() : 'unknown';

  // Check distributed rate limit using Redis sliding window
  const rateLimitCheck = await checkRateLimit(clientIp, 'login');
  
  if (!rateLimitCheck.allowed) {
    console.log(
      JSON.stringify({
        event: 'auth.login.rate_limited',
        ip_hash: clientIp.replace(/./g, 'x'),
        is_nat: rateLimitCheck.isNatClient,
        timestamp: new Date().toISOString(),
      })
    );
    
    // Add jitter to rate limit response
    await addJitter();
    
    return NextResponse.json(
      {
        error: 'RATE_LIMITED',
        message: ERROR_MESSAGES.RATE_LIMITED,
        retryAfter: rateLimitCheck.retryAfterMs 
          ? Math.ceil(rateLimitCheck.retryAfterMs / 1000) 
          : undefined,
      },
      { status: 429 }
    );
  }

  try {
    // Explicit body size limit BEFORE parsing
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_LOGIN_BODY_SIZE) {
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_REQUEST', message: 'Request body too large' },
        { status: 413 }
      );
    }
    
    // Read body as text first, then parse (avoids parsing large payloads)
    const rawBody = await request.text();
    if (rawBody.length > MAX_LOGIN_BODY_SIZE) {
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_REQUEST', message: 'Request body too large' },
        { status: 413 }
      );
    }
    
    const body = JSON.parse(rawBody) as LoginBody;
    const { email, userId, password, apiKey } = body;

    // Get client metadata for audit logging
    const metadata = getClientMetadata(request);

    // Log login attempt
    await logLoginAttempt(clientIp, metadata.userAgent, {
      identifier_type: email ? 'email' : 'userId',
    });

    // Validate request has identifier
    if (!email && !userId) {
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_REQUEST', message: ERROR_MESSAGES.INVALID_REQUEST },
        { status: 400 }
      );
    }

    // Validate credentials provided
    const credentialCheck = validateCredentials(body);
    if (!credentialCheck.valid) {
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_REQUEST', message: credentialCheck.error },
        { status: 400 }
      );
    }

    // Retrieve user by email or userId
    let user;
    if (email) {
      user = await getUserByEmail(email);
    } else if (userId) {
      user = await getUserByUserId(userId);
    }

    // SECURITY: Same error for user not found OR wrong password (no enumeration)
    // This prevents attackers from determining if an email/userId exists
    if (!user) {
      // Log failure without PII (only sanitized identifiers)
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'user_not_found',
        {
          identifier_type: email ? 'email' : 'userId',
          identifier_hash: email
            ? sanitizeForLog(email).replace(/./g, 'x')
            : 'unknown',
        }
      );
      // Timing oracle mitigation: verify against dummy hash to ensure consistent timing
      if (password) {
        await verifyPassword(password, DUMMY_HASH);
      }
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
        { status: 401 }
      );
    }

    // Verify password if provided
    if (password) {
      const passwordValid = await verifyPassword(password, user.passwordHash);
      if (!passwordValid) {
        await logLoginFailure(
          clientIp,
          metadata.userAgent,
          'invalid_password'
        );
        await addJitter();
        return NextResponse.json(
          { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
          { status: 401 }
        );
      }
    }

    // Verify API key if provided
    if (apiKey) {
      const apiKeyValid = await verifyApiKey(apiKey, user.apiKeyHash);
      if (!apiKeyValid) {
        await logLoginFailure(
          clientIp,
          metadata.userAgent,
          'invalid_api_key'
        );
        await addJitter();
        return NextResponse.json(
          { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
          { status: 401 }
        );
      }
    }

    // Create session with client metadata
    const session = await createSession(user.id, metadata);

    // Track concurrent session for NAT exemption
    const isNatClient = await trackConcurrentSession(clientIp, user.id);

    // Generate and store CSRF token
    const csrfToken = generateCsrfToken();
    await storeCsrfToken(session.token, csrfToken);

    // Log successful login
    await logLoginSuccess(
      user.id,
      clientIp,
      metadata.userAgent,
      { is_nat: isNatClient }
    );

    // Create response with session data
    const response = NextResponse.json({
      success: true,
      session: {
        token: session.token,
        expiresAt: session.expiresAt.toISOString(),
        version: session.version,
      },
      user: {
        id: user.id,
        email: user.email,
      },
    });

    // Set CSRF cookie (accessible to JavaScript for header injection)
    response.cookies.set('vane_csrf', csrfToken, {
      httpOnly: false,
      secure: true,
      sameSite: 'lax',
      maxAge: 15 * 60,
      path: '/',
    });

    return response;
  } catch (error) {
    // Log without PII
    console.error(
      JSON.stringify({
        event: 'auth.login.error',
        error: error instanceof Error ? error.message : 'Unknown error',
        ip_hash: clientIp.replace(/./g, 'x'),
        timestamp: new Date().toISOString(),
      })
    );
    await addJitter();
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: ERROR_MESSAGES.INTERNAL_ERROR },
      { status: 500 }
    );
  }
}