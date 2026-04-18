/**
 * Google OAuth2 callback handler.
 * 
 * Handles the OAuth callback from Google:
 * 1. Validates state parameter
 * 2. Exchanges code for tokens
 * 3. Gets user info from Google
 * 4. Finds or creates user by Google ID
 * 5. Creates session
 * 6. Redirects to app with session token
 * 
 * Security features:
 * - State parameter with Redis nonce for CSRF protection
 * - One-time use state validation
 * - Server-side code exchange
 * - Find or create user by Google ID
 * - Session creation with client metadata
 * 
 * Reference:
 * - Google OAuth2: https://developers.google.com/identity/protocols/oauth2/web
 */

import { NextRequest, NextResponse } from 'next/server';
import { validateStateNonce, exchangeCodeForTokens, getGoogleUserInfo } from '@/lib/auth/oauth/google';
import { consumeCodeVerifier } from '@/lib/auth/oauth/pkce';
import { getUserByGoogleId, createUserWithGoogleAtomic, linkGoogleAccountWithLock, getUserByEmail } from '@/lib/database/users';
import { createSession } from '@/lib/auth/verify';
import { logLoginAttempt, logLoginSuccess, logLoginFailure } from '@/lib/auth/audit';
import { checkRateLimit } from '@/lib/auth/rate-limit';
import { addJitter } from '@/lib/auth/timing';

// Standardized error responses
const ERROR_MESSAGES = {
  INVALID_STATE: 'Invalid state parameter',
  MISSING_CODE: 'Missing authorization code',
  GOOGLE_AUTH_FAILED: 'Google authentication failed',
  INTERNAL_ERROR: 'An internal error occurred',
} as const;

// Redirect URL after successful login (configurable via env)
const APP_REDIRECT_URL = process.env.OAUTH_SUCCESS_REDIRECT_URL || '/';

// Cookie name for state nonce
const STATE_COOKIE_NAME = 'oauth_state';

// Cookie name for PKCE ID
const PKCE_COOKIE_NAME = 'oauth_pkce_id';

/**
 * Extracts client metadata for session creation.
 */
function getClientMetadata(request: NextRequest): { ipAddress?: string; userAgent?: string } {
  const forwardedFor = request.headers.get('x-forwarded-for');
  const ipAddress = forwardedFor ? forwardedFor.split(',')[0].trim() : undefined;
  const userAgent = request.headers.get('user-agent') || undefined;
  return { ipAddress, userAgent };
}

/**
 * Sanitizes input to prevent log injection.
 */
function sanitizeForLog(input: string | undefined): string {
  if (!input) return 'undefined';
  return input.replace(/[\n\r\0]/g, '').substring(0, 100);
}

/**
 * GET /api/auth/oauth/google/callback
 * Handles the OAuth callback from Google.
 */
export async function GET(request: NextRequest) {
  const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';
  const metadata = getClientMetadata(request);


  try {
    // Rate limit by IP alone (not IP + state)
    const rateLimitResult = await checkRateLimit(clientIp, 'oauth_callback');
    
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'RATE_LIMITED', message: 'Too many requests, please try again later' },
        { status: 429 }
      );
    }

    // Get state from query parameter
    const searchParams = request.nextUrl.searchParams;
    const state = searchParams.get('state');
    const code = searchParams.get('code');
    const error = searchParams.get('error');

    // Log login attempt
    await logLoginAttempt(clientIp, metadata.userAgent, {
      identifier_type: 'google_oauth',
    });

    // Check for OAuth error from Google
    if (error) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'google_oauth_error',
        { error: sanitizeForLog(error) }
      );
      await addJitter();
      return NextResponse.json(
        { error: 'GOOGLE_AUTH_FAILED', message: ERROR_MESSAGES.GOOGLE_AUTH_FAILED },
        { status: 401 }
      );
    }

    // Validate state parameter
    if (!state) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'missing_state'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
        { status: 400 }
      );
    }

    // Get nonce from cookie
    const stateCookie = request.cookies.get(STATE_COOKIE_NAME);
    const nonce = stateCookie?.value;

    if (!nonce) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'missing_state_cookie'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
        { status: 400 }
      );
    }

    // Validate state nonce (one-time use)
    const stateValid = await validateStateNonce(state, nonce);
    if (!stateValid) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'invalid_state'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
        { status: 400 }
      );
    }

    // Validate authorization code
    if (!code) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'missing_code'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'MISSING_CODE', message: ERROR_MESSAGES.MISSING_CODE },
        { status: 400 }
      );
    }

    // FIRST: Consume PKCE verifier atomically (atomic delete BEFORE exchange)
    const pkceIdCookie = request.cookies.get(PKCE_COOKIE_NAME);
    const pkceId = pkceIdCookie?.value;

    if (!pkceId) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'missing_pkce_id'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
        { status: 400 }
      );
    }

    // Atomic consume - deletes from Redis and returns verifier
    const codeVerifier = await consumeCodeVerifier(pkceId);
    
    if (!codeVerifier) {
      // PKCE verifier not found or already consumed - reject immediately
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'pkce_verifier_not_found'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
        { status: 400 }
      );
    }

    // Exchange code for tokens (with PKCE verifier)
    const tokenResponse = await exchangeCodeForTokens(code, codeVerifier);

    // Get user info from Google
    const googleUser = await getGoogleUserInfo(tokenResponse.access_token);

    // Verify email is verified (Google verifies emails)
    if (!googleUser.email_verified) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'unverified_email'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'GOOGLE_AUTH_FAILED', message: 'Email not verified by Google' },
        { status: 401 }
      );
    }

    // Find or create user by Google ID (atomic operation)
    let user = await getUserByGoogleId(googleUser.sub);

    if (!user) {
      // Check if user exists with same email (allow linking)
      const existingUser = await getUserByEmail(googleUser.email);
      
      if (existingUser) {
        // Link Google account to existing user with row locking
        const result = await linkGoogleAccountWithLock(existingUser.id, googleUser.sub, googleUser.email);
        if (result.success && result.user) {
          user = result.user;
        } else {
          // If linking failed, try atomic create (may have been created by concurrent request)
          const atomicResult = await createUserWithGoogleAtomic({
            googleId: googleUser.sub,
            googleEmail: googleUser.email,
            name: googleUser.name,
          });
          user = atomicResult.user;
        }
      } else {
        // Create new user with Google (atomic)
        const atomicResult = await createUserWithGoogleAtomic({
          googleId: googleUser.sub,
          googleEmail: googleUser.email,
          name: googleUser.name,
        });
        user = atomicResult.user;
      }
    }

    if (!user) {
      await logLoginFailure(
        clientIp,
        metadata.userAgent,
        'user_creation_failed'
      );
      await addJitter();
      return NextResponse.json(
        { error: 'INTERNAL_ERROR', message: ERROR_MESSAGES.INTERNAL_ERROR },
        { status: 500 }
      );
    }

    // Create session
    const session = await createSession(user.id, metadata);

    // Log successful login
    await logLoginSuccess(
      user.id,
      clientIp,
      metadata.userAgent,
      { login_type: 'google_oauth' }
    );

    // Set session token in HttpOnly cookie (secure, not accessible to JavaScript)
    const response = NextResponse.redirect(new URL(APP_REDIRECT_URL, request.url));
    
    response.cookies.set('vane_session', session.token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60, // 15 minutes
      path: '/',
    });
    
    // Clear state and PKCE cookies
    response.cookies.delete(STATE_COOKIE_NAME);
    response.cookies.delete(PKCE_COOKIE_NAME);

    return response;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'auth.google.callback_error',
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