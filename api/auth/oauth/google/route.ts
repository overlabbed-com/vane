/**
 * Google OAuth2 callback handler.
 * 
 * Handles the OAuth2 authorization code flow:
 * 1. GET /api/auth/oauth/google - Redirect to Google consent screen
 * 2. GET /api/auth/oauth/google/callback - Handle OAuth callback
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
import { generateStateNonce, getGoogleAuthUrl, getGoogleAuthUrlWithPkce, generatePkce, exchangeCodeForTokens, getGoogleUserInfo } from '@/lib/auth/oauth/google';
import { getUserByGoogleId, createUserWithGoogle, linkGoogleAccount } from '@/lib/database/users';
import { createSession } from '@/lib/auth/verify';
import { logLoginAttempt, logLoginSuccess, logLoginFailure } from '@/lib/auth/audit';
import { checkRateLimit } from '@/lib/auth/rate-limit';

// Standardized error responses
const ERROR_MESSAGES = {
  INVALID_STATE: 'Invalid state parameter',
  MISSING_CODE: 'Missing authorization code',
  GOOGLE_AUTH_FAILED: 'Google authentication failed',
  INTERNAL_ERROR: 'An internal error occurred',
} as const;

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
 * GET /api/auth/oauth/google
 * Redirects to Google consent screen.
 */
export async function GET(request: NextRequest) {
  try {
    // Rate limit by IP only (not IP + user_agent)
    const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';
    const rateLimitResult = await checkRateLimit(clientIp, 'oauth_initiate');
    
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'RATE_LIMITED', message: 'Too many requests, please try again later' },
        { status: 429 }
      );
    }

    // Generate state nonce for CSRF protection
    const { state, nonce } = await generateStateNonce();

    // Generate PKCE pair and store verifier
    const { codeVerifier, codeChallenge, pkceId } = await generatePkce();

    // Build Google auth URL with PKCE
    const authUrl = await getGoogleAuthUrlWithPkce(state, codeChallenge);

    // Redirect to Google with state cookie for callback verification
    const response = NextResponse.redirect(authUrl);
    
    // Set state nonce in HTTP-only cookie for callback verification
    // Cookie is secure (HTTPS only) in production
    response.cookies.set('oauth_state', nonce, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 600, // 10 minutes
      path: '/',
    });

    // Set PKCE ID in HTTP-only cookie (separate from state)
    response.cookies.set('oauth_pkce_id', pkceId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 600, // 10 minutes
      path: '/',
    });

    return response;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'auth.google.initiate_error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: ERROR_MESSAGES.INTERNAL_ERROR },
      { status: 500 }
    );
  }
}

/**
 * POST /api/auth/oauth/google/callback
 * Handles the OAuth callback from Google.
 * This is a separate route file at /api/auth/oauth/google/callback
 */
export async function POST(request: NextRequest) {
  // This would handle the callback - but we use GET for OAuth redirect flow
  // See callback/route.ts for the actual callback handler
  return NextResponse.json(
    { error: 'METHOD_NOT_ALLOWED', message: 'Use GET to initiate OAuth flow' },
    { status: 405 }
  );
}