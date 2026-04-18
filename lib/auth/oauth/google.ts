/**
 * Google OAuth2 provider for social login.
 * 
 * Implements OAuth2/Web flow with OIDC for user authentication.
 * 
 * Security features:
 * - State parameter with Redis nonce for CSRF protection
 * - Minimal scopes (openid, email, profile)
 * - Server-side code exchange
 * - No token exposure to client
 * 
 * Reference:
 * - Google OAuth2: https://developers.google.com/identity/protocols/oauth2/web
 * - OIDC: https://developers.google.com/identity/openid-connect
 */

import { randomBytes } from 'crypto';
import { getRedisClient } from '../redis';
import { generatePkce as generatePkcePair, deriveCodeChallenge } from './pkce';

// Google OAuth2 configuration
const GOOGLE_CONFIG = {
  // Google OAuth2 endpoints
  authEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userInfoEndpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
  
  // Required scopes (minimal for authentication)
  scopes: ['openid', 'email', 'profile'],
  
  // State nonce TTL: 10 minutes
  stateTtlSeconds: 10 * 60,
  
  // State key prefix in Redis
  stateKeyPrefix: 'oauth:state:',
} as const;

// Cached redirect URI allowlist (validated at startup)
let redirectUriAllowlist: string[] | null = null;

/**
 * Validates that the configured GOOGLE_REDIRECT_URI is in the allowlist.
 * Called at startup and when GOOGLE_REDIRECT_URI changes.
 * 
 * @throws Error if GOOGLE_REDIRECT_URI is not in REDIRECT_URI_ALLOWLIST
 */
function validateRedirectUri(): void {
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;
  const allowlistStr = process.env.REDIRECT_URI_ALLOWLIST;

  // If no allowlist configured, skip validation
  if (!allowlistStr) {
    return;
  }

  const allowlist = allowlistStr.split(',').map(uri => uri.trim());

  // Cache the allowlist
  redirectUriAllowlist = allowlist;

  if (!redirectUri) {
    throw new Error('GOOGLE_REDIRECT_URI is required when REDIRECT_URI_ALLOWLIST is set');
  }

  if (!allowlist.includes(redirectUri)) {
    throw new Error(
      `GOOGLE_REDIRECT_URI '${redirectUri}' is not in REDIRECT_URI_ALLOWLIST. ` +
      `Allowed URIs: ${allowlist.join(', ')}`
    );
  }
}

// Google OAuth2 token response
export interface GoogleTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

// Google user profile
export interface GoogleUserInfo {
  sub: string;        // Google user ID
  email: string;
  email_verified: boolean;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
}

/**
 * Gets Google OAuth2 configuration from environment.
 * Validates redirect URI against allowlist on first call.
 */
function getGoogleConfig(): { clientId: string; clientSecret: string; redirectUri: string } {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error('Google OAuth environment variables are required: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI');
  }

  // Validate redirect URI against allowlist (once per process)
  if (redirectUriAllowlist === null) {
    validateRedirectUri();
  }

  return { clientId, clientSecret, redirectUri };
}

/**
 * Generates a cryptographically random state nonce for CSRF protection.
 * Stores the nonce in Redis with TTL.
 * 
 * @returns Object containing state parameter and stored nonce
 */
export async function generateStateNonce(): Promise<{ state: string; nonce: string }> {
  const redis = getRedisClient();

  // Generate 32-byte random nonce
  const nonceBytes = randomBytes(32);
  const nonce = nonceBytes.toString('hex');
  
  // State is the nonce itself (base64url encoded for URL safety)
  const state = nonceBytes.toString('base64url');
  
  // Store nonce in Redis with TTL
  const key = `${GOOGLE_CONFIG.stateKeyPrefix}${nonce}`;
  await redis.setex(key, GOOGLE_CONFIG.stateTtlSeconds, '1');

  return { state, nonce };
}

/**
 * Validates a state nonce from the OAuth callback.
 * Removes the nonce from Redis after validation (one-time use).
 * 
 * @param state - State parameter from callback
 * @param nonce - Nonce to validate
 * @returns true if state is valid and nonce matches
 */
export async function validateStateNonce(state: string, nonce: string): Promise<boolean> {
  if (!state || !nonce) {
    return false;
  }

  // Decode state from base64url
  const stateBytes = Buffer.from(state, 'base64url');
  const expectedNonce = stateBytes.toString('hex');

  // Check if nonce matches
  if (nonce !== expectedNonce) {
    return false;
  }

  // Verify nonce exists in Redis (and remove it - one-time use)
  const redis = getRedisClient();
  const key = `${GOOGLE_CONFIG.stateKeyPrefix}${nonce}`;
  
  const exists = await redis.del(key);
  
  // del returns number of keys deleted
  return exists === 1;
}

/**
 * Generates the Google OAuth2 authorization URL.
 * 
 * @param state - State parameter for CSRF protection
 * @returns Full authorization URL
 */
export function getGoogleAuthUrl(state: string): string {
  const { clientId, redirectUri } = getGoogleConfig();
  
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: GOOGLE_CONFIG.scopes.join(' '),
    state,
    access_type: 'offline',  // Get refresh token for potential future use
    prompt: 'select_account',  // Always ask for account selection
  });

  return `${GOOGLE_CONFIG.authEndpoint}?${params.toString()}`;
}

/**
 * Generates PKCE pair and builds Google auth URL with code challenge.
 * Combines state generation with PKCE for a single authorization request.
 * 
 * @returns Object containing auth URL, state, nonce, codeChallenge, and pkceId
 */
export async function getGoogleAuthUrlWithPkce(state: string, codeChallenge: string): Promise<string> {
  const { clientId, redirectUri } = getGoogleConfig();
  
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: GOOGLE_CONFIG.scopes.join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',  // Explicit S256 method
    access_type: 'offline',  // Get refresh token for potential future use
    prompt: 'select_account',  // Always ask for account selection
  });

  return `${GOOGLE_CONFIG.authEndpoint}?${params.toString()}`;
}

/**
 * Generates a complete PKCE pair for OAuth authorization.
 * Creates verifier, derives challenge, and stores verifier in Redis.
 * 
 * @returns PKCE pair with verifier, challenge, and pkceId
 */
export async function generatePkce(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
  pkceId: string;
}> {
  return generatePkcePair();
}

/**
 * Exchanges an authorization code for tokens.
 * 
 * @param code - Authorization code from callback
 * @param codeVerifier - PKCE code verifier (required for PKCE flow)
 * @returns Token response from Google
 */
export async function exchangeCodeForTokens(code: string, codeVerifier?: string): Promise<GoogleTokenResponse> {
  const { clientId, clientSecret, redirectUri } = getGoogleConfig();

  const bodyParams: Record<string, string> = {
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code,
  };

  // Add PKCE verifier if provided
  if (codeVerifier) {
    bodyParams.code_verifier = codeVerifier;
  }

  const response = await fetch(GOOGLE_CONFIG.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(bodyParams),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Google token exchange failed: ${response.status} ${error}`);
  }

  return response.json() as Promise<GoogleTokenResponse>;
}

/**
 * Retrieves user profile information from Google.
 * 
 * @param accessToken - OAuth2 access token
 * @returns Google user profile
 */
export async function getGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
  const response = await fetch(GOOGLE_CONFIG.userInfoEndpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Google user info request failed: ${response.status} ${error}`);
  }

  return response.json() as Promise<GoogleUserInfo>;
}

/**
 * Revokes a Google OAuth2 access token.
 * Called during logout to invalidate the Google token.
 * 
 * @param accessToken - OAuth2 access token to revoke
 */
export async function revokeGoogleToken(accessToken: string): Promise<void> {
  const { clientId, clientSecret } = getGoogleConfig();

  await fetch('https://oauth2.googleapis.com/revoke', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      token: accessToken,
    }),
  });
}