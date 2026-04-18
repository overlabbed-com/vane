/**
 * API key authentication guard for M2M requests.
 *
 * Security features:
 * - Prefix-based O(1) lookup (format: vane_<prefix>_<secret>)
 * - Constant-time response regardless of user existence
 * - Dummy verification for non-existent users
 * - Resource access validation via ProjectMember store
 *
 * Reference: IMPLEMENTATION-PLAN.md Phase 1.1
 */

import { NextRequest } from 'next/server';
import { verifyApiKey } from './api-key';
import { getUserByApiKeyPrefix, User } from '@/lib/database/users';
import { addJitter } from './timing';

// Standardized error responses (no enumeration)
const ERROR_MESSAGES = {
  MISSING_API_KEY: 'Missing API key',
  INVALID_API_KEY: 'Invalid API key',
  INTERNAL_ERROR: 'An internal error occurred',
  ACCESS_DENIED: 'Access denied',
} as const;

/**
 * Custom error class for API authentication failures.
 */
export class ApiAuthError extends Error {
  constructor(
    message: string,
    public statusCode: number = 401,
    public code: string = 'UNAUTHORIZED'
  ) {
    super(message);
    this.name = 'ApiAuthError';
  }
}

/**
 * Mock ProjectMember store for resource access validation.
 * Maps projectId -> Set of userIds with access.
 *
 * In production, this would be a database query:
 *   SELECT user_id FROM project_members WHERE project_id = $1
 */
const projectMembers = new Map<string, Set<string>>();

/**
 * Adds a user to a project's member set.
 * Used for testing and mock scenarios.
 */
export function addProjectMember(projectId: string, userId: string): void {
  let members = projectMembers.get(projectId);
  if (!members) {
    members = new Set<string>();
    projectMembers.set(projectId, members);
  }
  members.add(userId);
}

/**
 * Removes a user from a project's member set.
 */
export function removeProjectMember(projectId: string, userId: string): void {
  const members = projectMembers.get(projectId);
  if (members) {
    members.delete(userId);
  }
}

/**
 * Clears all project members (for testing).
 */
export function clearProjectMembers(): void {
  projectMembers.clear();
}

/**
 * Extracts the API key from request headers.
 * Supports X-API-Key header and Authorization: Bearer scheme.
 *
 * @param request - Next.js Request object
 * @returns The API key or null if not present
 */
function extractApiKey(request: NextRequest): string | null {
  // Try X-API-Key header first (standard)
  const apiKey = request.headers.get('x-api-key');
  if (apiKey && apiKey.length > 0) {
    return apiKey;
  }

  // Try Authorization header with Bearer prefix
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const bearerKey = authHeader.substring(7);
    if (bearerKey.length > 0) {
      return bearerKey;
    }
  }

  return null;
}

/**
 * Parses an API key into its components.
 * Format: vane_<prefix>_<secret>
 *
 * @param apiKey - The full API key
 * @returns Object with prefix and secret, or null if invalid format
 */
function parseApiKey(apiKey: string): { prefix: string; secret: string } | null {
  if (!apiKey || !apiKey.startsWith('vane_')) {
    return null;
  }

  // Split by underscore: vane_<prefix>_<secret>
  const parts = apiKey.split('_');
  if (parts.length !== 3) {
    return null;
  }

  const [, prefix, secret] = parts;
  if (!prefix || !secret) {
    return null;
  }

  return { prefix, secret };
}

/**
 * Authenticates an M2M request using API key.
 *
 * Flow:
 * 1. Extract API key from headers
 * 2. Parse to get prefix and secret
 * 3. O(1) lookup user by prefix
 * 4. If found, verify secret against stored hash
 * 5. If not found, perform dummy verification for constant-time response
 *
 * @param request - Next.js Request object
 * @returns The authenticated userId
 * @throws ApiAuthError if authentication fails
 */
export async function apiAuthGuard(request: NextRequest): Promise<string> {
  try {
    // Extract API key from headers
    const apiKey = extractApiKey(request);

    if (!apiKey) {
      await addJitter();
      throw new ApiAuthError(ERROR_MESSAGES.MISSING_API_KEY, 401, 'MISSING_API_KEY');
    }

    // Parse the API key to extract prefix and secret
    const parsed = parseApiKey(apiKey);
    if (!parsed) {
      // Use dummy verification to maintain consistent timing
      await verifyApiKey(
        apiKey,
        '$argon2id$v=19$m=65536,t=3,p=4$VHVzdFJhbmRvbVBhc3N3b3JkMTIzNDU2$8xJrhKLDhPQv1xJJrm8K1B5Vx8xJJrm8K1B5Vx8xJJ'
      );
      await addJitter();
      throw new ApiAuthError(ERROR_MESSAGES.INVALID_API_KEY, 401, 'INVALID_API_KEY');
    }

    const { prefix, secret } = parsed;

    // O(1) lookup by prefix
    const user = await getUserByApiKeyPrefix(prefix);

    if (!user) {
      // User not found - perform dummy verification for constant-time response
      // This ensures timing is consistent whether user exists or not
      await verifyApiKey(
        secret,
        '$argon2id$v=19$m=65536,t=3,p=4$VHVzdFJhbmRvbVBhc3N3b3JkMTIzNDU2$8xJrhKLDhPQv1xJJrm8K1B5Vx8xJJrm8K1B5Vx8xJJ'
      );
      await addJitter();
      throw new ApiAuthError(ERROR_MESSAGES.INVALID_API_KEY, 401, 'INVALID_API_KEY');
    }

    // User found - verify the secret against stored hash
    if (!user.apiKeyHash) {
      await addJitter();
      throw new ApiAuthError(ERROR_MESSAGES.INVALID_API_KEY, 401, 'INVALID_API_KEY');
    }

    const isValid = await verifyApiKey(secret, user.apiKeyHash);

    if (!isValid) {
      await addJitter();
      throw new ApiAuthError(ERROR_MESSAGES.INVALID_API_KEY, 401, 'INVALID_API_KEY');
    }

    return user.userId;
  } catch (error) {
    if (error instanceof ApiAuthError) {
      throw error;
    }

    // Log unexpected errors without sensitive data
    console.error(
      JSON.stringify({
        event: 'auth.api.error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );

    await addJitter();
    throw new ApiAuthError(ERROR_MESSAGES.INTERNAL_ERROR, 500, 'INTERNAL_ERROR');
  }
}

/**
 * Validates that a user has access to a specific resource.
 *
 * @param userId - The authenticated user ID
 * @param resourceId - The resource to access
 * @param resourceType - Type of resource ('project' | 'thread')
 * @returns true if access is allowed
 * @throws ApiAuthError if access is denied
 */
export async function validateResourceAccess(
  userId: string,
  resourceId: string,
  resourceType: 'project' | 'thread'
): Promise<boolean> {
  // Validate inputs
  if (!userId || !resourceId || !resourceType) {
    throw new ApiAuthError(ERROR_MESSAGES.ACCESS_DENIED, 403, 'ACCESS_DENIED');
  }

  // Validate resourceType
  if (resourceType !== 'project' && resourceType !== 'thread') {
    throw new ApiAuthError(ERROR_MESSAGES.ACCESS_DENIED, 403, 'ACCESS_DENIED');
  }

  // Constant-time pattern: always perform lookup, always apply jitter
  // This prevents timing attacks that could reveal resource existence
  const members = projectMembers.get(resourceId);
  const hasAccess = members ? members.has(userId) : false;

  // Apply jitter regardless of outcome to maintain consistent response time
  await addJitter();

  if (hasAccess) {
    return true;
  }

  // Access denied - do not leak resource existence or any internal state
  throw new ApiAuthError(ERROR_MESSAGES.ACCESS_DENIED, 403, 'ACCESS_DENIED');
}

/**
 * Creates an authenticated request context.
 * Useful for passing auth info to downstream handlers.
 *
 * @param request - Next.js Request object
 * @returns Authenticated context with userId
 */
export async function createAuthContext(request: NextRequest): Promise<{
  userId: string;
  apiKey: string | null;
}> {
  const apiKey = extractApiKey(request);
  const userId = apiKey ? await apiAuthGuard(request) : 'anonymous';

  return {
    userId,
    apiKey,
  };
}