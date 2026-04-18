/**
 * Mock user database for Vane authentication.
 * In production, this would be PostgreSQL or similar.
 */

export interface User {
  id: string;
  email: string;
  userId: string;
  passwordHash: string;
  apiKeyHash: string;
  apiKeyPrefix: string;
  googleId?: string;
  googleEmail?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Mock user store
const users = new Map<string, User>();

// Index for Google ID lookup
const googleIdIndex = new Map<string, string>(); // googleId -> userId

// Index for API key prefix lookup
const apiKeyPrefixIndex = new Map<string, string>(); // apiKeyPrefix -> userId

// Transaction lock for atomic operations (in production, use database transactions)
const transactionLock = new Map<string, Promise<unknown>>();

/**
 * Retrieves a user by email address.
 */
export async function getUserByEmail(email: string): Promise<User | null> {
  if (!email) {
    return null;
  }

  const normalizedEmail = email.toLowerCase().trim();

  for (const user of users.values()) {
    if (user.email.toLowerCase() === normalizedEmail) {
      return user;
    }
  }

  return null;
}

/**
 * Retrieves a user by Google ID.
 */
export async function getUserByGoogleId(googleId: string): Promise<User | null> {
  if (!googleId) {
    return null;
  }

  const userId = googleIdIndex.get(googleId);
  if (!userId) {
    return null;
  }

  return users.get(userId) || null;
}

/**
 * Retrieves a user by API key prefix.
 * This enables O(1) lookup for prefix-based API key authentication.
 *
 * @param prefix - The API key prefix (e.g., 'proj_abc123')
 * @returns The user or null if not found
 */
export async function getUserByApiKeyPrefix(prefix: string): Promise<User | null> {
  if (!prefix) {
    return null;
  }

  const userId = apiKeyPrefixIndex.get(prefix);
  if (!userId) {
    return null;
  }

  return users.get(userId) || null;
}

/**
 * Creates a new user with Google authentication.
 * Uses INSERT ... ON CONFLICT DO NOTHING pattern for atomicity.
 * Returns existing user if googleId already exists.
 */
export async function createUserWithGoogle(data: {
  googleId: string;
  googleEmail: string;
  name?: string;
}): Promise<User> {
  // Check if googleId already exists (INSERT ... ON CONFLICT DO NOTHING equivalent)
  const existingUserId = googleIdIndex.get(data.googleId);
  if (existingUserId) {
    const existingUser = users.get(existingUserId);
    if (existingUser) {
      return existingUser;
    }
  }

  const now = new Date();
  const userId = `user_${Date.now()}`;
  
  const user: User = {
    id: userId,
    email: data.googleEmail.toLowerCase().trim(),
    userId,
    passwordHash: '',
    apiKeyHash: '',
    apiKeyPrefix: '',
    googleId: data.googleId,
    googleEmail: data.googleEmail.toLowerCase().trim(),
    createdAt: now,
    updatedAt: now,
  };

  users.set(userId, user);
  googleIdIndex.set(data.googleId, userId);
  return user;
}

/**
 * Atomically creates a new user with Google authentication.
 * Uses a transaction lock to prevent race conditions.
 * 
 * Pattern:
 * 1. Acquire lock for googleId
 * 2. Check if googleId exists (INSERT ... ON CONFLICT DO NOTHING)
 * 3. If conflict, return existing user
 * 4. If no conflict, create user and return
 * 5. Release lock
 * 
 * @returns Object with user and created flag
 */
export async function createUserWithGoogleAtomic(data: {
  googleId: string;
  googleEmail: string;
  name?: string;
}): Promise<{ user: User; created: boolean }> {
  // Wait for any existing transaction to complete
  const lockKey = `google:${data.googleId}`;
  const existingLock = transactionLock.get(lockKey);
  if (existingLock) {
    await existingLock;
  }

  // Create a new transaction promise
  let resolveLock: (value: unknown) => void;
  const lockPromise = new Promise<unknown>(resolve => {
    resolveLock = resolve;
  });
  transactionLock.set(lockKey, lockPromise);

  try {
    // Check if googleId already exists (INSERT ... ON CONFLICT DO NOTHING equivalent)
    const existingUserId = googleIdIndex.get(data.googleId);
    if (existingUserId) {
      const existingUser = users.get(existingUserId);
      if (existingUser) {
        return { user: existingUser, created: false };
      }
    }

    const now = new Date();
    const userId = `user_${Date.now()}`;
    
    const user: User = {
      id: userId,
      email: data.googleEmail.toLowerCase().trim(),
      userId,
      passwordHash: '',
      apiKeyHash: '',
      apiKeyPrefix: '',
      googleId: data.googleId,
      googleEmail: data.googleEmail.toLowerCase().trim(),
      createdAt: now,
      updatedAt: now,
    };

    users.set(userId, user);
    googleIdIndex.set(data.googleId, userId);
    return { user, created: true };
  } finally {
    // Release lock
    transactionLock.delete(lockKey);
    resolveLock!(undefined);
  }
}

/**
 * Links a Google account to an existing user with row locking.
 * Uses SELECT ... FOR UPDATE pattern to lock the row before linking.
 * 
 * @returns Object with success flag and the updated user
 */
export async function linkGoogleAccountWithLock(
  userId: string,
  googleId: string,
  googleEmail: string
): Promise<{ success: boolean; user?: User }> {
  // Acquire lock for the user row (SELECT ... FOR UPDATE equivalent)
  const lockKey = `user:${userId}`;
  const existingLock = transactionLock.get(lockKey);
  if (existingLock) {
    await existingLock;
  }

  // Create a new transaction promise
  let resolveLock: (value: unknown) => void;
  const lockPromise = new Promise<unknown>(resolve => {
    resolveLock = resolve;
  });
  transactionLock.set(lockKey, lockPromise);

  try {
    const user = users.get(userId);
    if (!user) {
      return { success: false };
    }

    // Check if googleId is already linked to another user
    const existingUserId = googleIdIndex.get(googleId);
    if (existingUserId && existingUserId !== userId) {
      return { success: false };
    }

    user.googleId = googleId;
    user.googleEmail = googleEmail.toLowerCase().trim();
    user.updatedAt = new Date();
    
    googleIdIndex.set(googleId, userId);
    return { success: true, user };
  } finally {
    // Release lock
    transactionLock.delete(lockKey);
    resolveLock!(undefined);
  }
}

/**
 * Links a Google account to an existing user.
 * Note: For production use, prefer linkGoogleAccountWithLock() for atomicity.
 */
export async function linkGoogleAccount(
  userId: string,
  googleId: string,
  googleEmail: string
): Promise<boolean> {
  const user = users.get(userId);

  if (!user) {
    return false;
  }

  user.googleId = googleId;
  user.googleEmail = googleEmail.toLowerCase().trim();
  user.updatedAt = new Date();
  
  googleIdIndex.set(googleId, userId);
  return true;
}

/**
 * Retrieves a user by userId.
 */
export async function getUserByUserId(userId: string): Promise<User | null> {
  if (!userId) {
    return null;
  }

  return users.get(userId) || null;
}

/**
 * Creates a new user.
 */
export async function createUser(data: {
  email: string;
  userId: string;
  passwordHash: string;
  apiKeyHash: string;
}): Promise<User> {
  const now = new Date();
  const user: User = {
    id: `user_${Date.now()}`,
    email: data.email.toLowerCase().trim(),
    userId: data.userId,
    passwordHash: data.passwordHash,
    apiKeyHash: data.apiKeyHash,
    apiKeyPrefix: '',
    createdAt: now,
    updatedAt: now,
  };

  users.set(user.userId, user);
  return user;
}

/**
 * Updates a user's password hash.
 */
export async function updateUserPassword(
  userId: string,
  passwordHash: string
): Promise<boolean> {
  const user = users.get(userId);

  if (!user) {
    return false;
  }

  user.passwordHash = passwordHash;
  user.updatedAt = new Date();
  return true;
}

/**
 * Updates a user's API key hash and prefix.
 */
export async function updateUserApiKey(
  userId: string,
  apiKeyHash: string,
  apiKeyPrefix: string
): Promise<boolean> {
  const user = users.get(userId);

  if (!user) {
    return false;
  }

  // Remove old prefix from index if it exists
  if (user.apiKeyPrefix) {
    apiKeyPrefixIndex.delete(user.apiKeyPrefix);
  }

  user.apiKeyHash = apiKeyHash;
  user.apiKeyPrefix = apiKeyPrefix;
  user.updatedAt = new Date();

  // Add new prefix to index
  if (apiKeyPrefix) {
    apiKeyPrefixIndex.set(apiKeyPrefix, userId);
  }

  return true;
}

/**
 * Unlinks a Google account from a user.
 */
export async function unlinkGoogleAccount(userId: string): Promise<boolean> {
  const user = users.get(userId);

  if (!user || !user.googleId) {
    return false;
  }

  googleIdIndex.delete(user.googleId);
  user.googleId = undefined;
  user.googleEmail = undefined;
  user.updatedAt = new Date();
  
  return true;
}

/**
 * Retrieves all users (for internal use only).
 * In production, this would be replaced with a direct database query.
 * Used by api-guard.ts for API key lookup.
 */
export async function getAllUsers(): Promise<User[]> {
  return Array.from(users.values());
}