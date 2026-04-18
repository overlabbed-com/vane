/**
 * Timing utilities for defense against timing attacks.
 * 
 * Features:
 * - Random jitter on error responses
 * - Consistent base delay
 * - Constant-time operations
 * 
 * Reference: M1 finding
 */

/**
 * Jitter configuration.
 * Base delay + random jitter = total delay.
 */
const JITTER_CONFIG = {
  // Base delay: 50ms (covers typical Redis variance)
  baseDelayMs: 50,
  // Jitter range: 0-50ms (random additional delay)
  jitterRangeMs: 50,
  // Maximum total delay: 100ms
  maxDelayMs: 100,
} as const;

// Track actual delay for testing
let lastDelayMs: number | null = null;

/**
 * Adds random jitter to response time.
 * Uses a Promise with setTimeout to delay response.
 * 
 * @param baseMs - Base delay in milliseconds (default: 50)
 * @param rangeMs - Jitter range in milliseconds (default: 50)
 * @returns Promise that resolves after the delay
 */
export function addJitter(
  baseMs: number = JITTER_CONFIG.baseDelayMs,
  rangeMs: number = JITTER_CONFIG.jitterRangeMs
): Promise<void> {
  // Calculate jitter: random value between 0 and rangeMs
  const jitter = Math.floor(Math.random() * (rangeMs + 1));
  
  // Total delay = base + jitter (capped at maxDelayMs)
  const totalDelay = Math.min(baseMs + jitter, JITTER_CONFIG.maxDelayMs);
  
  // Track for testing
  lastDelayMs = totalDelay;
  
  return new Promise(resolve => setTimeout(resolve, totalDelay));
}

/**
 * Gets the actual delay from the last addJitter call.
 * Useful for testing.
 * 
 * @returns The delay in ms, or null if addJitter hasn't been called
 */
export function getJitterDelay(): number | null {
  return lastDelayMs;
}

/**
 * Gets the current jitter configuration.
 * Useful for testing and monitoring.
 */
export function getJitterConfig(): Readonly<{
  baseDelayMs: number;
  jitterRangeMs: number;
  maxDelayMs: number;
}> {
  return { ...JITTER_CONFIG };
}