/**
 * Graceful shutdown handler for Auth Gateway.
 * 
 * Features:
 * - SIGTERM/SIGINT handling
 * - Race guard mutex to prevent double-close
 * - Active request tracking
 * - Drain timeout
 * - Force exit after timeout with unref()
 * - Error handling during shutdown
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 4
 * STRIDE: Mitigates E-03 (Rolling deployment request drops)
 */

// Shutdown state
let isShuttingDown = false;
let shutdownMutex = false;  // Race guard mutex
let activeRequests = 0;
let forceExitTimer: NodeJS.Timeout | null = null;

// Configuration
const SHUTDOWN_CONFIG = {
  // Drain timeout: 30 seconds (wait for active requests)
  drainTimeoutMs: 30000,
  // Force exit delay: 1 second (after drain timeout)
  forceExitDelayMs: 1000,
} as const;

/**
 * Sets up graceful shutdown handlers.
 * Call this at application startup.
 * 
 * @param server - HTTP server instance
 */
export function setupGracefulShutdown(server: {
  close: (callback: (err?: Error) => void) => void;
}): void {
  // SIGTERM: Kubernetes/Docker stop signal
  process.on('SIGTERM', () => {
    initiateShutdown(server, 'SIGTERM');
  });

  // SIGINT: Ctrl+C
  process.on('SIGINT', () => {
    initiateShutdown(server, 'SIGINT');
  });
}

/**
 * Initiates graceful shutdown sequence.
 * Uses mutex to prevent double-close.
 * 
 * @param server - HTTP server instance
 * @param signal - Signal that triggered shutdown
 */
export function initiateShutdown(
  server: { close: (callback: (err?: Error) => void) => void },
  signal: 'SIGTERM' | 'SIGINT'
): void {
  // Race guard - prevent double-close
  if (shutdownMutex) {
    return;
  }
  shutdownMutex = true;
  
  console.log(`${signal} received, starting graceful shutdown`);
  isShuttingDown = true;
  
  // Clear any existing force-exit timer
  if (forceExitTimer) {
    clearTimeout(forceExitTimer);
    forceExitTimer = null;
  }

  // Stop accepting new requests by closing the server
  server.close(async (err?: Error) => {
    const deadline = Date.now() + SHUTDOWN_CONFIG.drainTimeoutMs;
    
    try {
      // Wait for active requests to complete
      while (activeRequests > 0 && Date.now() < deadline) {
        await sleep(100);
      }
      
      if (activeRequests > 0) {
        console.warn(`Force closing with ${activeRequests} active requests`);
      }
    } catch (error) {
      console.error('Error during graceful shutdown:', error instanceof Error ? error.message : 'Unknown error');
    } finally {
      // Clear the force-exit timer - we're exiting normally
      if (forceExitTimer) {
        clearTimeout(forceExitTimer);
        forceExitTimer = null;
      }
      await cleanup();
      process.exit(activeRequests > 0 ? 1 : 0);
    }
  });

  // Force exit after drain timeout - unref() eliminates the race.
  // Without unref(): timer callback is queued in event loop, may fire
  // while server.close() callback runs, causing double process.exit().
  // With unref(): timer is skipped when process.exit() starts winding
  // down the event loop. The race is impossible, not mitigated.
  forceExitTimer = setTimeout(() => {
    console.error('Graceful shutdown timeout, forcing exit');
    process.exit(1);
  }, SHUTDOWN_CONFIG.drainTimeoutMs + SHUTDOWN_CONFIG.forceExitDelayMs);
  forceExitTimer.unref();
}

/**
 * Tracks a new active request.
 * Throws if server is shutting down.
 * 
 * @returns Cleanup function to call when request completes
 * @throws Error if server is shutting down
 */
export function trackRequest(): () => void {
  if (isShuttingDown || shutdownMutex) {
    throw new Error('Server shutting down');
  }
  activeRequests++;
  return () => {
    activeRequests--;
  };
}

/**
 * Checks if server is shutting down.
 * 
 * @returns true if shutdown in progress
 */
export function isServerShuttingDown(): boolean {
  return isShuttingDown;
}

/**
 * Gets the number of active requests.
 * 
 * @returns Number of active requests
 */
export function getActiveRequestCount(): number {
  return activeRequests;
}

/**
 * Cleanup function.
 * Call this before exiting.
 */
async function cleanup(): Promise<void> {
  try {
    // Close Redis connection
    const { closeRedisClient } = await import('./redis');
    await closeRedisClient();
  } catch (error) {
    console.error('Cleanup error:', error instanceof Error ? error.message : 'Unknown error');
  }
}

/**
 * Sleep utility.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resets shutdown state (for testing).
 */
export function resetShutdownState(): void {
  isShuttingDown = false;
  shutdownMutex = false;
  activeRequests = 0;
  if (forceExitTimer) {
    clearTimeout(forceExitTimer);
    forceExitTimer = null;
  }
}