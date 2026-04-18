/**
 * Semaphore for limiting concurrent Argon2id operations.
 * 
 * Prevents CPU exhaustion under load (E-02 mitigation):
 * - Maximum 10 concurrent Argon2id operations
 * - Queue overflow with 30 second timeout
 * - Prevents resource exhaustion from parallel hashing
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 2
 * STRIDE: Mitigates E-02 (resource exhaustion)
 */

import { EventEmitter } from 'events';

// Semaphore configuration
const SEMAPHORE_CONFIG = {
  // Maximum concurrent operations
  maxConcurrent: 10,
  // Queue timeout in milliseconds (30 seconds)
  queueTimeoutMs: 30000,
  // Queue max size (0 = unlimited, but bounded by memory)
  queueMaxSize: 100,
} as const;

interface QueuedOperation<T> {
  operation: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  queuedAt: number;
  timeoutId?: ReturnType<typeof setTimeout>;
}

/**
 * Semaphore class for limiting concurrent operations.
 * Uses a queue with timeout for overflow handling.
 */
export class Semaphore extends EventEmitter {
  private running: number = 0;
  private queue: QueuedOperation<unknown>[] = [];
  private readonly maxConcurrent: number;
  private readonly queueTimeoutMs: number;
  private readonly queueMaxSize: number;

  constructor(
    maxConcurrent: number = SEMAPHORE_CONFIG.maxConcurrent,
    queueTimeoutMs: number = SEMAPHORE_CONFIG.queueTimeoutMs,
    queueMaxSize: number = SEMAPHORE_CONFIG.queueMaxSize
  ) {
    super();
    this.maxConcurrent = maxConcurrent;
    this.queueTimeoutMs = queueTimeoutMs;
    this.queueMaxSize = queueMaxSize;
  }

  /**
   * Gets the number of currently running operations.
   */
  get runningCount(): number {
    return this.running;
  }

  /**
   * Gets the number of queued operations.
   */
  get queuedCount(): number {
    return this.queue.length;
  }

  /**
   * Gets the total number of operations (running + queued).
   */
  get totalCount(): number {
    return this.running + this.queue.length;
  }

  /**
   * Checks if the semaphore is at capacity.
   */
  get isAtCapacity(): boolean {
    return this.running >= this.maxConcurrent;
  }

  /**
   * Executes an operation with semaphore protection.
   * If at capacity, queues the operation with a timeout.
   * 
   * @param operation - Async operation to execute
   * @returns Promise resolving to the operation result
   * @throws Error if queue is full or operation times out
   */
  async acquire<T>(operation: () => Promise<T>): Promise<T> {
    // If not at capacity, run immediately
    if (this.running < this.maxConcurrent) {
      return this.runOperation(operation);
    }

    // Check queue capacity (before adding to queue)
    if (this.queueMaxSize > 0 && this.queue.length >= this.queueMaxSize) {
      throw new Error('Semaphore queue is full');
    }

    // Queue the operation with timeout
    return this.queueOperation(operation);
  }

  /**
   * Runs an operation immediately.
   */
  private async runOperation<T>(operation: () => Promise<T>): Promise<T> {
    this.running++;

    try {
      const result = await operation();
      return result;
    } finally {
      this.running--;
      this.processQueue();
    }
  }

  /**
   * Queues an operation with timeout.
   */
  private queueOperation<T>(operation: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const queuedAt = Date.now();

      // Create timeout for this queued operation
      const timeoutId = setTimeout(() => {
        // Find and remove from queue
        const index = this.queue.findIndex((q) => q.queuedAt === queuedAt);
        if (index !== -1) {
          this.queue.splice(index, 1);
          reject(new Error('Semaphore operation timed out in queue'));
        }
      }, this.queueTimeoutMs);

      // Add to queue with timeout ID for cancellation
      this.queue.push({
        operation,
        resolve: resolve as (value: unknown) => void,
        reject,
        queuedAt,
        timeoutId,
      });

      // Process queue if there's capacity
      this.processQueue();
    });
  }

  /**
   * Processes the queue if there's capacity.
   */
  private processQueue(): void {
    if (this.queue.length === 0) {
      return;
    }

    if (this.running < this.maxConcurrent) {
      const queued = this.queue.shift();
      if (queued) {
        // Clear the timeout since operation is now starting
        if (queued.timeoutId) {
          clearTimeout(queued.timeoutId);
        }

        // Run the queued operation
        this.running++;


        queued
          .operation()
          .then(queued.resolve)
          .catch(queued.reject)
          .finally(() => {
            this.running--;
            this.processQueue();
          });
      }
    }
  }

  /**
   * Drains the semaphore, rejecting all queued operations.
   * Use for graceful shutdown.
   */
  async drain(): Promise<void> {
    // Clear all timeouts and reject all queued operations
    for (const queued of this.queue) {
      if (queued.timeoutId) {
        clearTimeout(queued.timeoutId);
      }
      queued.reject(new Error('Semaphore drained'));
    }
    this.queue = [];
    this.running = 0;
  }

  /**
   * Gets semaphore statistics.
   */
  getStats(): { running: number; queued: number; maxConcurrent: number; queueTimeoutMs: number } {
    return {
      running: this.running,
      queued: this.queue.length,
      maxConcurrent: this.maxConcurrent,
      queueTimeoutMs: this.queueTimeoutMs,
    };
  }
}

// Singleton semaphore instance for Argon2id operations
let argon2Semaphore: Semaphore | null = null;

/**
 * Gets the singleton semaphore for Argon2id operations.
 */
export function getArgon2Semaphore(): Semaphore {
  if (!argon2Semaphore) {
    argon2Semaphore = new Semaphore();
  }
  return argon2Semaphore;
}

/**
 * Resets the singleton semaphore (for testing).
 */
export function resetArgon2Semaphore(): void {
  if (argon2Semaphore) {
    argon2Semaphore.drain();
    argon2Semaphore = null;
  }
}

/**
 * Executes an Argon2id operation with semaphore protection.
 * 
 * @param operation - Async Argon2id operation
 * @returns Promise resolving to the operation result
 */
export async function withSemaphore<T>(operation: () => Promise<T>): Promise<T> {
  const semaphore = getArgon2Semaphore();
  return semaphore.acquire(operation);
}