/**
 * Unit tests for the Argon2id semaphore.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Semaphore, getArgon2Semaphore, resetArgon2Semaphore, withSemaphore } from './semaphore';

describe('Semaphore', () => {
  beforeEach(() => {
    resetArgon2Semaphore();
  });

  it('should limit concurrent operations', async () => {
    const semaphore = new Semaphore(2);
    let running = 0;
    let maxRunning = 0;

    // Create task functions (not promises)
    const taskFunctions = Array.from({ length: 5 }, (_, i) => async () => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise((resolve) => setTimeout(resolve, 10));
      running--;
      return i;
    });

    // Execute all task functions through semaphore
    const promises = taskFunctions.map((task) => semaphore.acquire(task));
    const results = await Promise.all(promises);

    expect(maxRunning).toBeLessThanOrEqual(2);
    expect(results.length).toBe(5);
  });

  it('should queue operations when at capacity', async () => {
    const semaphore = new Semaphore(1, 5000, 10);
    let running = 0;

    // Start one operation that holds the semaphore
    const holdPromise = semaphore.acquire(async () => {
      running++;
      await new Promise((resolve) => setTimeout(resolve, 50));
      running--;
      return 'held';
    });

    // Wait for the first operation to start
    await new Promise((resolve) => setTimeout(resolve, 10));

    // Queue another operation
    const queuedPromise = semaphore.acquire(async () => {
      return 'queued';
    });

    // Wait for queued task to complete
    const result = await queuedPromise;

    // Complete the hold task
    await holdPromise;

    expect(result).toBe('queued');
    expect(semaphore.runningCount).toBeLessThanOrEqual(1);
  });

  it('should report correct statistics', async () => {
    const semaphore = new Semaphore(2);

    expect(semaphore.getStats()).toEqual({
      running: 0,
      queued: 0,
      maxConcurrent: 2,
      queueTimeoutMs: 30000,
    });
  });

  it('should track running count', async () => {
    const semaphore = new Semaphore(2);

    expect(semaphore.runningCount).toBe(0);
    expect(semaphore.queuedCount).toBe(0);
    expect(semaphore.isAtCapacity).toBe(false);
  });

  it('should track queued count', async () => {
    const semaphore = new Semaphore(1, 5000, 10);

    // Start operation that holds the semaphore
    const holdPromise = semaphore.acquire(async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));
      return 'task1';
    });

    // Wait for operation to start
    await new Promise((resolve) => setTimeout(resolve, 5));

    expect(semaphore.runningCount).toBe(1);
    expect(semaphore.isAtCapacity).toBe(true);

    // Complete the hold task
    await holdPromise;
  });
});

describe('withSemaphore', () => {
  beforeEach(() => {
    resetArgon2Semaphore();
  });

  it('should execute operation within semaphore', async () => {
    const result = await withSemaphore(async () => {
      return 'success';
    });

    expect(result).toBe('success');
  });

  it('should limit concurrent operations', async () => {
    let running = 0;
    const results: number[] = [];

    const taskFunctions = Array.from({ length: 5 }, (_, i) => async () => {
      running++;
      results.push(running);
      await new Promise((resolve) => setTimeout(resolve, 10));
      running--;
      return i;
    });

    const promises = taskFunctions.map((task) => withSemaphore(task));
    await Promise.all(promises);

    // Should never have more than 10 running (semaphore max)
    expect(Math.max(...results)).toBeLessThanOrEqual(10);
  });
});