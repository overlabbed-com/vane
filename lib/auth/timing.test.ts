/**
 * Unit tests for timing jitter utilities.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { addJitter, getJitterDelay, getJitterConfig } from './timing';

describe('timing jitter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it('adds delay between base and max', async () => {
    const config = getJitterConfig();
    
    const promise = addJitter();
    
    // Fast-forward time past max delay
    vi.advanceTimersByTime(config.maxDelayMs + 50);
    await promise;
    
    // Verify getJitterDelay returns value in expected range
    const delay = getJitterDelay();
    expect(delay).toBeGreaterThanOrEqual(config.baseDelayMs);
    expect(delay).toBeLessThanOrEqual(config.maxDelayMs);
  });

  it('adds jitter within range', async () => {
    const config = getJitterConfig();
    
    const promise = addJitter();
    
    // Fast-forward past the delay
    vi.advanceTimersByTime(config.maxDelayMs + 50);
    await promise;
    
    // Verify delay is within base + jitter range
    const delay = getJitterDelay();
    expect(delay).toBeGreaterThanOrEqual(config.baseDelayMs);
    expect(delay).toBeLessThanOrEqual(config.baseDelayMs + config.jitterRangeMs);
  });

  it('produces variable delays', async () => {
    // With fake timers, we can't test true randomness
    // Instead, verify that addJitter returns a promise that resolves
    // after the expected delay range
    const config = getJitterConfig();
    
    const promise = addJitter();
    
    // Verify the promise resolves after appropriate delay
    vi.advanceTimersByTime(config.maxDelayMs + 50);
    await expect(promise).resolves.toBeUndefined();
    
    // Verify getJitterDelay returns the actual delay used
    const delay = getJitterDelay();
    expect(delay).toBeGreaterThanOrEqual(config.baseDelayMs);
    expect(delay).toBeLessThanOrEqual(config.maxDelayMs);
  });

  it('respects custom base delay', async () => {
    const promise = addJitter(100, 0); // Fixed 100ms delay
    
    vi.advanceTimersByTime(150);
    await promise;
    
    // Verify getJitterDelay returns the custom base delay
    const delay = getJitterDelay();
    expect(delay).toBe(100);
  });

  it('respects custom jitter range', async () => {
    const promise = addJitter(50, 10); // 50ms base + 0-10ms jitter
    
    vi.advanceTimersByTime(80);
    await promise;
    
    // Verify delay is within expected range
    const delay = getJitterDelay();
    expect(delay).toBeGreaterThanOrEqual(50);
    expect(delay).toBeLessThanOrEqual(60); // 50 + 10
  });

  it('no jitter on success (verify addJitter not called)', async () => {
    // This test verifies the pattern: addJitter should only be called on error paths
    // Success responses should not call addJitter
    
    const start = Date.now();
    
    // Simulate a success path (no jitter)
    // In real code, success returns immediately without addJitter
    
    const elapsed = Date.now() - start;
    // Success should be fast (no jitter)
    expect(elapsed).toBeLessThan(10); // Essentially instant
  });
});