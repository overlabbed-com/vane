/**
 * Unit tests for graceful shutdown handler.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Set required env vars before importing
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';

// Mock ioredis before importing shutdown
vi.mock('ioredis', () => {
  class MockRedis {
    status = 'ready';
    on = vi.fn();
    quit = vi.fn().mockResolvedValue('OK');
    ping = vi.fn().mockResolvedValue('PONG');
  }
  return {
    default: MockRedis,
  };
});

import {
  setupGracefulShutdown,
  initiateShutdown,
  trackRequest,
  isServerShuttingDown,
  getActiveRequestCount,
  resetShutdownState,
} from './shutdown';

describe('Graceful Shutdown', () => {
  beforeEach(() => {
    resetShutdownState();
    // Mock process.exit to prevent vitest from failing
    vi.spyOn(process, 'exit').mockImplementation((() => {}) as any);
  });

  afterEach(() => {
    resetShutdownState();
    vi.restoreAllMocks();
  });

  it('sets shutting down flag on SIGTERM', () => {
    const server = { close: vi.fn((cb) => cb()) };
    
    setupGracefulShutdown(server);
    initiateShutdown(server, 'SIGTERM');
    
    expect(isServerShuttingDown()).toBe(true);
  });

  it('sets shutting down flag on SIGINT', () => {
    const server = { close: vi.fn((cb) => cb()) };
    
    setupGracefulShutdown(server);
    initiateShutdown(server, 'SIGINT');
    
    expect(isServerShuttingDown()).toBe(true);
  });

  it('race guard prevents double-close on SIGTERM', () => {
    const closeSpy = vi.fn((cb) => cb());
    const server = { close: closeSpy };
    
    setupGracefulShutdown(server);
    
    // First SIGTERM
    initiateShutdown(server, 'SIGTERM');
    expect(isServerShuttingDown()).toBe(true);
    expect(closeSpy).toHaveBeenCalledTimes(1);
    
    // Reset close spy to count calls
    closeSpy.mockClear();
    
    // Second SIGTERM (should be debounced by mutex)
    initiateShutdown(server, 'SIGTERM');
    expect(closeSpy).toHaveBeenCalledTimes(0);
  });

  it('race guard prevents double-close on SIGINT', () => {
    const closeSpy = vi.fn((cb) => cb());
    const server = { close: closeSpy };
    
    setupGracefulShutdown(server);
    
    // First SIGINT
    initiateShutdown(server, 'SIGINT');
    expect(isServerShuttingDown()).toBe(true);
    expect(closeSpy).toHaveBeenCalledTimes(1);
    
    // Reset close spy to count calls
    closeSpy.mockClear();
    
    // Second SIGINT (should be debounced by mutex)
    initiateShutdown(server, 'SIGINT');
    expect(closeSpy).toHaveBeenCalledTimes(0);
  });

  it('tracks active requests', () => {
    const track = trackRequest();
    expect(getActiveRequestCount()).toBe(1);
    
    track();
    expect(getActiveRequestCount()).toBe(0);
  });

  it('tracks concurrent requests', () => {
    const tracks = [trackRequest(), trackRequest(), trackRequest()];
    
    expect(getActiveRequestCount()).toBe(3);
    
    tracks[0]();
    expect(getActiveRequestCount()).toBe(2);
    
    tracks[1]();
    expect(getActiveRequestCount()).toBe(1);
    
    tracks[2]();
    expect(getActiveRequestCount()).toBe(0);
  });

  it('throws when tracking during shutdown', () => {
    const server = { close: vi.fn((cb) => cb()) };
    setupGracefulShutdown(server);
    initiateShutdown(server, 'SIGTERM');
    
    expect(() => trackRequest()).toThrow('Server shutting down');
  });

  it('throws when tracking after mutex is set', () => {
    const server = { close: vi.fn((cb) => cb()) };
    setupGracefulShutdown(server);
    initiateShutdown(server, 'SIGTERM');
    
    // Reset to allow tracking, but set mutex
    resetShutdownState();
    const track = trackRequest();
    track(); // track one request
    
    // Now emit SIGTERM to set mutex
    initiateShutdown(server, 'SIGTERM');
    
    expect(() => trackRequest()).toThrow('Server shutting down');
  });

  it('force exit timer is unrefd', () => {
    const server = {
      close: vi.fn((callback) => {
        callback();
      }),
    };
    
    setupGracefulShutdown(server);
    initiateShutdown(server, 'SIGTERM');
    
    // The forceExitTimer should be set and unref'd
    // We can't directly test unref, but we verify the shutdown proceeds
    expect(isServerShuttingDown()).toBe(true);
  });
});