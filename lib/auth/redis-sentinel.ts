/**
 * Redis Sentinel connection manager.
 * 
 * Features:
 * - Automatic master/slave discovery via ioredis built-in Sentinel support
 * - Failover detection and reconnection
 * - Health check with Sentinel status
 * - Wait for failover completion
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 3
 * STRIDE: Mitigates E-04 (Auth Gateway SPOF)
 */

import Redis from 'ioredis';

interface SentinelConfig {
  sentinels: Array<{ host: string; port: number }>;
  masterName: string;
  password?: string;
  sentinelPassword?: string;
  db?: number;
}

export interface SentinelStatus {
  master: { host: string; port: number } | null;
  slaves: Array<{ host: string; port: number; lag: number }>;
  quorum: number;
  healthy: boolean;
}

// Sentinel configuration from environment
function getSentinelConfig(): SentinelConfig {
  const sentinelHosts = process.env.REDIS_SENTINEL_HOSTS || 'localhost:26379';
  const sentinelList = sentinelHosts.split(',').map((s) => {
    const [host, port] = s.split(':');
    return { host, port: parseInt(port, 10) || 26379 };
  });

  return {
    sentinels: sentinelList,
    masterName: process.env.REDIS_SENTINEL_MASTER_NAME || 'mymaster',
    password: process.env.REDIS_AUTH_SECRET,
    sentinelPassword: process.env.REDIS_SENTINEL_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0', 10),
  };
}

// Singleton Sentinel client
let sentinelClient: Redis | null = null;
let connectionError: Error | null = null;
let initPromise: Promise<Redis> | null = null;

// Track failover events
let failoverEventListeners: Array<(masterName: string) => void> = [];

/**
 * Initializes the Sentinel client.
 * Call this once at application startup.
 * Uses initPromise to prevent race conditions from concurrent calls.
 * 
 * @returns Redis client instance connected via Sentinel
 */
export function initSentinelClient(): Redis {
  if (sentinelClient) {
    return sentinelClient;
  }

  if (!initPromise) {
    initPromise = doInitSentinelClient();
  }

  return sentinelClient!;
}

/**
 * Creates a Redis client connected via Sentinel.
 * The client automatically tracks the current master.
 * 
 * @returns Redis client instance
 */
export function createSentinelClient(): Redis {
  return initSentinelClient();
}

async function doInitSentinelClient(): Promise<Redis> {
  const config = getSentinelConfig();

  // ioredis built-in Sentinel support
  // When sentinels are provided, ioredis automatically discovers the master
  sentinelClient = new Redis({
    sentinels: config.sentinels,
    name: config.masterName,
    password: config.password,
    db: config.db,
    // Sentinel-specific options
    sentinelPassword: config.sentinelPassword,
    // Retry strategy for Sentinel mode
    sentinelRetryStrategy: (times: number) => {
      if (times > 10) {
        return null;
      }
      return Math.min(times * 100, 3000);
    },
    // Retry strategy for Redis commands
    retryStrategy: (times: number) => {
      if (times > 10) {
        return null;
      }
      return Math.min(times * 100, 3000);
    },
    // Connection settings
    connectTimeout: 10000,
    commandTimeout: 5000,
    lazyConnect: true,
    // Key prefix for namespace isolation
    keyPrefix: 'vane:',
  });

  // Event handlers
  sentinelClient.on('error', (error) => {
    console.error('Redis Sentinel client error:', error.message);
    connectionError = error;
  });

  sentinelClient.on('connect', () => {
    console.log('Redis Sentinel client connected');
    connectionError = null;
  });

  sentinelClient.on('close', () => {
    console.log('Redis Sentinel client disconnected');
  });

  sentinelClient.on('reconnecting', () => {
    console.log('Redis Sentinel client reconnecting...');
  });

  // Failover event - ioredis emits '+switch-master' on failover
  sentinelClient.on('+switch-master', (result: string) => {
    console.log(`Failover detected: ${result}`);
    // Notify listeners
    for (const listener of failoverEventListeners) {
      listener(result);
    }
    // Invalidate cached client
    if (sentinelClient) {
      sentinelClient.disconnect();
      sentinelClient = null;
    }
    initPromise = null;
  });

  sentinelClient.on('sentinel', (sentinelInfo: { ip: string; port: number }) => {
    console.log(`Sentinel event from: ${sentinelInfo.ip}:${sentinelInfo.port}`);
  });

  return sentinelClient;
}

/**
 * Gets the Redis client via Sentinel.
 * Initializes if not already done.
 * 
 * @returns Redis client instance
 */
export function getSentinelRedisClient(): Redis {
  if (!sentinelClient) {
    return initSentinelClient();
  }
  return sentinelClient;
}

/**
 * Gets the current Sentinel status.
 * Queries Sentinel for master/slave information.
 * 
 * @returns Sentinel status including master and slave info
 */
export async function getSentinelStatus(): Promise<SentinelStatus> {
  const client = getSentinelRedisClient();
  const config = getSentinelConfig();

  try {
    // Get master info using SENTINEL command
    // Type assertion needed as ioredis Sentinel types don't include sentinel() method
    const masterResult = await (client as any).sentinel('MASTER', config.masterName);
    
    let master: { host: string; port: number } | null = null;
    if (masterResult && masterResult[0]) {
      // Parse SENTINEL MASTER output
      // Format: ["ip", "127.0.0.1", "port", "6379", ...]
      const resultObj: Record<string, string> = {};
      for (let i = 0; i < masterResult.length; i += 2) {
        resultObj[masterResult[i]] = masterResult[i + 1];
      }
      master = {
        host: resultObj.ip || '127.0.0.1',
        port: parseInt(resultObj.port || '6379', 10),
      };
    }

    // Get slave info
    const slavesResult = await (client as any).sentinel('SLAVES', config.masterName);
    const slaves: Array<{ host: string; port: number; lag: number }> = [];
    
    if (slavesResult) {
      for (const slaveResult of slavesResult) {
        const slaveObj: Record<string, string> = {};
        for (let i = 0; i < slaveResult.length; i += 2) {
          slaveObj[slaveResult[i]] = slaveResult[i + 1];
        }
        slaves.push({
          host: slaveObj.ip || '127.0.0.1',
          port: parseInt(slaveObj.port || '6379', 10),
          lag: parseInt(slaveObj.lag || '0', 10),
        });
      }
    }

    return {
      master,
      slaves,
      quorum: 2, // Configured quorum
      healthy: master !== null,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(`Failed to get Sentinel status: ${message}`);
    return {
      master: null,
      slaves: [],
      quorum: 2,
      healthy: false,
    };
  }
}

/**
 * Gets the current master address from Sentinel.
 * 
 * @returns Master address or null if unavailable
 */
export async function getCurrentMaster(): Promise<{ host: string; port: number } | null> {
  const client = getSentinelRedisClient();
  const config = getSentinelConfig();

  try {
    const masterResult = await (client as any).sentinel('MASTER', config.masterName);
    
    if (masterResult && masterResult[0]) {
      const resultObj: Record<string, string> = {};
      for (let i = 0; i < masterResult.length; i += 2) {
        resultObj[masterResult[i]] = masterResult[i + 1];
      }
      return {
        host: resultObj.ip || '127.0.0.1',
        port: parseInt(resultObj.port || '6379', 10),
      };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Waits for failover to complete.
 * Polls Sentinel until master changes or timeout.
 * 
 * @param timeoutMs - Maximum time to wait (default: 30000ms)
 * @returns true if failover detected, false if timeout
 */
export async function waitForFailover(timeoutMs: number = 30000): Promise<boolean> {
  const start = Date.now();
  const initialMaster = await getCurrentMaster();

  while (Date.now() - start < timeoutMs) {
    const currentMaster = await getCurrentMaster();
    
    // Master changed (failover detected)
    if (currentMaster && initialMaster) {
      if (currentMaster.host !== initialMaster.host || currentMaster.port !== initialMaster.port) {
        console.log(`Failover detected: ${initialMaster.host}:${initialMaster.port} -> ${currentMaster.host}:${currentMaster.port}`);
        return true;
      }
    } else if (currentMaster && !initialMaster) {
      // Master came online (initial failover)
      console.log(`Master online: ${currentMaster.host}:${currentMaster.port}`);
      return true;
    }

    await sleep(100);
  }

  console.warn(`Failover wait timeout after ${timeoutMs}ms`);
  return false;
}

/**
 * Checks if Sentinel is currently connected.
 */
export function isSentinelConnected(): boolean {
  return sentinelClient !== null && sentinelClient.status === 'ready' && connectionError === null;
}

/**
 * Registers a failover event listener.
 * 
 * @param listener - Callback function called on failover
 */
export function onFailover(listener: (masterName: string) => void): void {
  failoverEventListeners.push(listener);
}

/**
 * Closes the Sentinel connection.
 * Call this at application shutdown.
 */
export async function closeSentinelClient(): Promise<void> {
  if (sentinelClient) {
    await sentinelClient.quit();
    sentinelClient = null;
  }
  initPromise = null;
}

// Utility function
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}