/**
 * Health check endpoint with API key authentication.
 * 
 * Security features:
 * - Validates API key authentication is working
 * - Returns health status of the security perimeter
 * - Uses apiAuthGuard to verify X-API-Key validation
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 */

import { NextRequest, NextResponse } from 'next/server';
import { apiAuthGuard, ApiAuthError } from '@/lib/auth/api-guard';
import { isRedisConnected } from '@/lib/auth/redis';
import { addJitter } from '@/lib/auth/timing';

// Health check response structure
interface HealthResponse {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  security: {
    apiKeyAuth: 'enabled' | 'disabled';
    authenticated: boolean;
    userId?: string;
  };
  services: {
    redis: 'connected' | 'disconnected';
  };
}

/**
 * GET /api/v1/health
 * 
 * Health check with API key authentication verification.
 * Returns 200 if security perimeter is operational.
 */
export async function GET(request: NextRequest) {
  try {
    // Attempt API key authentication
    let userId: string | null = null;
    let authenticated = false;

    try {
      userId = await apiAuthGuard(request);
      authenticated = true;
    } catch (error) {
      // Authentication failed - but we still report health
      if (error instanceof ApiAuthError) {
        // Log the auth failure for monitoring
        console.log(
          JSON.stringify({
            event: 'health.auth_check',
            status: 'unauthenticated',
            error: error.code,
            timestamp: new Date().toISOString(),
          })
        );
      }
    }

    // Check Redis connectivity
    const redisConnected = isRedisConnected();

    // Build health response
    const health: HealthResponse = {
      status: 'healthy', // Health check itself is always healthy
      timestamp: new Date().toISOString(),
      security: {
        apiKeyAuth: 'enabled',
        authenticated,
        userId: authenticated ? userId || undefined : undefined,
      },
      services: {
        redis: redisConnected ? 'connected' : 'disconnected',
      },
    };

    // Add jitter to prevent timing analysis
    await addJitter();

    return NextResponse.json(health, { status: 200 });
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'health.error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );

    await addJitter();

    return NextResponse.json(
      {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check failed',
      },
      { status: 503 }
    );
  }
}