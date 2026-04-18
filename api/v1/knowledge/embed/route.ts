/**
 * Knowledge Embedding API Endpoint.
 *
 * Security features:
 * - API key authentication via apiAuthGuard
 * - Resource access validation via validateResourceAccess
 * - Batch size limit (100 items)
 * - Token budget enforcement (8192 tokens)
 * - Anti-spoofing: projectId deleted from client metadata
 *
 * Reference: IMPLEMENTATION-PLAN.md Phase 2.2
 */

import { NextRequest, NextResponse } from 'next/server';
import { apiAuthGuard, validateResourceAccess, ApiAuthError } from '@/lib/auth/api-guard';
import { getVectorDBClient, estimateTokens, MAX_BATCH_SIZE, MAX_TOKENS_PER_BATCH } from '@/lib/db/embeddings';
import { addJitter } from '@/lib/auth/timing';

// Standardized error responses
const ERROR_MESSAGES = {
  MISSING_API_KEY: 'Missing API key',
  INVALID_API_KEY: 'Invalid API key',
  ACCESS_DENIED: 'Access denied',
  BATCH_TOO_LARGE: 'Batch exceeds maximum size of 100 items',
  TOKEN_LIMIT_EXCEEDED: 'Batch exceeds maximum token limit of 8192',
  INVALID_REQUEST: 'Invalid request body',
  INTERNAL_ERROR: 'An internal error occurred',
} as const;

/**
 * Request body for embed endpoint.
 */
interface EmbedRequestBody {
  projectId: string;
  items: Array<{
    content: string;
    metadata?: Record<string, unknown>;
  }>;
}

/**
 * Embed response structure.
 */
interface EmbedResponse {
  success: boolean;
  results: Array<{
    id: string;
    success: boolean;
  }>;
  totalTokens: number;
  projectId: string;
}

/**
 * Error response structure.
 */
interface ErrorResponse {
  error: string;
  code: string;
  details?: {
    maxBatchSize?: number;
    maxTokens?: number;
    actualTokens?: number;
    actualBatchSize?: number;
  };
}

/**
 * POST /api/v1/knowledge/embed
 *
 * Stores embeddings for a project.
 *
 * Security flow:
 * 1. Extract and validate API key
 * 2. Validate resource access (project membership)
 * 3. Validate batch constraints
 * 4. Sanitize metadata (delete projectId)
 * 5. Store embeddings with injected projectId
 */
export async function POST(request: NextRequest) {
  try {
    // Step 1: Authenticate
    let userId: string;
    try {
      userId = await apiAuthGuard(request);
    } catch (error) {
      if (error instanceof ApiAuthError) {
        return NextResponse.json(
          {
            error: error.message,
            code: error.code,
          } as ErrorResponse,
          { status: error.statusCode }
        );
      }
      throw error;
    }

    // Step 2: Parse and validate request body
    let body: EmbedRequestBody;
    try {
      body = await request.json() as EmbedRequestBody;
    } catch {
      await addJitter();
      return NextResponse.json(
        {
          error: ERROR_MESSAGES.INVALID_REQUEST,
          code: 'INVALID_REQUEST',
        } as ErrorResponse,
        { status: 400 }
      );
    }

    const { projectId, items } = body;

    // Validate required fields
    if (!projectId || typeof projectId !== 'string') {
      await addJitter();
      return NextResponse.json(
        {
          error: ERROR_MESSAGES.INVALID_REQUEST,
          code: 'INVALID_REQUEST',
        } as ErrorResponse,
        { status: 400 }
      );
    }

    if (!Array.isArray(items) || items.length === 0) {
      await addJitter();
      return NextResponse.json(
        {
          error: ERROR_MESSAGES.INVALID_REQUEST,
          code: 'INVALID_REQUEST',
        } as ErrorResponse,
        { status: 400 }
      );
    }

    // Step 3: Validate resource access
    try {
      await validateResourceAccess(userId, projectId, 'project');
    } catch (error) {
      if (error instanceof ApiAuthError) {
        return NextResponse.json(
          {
            error: ERROR_MESSAGES.ACCESS_DENIED,
            code: 'ACCESS_DENIED',
          } as ErrorResponse,
          { status: 403 }
        );
      }
      throw error;
    }

    // Step 4: Validate batch constraints
    if (items.length > MAX_BATCH_SIZE) {
      await addJitter();
      return NextResponse.json(
        {
          error: ERROR_MESSAGES.BATCH_TOO_LARGE,
          code: 'BATCH_TOO_LARGE',
          details: {
            maxBatchSize: MAX_BATCH_SIZE,
            actualBatchSize: items.length,
          },
        } as ErrorResponse,
        { status: 413 }
      );
    }

    // Calculate token count
    const totalTokens = items.reduce(
      (sum, item) => sum + estimateTokens(item.content || ''),
      0
    );

    if (totalTokens > MAX_TOKENS_PER_BATCH) {
      await addJitter();
      return NextResponse.json(
        {
          error: ERROR_MESSAGES.TOKEN_LIMIT_EXCEEDED,
          code: 'TOKEN_LIMIT_EXCEEDED',
          details: {
            maxTokens: MAX_TOKENS_PER_BATCH,
            actualTokens: totalTokens,
          },
        } as ErrorResponse,
        { status: 413 }
      );
    }

    // Step 5: Store embeddings
    try {
      const vectorDB = getVectorDBClient();
      const result = await vectorDB.embed(projectId, items);

      await addJitter();

      const response: EmbedResponse = {
        success: true,
        results: result.results.map(r => ({
          id: r.id,
          success: r.success,
        })),
        totalTokens: result.totalTokens,
        projectId: result.projectId,
      };

      return NextResponse.json(response, { status: 200 });
    } catch (error) {
      console.error(
        JSON.stringify({
          event: 'knowledge.embed.error',
          error: error instanceof Error ? error.message : 'Unknown error',
          projectId,
          userId,
          timestamp: new Date().toISOString(),
        })
      );

      await addJitter();

      // Check for specific error types
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      if (errorMessage === ERROR_MESSAGES.BATCH_TOO_LARGE) {
        return NextResponse.json(
          {
            error: ERROR_MESSAGES.BATCH_TOO_LARGE,
            code: 'BATCH_TOO_LARGE',
            details: {
              maxBatchSize: MAX_BATCH_SIZE,
              actualBatchSize: items.length,
            },
          } as ErrorResponse,
          { status: 413 }
        );
      }

      if (errorMessage === ERROR_MESSAGES.TOKEN_LIMIT_EXCEEDED) {
        return NextResponse.json(
          {
            error: ERROR_MESSAGES.TOKEN_LIMIT_EXCEEDED,
            code: 'TOKEN_LIMIT_EXCEEDED',
            details: {
              maxTokens: MAX_TOKENS_PER_BATCH,
              actualTokens: totalTokens,
            },
          } as ErrorResponse,
          { status: 413 }
        );
      }

      return NextResponse.json(
        {
          error: ERROR_MESSAGES.INTERNAL_ERROR,
          code: 'INTERNAL_ERROR',
        } as ErrorResponse,
        { status: 500 }
      );
    }
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'knowledge.embed.critical_error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );

    await addJitter();

    return NextResponse.json(
      {
        error: ERROR_MESSAGES.INTERNAL_ERROR,
        code: 'INTERNAL_ERROR',
      } as ErrorResponse,
      { status: 500 }
    );
  }
}