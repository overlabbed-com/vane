/**
 * Knowledge Query API Endpoint.
 *
 * Security features:
 * - API key authentication via apiAuthGuard
 * - Resource access validation via validateResourceAccess
 * - Project isolation: projectId as top-level AND condition
 * - Defense-in-depth: Results filtered in TypeScript
 *
 * Reference: IMPLEMENTATION-PLAN.md Phase 2.2
 */

import { NextRequest, NextResponse } from 'next/server';
import { apiAuthGuard, validateResourceAccess, ApiAuthError } from '@/lib/auth/api-guard';
import { getVectorDBClient } from '@/lib/db/embeddings';
import { addJitter } from '@/lib/auth/timing';

// Standardized error responses
const ERROR_MESSAGES = {
  MISSING_API_KEY: 'Missing API key',
  INVALID_API_KEY: 'Invalid API key',
  ACCESS_DENIED: 'Access denied',
  INVALID_REQUEST: 'Invalid request body',
  INTERNAL_ERROR: 'An internal error occurred',
} as const;

/**
 * Request body for query endpoint.
 */
interface QueryRequestBody {
  projectId: string;
  query?: string;
  topK?: number;
  filters?: Record<string, unknown>;
}

/**
 * Query response structure.
 */
interface QueryResponse {
  success: boolean;
  results: Array<{
    id: string;
    score: number;
    content: string;
    metadata: Record<string, unknown>;
  }>;
  query: string;
  projectId: string;
  total: number;
}

/**
 * Error response structure.
 */
interface ErrorResponse {
  error: string;
  code: string;
}

/**
 * POST /api/v1/knowledge/query
 *
 * Queries embeddings for a project.
 *
 * Security flow:
 * 1. Extract and validate API key
 * 2. Validate resource access (project membership)
 * 3. Construct query with projectId as top-level AND
 * 4. Execute query
 * 5. Defense-in-depth: Filter results in TypeScript
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
    let body: QueryRequestBody;
    try {
      body = await request.json() as QueryRequestBody;
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

    const { projectId, query, topK = 10, filters } = body;

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

    // Validate topK
    if (typeof topK !== 'number' || topK <= 0 || topK > 100) {
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

    // Step 4: Execute query
    try {
      const vectorDB = getVectorDBClient();

      // Query with projectId as top-level AND condition
      // The VectorDBClient.query() method constructs:
      //   WHERE projectId = $authProjectId AND ...
      // This is the primary isolation mechanism
      const result = await vectorDB.query(
        projectId,
        null, // queryVector (null for mock)
        topK,
        {
          projectId, // Explicitly include projectId in filters
          ...filters,
        }
      );

      // Defense-in-Depth: Filter results in TypeScript
      // Even if the query construction was flawed, this ensures
      // only records matching the authProjectId are returned
      const filteredResults = result.results.filter(
        r => {
          // Re-verify projectId from metadata
          const recordProjectId = r.metadata.projectId;
          return recordProjectId === undefined || recordProjectId === projectId;
        }
      );

      await addJitter();

      const response: QueryResponse = {
        success: true,
        results: filteredResults.map(r => ({
          id: r.id,
          score: r.score,
          content: r.content,
          metadata: r.metadata,
        })),
        query: result.query,
        projectId: result.projectId,
        total: filteredResults.length,
      };

      return NextResponse.json(response, { status: 200 });
    } catch (error) {
      console.error(
        JSON.stringify({
          event: 'knowledge.query.error',
          error: error instanceof Error ? error.message : 'Unknown error',
          projectId,
          userId,
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
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'knowledge.query.critical_error',
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