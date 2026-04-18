/**
 * Vector Database Client for Knowledge Embeddings.
 *
 * Security features:
 * - Project isolation via projectId injection at storage time
 * - Defense-in-depth filtering on query
 * - Anti-spoofing: client-provided projectId deleted before storage
 *
 * Interface for Milvus/Qdrant in production.
 * Current implementation is a mock for development.
 *
 * Reference: IMPLEMENTATION-PLAN.md Phase 2.2
 */

import { randomBytes } from 'crypto';

// Configuration
export const MAX_BATCH_SIZE = 100;
export const MAX_TOKENS_PER_BATCH = 8192;
const TOKEN_ESTIMATE_CHARS = 4; // Rough estimate: 1 token ≈ 4 chars

// Standardized error responses
const ERROR_MESSAGES = {
  BATCH_TOO_LARGE: 'Batch exceeds maximum size of 100 items',
  TOKEN_LIMIT_EXCEEDED: 'Batch exceeds maximum token limit of 8192',
  INVALID_PROJECT_ID: 'Invalid project ID',
  INVALID_QUERY: 'Invalid query parameters',
  STORAGE_ERROR: 'Failed to store embeddings',
  QUERY_ERROR: 'Failed to query embeddings',
} as const;

/**
 * Embedding record stored in the vector database.
 */
export interface EmbeddingRecord {
  id: string;
  projectId: string;
  content: string;
  vector: number[];
  metadata: Record<string, unknown>;
  createdAt: string;
}

/**
 * Input for embedding a single item.
 */
export interface EmbedInput {
  content: string;
  metadata?: Record<string, unknown>;
}

/**
 * Result of embedding a single item.
 */
export interface EmbedResult {
  id: string;
  success: boolean;
  error?: string;
}

/**
 * Batch embedding result.
 */
export interface EmbedBatchResult {
  results: EmbedResult[];
  totalTokens: number;
  projectId: string;
}

/**
 * Query filters for vector search.
 */
export interface QueryFilters {
  projectId: string;
  [key: string]: unknown;
}

/**
 * Query result item.
 */
export interface QueryResult {
  id: string;
  score: number;
  content: string;
  metadata: Record<string, unknown>;
}

/**
 * Query response.
 */
export interface QueryResponse {
  results: QueryResult[];
  query: string;
  projectId: string;
  total: number;
}

/**
 * Mock vector database store.
 * In production, this would be Milvus or Qdrant.
 */
const embeddingStore = new Map<string, EmbeddingRecord[]>();

/**
 * Mock embedding generation.
 * In production, this would call an embedding model API.
 *
 * @param content - Text content to embed
 * @returns Mock vector embedding (random 1536-dimensional)
 */
function generateEmbedding(content: string): number[] {
  // Generate a deterministic mock embedding based on content hash
  // In production, this would call OpenAI/Cohere/etc. embedding API
  const vector: number[] = [];
  const hash = content.split('').reduce((acc, char, i) => {
    return acc + char.charCodeAt(0) * (i + 1);
  }, 0);

  // Generate pseudo-random but deterministic vector
  for (let i = 0; i < 1536; i++) {
    const seed = hash * (i + 1);
    vector.push(Math.sin(seed) * Math.cos(seed));
  }

  // Normalize the vector
  const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
  return vector.map(val => val / magnitude);
}

/**
 * Estimates token count from content.
 * Uses character-based approximation.
 *
 * @param content - Text content
 * @returns Estimated token count
 */
export function estimateTokens(content: string): number {
  return Math.ceil(content.length / TOKEN_ESTIMATE_CHARS);
}

/**
 * Vector Database Client.
 * Provides project-isolated embedding storage and retrieval.
 */
export class VectorDBClient {
  /**
   * Stores embeddings for a project.
   *
   * Security features:
   * - projectId is injected, not client-provided
   * - Client metadata is sanitized (projectId key deleted)
   * - Token budget enforced
   *
   * @param projectId - Project ID (from auth)
   * @param items - Items to embed
   * @returns Batch result with token count
   */
  async embed(
    projectId: string,
    items: EmbedInput[]
  ): Promise<EmbedBatchResult> {
    // Validate inputs
    if (!projectId) {
      throw new Error(ERROR_MESSAGES.INVALID_PROJECT_ID);
    }

    if (!Array.isArray(items) || items.length === 0) {
      throw new Error('Empty batch');
    }

    if (items.length > MAX_BATCH_SIZE) {
      throw new Error(ERROR_MESSAGES.BATCH_TOO_LARGE);
    }

    // Calculate total tokens
    const totalTokens = items.reduce(
      (sum, item) => sum + estimateTokens(item.content),
      0
    );

    if (totalTokens > MAX_TOKENS_PER_BATCH) {
      throw new Error(ERROR_MESSAGES.TOKEN_LIMIT_EXCEEDED);
    }

    // Process each item
    const results: EmbedResult[] = [];
    const records: EmbeddingRecord[] = [];

    for (const item of items) {
      const id = `emb_${randomBytes(16).toString('hex')}`;

      // Anti-spoofing: Delete any client-provided projectId from metadata
      const sanitizedMetadata = { ...item.metadata };
      delete sanitizedMetadata.projectId;

      // Generate embedding
      const vector = generateEmbedding(item.content);

      // Create record with injected projectId
      const record: EmbeddingRecord = {
        id,
        projectId,
        content: item.content,
        vector,
        metadata: sanitizedMetadata,
        createdAt: new Date().toISOString(),
      };

      records.push(record);
      results.push({ id, success: true });
    }

    // Store in mock database
    const existing = embeddingStore.get(projectId) || [];
    embeddingStore.set(projectId, [...existing, ...records]);

    return {
      results,
      totalTokens,
      projectId,
    };
  }

  /**
   * Queries embeddings for a project.
   *
   * Security features:
   * - projectId is a top-level AND condition
   * - Defense-in-depth: Results filtered in TypeScript
   *
   * @param projectId - Project ID (from auth)
   * @param queryVector - Query vector (or null for mock)
   * @param topK - Number of results to return
   * @param filters - Additional filters
   * @returns Query results
   */
  async query(
    projectId: string,
    queryVector: number[] | null,
    topK: number,
    filters: QueryFilters
  ): Promise<QueryResponse> {
    // Validate inputs
    if (!projectId) {
      throw new Error(ERROR_MESSAGES.INVALID_PROJECT_ID);
    }

    if (topK <= 0 || topK > 100) {
      throw new Error(ERROR_MESSAGES.INVALID_QUERY);
    }

    // Get all embeddings for the project
    const allRecords = embeddingStore.get(projectId) || [];

    // Defense-in-Depth: Filter results in TypeScript
    // This ensures projectId isolation even if the query construction was flawed
    const filteredRecords = allRecords.filter(
      record => record.projectId === projectId
    );

    // Mock query: Return topK results sorted by score
    // In production, this would use vector similarity search
    const results: QueryResult[] = filteredRecords
      .slice(0, topK)
      .map(record => ({
        id: record.id,
        score: 0.9 + Math.random() * 0.1, // Mock score
        content: record.content,
        metadata: record.metadata,
      }));

    return {
      results,
      query: 'vector_search',
      projectId,
      total: results.length,
    };
  }

  /**
   * Deletes all embeddings for a project.
   * Used for testing and cleanup.
   */
  async deleteProject(projectId: string): Promise<void> {
    embeddingStore.delete(projectId);
  }

  /**
   * Gets the count of embeddings for a project.
   * Used for testing.
   */
  async getCount(projectId: string): Promise<number> {
    const records = embeddingStore.get(projectId) || [];
    return records.length;
  }
}

// Singleton instance
let vectorDBClient: VectorDBClient | null = null;

/**
 * Gets the VectorDBClient singleton.
 */
export function getVectorDBClient(): VectorDBClient {
  if (!vectorDBClient) {
    vectorDBClient = new VectorDBClient();
  }
  return vectorDBClient;
}

/**
 * Clears the mock store (for testing).
 */
export function clearEmbeddingStore(): void {
  embeddingStore.clear();
}