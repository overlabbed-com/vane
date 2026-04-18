/**
 * Mock database client for health checks.
 * In production, this would be a real database client (e.g., postgres).
 */

export const db = {
  /**
   * Executes a raw query.
   * For health checks, we just verify connection.
   */
  async raw(query: string): Promise<unknown> {
    // Mock implementation - in production this would be a real DB query
    if (query.includes('SELECT 1')) {
      return { rows: [{ '?column?': 1 }] };
    }
    throw new Error('Unknown query');
  },
};