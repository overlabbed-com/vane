import { defineConfig } from 'vitest/config';

/**
 * Vitest 4 configuration for Vane authentication service.
 * Uses Rolldown instead of esbuild.
 */
export default defineConfig({
  test: {
    include: ['lib/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
    },
  },
});