import { defineConfig } from 'vitest/config';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      // Tests import `shared` from source so they don't depend on a prior build.
      shared: fileURLToPath(new URL('./shared/src/index.ts', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    globals: true,
    include: [
      'shared/src/**/*.test.ts',
      'client/src/**/*.test.ts',
      'server/src/**/*.test.ts',
    ],
    exclude: ['**/node_modules/**', '**/dist/**'],
  },
});
