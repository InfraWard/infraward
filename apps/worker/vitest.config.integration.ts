import { defineConfig } from 'vitest/config';

/**
 * Coordinación entre réplicas contra un Redis real (DESIGN §20): REDIS_TEST_URL o, si no,
 * Testcontainers.
 */
export default defineConfig({
  test: {
    globals: true,
    include: ['src/**/*.int-spec.ts'],
    // Comparten el Redis (db 13) y lo vacían entre tests: uno a la vez.
    fileParallelism: false,
    hookTimeout: 120_000,
    testTimeout: 60_000,
  },
});
