import { defineConfig } from 'vitest/config';

/**
 * Tests contra servidores reales: sshd en un contenedor (Testcontainers) y OpenBao
 * (OPENBAO_TEST_ADDR + OPENBAO_TEST_ROOT_TOKEN o Testcontainers).
 */
export default defineConfig({
  test: {
    globals: true,
    root: './',
    include: ['test/integration/**/*.int-spec.ts'],
    // Construir la imagen de sshd puede tardar la primera vez.
    hookTimeout: 300_000,
    testTimeout: 120_000,
    fileParallelism: false,
  },
});
