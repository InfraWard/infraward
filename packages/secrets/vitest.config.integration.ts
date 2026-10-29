import { defineConfig } from 'vitest/config';

/** Tests contra un OpenBao real (Testcontainers u OPENBAO_TEST_ADDR + OPENBAO_TEST_ROOT_TOKEN). */
export default defineConfig({
  test: {
    include: ['src/**/*.int-spec.ts'],
    // Arrancar el contenedor puede tardar la primera vez; la renovación espera de verdad.
    hookTimeout: 120_000,
    testTimeout: 60_000,
  },
});
