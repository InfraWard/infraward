import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    root: './',
    include: ['test/**/*.e2e-spec.ts'],
    globalSetup: ['test/global-setup.ts'],
    // Los ficheros comparten servidores (PostgreSQL y Redis): uno detrás de otro.
    fileParallelism: false,
    // Arrancar los contenedores (Testcontainers) puede tardar la primera vez.
    hookTimeout: 120_000,
    // Cada test recorre flujos completos (worker como proceso aparte, argon2, varias peticiones):
    // los 5 s por defecto no bastan en runners de CI lentos. Los helpers ya acotan cada espera.
    testTimeout: 60_000,
  },
});
