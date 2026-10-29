import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import {
  RedisContainer,
  type StartedRedisContainer,
} from '@testcontainers/redis';
import type { TestProject } from 'vitest/node';

declare module 'vitest' {
  export interface ProvidedContext {
    databaseUrl: string;
    redisUrl: string;
  }
}

/**
 * Servicios de los e2e, arrancados una vez para todos los ficheros:
 * - PostgreSQL: DATABASE_URL si está definida (en CI, un `services: postgres`) o un
 *   contenedor efímero. Cada fichero crea su propia BD a partir de ella.
 * - Redis: REDIS_URL si está definida o un contenedor efímero.
 */
export default async function setup(project: TestProject) {
  // Ryuk (limpieza de contenedores) no funciona con Podman rootless; aquí se paran los
  // contenedores al terminar. Reactivable con TESTCONTAINERS_RYUK_DISABLED=false.
  process.env.TESTCONTAINERS_RYUK_DISABLED ??= 'true';

  let postgres: StartedPostgreSqlContainer | undefined;
  let redis: StartedRedisContainer | undefined;

  const databaseUrl =
    process.env.DATABASE_URL ??
    (postgres = await new PostgreSqlContainer(
      'docker.io/library/postgres:18-alpine',
    ).start()).getConnectionUri();
  const redisUrl =
    process.env.REDIS_URL ??
    (redis = await new RedisContainer(
      'docker.io/library/redis:7-alpine',
    ).start()).getConnectionUrl();

  project.provide('databaseUrl', databaseUrl);
  project.provide('redisUrl', redisUrl);

  return async () => {
    await postgres?.stop();
    await redis?.stop();
  };
}
