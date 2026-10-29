import {
  RedisContainer,
  type StartedRedisContainer,
} from '@testcontainers/redis';
import type { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { WorkerRedis } from '../redis/redis.js';

/** Redis de los tests de integración: REDIS_TEST_URL o un contenedor efímero. */
export async function startRedis(): Promise<{
  url: URL;
  stop: () => Promise<void>;
}> {
  // Ryuk no funciona con Podman rootless: el contenedor se para al terminar.
  process.env.TESTCONTAINERS_RYUK_DISABLED ??= 'true';
  let container: StartedRedisContainer | undefined;
  const url = new URL(
    process.env.REDIS_TEST_URL ??
      (container = await new RedisContainer(
        'docker.io/library/redis:7-alpine',
      ).start()).getConnectionUrl(),
  );
  return { url, stop: async () => void (await container?.stop()) };
}

/** Configuración de prueba con el Redis dado (db 13: no se mezcla con desarrollo). */
export function testConfig(
  url: URL,
  values: Partial<EnvironmentVariables> = {},
): ConfigService<EnvironmentVariables, true> {
  const all: Partial<EnvironmentVariables> = {
    REDIS_HOST: url.hostname,
    REDIS_PORT: Number(url.port || 6379),
    REDIS_DB: 13,
    HOST_MAX_JOBS: 2,
    HOST_MAX_SCAN_JOBS: 1,
    ...values,
  };
  return {
    get: (k: keyof EnvironmentVariables) => all[k],
  } as unknown as ConfigService<EnvironmentVariables, true>;
}

export async function connect(
  config: ConfigService<EnvironmentVariables, true>,
): Promise<WorkerRedis> {
  const redis = new WorkerRedis(config);
  await redis.client.connect();
  return redis;
}
