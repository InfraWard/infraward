import { Injectable, type OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { WORKER_KEY_PREFIX } from '@infraward/shared-types';
import { Redis } from 'ioredis';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Conexión propia con Redis para coordinar las réplicas del worker (DESIGN §20): locks, líder,
 * identidades y semáforos por host. Las claves llevan `WORKER_KEY_PREFIX`. Se cierra la última, al
 * apagar, después de soltar lo que tenga esta réplica.
 */
@Injectable()
export class WorkerRedis implements OnApplicationShutdown {
  readonly client: Redis;

  constructor(config: ConfigService<EnvironmentVariables, true>) {
    this.client = new Redis({
      host: config.get('REDIS_HOST', { infer: true }),
      port: config.get('REDIS_PORT', { infer: true }),
      password: config.get('REDIS_PASSWORD', { infer: true }),
      db: config.get('REDIS_DB', { infer: true }),
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });
  }

  /** Clave de coordinación: `infraward:workers:<partes>`. */
  key(...parts: string[]): string {
    return WORKER_KEY_PREFIX + parts.join(':');
  }

  async onApplicationShutdown(): Promise<void> {
    await this.client.quit().catch(() => undefined);
  }
}

/** Libera una clave solo si sigue siendo nuestra (mismo token). */
export const RELEASE_IF_OWNER = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0`;

/** Alarga la vida de una clave solo si sigue siendo nuestra. */
export const EXTEND_IF_OWNER = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0`;
