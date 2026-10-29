import { Injectable, Module, type OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { ThrottlerStorage } from '@nestjs/throttler';
import { Redis } from 'ioredis';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Ventana fija y bloqueo, de forma atómica. KEYS: hits, block. ARGV: ttl, limit, blockDuration (ms).
 * Devuelve { totalHits, msToExpire, blocked (0/1), msToBlockExpire }, con la misma semántica que el
 * almacén en memoria de @nestjs/throttler: al superar el límite la clave queda bloqueada
 * blockDuration y se rechaza todo lo que llegue mientras tanto.
 */
const INCREMENT_SCRIPT = `
local ttl = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local blockDuration = tonumber(ARGV[3])
local blockTtl = redis.call('PTTL', KEYS[2])
if blockTtl > 0 then
  local hits = redis.call('INCR', KEYS[1])
  local hitsTtl = redis.call('PTTL', KEYS[1])
  if hitsTtl < 0 then
    redis.call('PEXPIRE', KEYS[1], ttl)
    hitsTtl = ttl
  end
  return { hits, hitsTtl, 1, blockTtl }
end
local hits = redis.call('INCR', KEYS[1])
local hitsTtl = redis.call('PTTL', KEYS[1])
if hitsTtl < 0 then
  redis.call('PEXPIRE', KEYS[1], ttl)
  hitsTtl = ttl
end
if hits > limit then
  redis.call('SET', KEYS[2], '1', 'PX', blockDuration)
  redis.call('SET', KEYS[1], '0', 'PX', blockDuration)
  return { hits, blockDuration, 1, blockDuration }
end
return { hits, hitsTtl, 0, 0 }
`;

/**
 * Contadores de los límites de intentos en Redis, compartidos por todas las réplicas de la API (el
 * almacén en memoria cuenta por proceso: N réplicas dejan N veces el límite). La conexión se abre
 * al primer uso, así que con THROTTLE_STORAGE=memory nunca conecta. También la usa el límite de
 * login por cuenta (LoginAccountLimiter).
 */
@Injectable()
export class RedisThrottlerStorage
  implements ThrottlerStorage, OnModuleDestroy
{
  private connection?: Redis;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ): ReturnType<ThrottlerStorage['increment']> {
    const prefix = `infraward:throttle:${throttlerName}:${key}`;
    const [totalHits, msToExpire, blocked, msToBlockExpire] =
      (await this.client().eval(
        INCREMENT_SCRIPT,
        2,
        `${prefix}:hits`,
        `${prefix}:block`,
        ttl,
        limit,
        blockDuration,
      )) as [number, number, number, number];
    return {
      totalHits,
      timeToExpire: Math.ceil(msToExpire / 1000),
      isBlocked: blocked === 1,
      timeToBlockExpire: Math.ceil(msToBlockExpire / 1000),
    };
  }

  async onModuleDestroy(): Promise<void> {
    await this.connection?.quit().catch(() => undefined);
  }

  /** La conexión a Redis (se abre al primer uso). */
  client(): Redis {
    this.connection ??= new Redis({
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
      maxRetriesPerRequest: 2,
    });
    return this.connection;
  }
}

/** Da el almacén en Redis a `ThrottlerModule.forRootAsync` (y lo cierra al parar). */
@Module({
  providers: [RedisThrottlerStorage],
  exports: [RedisThrottlerStorage],
})
export class RedisThrottlerStorageModule {}
