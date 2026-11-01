import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { normalizeIp } from '@nestjs/throttler';
import { createHash } from 'node:crypto';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { normalizeEmail } from '../users/users.service.js';
import { RedisThrottlerStorage } from './redis-throttler.storage.js';

/** Cuánto tiempo sigue siendo conocida una red desde la que la cuenta entró bien (30 días). */
export const KNOWN_CLIENT_TTL_MS = 30 * 24 * 3600 * 1000;
/** Prefijo de las claves en Redis (los e2e las borran por él). */
const PREFIX = 'infraward:throttle:login-account';

/** Contadores de fallos y redes conocidas, en Redis o en memoria (THROTTLE_STORAGE). */
interface LimiterStore {
  /** Fallos acumulados y ms hasta que caducan (null si no hay). */
  failures(key: string): Promise<{ count: number; ttlMs: number } | null>;
  /** Suma un fallo. La ventana empieza con el primero y, al llegar al límite, vuelve a empezar. */
  fail(key: string, limit: number, ttlMs: number): Promise<void>;
  remember(key: string, ttlMs: number): Promise<void>;
  known(key: string): Promise<boolean>;
  forget(key: string): Promise<void>;
}

/**
 * Límite de intentos de login por cuenta (el email), desde cualquier IP, además del límite por IP
 * (ThrottlerGuard): repartir la fuerza bruta entre muchas IP (o falsear X-Forwarded-For con un
 * TRUST_PROXY demasiado amplio) no da más intentos contra la misma cuenta.
 *
 * Solo cuentan los fallos (LOGIN_ACCOUNT_THROTTLE_LIMIT cada LOGIN_ACCOUNT_THROTTLE_TTL) y el
 * bloqueo no se aplica a las redes desde las que la cuenta ya entró bien (la IP, o su /64 en IPv6,
 * durante KNOWN_CLIENT_TTL_MS). Así, quien inunde una cuenta de intentos no deja fuera a su dueño
 * (ni al admin de emergencia) desde donde suele entrar; desde esas redes sigue valiendo el límite
 * por IP. Un login correcto pone el contador a cero.
 */
@Injectable()
export class LoginAccountLimiter {
  private readonly store: LimiterStore;
  private readonly limit: number;
  private readonly ttlMs: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    redis: RedisThrottlerStorage,
  ) {
    this.limit = config.get('LOGIN_ACCOUNT_THROTTLE_LIMIT', { infer: true });
    this.ttlMs = config.get('LOGIN_ACCOUNT_THROTTLE_TTL', { infer: true }) * 1000;
    this.store =
      config.get('THROTTLE_STORAGE', { infer: true }) === 'redis'
        ? new RedisLimiterStore(redis)
        : new MemoryLimiterStore();
  }

  /**
   * Segundos que le quedan al bloqueo de la cuenta para este cliente, o null si puede intentarlo.
   */
  async retryAfter(email: string, ip: string | null): Promise<number | null> {
    const failures = await this.store.failures(accountKey(email));
    if (!failures || failures.count < this.limit) return null;
    if (await this.store.known(clientKey(email, ip))) return null;
    return Math.max(1, Math.ceil(failures.ttlMs / 1000));
  }

  async failed(email: string): Promise<void> {
    await this.store.fail(accountKey(email), this.limit, this.ttlMs);
  }

  async succeeded(email: string, ip: string | null): Promise<void> {
    await Promise.all([
      this.store.forget(accountKey(email)),
      this.store.remember(clientKey(email, ip), KNOWN_CLIENT_TTL_MS),
    ]);
  }
}

/** Claves con hash: ni emails ni IP en claro en Redis. */
function accountKey(email: string): string {
  return `${PREFIX}:failures:${sha256(normalizeEmail(email))}`;
}

function clientKey(email: string, ip: string | null): string {
  const network = ip ? normalizeIp(ip) : '';
  return `${PREFIX}:known:${sha256(`${normalizeEmail(email)}|${network}`)}`;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** KEYS: contador. ARGV: límite, ventana (ms). */
const FAIL_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 or count == tonumber(ARGV[1]) then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return count
`;

class RedisLimiterStore implements LimiterStore {
  constructor(private readonly redis: RedisThrottlerStorage) {}

  async failures(key: string): Promise<{ count: number; ttlMs: number } | null> {
    const result = await this.redis.client().multi().get(key).pttl(key).exec();
    const count = Number(result?.[0]?.[1] ?? 0);
    const ttlMs = Number(result?.[1]?.[1] ?? -2);
    return count > 0 && ttlMs > 0 ? { count, ttlMs } : null;
  }

  async fail(key: string, limit: number, ttlMs: number): Promise<void> {
    await this.redis.client().eval(FAIL_SCRIPT, 1, key, limit, ttlMs);
  }

  async remember(key: string, ttlMs: number): Promise<void> {
    await this.redis.client().set(key, '1', 'PX', ttlMs);
  }

  async known(key: string): Promise<boolean> {
    return (await this.redis.client().exists(key)) === 1;
  }

  async forget(key: string): Promise<void> {
    await this.redis.client().del(key);
  }
}

/** Por proceso (tests y una sola réplica): cada réplica cuenta por su cuenta. */
export class MemoryLimiterStore implements LimiterStore {
  private readonly entries = new Map<string, { count: number; expiresAt: number }>();

  constructor(private readonly now: () => number = Date.now) {}

  failures(key: string): Promise<{ count: number; ttlMs: number } | null> {
    const entry = this.live(key);
    return Promise.resolve(
      entry ? { count: entry.count, ttlMs: entry.expiresAt - this.now() } : null,
    );
  }

  fail(key: string, limit: number, ttlMs: number): Promise<void> {
    if (this.entries.size >= 10_000)
      for (const k of this.entries.keys()) this.live(k); // purga las caducadas
    const entry = this.live(key) ?? { count: 0, expiresAt: this.now() + ttlMs };
    entry.count++;
    if (entry.count === limit) entry.expiresAt = this.now() + ttlMs;
    this.entries.set(key, entry);
    return Promise.resolve();
  }

  remember(key: string, ttlMs: number): Promise<void> {
    this.entries.set(key, { count: 1, expiresAt: this.now() + ttlMs });
    return Promise.resolve();
  }

  known(key: string): Promise<boolean> {
    return Promise.resolve(this.live(key) !== undefined);
  }

  forget(key: string): Promise<void> {
    this.entries.delete(key);
    return Promise.resolve();
  }

  private live(key: string): { count: number; expiresAt: number } | undefined {
    const entry = this.entries.get(key);
    if (entry && entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }
}
