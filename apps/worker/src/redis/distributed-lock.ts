import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { EXTEND_IF_OWNER, RELEASE_IF_OWNER, WorkerRedis } from './redis.js';

/** Vida por defecto de un lock; se renueva cada tercio mientras se tiene. */
export const LOCK_TTL_MS = 60_000;

/** Un lock tomado: se renueva solo hasta que se suelta. `lost` avisa si otro se lo quedó. */
export interface HeldLock {
  readonly key: string;
  readonly token: string;
  /** Se aborta si no se pudo renovar (caducó y lo tomó otro). */
  readonly lost: AbortSignal;
  release(): Promise<void>;
}

/**
 * Locks entre réplicas (DESIGN §20): `SET NX PX` con un token propio, renovación periódica y
 * liberación con Lua comparando el token (nunca se suelta el lock de otro). Si la réplica muere,
 * el lock caduca solo.
 */
@Injectable()
export class DistributedLock {
  private readonly logger = new Logger(DistributedLock.name);

  constructor(private readonly redis: WorkerRedis) {}

  /** Toma el lock si está libre; null si lo tiene otro. */
  async tryAcquire(name: string, ttlMs = LOCK_TTL_MS): Promise<HeldLock | null> {
    const key = this.redis.key('lock', name);
    const token = randomUUID();
    const ok = await this.redis.client.set(key, token, 'PX', ttlMs, 'NX');
    return ok ? this.hold(key, token, ttlMs) : null;
  }

  /**
   * Espera al lock (sondeando cada `pollMs`) hasta `waitMs`; null si no llega a tenerlo. Corta
   * antes si `signal` se aborta.
   */
  async acquire(
    name: string,
    options: {
      waitMs: number;
      ttlMs?: number;
      pollMs?: number;
      signal?: AbortSignal;
    },
  ): Promise<HeldLock | null> {
    const deadline = Date.now() + options.waitMs;
    for (;;) {
      const lock = await this.tryAcquire(name, options.ttlMs);
      if (lock) return lock;
      if (Date.now() >= deadline || options.signal?.aborted) return null;
      await sleep(options.pollMs ?? 2000, undefined, {
        signal: options.signal,
      }).catch(() => undefined);
    }
  }

  /** Ejecuta `fn` con el lock si está libre; si lo tiene otro, no la ejecuta (`skipped`). */
  async runExclusive<T>(
    name: string,
    fn: (lock: HeldLock) => Promise<T>,
    ttlMs?: number,
  ): Promise<{ skipped: true } | { skipped: false; value: T }> {
    const lock = await this.tryAcquire(name, ttlMs);
    if (!lock) return { skipped: true };
    try {
      return { skipped: false, value: await fn(lock) };
    } finally {
      await lock.release();
    }
  }

  private hold(key: string, token: string, ttlMs: number): HeldLock {
    const lost = new AbortController();
    const client = this.redis.client;
    const timer = setInterval(() => {
      client
        .eval(EXTEND_IF_OWNER, 1, key, token, ttlMs)
        .then((extended) => {
          if (extended === 1) return;
          clearInterval(timer);
          this.logger.warn(`Lock ${key} perdido (caducó y lo tomó otro)`);
          lost.abort(new Error(`Lock ${key} perdido`));
        })
        // Un fallo puntual de Redis no da el lock por perdido: se reintenta en el siguiente.
        .catch(() => undefined);
    }, Math.max(1000, Math.floor(ttlMs / 3)));
    timer.unref();
    return {
      key,
      token,
      lost: lost.signal,
      release: async () => {
        clearInterval(timer);
        await client.eval(RELEASE_IF_OWNER, 1, key, token).catch(() => undefined);
      },
    };
  }
}
