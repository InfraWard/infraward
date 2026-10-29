import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { WorkerRedis } from '../redis/redis.js';
import { currentJob, HostBusy, type JobLease } from './job-context.js';

/** Vida de una concesión; el job la renueva cada tercio mientras corre. */
export const SLOT_TTL_MS = 60_000;
/** Retraso antes de volver a intentarlo (más jitter) si el host está ocupado. */
const BUSY_DELAY_MS = { normal: 5_000, scan: 20_000 } as const;

/** Clase de un job frente al límite por host: los escaneos y rellenos tienen un tope menor. */
export type SlotClass = 'normal' | 'scan';

/**
 * Pide un hueco en el semáforo del host (ZSET miembro = id del job, puntuación = caducidad).
 * KEYS: semáforo del host, conjunto de los escaneos de ese host.
 * ARGV: miembro, ahora, caducidad, máximo total, máximo de escaneos, clase.
 * Devuelve 1 si lo concede (o ya lo tenía), 0 si no, y cuántos hay en curso.
 */
const ACQUIRE = `
redis.call('zremrangebyscore', KEYS[1], '-inf', ARGV[2])
redis.call('zremrangebyscore', KEYS[2], '-inf', ARGV[2])
if redis.call('zscore', KEYS[1], ARGV[1]) then
  redis.call('zadd', KEYS[1], ARGV[3], ARGV[1])
  if ARGV[6] == 'scan' then redis.call('zadd', KEYS[2], ARGV[3], ARGV[1]) end
  return {1, redis.call('zcard', KEYS[1])}
end
local total = redis.call('zcard', KEYS[1])
if total >= tonumber(ARGV[4]) then return {0, total} end
if ARGV[6] == 'scan' and redis.call('zcard', KEYS[2]) >= tonumber(ARGV[5]) then
  return {0, total}
end
redis.call('zadd', KEYS[1], ARGV[3], ARGV[1])
if ARGV[6] == 'scan' then redis.call('zadd', KEYS[2], ARGV[3], ARGV[1]) end
redis.call('pexpire', KEYS[1], ARGV[7])
redis.call('pexpire', KEYS[2], ARGV[7])
return {1, total + 1}`;

/** Renueva la concesión solo si sigue concedida (si caducó, no se recupera a escondidas). */
const RENEW = `
if not redis.call('zscore', KEYS[1], ARGV[1]) then return 0 end
redis.call('zadd', KEYS[1], ARGV[2], ARGV[1])
if redis.call('zscore', KEYS[2], ARGV[1]) then redis.call('zadd', KEYS[2], ARGV[2], ARGV[1]) end
redis.call('pexpire', KEYS[1], ARGV[3])
redis.call('pexpire', KEYS[2], ARGV[3])
return 1`;

const RELEASE = `
redis.call('zrem', KEYS[1], ARGV[1])
redis.call('zrem', KEYS[2], ARGV[1])
return 1`;

/**
 * Límite de jobs a la vez contra un mismo host raíz, entre todas las réplicas (DESIGN §20): el
 * asset dueño de la conexión SSH (un CT o un Docker dentro de un CT cuentan contra su nodo). Como
 * mucho `HOST_MAX_JOBS` en total y `HOST_MAX_SCAN_JOBS` escaneos o rellenos. Las concesiones
 * caducan si la réplica muere. Sin hueco, el job no espera ocupando un hueco del worker: lanza
 * `HostBusy` y la envoltura lo devuelve a la cola retrasado.
 */
@Injectable()
export class HostSlots {
  private readonly logger = new Logger(HostSlots.name);
  private readonly maxJobs: number;
  private readonly maxScanJobs: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    private readonly redis: WorkerRedis,
  ) {
    this.maxJobs = config.get('HOST_MAX_JOBS', { infer: true });
    this.maxScanJobs = config.get('HOST_MAX_SCAN_JOBS', { infer: true });
  }

  keys(hostAssetId: string): [string, string] {
    return [
      this.redis.key('slots', hostAssetId),
      this.redis.key('slots', hostAssetId, 'scan'),
    ];
  }

  /**
   * Hueco para el job en curso contra `hostAssetId` (`hostName` solo para el mensaje). Fuera de
   * un job no limita. Con hueco lo añade a los recursos del job (se renueva y se suelta solo).
   */
  async acquire(
    hostAssetId: string,
    hostName: string,
    kind: SlotClass = 'normal',
  ): Promise<void> {
    const context = currentJob();
    const member = context?.job.id;
    if (!context || !member) return;
    const keys = this.keys(hostAssetId);
    const now = Date.now();
    const [granted, running] = (await this.redis.client.eval(
      ACQUIRE,
      2,
      ...keys,
      member,
      now,
      now + SLOT_TTL_MS,
      this.maxJobs,
      this.maxScanJobs,
      kind,
      SLOT_TTL_MS * 2,
    )) as [number, number];
    if (granted !== 1) {
      const base = BUSY_DELAY_MS[kind];
      throw new HostBusy(
        `Esperando turno en ${hostName} (${running} jobs en curso, máximo ${kind === 'scan' ? `${this.maxScanJobs} escaneos y ` : ''}${this.maxJobs})`,
        base + Math.floor(Math.random() * base),
      );
    }
    if (context.leases.some((l) => l instanceof SlotLease && l.member === member && l.keys[0] === keys[0]))
      return;
    context.leases.push(new SlotLease(this.redis, keys, member, this.logger));
  }

  /**
   * Hueco en un semáforo propio de la terminal (sesión 21): las sesiones interactivas tienen su
   * cupo por host (`slots:<host>:terminal`) y por persona (`terminal-user:<id>`), aparte del de
   * los jobs (una terminal abierta no frena la recolección, ni al revés). El mismo Lua, sobre una
   * sola clave. Fuera de un job: quien lo pide renueva la concesión (`renew` cada tercio de
   * `SLOT_TTL_MS`) y la suelta; si el proceso muere, caduca sola.
   */
  async acquireTerminal(
    scope: { host: string } | { user: string },
    member: string,
    max: number,
  ): Promise<{ lease: SlotLease | null; running: number }> {
    const key =
      'host' in scope
        ? this.redis.key('slots', scope.host, 'terminal')
        : this.redis.key('terminal-user', scope.user);
    const now = Date.now();
    const [granted, running] = (await this.redis.client.eval(
      ACQUIRE,
      2,
      key,
      key,
      member,
      now,
      now + SLOT_TTL_MS,
      max,
      max,
      'normal',
      SLOT_TTL_MS * 2,
    )) as [number, number];
    return {
      lease: granted === 1 ? new SlotLease(this.redis, [key, key], member, this.logger) : null,
      running,
    };
  }
}

export class SlotLease implements JobLease {
  constructor(
    private readonly redis: WorkerRedis,
    readonly keys: [string, string],
    readonly member: string,
    private readonly logger: Logger,
  ) {}

  async renew(): Promise<void> {
    const renewed = await this.redis.client.eval(
      RENEW,
      2,
      ...this.keys,
      this.member,
      Date.now() + SLOT_TTL_MS,
      SLOT_TTL_MS * 2,
    );
    if (renewed !== 1)
      this.logger.warn(
        `La concesión de ${this.member} en ${this.keys[0]} caducó: el límite por host puede pasarse un momento`,
      );
  }

  async release(): Promise<void> {
    await this.redis.client.eval(RELEASE, 2, ...this.keys, this.member);
  }
}
