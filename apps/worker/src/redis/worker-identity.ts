import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { hostname } from 'node:os';
import { randomUUID } from 'node:crypto';
import {
  WORKER_REPLICA_KEY_PREFIX,
  type QueueName,
  type WorkerReplicaInfo,
} from '@infraward/shared-types';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { EXTEND_IF_OWNER, RELEASE_IF_OWNER, WorkerRedis } from './redis.js';

/** Vida de la reserva del nombre; se renueva cada tercio. */
export const IDENTITY_TTL_MS = 30_000;
/** Tope de réplicas sin `WORKER_NAME` (`worker-1` … `worker-999`). */
const MAX_ORDINAL = 999;

/** Nombre de esta réplica para quien no tiene a mano el servicio (directorios de trabajo). */
let processWorkerName = 'local';
export function currentWorkerName(): string {
  return processWorkerName;
}

/**
 * Identificador estable de la réplica (DESIGN §20): `WORKER_NAME` o, si no, `worker-<n>` con el
 * menor `n` libre, reservado en Redis con un lease que se renueva. Una réplica que reinicia (o
 * se recrea con `--scale`) recupera su número: lo suelta al parar limpio y, si murió, caduca en
 * `IDENTITY_TTL_MS`. Es el nombre del `Worker` de BullMQ (`processedBy`) y el de la Actividad.
 */
@Injectable()
export class WorkerIdentity {
  private readonly logger = new Logger(WorkerIdentity.name);
  private readonly token = `${hostname()}:${process.pid}:${randomUUID()}`;
  private readonly configured?: string;
  private timer?: NodeJS.Timeout;
  private current: string | null = null;
  private info: string | null = null;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    private readonly redis: WorkerRedis,
  ) {
    this.configured = config.get(this.nameVariable as 'WORKER_NAME', { infer: true });
  }

  /** Prefijo de los nombres automáticos (`worker-<n>`; el gateway, `gateway-<n>`). */
  protected get prefix(): string {
    return 'worker';
  }

  /** Variable con un nombre fijo. */
  protected get nameVariable(): string {
    return 'WORKER_NAME';
  }

  get name(): string {
    if (!this.current) throw new Error('Identidad del worker sin reservar');
    return this.current;
  }

  get host(): string {
    return hostname();
  }

  /** Reserva el nombre y empieza a renovarlo. */
  async claim(): Promise<string> {
    if (this.configured) {
      const ok = await this.take(this.configured);
      if (!ok)
        this.logger.warn(
          `Ya hay otra réplica viva con ${this.nameVariable}=${this.configured}: la Actividad las mezclará`,
        );
      this.current = this.configured;
    } else {
      for (let n = 1; n <= MAX_ORDINAL && !this.current; n++)
        if (await this.take(`${this.prefix}-${n}`)) this.current = `${this.prefix}-${n}`;
      if (!this.current)
        throw new Error(
          `No hay ningún nombre libre entre ${this.prefix}-1 y ${this.prefix}-${MAX_ORDINAL}`,
        );
    }
    processWorkerName = this.current;
    this.timer = setInterval(() => void this.renew(), IDENTITY_TTL_MS / 3);
    this.timer.unref();
    return this.current;
  }

  /**
   * Publica la ficha de la réplica (colas que consume) para `GET /jobs/workers`; se renueva y
   * caduca con el nombre.
   */
  async publish(queues: QueueName[]): Promise<void> {
    if (!this.current) return;
    const info: WorkerReplicaInfo = {
      name: this.current,
      host: hostname(),
      queues,
      startedAt: new Date().toISOString(),
    };
    this.info = JSON.stringify(info);
    await this.redis.client.set(
      WORKER_REPLICA_KEY_PREFIX + this.current,
      this.info,
      'PX',
      IDENTITY_TTL_MS,
    );
  }

  /** ¿Hay una réplica viva con ese nombre? (directorios de trabajo de réplicas muertas). */
  async alive(name: string): Promise<boolean> {
    return (await this.redis.client.exists(this.redis.key('id', name))) === 1;
  }

  /** Suelta el nombre (parada limpia): la réplica que arranque después puede tomarlo ya. */
  async release(): Promise<void> {
    clearInterval(this.timer);
    if (!this.current) return;
    await this.redis.client
      .del(WORKER_REPLICA_KEY_PREFIX + this.current)
      .catch(() => undefined);
    await this.redis.client
      .eval(RELEASE_IF_OWNER, 1, this.redis.key('id', this.current), this.token)
      .catch(() => undefined);
  }

  private async take(name: string): Promise<boolean> {
    const ok = await this.redis.client.set(
      this.redis.key('id', name),
      this.token,
      'PX',
      IDENTITY_TTL_MS,
      'NX',
    );
    return ok === 'OK';
  }

  private async renew(): Promise<void> {
    if (!this.current) return;
    try {
      const key = this.redis.key('id', this.current);
      const extended = await this.redis.client.eval(
        EXTEND_IF_OWNER,
        1,
        key,
        this.token,
        IDENTITY_TTL_MS,
      );
      // Caducó (Redis caído o el proceso parado mucho rato): se vuelve a reservar si está libre.
      if (extended !== 1 && !(await this.take(this.current)))
        this.logger.warn(
          `El nombre ${this.current} lo ha reservado otra réplica mientras esta no respondía`,
        );
      if (this.info)
        await this.redis.client.set(
          WORKER_REPLICA_KEY_PREFIX + this.current,
          this.info,
          'PX',
          IDENTITY_TTL_MS,
        );
    } catch {
      // Redis no disponible: se reintenta en la siguiente renovación.
    }
  }
}
