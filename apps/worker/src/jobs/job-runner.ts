import { Injectable, Logger } from '@nestjs/common';
import { JOB_NAMES } from '@infraward/shared-types';
import { DelayedError, type Job } from 'bullmq';
import { DistributedLock, LOCK_TTL_MS } from '../redis/distributed-lock.js';
import { JobRuns } from './job-runs.js';
import {
  HostBusy,
  JobAborted,
  runInJobContext,
  SupersededError,
  type AbortReason,
  type JobContext,
} from './job-context.js';

/** Cada cuánto se renuevan las concesiones y locks de un job en curso. */
const LEASE_RENEW_MS = 20_000;
/** Reintento si la misma operación sobre el mismo asset sigue en curso en otra réplica. */
const SAME_OPERATION_DELAY_MS = 15_000;

/** Datos que identifican el objeto de cada operación (un job a la vez por operación y objeto). */
const OPERATION_TARGET: Partial<Record<string, string>> = {
  [JOB_NAMES.assetCollect]: 'assetId',
  [JOB_NAMES.assetDiscover]: 'assetId',
  [JOB_NAMES.hostScan]: 'assetId',
  [JOB_NAMES.domainsSync]: 'assetId',
  [JOB_NAMES.imageScan]: 'imageId',
  [JOB_NAMES.enrollmentVerify]: 'enrollmentId',
};

/** Clave del lock de la operación del job (`asset.collect:<assetId>`), o null si no tiene. */
export function operationKey(job: Pick<Job, 'name' | 'data'>): string | null {
  const field = OPERATION_TARGET[job.name];
  const target = field
    ? (job.data as Record<string, unknown> | undefined)?.[field]
    : undefined;
  return typeof target === 'string' && target ? `${job.name}:${target}` : null;
}

/**
 * Envoltura común de todos los jobs (DESIGN §20). Crea su contexto (señal de aborto, token, fencing
 * token), lo registra en `job_runs` con la réplica, toma el lock de su operación y mantiene vivos
 * sus recursos. Resuelve el control de flujo:
 * - host ocupado (`HostBusy`) o réplica parándose: el job vuelve a la cola (retrasado, sin gastar
 *   intento ni soltar la deduplicación) con el motivo en la Actividad;
 * - lock de BullMQ perdido o ejecución sustituida: no se toca nada (el job ya es de otra réplica).
 */
@Injectable()
export class JobRunner {
  private readonly logger = new Logger(JobRunner.name);
  private readonly running = new Map<string, AbortController>();
  private worker = 'local';

  constructor(
    private readonly runs: JobRuns,
    private readonly locks: DistributedLock,
  ) {}

  setWorkerName(name: string): void {
    this.worker = name;
  }

  /** Jobs en curso en esta réplica. */
  get active(): number {
    return this.running.size;
  }

  /** Aborta jobs en curso: todos (parada) o los de `ids` (lock perdido). */
  abort(reason: AbortReason, ids?: readonly string[]): void {
    for (const [id, controller] of this.running)
      if (!ids || ids.includes(id)) controller.abort(reason);
  }

  async run(
    job: Job,
    token: string | undefined,
    process: (job: Job) => Promise<unknown>,
  ): Promise<unknown> {
    const controller = new AbortController();
    const context: JobContext = {
      job,
      token,
      worker: this.worker,
      signal: controller.signal,
      attempt: null,
      leases: [],
    };
    const id = job.id ?? '';
    this.running.set(id, controller);
    const heartbeat = setInterval(() => {
      for (const lease of context.leases)
        lease.renew().catch(() => undefined);
    }, LEASE_RENEW_MS);
    heartbeat.unref();
    try {
      return await runInJobContext(context, async () => {
        context.attempt = await this.runs.start(job, this.worker).catch(
          (error: unknown) => {
            // Tipo y código al log (nunca el mensaje de un error ajeno); el job, uno genérico.
            const code = (error as { code?: string }).code;
            this.logger.error(
              `${job.name} ${id}: no se pudo registrar el inicio: ${(error as Error).name}${code ? ` (${code})` : ''}`,
            );
            throw new Error(
              'No se pudo registrar el job en la Actividad (base de datos no disponible o sin migrar)',
            );
          },
        );
        await this.lockOperation(context);
        return process(job);
      });
    } catch (error) {
      const reason = controller.signal.aborted
        ? (controller.signal.reason as AbortReason)
        : null;
      // El job ya no es de esta réplica: ni se mueve ni se registra nada.
      if (reason === 'lock-lost' || error instanceof SupersededError) {
        this.logger.warn(
          `${job.name} ${id}: ${error instanceof SupersededError ? error.message : new JobAborted('lock-lost').message}`,
        );
        throw error;
      }
      if (reason === 'shutdown' || error instanceof HostBusy) {
        const busy = error instanceof HostBusy ? error : null;
        const message =
          busy?.message ?? `Devuelto a la cola al parar ${this.worker}`;
        await job.moveToDelayed(Date.now() + (busy?.delayMs ?? 0), token);
        await this.runs.track(job, { state: 'queued', message });
        if (!busy) this.logger.log(`${job.name} ${id}: ${message}`);
        throw new DelayedError();
      }
      throw error;
    } finally {
      clearInterval(heartbeat);
      await Promise.allSettled(context.leases.map((l) => l.release()));
      this.running.delete(id);
    }
  }

  /**
   * Un job a la vez por operación y objeto entre todas las réplicas, además de la deduplicación de
   * BullMQ: cubre la réplica lenta que perdió el lock y sigue corriendo mientras otra lo retoma.
   */
  private async lockOperation(context: JobContext): Promise<void> {
    const key = operationKey(context.job);
    if (!key) return;
    const lock = await this.locks.tryAcquire(`op:${key}`, LOCK_TTL_MS);
    if (!lock)
      throw new HostBusy(
        'Otra ejecución de esta operación sobre el mismo objeto sigue en curso',
        SAME_OPERATION_DELAY_MS,
      );
    context.leases.push({
      // El lock se renueva solo; si se pierde, el job sigue (el fencing protege las escrituras).
      renew: () => Promise.resolve(),
      release: () => lock.release(),
    });
  }
}
