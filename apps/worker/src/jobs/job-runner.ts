import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JOB_NAMES } from '@infraward/shared-types';
import { DelayedError, type Job } from 'bullmq';
import { DistributedLock, LOCK_TTL_MS } from '../redis/distributed-lock.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { JobRunLogs } from './job-run-logs.js';
import { JobRuns } from './job-runs.js';
import { clipText, RunLog } from './run-log.js';
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
/** Cada cuánto se guarda, como mucho, el log de un job en curso (la web lo va refrescando). */
const LOG_FLUSH_MS = 2000;
/** Tope del log de una ejecución si no hay configuración (tests). */
const DEFAULT_LOG_MAX_KB = 256;
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

  private readonly logMaxBytes: number;

  constructor(
    private readonly runs: JobRuns,
    private readonly locks: DistributedLock,
    @Optional() private readonly logs?: JobRunLogs,
    @Optional() config?: ConfigService<EnvironmentVariables, true>,
  ) {
    this.logMaxBytes =
      (config?.get('COLLECTION_LOG_MAX_KB', { infer: true }) ??
        DEFAULT_LOG_MAX_KB) * 1024;
  }

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
    const logWriter = this.logWriter(context);
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
        logWriter.open();
        await this.lockOperation(context);
        const result = await process(job);
        logWriter.finished(result);
        return result;
      });
    } catch (error) {
      const reason = controller.signal.aborted
        ? (controller.signal.reason as AbortReason)
        : null;
      logWriter.failed(error, reason);
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
      await logWriter.close();
      this.running.delete(id);
    }
  }

  /**
   * Log del intento (DESIGN §20, «Log de cada ejecución»): se abre con el fencing token (solo los
   * jobs con fila en la Actividad), se guarda cada `LOG_FLUSH_MS` como mucho mientras cambia (la
   * web lo refresca) y al terminar, con el resultado o el fallo. Un intento que no llegó a hacer
   * nada (host ocupado, misma operación en curso) no deja log: solo sería ruido.
   */
  private logWriter(context: JobContext) {
    const { job } = context;
    let timer: NodeJS.Timeout | undefined;
    let writing: Promise<void> = Promise.resolve();
    let skip = false;
    const save = () => {
      const { log, attempt } = context;
      if (!log || attempt === null || !this.logs || skip) return writing;
      writing = writing.then(() =>
        this.logs!.save(job.id, attempt, this.worker, log),
      );
      return writing;
    };
    const schedule = () => {
      timer ??= setTimeout(() => {
        timer = undefined;
        void save();
      }, LOG_FLUSH_MS);
      timer.unref();
    };
    const elapsed = () => {
      const started = context.log?.startedAt.getTime() ?? Date.now();
      return Date.now() - started;
    };
    return {
      open: () => {
        if (!this.logs || context.attempt === null) return;
        context.log = new RunLog(this.logMaxBytes, schedule);
        context.log.info(
          `${job.name} en ${this.worker} (intento ${context.attempt})`,
        );
      },
      finished: (result: unknown) => {
        const log = context.log;
        if (!log) return;
        for (const warning of resultWarnings(result))
          log.add('warn', 'result', `Aviso: ${warning}`);
        log.add('info', 'result', `Terminado: ${summarizeResult(result)}`, {
          durationMs: elapsed(),
        });
      },
      failed: (error: unknown, reason: AbortReason | null) => {
        const log = context.log;
        if (!log) return;
        if (
          error instanceof HostBusy &&
          !log.entries.some((e) => e.kind === 'command')
        ) {
          skip = true;
          return;
        }
        const message = (error as Error).message ?? 'Error';
        if (
          reason ||
          error instanceof HostBusy ||
          error instanceof SupersededError
        )
          log.add('warn', 'result', `Interrumpido: ${message}`, {
            durationMs: elapsed(),
          });
        else
          log.add('error', 'result', `Fallido: ${message}`, {
            durationMs: elapsed(),
          });
      },
      close: async () => {
        clearTimeout(timer);
        timer = undefined;
        await save();
      },
    };
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

/** Avisos de un resultado (`warnings` de la recolección, del escaneo…). */
export function resultWarnings(result: unknown): string[] {
  const warnings = (result as { warnings?: unknown } | null | undefined)
    ?.warnings;
  return Array.isArray(warnings)
    ? warnings.filter((w): w is string => typeof w === 'string')
    : [];
}

/**
 * Resumen del resultado para el log: sus campos simples (`snapshotId: …, roles: [a, b]…`), sin los
 * avisos (van aparte) ni objetos grandes. El resultado nunca lleva secretos (BullMQ lo guarda y
 * la API lo devuelve), pero pasa igualmente por la censura al añadirse.
 */
export function summarizeResult(result: unknown): string {
  if (result === undefined || result === null) return 'sin resultado';
  if (typeof result !== 'object') return clipText(String(result), 500);
  const parts: string[] = [];
  for (const [key, value] of Object.entries(
    result as Record<string, unknown>,
  )) {
    if (key === 'warnings' || value === undefined) continue;
    if (
      value === null ||
      ['string', 'number', 'boolean'].includes(typeof value)
    )
      parts.push(`${key}: ${String(value)}`);
    else if (Array.isArray(value))
      parts.push(
        value.every((v) => ['string', 'number'].includes(typeof v))
          ? `${key}: [${clipText(value.join(', '), 300)}]`
          : `${key}: ${value.length} elementos`,
      );
    else if (typeof value === 'object') {
      const name = (value as { name?: unknown }).name;
      parts.push(`${key}: ${typeof name === 'string' ? name : '{…}'}`);
    }
  }
  return clipText(parts.join(', ') || 'sin datos', 2000);
}
