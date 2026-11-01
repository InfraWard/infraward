import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  QUEUE_PREFIX,
  type JobProgressEvent,
  type QueueName,
} from '@infraward/shared-types';
import { QueueEvents, type Job, type Queue } from 'bullmq';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { WorkerRedis } from '../redis/redis.js';
import { JobQueues } from './job-queues.js';
import {
  failedUpdate,
  isTrackedJobId,
  JobRuns,
  type JobRunUpdate,
} from './job-runs.js';

/** Cada cuánto se guarda en Redis el último evento leído de cada cola. */
const CURSOR_FLUSH_MS = 2000;

/**
 * Único oyente de los eventos de todas las colas (DESIGN §20), en el líder: lleva a `job_runs`
 * lo que hacen todas las réplicas (empieza, avanza, termina, falla, vuelve a la cola, se queda
 * colgado). Guarda en Redis el último evento leído de cada cola: un líder nuevo sigue donde lo
 * dejó el anterior (los eventos son idempotentes si se repiten).
 */
@Injectable()
export class JobEventsListener {
  private readonly logger = new Logger(JobEventsListener.name);
  private listeners: { queue: QueueName; events: QueueEvents }[] = [];
  private readonly cursors = new Map<QueueName, string>();
  private flushTimer?: NodeJS.Timeout;
  /** Eventos pendientes de cada job: se aplican en orden. */
  private readonly pending = new Map<string, Promise<void>>();

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly queues: JobQueues,
    private readonly runs: JobRuns,
    private readonly redis: WorkerRedis,
  ) {}

  async start(): Promise<void> {
    if (this.listeners.length) return;
    const connection = {
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
    };
    for (const [name, queue] of this.queues.entries()) {
      const lastEventId =
        (await this.redis.client.get(this.cursorKey(name))) ?? undefined;
      const events = new QueueEvents(name, {
        connection,
        prefix: QUEUE_PREFIX,
        lastEventId,
      });
      this.attach(name, queue, events);
      this.listeners.push({ queue: name, events });
    }
    this.flushTimer = setInterval(() => void this.flushCursors(), CURSOR_FLUSH_MS);
    this.flushTimer.unref();
  }

  async stop(): Promise<void> {
    const listeners = this.listeners;
    this.listeners = [];
    clearInterval(this.flushTimer);
    await Promise.allSettled(listeners.map((l) => l.events.close()));
    await this.flush();
    await this.flushCursors();
  }

  /** Espera a que se registren los eventos pendientes (tests y parada). */
  async flush(): Promise<void> {
    await Promise.all(this.pending.values());
  }

  attach(name: QueueName, queue: Queue, events: QueueEvents): void {
    const on = (
      event: string,
      update: (
        job: Job,
        args: Record<string, unknown>,
      ) => JobRunUpdate | null | Promise<JobRunUpdate | null>,
    ) =>
      events.on(event as 'active', (args: unknown, id: string) => {
        this.cursors.set(name, id);
        const { jobId } = args as { jobId: string };
        if (!isTrackedJobId(jobId)) return;
        this.enqueue(jobId, async () => {
          const job = (await queue.getJob(jobId)) as Job | undefined;
          if (!job) return;
          const result = await update(job, args as Record<string, unknown>);
          if (result) await this.runs.track(job, result);
        });
      });

    on('active', (job) => ({
      state: 'active',
      started: true,
      worker: job.processedBy ?? null,
    }));
    on('progress', async (job, args) =>
      typeof args.data === 'number'
        ? {
            state: 'active',
            progress: args.data,
            message: await this.lastMessage(queue, job.id!),
          }
        : null,
    );
    on('completed', () => ({
      state: 'completed',
      progress: 100,
      finished: true,
    }));
    on('failed', (job) => failedUpdate(job));
    // Reintento con espera, host ocupado o devuelto al parar (el motivo lo anota quien lo movió).
    on('delayed', () => ({ state: 'queued' }));
    events.on('stalled', (args: { jobId: string }, id: string) => {
      this.cursors.set(name, id);
      if (!isTrackedJobId(args.jobId)) return;
      this.enqueue(args.jobId, () =>
        this.runs.requeuedById(
          args.jobId,
          (worker) => `Vuelve a la cola: ${worker} dejó de responder`,
        ),
      );
    });
    events.on('error', (error: Error) =>
      this.logger.warn(`Eventos de la cola ${name}: ${error.name}`),
    );
  }

  private enqueue(id: string, fn: () => Promise<void>): void {
    const next = (this.pending.get(id) ?? Promise.resolve())
      .then(fn)
      .catch((error: unknown) =>
        this.logger.warn(
          `No se pudo registrar un evento del job ${id}: ${(error as Error).name}`,
        ),
      )
      .finally(() => {
        if (this.pending.get(id) === next) this.pending.delete(id);
      });
    this.pending.set(id, next);
  }

  /** Último evento de progreso del log del job (lo escribe `reportProgress`). */
  private async lastMessage(queue: Queue, id: string): Promise<string | null> {
    try {
      const { logs } = await queue.getJobLogs(id, -1, -1);
      const event = JSON.parse(
        logs.at(-1) ?? 'null',
      ) as Partial<JobProgressEvent> | null;
      return typeof event?.message === 'string' ? event.message : null;
    } catch {
      return null;
    }
  }

  private cursorKey(queue: QueueName): string {
    return this.redis.key('events', queue);
  }

  private async flushCursors(): Promise<void> {
    if (!this.cursors.size) return;
    const entries = [...this.cursors];
    this.cursors.clear();
    try {
      await this.redis.client.mset(
        ...entries.flatMap(([queue, id]) => [this.cursorKey(queue), id]),
      );
    } catch {
      for (const [queue, id] of entries)
        if (!this.cursors.has(queue)) this.cursors.set(queue, id);
    }
  }
}
