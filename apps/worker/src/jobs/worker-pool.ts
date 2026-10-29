import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  QUEUE_NAMES,
  QUEUE_PREFIX,
  type QueueName,
} from '@infraward/shared-types';
import { Worker, type Job } from 'bullmq';
import {
  queueConcurrency,
  type EnvironmentVariables,
} from '../config/env.validation.js';
import { DiscoveryProcessor } from './discovery.processor.js';
import { EnrollmentProcessor } from './enrollment.processor.js';
import { JobRunner } from './job-runner.js';
import { ScanProcessor } from './scan.processor.js';
import { SystemProcessor } from './system.processor.js';

/** Lock de BullMQ de cada job en curso: si la réplica muere, otra lo retoma tras caducar. */
export const JOB_LOCK_MS = 60_000;
/** Cada cuánto busca cada réplica jobs de réplicas muertas (*stalled*). */
export const STALLED_INTERVAL_MS = 30_000;

interface JobProcessor {
  process(job: Job): Promise<unknown>;
}

/**
 * Los `Worker` de BullMQ de esta réplica (DESIGN §20): uno por cola con concurrencia > 0, con el
 * nombre de la réplica (lo guarda BullMQ en cada job como `processedBy`). Se crean sin autorun y
 * solo arrancan cuando la réplica está lista; al parar, dejan de pedir jobs y esperan a los que
 * están en curso como mucho `WORKER_SHUTDOWN_GRACE`: después se abortan y vuelven a la cola.
 */
@Injectable()
export class WorkerPool {
  private readonly logger = new Logger(WorkerPool.name);
  private readonly processors: Record<QueueName, JobProcessor>;
  private workers: Worker[] = [];

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly runner: JobRunner,
    system: SystemProcessor,
    enrollment: EnrollmentProcessor,
    discovery: DiscoveryProcessor,
    scan: ScanProcessor,
  ) {
    this.processors = {
      [QUEUE_NAMES.system]: system,
      [QUEUE_NAMES.enrollment]: enrollment,
      [QUEUE_NAMES.collect]: discovery,
      [QUEUE_NAMES.discovery]: discovery,
      [QUEUE_NAMES.domains]: discovery,
      [QUEUE_NAMES.reconcile]: discovery,
      [QUEUE_NAMES.imageScan]: scan,
      [QUEUE_NAMES.hostScan]: scan,
      [QUEUE_NAMES.sbom]: scan,
      [QUEUE_NAMES.scan]: scan,
    };
  }

  /** Crea y arranca los workers; devuelve la concurrencia de cada cola consumida. */
  start(name: string): Partial<Record<QueueName, number>> {
    const concurrency = queueConcurrency({
      WORKER_CONCURRENCY: this.config.get('WORKER_CONCURRENCY', { infer: true }),
      COLLECT_CONCURRENCY: this.config.get('COLLECT_CONCURRENCY', { infer: true }),
      DISCOVERY_CONCURRENCY: this.config.get('DISCOVERY_CONCURRENCY', { infer: true }),
      DOMAINS_SYNC_CONCURRENCY: this.config.get('DOMAINS_SYNC_CONCURRENCY', { infer: true }),
      RECONCILE_CONCURRENCY: this.config.get('RECONCILE_CONCURRENCY', { infer: true }),
      IMAGE_SCAN_CONCURRENCY: this.config.get('IMAGE_SCAN_CONCURRENCY', { infer: true }),
      SCAN_CONCURRENCY: this.config.get('SCAN_CONCURRENCY', { infer: true }),
      HOST_SCAN_CONCURRENCY: this.config.get('HOST_SCAN_CONCURRENCY', { infer: true }),
      SBOM_CONCURRENCY: this.config.get('SBOM_CONCURRENCY', { infer: true }),
    });
    if (this.config.get('SCAN_CONCURRENCY', { infer: true }) !== undefined)
      this.logger.warn(
        'SCAN_CONCURRENCY está obsoleta: usa IMAGE_SCAN_CONCURRENCY y HOST_SCAN_CONCURRENCY',
      );
    this.runner.setWorkerName(name);
    const connection = {
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
    };
    const consumed: Partial<Record<QueueName, number>> = {};
    for (const [queue, processor] of Object.entries(this.processors) as [
      QueueName,
      JobProcessor,
    ][]) {
      const n = concurrency[queue];
      if (!n) continue;
      const worker = new Worker(
        queue,
        (job: Job, token?: string) =>
          this.runner.run(job, token, (j) => processor.process(j)),
        {
          connection,
          prefix: QUEUE_PREFIX,
          name,
          concurrency: n,
          autorun: false,
          lockDuration: JOB_LOCK_MS,
          stalledInterval: STALLED_INTERVAL_MS,
          maxStalledCount: 1,
        },
      );
      // Sin poder renovar el lock, el job ya no es de esta réplica: se aborta (otra lo retomará).
      worker.on('lockRenewalFailed', (ids: string[]) => {
        this.logger.warn(`Lock perdido de los jobs ${ids.join(', ')}: se abortan`);
        this.runner.abort('lock-lost', ids);
      });
      worker.on('error', (error: Error) =>
        this.logger.warn(`Worker de la cola ${queue}: ${error.name}: ${error.message}`),
      );
      worker.run().catch((error: unknown) =>
        this.logger.error(
          `El worker de la cola ${queue} se detuvo: ${(error as Error).name}`,
        ),
      );
      this.workers.push(worker);
      consumed[queue] = n;
    }
    return consumed;
  }

  /**
   * Parada ordenada: deja de pedir jobs y espera a los que están en curso hasta `graceMs`;
   * pasado ese tiempo los aborta (procesos hijos incluidos) y vuelven a la cola.
   */
  async stop(graceMs: number): Promise<void> {
    const workers = this.workers;
    this.workers = [];
    if (!workers.length) return;
    const running = this.runner.active;
    if (running)
      this.logger.log(
        `Esperando a ${running} jobs en curso (como mucho ${Math.round(graceMs / 1000)} s)`,
      );
    const closing = Promise.allSettled(workers.map((w) => w.close()));
    let timer: NodeJS.Timeout | undefined;
    const expired = new Promise<'expired'>((done) => {
      timer = setTimeout(() => done('expired'), graceMs);
    });
    if ((await Promise.race([closing, expired])) === 'expired') {
      this.logger.warn(
        `${this.runner.active} jobs siguen en curso tras ${Math.round(graceMs / 1000)} s: se abortan y vuelven a la cola`,
      );
      this.runner.abort('shutdown');
      await closing;
    }
    clearTimeout(timer);
  }
}
