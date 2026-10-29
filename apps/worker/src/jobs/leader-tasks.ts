import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  INVENTORY_RECONCILE_ID,
  QUEUE_NAMES,
  SBOM_REEVALUATE_ID,
} from '@infraward/shared-types';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { IntelUpdater } from '../intel/intel-updater.js';
import { PrioritizeTrigger } from '../intel/prioritize-trigger.js';
import { InventoryReconciler } from '../inventory/reconciler.js';
import { MetricSampler } from '../metrics/metric-sampler.js';
import { DistributedLock } from '../redis/distributed-lock.js';
import type { LeaderHooks } from '../redis/leader.js';
import { ScanScheduler } from '../scan/scan-scheduler.js';
import { JobEventsListener } from './job-events-listener.js';
import { JobQueues } from './job-queues.js';
import { JobRuns } from './job-runs.js';
import { OrphanSweeper } from './orphan-sweeper.js';

const SWEEP_EVERY_MS = 60_000;
const PRUNE_EVERY_MS = 60 * 60_000;

/**
 * Lo que hace solo el líder (DESIGN §20): programar los jobs periódicos (job schedulers de BullMQ:
 * un disparo por intervalo para todas las réplicas), pedir el recálculo de prioridades del
 * arranque, escuchar los eventos de las colas (Actividad), recuperar huérfanos y podar el
 * historial. Si deja de ser líder, para lo suyo; el siguiente lo retoma.
 */
@Injectable()
export class LeaderTasks implements LeaderHooks {
  private readonly logger = new Logger(LeaderTasks.name);
  private timers: NodeJS.Timeout[] = [];

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly queues: JobQueues,
    private readonly locks: DistributedLock,
    private readonly listener: JobEventsListener,
    private readonly sweeper: OrphanSweeper,
    private readonly runs: JobRuns,
    private readonly reconciler: InventoryReconciler,
    private readonly scans: ScanScheduler,
    private readonly intel: IntelUpdater,
    private readonly metrics: MetricSampler,
    @Optional() private readonly prioritize?: PrioritizeTrigger,
  ) {}

  async elected(): Promise<void> {
    await this.listener.start();
    // Con dos líderes un instante (relevo), solo uno toca los schedulers.
    await this.locks.runExclusive('schedules', () => this.schedule());
    // Al relevar (p. ej. tras una migración o un cambio de pesos), todo se recalcula una vez.
    await this.prioritize?.request('arranque');
    const every = (ms: number, fn: () => Promise<unknown>) => {
      const timer = setInterval(
        () =>
          void fn().catch((error: unknown) =>
            this.logger.warn(`Tarea del líder: ${(error as Error).name}`),
          ),
        ms,
      );
      timer.unref();
      this.timers.push(timer);
    };
    every(SWEEP_EVERY_MS, () => this.sweeper.sweep());
    // Al relevar, lo que dejó a medias el líder anterior (o una réplica caída) se mira ya.
    void this.sweeper
      .sweep()
      .catch((error: unknown) =>
        this.logger.warn(`Barrido de huérfanos: ${(error as Error).name}`),
      );
    every(PRUNE_EVERY_MS, () =>
      this.runs.prune(this.config.get('JOB_RUNS_RETENTION_DAYS', { infer: true })),
    );
    void this.runs.prune(this.config.get('JOB_RUNS_RETENTION_DAYS', { infer: true }));
  }

  async demoted(): Promise<void> {
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    await this.listener.stop();
  }

  /** Jobs periódicos. Un fallo en uno no impide los demás (se reintenta al siguiente relevo). */
  private async schedule(): Promise<void> {
    const steps: [string, () => Promise<unknown>][] = [
      [
        'la reconciliación',
        () => this.reconciler.schedule(this.config.get('RECONCILE_TICK', { infer: true })),
      ],
      [
        'la re-evaluación de los SBOMs',
        () =>
          this.scans.scheduleReevaluation(
            this.config.get('SBOM_REEVALUATE_INTERVAL', { infer: true }),
          ),
      ],
      [
        'la descarga de KEV y EPSS',
        () => this.intel.schedule(this.config.get('VULN_INTEL_INTERVAL', { infer: true })),
      ],
      [
        'la muestra de métricas',
        () =>
          this.metrics.schedule(this.config.get('METRICS_SAMPLE_INTERVAL', { infer: true })),
      ],
      // Schedulers de antes de separar las colas (sesión W-0).
      [
        'los schedulers antiguos',
        async () => {
          await this.queues
            .get(QUEUE_NAMES.discovery)
            .removeJobScheduler(INVENTORY_RECONCILE_ID);
          await this.queues.get(QUEUE_NAMES.scan).removeJobScheduler(SBOM_REEVALUATE_ID);
        },
      ],
    ];
    for (const [what, step] of steps)
      await step().catch((error: unknown) =>
        this.logger.warn(
          `No se pudo programar ${what}: ${(error as Error).name}: ${(error as Error).message}`,
        ),
      );
  }
}
