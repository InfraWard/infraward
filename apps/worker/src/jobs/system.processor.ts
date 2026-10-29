import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  JOB_NAMES,
  QUEUE_NAMES,
  VULNERABILITY_ID_PATTERN,
  type FindingsPrioritizeJobResult,
  type MetricsSampleJobData,
  type MetricsSampleJobResult,
  type PingJobData,
  type PingJobResult,
  type VulnerabilityLookupJobData,
  type VulnerabilityIntelJobData,
  type VulnerabilityIntelJobResult,
  type VulnerabilityLookupJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { setTimeout as sleep } from 'node:timers/promises';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { IntelUpdater } from '../intel/intel-updater.js';
import { FindingPrioritizer } from '../intel/prioritizer.js';
import { MetricSampler } from '../metrics/metric-sampler.js';
import { TrivyDb } from '../scan/trivy-db.js';
import { TrivyRunner } from '../scan/trivy-runner.js';
import { reportProgress } from './progress.js';
import { currentJob } from './job-context.js';

/** Jobs de la cola `system` (internos y de prueba). Los programa el líder (`LeaderTasks`). */
@Injectable()
export class SystemProcessor {
  private readonly logger = new Logger(SystemProcessor.name);
  private readonly trivyDb: TrivyDb;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    trivy: TrivyRunner,
    private readonly intel: IntelUpdater,
    private readonly prioritizer: FindingPrioritizer,
    private readonly metrics: MetricSampler,
  ) {
    this.trivyDb = new TrivyDb(trivy.cacheDir);
  }

  async process(job: Job): Promise<unknown> {
    this.logger.log(`Procesando ${job.name} ${job.id}`);
    switch (job.name) {
      case JOB_NAMES.ping:
        return this.ping(job as Job<PingJobData, PingJobResult>);
      case JOB_NAMES.vulnerabilityLookup:
        return this.lookup(job as Job<VulnerabilityLookupJobData>);
      case JOB_NAMES.vulnerabilityIntel:
        // El del job scheduler (id `repeat:…`) solo encola otro con un UUID (Actividad).
        if (job.repeatJobKey) return { queued: await this.intel.enqueue() };
        return this.intel.run(
          job as Job<VulnerabilityIntelJobData, VulnerabilityIntelJobResult>,
        );
      case JOB_NAMES.metricsSample:
        // Como KEV/EPSS: el del job scheduler encola otro con un UUID (Actividad).
        if (job.repeatJobKey)
          return { queued: await this.metrics.enqueue('schedule') };
        return this.metrics.run(
          job as Job<MetricsSampleJobData, MetricsSampleJobResult>,
        );
      case JOB_NAMES.findingsPrioritize:
        return this.prioritizer.run() satisfies Promise<FindingsPrioritizeJobResult>;
      default:
        throw new Error(
          `Job desconocido en la cola ${QUEUE_NAMES.system}: ${job.name}`,
        );
    }
  }

  /** Detalles de un CVE en la BD de Trivy de la caché (solo lectura, sin candados). */
  private async lookup(
    job: Job<VulnerabilityLookupJobData>,
  ): Promise<VulnerabilityLookupJobResult> {
    const id = job.data.vulnerabilityId;
    if (typeof id !== 'string' || !VULNERABILITY_ID_PATTERN.test(id))
      throw new Error('Identificador de vulnerabilidad no válido');
    return this.trivyDb.lookup(id);
  }

  private async ping(
    job: Job<PingJobData, PingJobResult>,
  ): Promise<PingJobResult> {
    const { steps, stepDelayMs, message } = job.data;
    await reportProgress(job, 0, 'Inicio');
    for (let step = 1; step <= steps; step++) {
      // Al parar la réplica, la espera se corta y el job vuelve a la cola (DESIGN §20).
      await sleep(stepDelayMs, undefined, { signal: currentJob()?.signal });
      await reportProgress(
        job,
        Math.round((step / steps) * 100),
        `Paso ${step}/${steps}`,
      );
    }
    this.logger.log(`Completado ${job.name} ${job.id}`);
    return {
      pong: true,
      message,
      steps,
      processedAt: new Date().toISOString(),
    };
  }
}
