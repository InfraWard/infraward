import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { NOT_UNUSED_IMAGE, SCAN_ENABLED_OWNER } from '@infraward/domain';
import {
  JOB_NAMES,
  METRICS_SAMPLE_ID,
  PRIORITY_BAND_MIN,
  QUEUE_NAMES,
  type MetricsSampleJobData,
  type MetricsSampleJobResult,
} from '@infraward/shared-types';
import { Queue, type Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { DataSource, type EntityManager } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { recordQueued } from '../jobs/job-runs.js';
import { reportProgress } from '../jobs/progress.js';

/** El día de hoy en UTC (el de las muestras). */
const TODAY = `(now() AT TIME ZONE 'UTC')::date`;

/** Ámbitos: el global (`project_id` null) y cada proyecto. */
const SCOPES = `(SELECT NULL::uuid AS id UNION ALL SELECT id FROM projects)`;

/**
 * Upsert de la muestra de hoy de una métrica para cada ámbito, a partir de `values` (columnas
 * `project_id`, `v`): una segunda ejecución el mismo día la sustituye.
 */
function upsert(metric: string, values: string): string {
  return `
    INSERT INTO metric_samples (day, project_id, metric, "values", granularity)
    SELECT ${TODAY}, s.id, '${metric}', COALESCE(c.v, '{}'::jsonb), 'day'
      FROM ${SCOPES} s
      LEFT JOIN (${values}) c ON c.project_id IS NOT DISTINCT FROM s.id
    ON CONFLICT (day, project_id, metric)
    DO UPDATE SET "values" = EXCLUDED."values", granularity = 'day'`;
}

/**
 * CVE de la vista principal de Vulnerabilidades (abiertos, sin ruido, sin imágenes sin uso ni
 * escaneo desactivado, prioridad ≥ media; DESIGN §9) por banda y en KEV, por ámbito. Las
 * imágenes ya están en los proyectos de quienes las usan.
 */
const CVES_BY_BAND = `
  WITH base AS (
    SELECT f.vulnerability_id, f.priority, COALESCE(vi.in_kev, false) AS kev,
           o.effective_projects
      FROM findings f JOIN assets o ON o.id = f.asset_id
      LEFT JOIN vulnerability_intel vi ON vi.vulnerability_id = f.vulnerability_id
     WHERE f.status = 'open' AND o.status <> 'retired' AND f.noise_reason IS NULL
       AND f.priority >= ${PRIORITY_BAND_MIN.medium}
       AND ${NOT_UNUSED_IMAGE} AND ${SCAN_ENABLED_OWNER}),
  scoped AS (
    SELECT NULL::uuid AS project_id, vulnerability_id, priority, kev FROM base
    UNION ALL
    SELECT p, vulnerability_id, priority, kev FROM base, unnest(effective_projects) p),
  g AS (
    SELECT project_id, vulnerability_id, max(priority) AS score, bool_or(kev) AS kev
      FROM scoped GROUP BY project_id, vulnerability_id)
  SELECT project_id, jsonb_build_object(
           'urgent', count(*) FILTER (WHERE score >= ${PRIORITY_BAND_MIN.urgent}),
           'high', count(*) FILTER (WHERE score >= ${PRIORITY_BAND_MIN.high}
                                      AND score < ${PRIORITY_BAND_MIN.urgent}),
           'medium', count(*) FILTER (WHERE score < ${PRIORITY_BAND_MIN.high}),
           'kev', count(*) FILTER (WHERE kev),
           'cves', count(*)) AS v
    FROM g GROUP BY project_id`;

/** Assets por estado, por ámbito. */
const ASSETS_BY_STATUS = `
  SELECT project_id, jsonb_object_agg(status, n) AS v FROM (
    SELECT project_id, status, count(*)::int AS n FROM (
      SELECT NULL::uuid AS project_id, a.status::text AS status FROM assets a
      UNION ALL
      SELECT p, a.status::text FROM assets a, unnest(a.effective_projects) p) x
    GROUP BY project_id, status) y
  GROUP BY project_id`;

/**
 * Muestras diarias de los gráficos de evolución (`metrics.sample`, QoL-8, DESIGN §15): CVE por
 * banda de prioridad y assets por estado, global y por proyecto. Idempotente por día. Retención:
 * diarias durante `METRICS_DAILY_RETENTION_DAYS`; después, la última de cada semana, y esas se
 * borran pasados `METRICS_RETENTION_DAYS` (0 = nunca).
 */
@Injectable()
export class MetricSampler {
  private readonly logger = new Logger(MetricSampler.name);

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    @InjectQueue(QUEUE_NAMES.system) private readonly queue: Queue,
  ) {}

  async run(
    job: Job<MetricsSampleJobData, MetricsSampleJobResult>,
  ): Promise<MetricsSampleJobResult> {
    await reportProgress(job, 0, 'Calculando las muestras de hoy');
    const result = await this.db.transaction((m) => this.sample(m));
    await reportProgress(
      job,
      100,
      `Muestra del ${result.day}: ${result.scopes} ${result.scopes === 1 ? 'ámbito' : 'ámbitos'}` +
        (result.compacted || result.deleted
          ? ` · ${result.compacted} pasadas a semanales, ${result.deleted} borradas`
          : ''),
    );
    return result;
  }

  /** Las muestras de hoy y la retención, en una transacción. */
  async sample(m: EntityManager): Promise<MetricsSampleJobResult> {
    await m.query(upsert('cves_by_band', CVES_BY_BAND));
    await m.query(upsert('assets_by_status', ASSETS_BY_STATUS));
    const [{ day, scopes }] = (await m.query(
      `SELECT ${TODAY}::text AS day, (SELECT count(*)::int + 1 FROM projects) AS scopes`,
    )) as [{ day: string; scopes: number }];
    const { compacted, deleted } = await this.retain(m);
    return { day, scopes, compacted, deleted };
  }

  /**
   * Las diarias más antiguas que el plazo pasan a semanales: de cada semana ISO (y ámbito y
   * métrica) queda la del último día, contando las que ya eran semanales (así una semana que
   * cruza el plazo en varios días acaba con una sola). Las semanales vencidas se borran.
   */
  private async retain(
    m: EntityManager,
  ): Promise<{ compacted: number; deleted: number }> {
    const daily = this.config.get('METRICS_DAILY_RETENTION_DAYS', {
      infer: true,
    });
    const weekly = this.config.get('METRICS_RETENTION_DAYS', { infer: true });
    const [compacted] = (await m.query(
      `WITH old AS (
         SELECT id, granularity, row_number() OVER (
                  PARTITION BY project_id, metric, date_trunc('week', day)
                  ORDER BY day DESC) AS rn
           FROM metric_samples WHERE day < ${TODAY} - $1::int),
       promoted AS (
         UPDATE metric_samples SET granularity = 'week'
          WHERE id IN (SELECT id FROM old WHERE rn = 1 AND granularity = 'day')
          RETURNING 1),
       dropped AS (
         DELETE FROM metric_samples WHERE id IN (SELECT id FROM old WHERE rn > 1)
         RETURNING granularity)
       SELECT (SELECT count(*) FROM promoted)::int AS promoted,
              (SELECT count(*) FROM dropped WHERE granularity = 'day')::int AS merged`,
      [daily],
    )) as { promoted: number; merged: number }[];
    let deleted = 0;
    if (weekly > 0) {
      const [rows] = (await m.query(
        `DELETE FROM metric_samples
          WHERE granularity = 'week' AND day < ${TODAY} - $1::int RETURNING 1`,
        [weekly],
      )) as [unknown[], number];
      deleted = rows.length;
    }
    return {
      compacted: (compacted?.promoted ?? 0) + (compacted?.merged ?? 0),
      deleted,
    };
  }

  /** Encola una muestra (como mucho una en cola), con su fila en la Actividad. */
  async enqueue(reason: string): Promise<string | null> {
    try {
      const job = await this.queue.add(
        JOB_NAMES.metricsSample,
        { reason } satisfies MetricsSampleJobData,
        { jobId: randomUUID(), deduplication: { id: METRICS_SAMPLE_ID } },
      );
      await recordQueued(this.db, job, null, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la muestra de métricas: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /**
   * Muestra cada `hours` horas (0 = desactivada) y, al arrancar, la de hoy si aún no está (así
   * un worker que se reinicia no deja huecos ni repite).
   */
  async schedule(hours: number): Promise<void> {
    const current = await this.queue.getJobScheduler(METRICS_SAMPLE_ID);
    if (hours <= 0) {
      if (current) await this.queue.removeJobScheduler(METRICS_SAMPLE_ID);
      return;
    }
    const every = hours * 3_600_000;
    if (!current || Number(current.every) !== every) {
      await this.queue.upsertJobScheduler(
        METRICS_SAMPLE_ID,
        { every },
        {
          name: JOB_NAMES.metricsSample,
          data: { reason: 'schedule' } satisfies MetricsSampleJobData,
        },
      );
      this.logger.log(`Muestra de métricas programada cada ${hours} h`);
    }
    const [today] = (await this.db.query(
      `SELECT 1 FROM metric_samples WHERE day = ${TODAY} AND project_id IS NULL LIMIT 1`,
    )) as unknown[];
    if (!today) await this.enqueue('startup');
  }
}
