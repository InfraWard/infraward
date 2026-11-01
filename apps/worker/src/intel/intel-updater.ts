import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { IntelFeed } from '@infraward/domain';
import {
  INTEL_SOURCES,
  JOB_NAMES,
  QUEUE_NAMES,
  VULNERABILITY_INTEL_ID,
  type IntelSource,
  type VulnerabilityIntelFeedResult,
  type VulnerabilityIntelJobData,
  type VulnerabilityIntelJobResult,
} from '@infraward/shared-types';
import { Queue, type Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { DataSource, type EntityManager } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { recordQueued } from '../jobs/job-runs.js';
import { reportProgress } from '../jobs/progress.js';
import {
  fetchConditional,
  IntelFeedError,
  parseEpss,
  parseKev,
  type FetchFn,
  type EpssScores,
  type KevCatalog,
} from './feeds.js';
import { PrioritizeTrigger } from './prioritize-trigger.js';

/** Filas por sentencia al volcar EPSS (~300 000 CVE). */
const EPSS_BATCH = 20_000;

/**
 * Descarga CISA KEV y EPSS (`vulnerability.intel`, DESIGN §9). Por fuente: GET condicional (un
 * 304 no descarga), la misma versión no reescribe nada y un fallo deja los datos como estaban
 * con el error y su fecha en `intel_feeds`. El job termina bien aunque falle una fuente: lo dice
 * su resultado y la web enseña la antigüedad.
 */
@Injectable()
export class IntelUpdater {
  private readonly logger = new Logger(IntelUpdater.name);
  /** Sustituible en los tests. */
  fetchFn: FetchFn = fetch;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    @InjectQueue(QUEUE_NAMES.system) private readonly queue: Queue,
    private readonly prioritize: PrioritizeTrigger,
  ) {}

  private url(source: IntelSource): string {
    return source === 'kev'
      ? this.config.get('KEV_URL', { infer: true })
      : this.config.get('EPSS_URL', { infer: true });
  }

  async run(
    job: Job<VulnerabilityIntelJobData, VulnerabilityIntelJobResult>,
  ): Promise<VulnerabilityIntelJobResult> {
    const feeds: VulnerabilityIntelFeedResult[] = [];
    for (const [i, source] of INTEL_SOURCES.entries()) {
      await reportProgress(
        job,
        Math.round((i / INTEL_SOURCES.length) * 100),
        `Descargando ${source === 'kev' ? 'CISA KEV' : 'EPSS'}`,
      );
      feeds.push(await this.update(source, job.data.force === true));
    }
    if (feeds.some((f) => f.outcome === 'updated'))
      await this.prioritize.request('KEV/EPSS');
    const failed = feeds.filter((f) => f.outcome === 'failed');
    await reportProgress(
      job,
      100,
      failed.length
        ? `Se conservan los datos anteriores de ${failed.map((f) => f.source.toUpperCase()).join(' y ')}: ${failed.map((f) => f.error).join('; ')}`
        : feeds.map(summary).join(' · '),
    );
    return { feeds };
  }

  /** Una fuente: nunca lanza por un fallo de red o de formato. */
  async update(
    source: IntelSource,
    force = false,
  ): Promise<VulnerabilityIntelFeedResult> {
    const url = this.url(source);
    if (!url) {
      await this.saveFeed(source, { enabled: false });
      return { source, outcome: 'disabled' };
    }
    const feed = (await this.db
      .getRepository(IntelFeed)
      .findOneBy({ source })) ?? {
      etag: null,
      lastModified: null,
      version: null,
      fetchedAt: null,
    };
    try {
      const res = await fetchConditional(
        url,
        // Sin datos cargados o forzado: descarga entera.
        force || !feed.fetchedAt
          ? { etag: null, lastModified: null }
          : { etag: feed.etag, lastModified: feed.lastModified },
        this.config.get('VULN_INTEL_TIMEOUT_MS', { infer: true }),
        this.fetchFn,
      );
      if (res.status === 'not_modified') {
        await this.saveFeed(source, {
          enabled: true,
          checkedAt: new Date(),
          lastError: null,
          lastErrorAt: null,
        });
        return { source, outcome: 'not_modified' };
      }
      const parsed =
        source === 'kev' ? parseKev(res.body) : parseEpss(res.body);
      const cache = { etag: res.etag, lastModified: res.lastModified };
      if (!force && feed.fetchedAt && parsed.version === feed.version) {
        await this.saveFeed(source, {
          ...cache,
          enabled: true,
          checkedAt: new Date(),
          lastError: null,
          lastErrorAt: null,
        });
        return { source, outcome: 'unchanged' };
      }
      const records = await this.db.transaction(async (m) => {
        const n =
          source === 'kev'
            ? await storeKev(m, parsed as KevCatalog)
            : await storeEpss(m, parsed as EpssScores);
        const now = new Date();
        await m.upsert(
          IntelFeed,
          {
            source,
            ...cache,
            enabled: true,
            version: parsed.version,
            recordCount: n,
            fetchedAt: now,
            checkedAt: now,
            lastError: null,
            lastErrorAt: null,
          },
          ['source'],
        );
        return n;
      });
      this.logger.log(
        `${source.toUpperCase()} ${parsed.version}: ${records} CVE`,
      );
      return { source, outcome: 'updated', records };
    } catch (error) {
      const message =
        error instanceof IntelFeedError
          ? error.message
          : `error inesperado (${(error as Error).name})`;
      this.logger.warn(
        `${source.toUpperCase()}: ${message}; se conservan los datos anteriores`,
      );
      await this.saveFeed(source, {
        enabled: true,
        lastError: message.slice(0, 500),
        lastErrorAt: new Date(),
      });
      return { source, outcome: 'failed', error: message };
    }
  }

  private async saveFeed(
    source: IntelSource,
    values: Partial<Omit<IntelFeed, 'source'>>,
  ): Promise<void> {
    await this.db
      .getRepository(IntelFeed)
      .upsert({ source, ...values }, ['source']);
  }

  /** Encola una descarga (Actividad), deduplicada. */
  async enqueue(force = false): Promise<string | null> {
    try {
      const job = await this.queue.add(
        JOB_NAMES.vulnerabilityIntel,
        { force } satisfies VulnerabilityIntelJobData,
        { jobId: randomUUID(), deduplication: { id: VULNERABILITY_INTEL_ID } },
      );
      await recordQueued(this.db, job, null, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la descarga de KEV/EPSS: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /**
   * Descarga periódica cada `hours` horas (0 = desactivada). Como la re-evaluación de los SBOMs:
   * solo se toca el job scheduler si no existe o cambió el intervalo.
   */
  async schedule(hours: number): Promise<void> {
    const current = await this.queue.getJobScheduler(VULNERABILITY_INTEL_ID);
    if (hours <= 0) {
      if (current) await this.queue.removeJobScheduler(VULNERABILITY_INTEL_ID);
      return;
    }
    const every = hours * 3_600_000;
    if (current && Number(current.every) === every) return;
    await this.queue.upsertJobScheduler(
      VULNERABILITY_INTEL_ID,
      { every },
      {
        name: JOB_NAMES.vulnerabilityIntel,
        data: {} satisfies VulnerabilityIntelJobData,
      },
    );
    this.logger.log(`Descarga de KEV y EPSS programada cada ${hours} h`);
  }
}

function summary(f: VulnerabilityIntelFeedResult): string {
  const name = f.source === 'kev' ? 'KEV' : 'EPSS';
  switch (f.outcome) {
    case 'updated':
      return `${name}: ${f.records} CVE`;
    case 'not_modified':
    case 'unchanged':
      return `${name}: sin cambios`;
    case 'disabled':
      return `${name}: desactivado`;
    case 'failed':
      return `${name}: ${f.error}`;
  }
}

/** Vuelca el catálogo KEV: lo que sale del catálogo deja de estar en KEV. */
async function storeKev(m: EntityManager, kev: KevCatalog): Promise<number> {
  await m.query(
    `UPDATE vulnerability_intel
        SET in_kev = false, kev_added = NULL, kev_due = NULL, kev_ransomware = false,
            kev_name = NULL, updated_at = now()
      WHERE in_kev AND NOT (vulnerability_id = ANY($1::text[]))`,
    [kev.entries.map((e) => e.vulnerabilityId)],
  );
  await m.query(
    `INSERT INTO vulnerability_intel AS v
            (vulnerability_id, in_kev, kev_added, kev_due, kev_ransomware, kev_name)
     SELECT x."vulnerabilityId", true, x.added::date, x.due::date, x.ransomware, x.name
       FROM jsonb_to_recordset($1::jsonb) AS x(
              "vulnerabilityId" text, added text, due text, ransomware boolean, name text)
     ON CONFLICT (vulnerability_id) DO UPDATE SET
       in_kev = true, kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due,
       kev_ransomware = EXCLUDED.kev_ransomware, kev_name = EXCLUDED.kev_name,
       updated_at = now()
     WHERE (v.in_kev, v.kev_added, v.kev_due, v.kev_ransomware, v.kev_name)
           IS DISTINCT FROM (true, EXCLUDED.kev_added, EXCLUDED.kev_due,
                             EXCLUDED.kev_ransomware, EXCLUDED.kev_name)`,
    [JSON.stringify(kev.entries)],
  );
  return kev.entries.length;
}

/** Vuelca EPSS por lotes (solo reescribe lo que cambia). */
async function storeEpss(m: EntityManager, epss: EpssScores): Promise<number> {
  for (let i = 0; i < epss.rows.length; i += EPSS_BATCH) {
    await m.query(
      `INSERT INTO vulnerability_intel AS v (vulnerability_id, epss, epss_percentile)
       SELECT x."vulnerabilityId", x.epss, x.percentile
         FROM jsonb_to_recordset($1::jsonb) AS x(
                "vulnerabilityId" text, epss real, percentile real)
       ON CONFLICT (vulnerability_id) DO UPDATE SET
         epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile, updated_at = now()
       WHERE (v.epss, v.epss_percentile) IS DISTINCT FROM (EXCLUDED.epss, EXCLUDED.epss_percentile)`,
      [JSON.stringify(epss.rows.slice(i, i + EPSS_BATCH))],
    );
  }
  return epss.rows.length;
}
