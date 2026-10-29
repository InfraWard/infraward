import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  type AssetType,
  type JobName,
  type JobRunListQuery,
  type JobRunState,
  type JobRunSummary,
  type Page,
  type QueueName,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { JobsService } from './jobs.service.js';

const DEFAULT_LIMIT = 50;
/** Una fila sin terminar se contrasta con BullMQ pasado este tiempo. */
const ORPHAN_AFTER_MS = 2 * 60_000;
/** Filas que se revisan como mucho en cada consulta. */
const ORPHAN_CHECK_MAX = 20;
export const ORPHAN_ERROR =
  'El job ya no está en la cola (el worker se reinició o caducó)';

interface JobRunRow {
  id: string;
  name: JobName;
  queue: QueueName;
  asset_id: string | null;
  asset_name: string | null;
  asset_type: AssetType | null;
  state: JobRunState;
  progress: number;
  message: string | null;
  error: string | null;
  parent_job_id: string | null;
  worker: string | null;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
  total?: number;
}

/** Columnas de una ejecución con el nombre y el tipo actuales de su asset (alias `r`, `a`). */
export const JOB_RUN_COLUMNS = `r.id, r.name, r.queue, r.asset_id,
  coalesce(a.name, r.asset_name) AS asset_name, a.type AS asset_type, r.state, r.progress,
  r.message, r.error, r.parent_job_id, r.worker, r.created_at, r.started_at, r.finished_at`;

export function toJobRunSummary(
  row: JobRunRow,
  now: number = Date.now(),
): JobRunSummary {
  const started = row.started_at?.getTime() ?? null;
  const end =
    row.finished_at?.getTime() ?? (row.state === 'active' ? now : null);
  return {
    id: row.id,
    name: row.name,
    queue: row.queue,
    assetId: row.asset_id,
    assetName: row.asset_name,
    assetType: row.asset_type,
    state: row.state,
    progress: row.progress,
    message: row.message,
    error: row.error,
    parentJobId: row.parent_job_id,
    worker: row.worker,
    createdAt: row.created_at.toISOString(),
    startedAt: row.started_at?.toISOString() ?? null,
    finishedAt: row.finished_at?.toISOString() ?? null,
    durationMs:
      started !== null && end !== null ? Math.max(0, end - started) : null,
  };
}

/** Historial de ejecuciones (tabla `job_runs`) para la Actividad, el panel y la ficha. */
@Injectable()
export class JobRunsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly jobs: JobsService,
  ) {}

  async list(query: JobRunListQuery): Promise<Page<JobRunSummary>> {
    await this.reconcileOrphans();
    const params: unknown[] = [];
    const where: string[] = [];
    const add = (sql: string, value: unknown) => {
      params.push(value);
      where.push(sql.replaceAll('?', `$${params.length}`));
    };
    if (query.assetId)
      // Un contenedor no tiene escaneos propios: son los de su imagen.
      add(
        `(r.asset_id = ? OR r.asset_id IN (
            SELECT child_id FROM asset_relations WHERE parent_id = ? AND type = 'instance_of'))`,
        query.assetId,
      );
    if (query.state === 'running')
      where.push(`r.state IN ('queued', 'active')`);
    else if (query.state) add('r.state = ?', query.state);
    if (query.name) add('r.name = ?', query.name);
    if (query.parentJobId) add('r.parent_job_id = ?', query.parentJobId);
    params.push(query.limit ?? DEFAULT_LIMIT, query.offset ?? 0);
    const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows: JobRunRow[] = await this.db.query(
      `SELECT ${JOB_RUN_COLUMNS}, count(*) OVER ()::int AS total
         FROM job_runs r LEFT JOIN assets a ON a.id = r.asset_id
         ${sqlWhere}
        ORDER BY r.created_at DESC, r.id
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    const total =
      rows[0]?.total ??
      (
        (await this.db.query(
          `SELECT count(*)::int AS n FROM job_runs r ${sqlWhere}`,
          params.slice(0, -2),
        )) as { n: number }[]
      )[0]!.n;
    const now = Date.now();
    const children = await this.childrenOf(rows.map((r) => r.id));
    return {
      items: rows.map((r) => {
        const summary = toJobRunSummary(r, now);
        const counts = children.get(r.id);
        return counts ? { ...summary, children: counts } : summary;
      }),
      total,
    };
  }

  /** Cuántos jobs colgaron de cada fila (lotes y cadenas) y en qué estado están. */
  private async childrenOf(
    ids: string[],
  ): Promise<Map<string, NonNullable<JobRunSummary['children']>>> {
    if (!ids.length) return new Map();
    const rows: {
      parent_job_id: string;
      total: number;
      running: number;
      failed: number;
    }[] = await this.db.query(
      `SELECT parent_job_id, count(*)::int AS total,
              count(*) FILTER (WHERE state IN ('queued', 'active'))::int AS running,
              count(*) FILTER (WHERE state = 'failed')::int AS failed
         FROM job_runs WHERE parent_job_id = ANY($1::uuid[])
        GROUP BY parent_job_id`,
      [ids],
    );
    return new Map(
      rows.map((r) => [
        r.parent_job_id,
        { total: r.total, running: r.running, failed: r.failed },
      ]),
    );
  }

  /**
   * Filas que siguen `queued`/`active` mucho después pero cuyo job ya no está en BullMQ (worker
   * caído a medias, retención agotada): pasan a `failed` para no bloquear las acciones del asset.
   */
  async reconcileOrphans(): Promise<number> {
    const rows: { id: string; queue: string }[] = await this.db.query(
      `SELECT id, queue FROM job_runs
        WHERE state IN ('queued', 'active') AND created_at < now() - $1::interval
        ORDER BY created_at LIMIT $2`,
      [`${ORPHAN_AFTER_MS} milliseconds`, ORPHAN_CHECK_MAX],
    );
    let fixed = 0;
    for (const row of rows) {
      const state = await this.jobs.state(row.id, row.queue);
      if (state !== 'unknown') continue;
      await this.db.query(
        `UPDATE job_runs SET state = 'failed', error = $2, finished_at = now()
          WHERE id = $1 AND state IN ('queued', 'active')`,
        [row.id, ORPHAN_ERROR],
      );
      fixed++;
    }
    return fixed;
  }
}
