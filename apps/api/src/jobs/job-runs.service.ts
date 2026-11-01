import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  JOB_NAMES,
  jobRunOrigin,
  type AssetType,
  type JobLogEntry,
  type JobName,
  type JobRunListQuery,
  type JobRunLog,
  type JobRunOrigin,
  type JobRunState,
  type JobRunSummary,
  type JobRunTrigger,
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
  trigger: JobRunTrigger | null;
  worker: string | null;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
  /** El padre (`JOB_RUN_FROM`), si sigue en el historial. */
  p_id: string | null;
  p_name: JobName | null;
  p_asset_id: string | null;
  p_asset_name: string | null;
  p_asset_type: AssetType | null;
  p_state: JobRunState | null;
  p_message: string | null;
  total?: number;
  has_log?: boolean;
}

interface JobRunLogRow {
  attempt: number;
  worker: string | null;
  entries: JobLogEntry[];
  truncated: boolean;
  dropped: number;
  bytes: number;
  started_at: Date;
  updated_at: Date;
}

/** Ejecuciones del asset `$1` y, si es un contenedor, las de su imagen (alias `r`). */
const OF_ASSET = `(r.asset_id = $1 OR r.asset_id IN (
    SELECT child_id FROM asset_relations WHERE parent_id = $1 AND type = 'instance_of'))`;

/**
 * Ejecuciones (`r`) con su asset (`a`) y la tarea de la que cuelgan (`p`, con su asset `pa`): el
 * lote o el job que las encoló.
 */
export const JOB_RUN_FROM = `job_runs r LEFT JOIN assets a ON a.id = r.asset_id
  LEFT JOIN job_runs p ON p.id = r.parent_job_id LEFT JOIN assets pa ON pa.id = p.asset_id`;

/** Columnas de una ejecución (sobre `JOB_RUN_FROM`) con los nombres actuales de los assets. */
export const JOB_RUN_COLUMNS = `r.id, r.name, r.queue, r.asset_id,
  coalesce(a.name, r.asset_name) AS asset_name, a.type AS asset_type, r.state, r.progress,
  r.message, r.error, r.parent_job_id, r.trigger, r.worker, r.created_at, r.started_at,
  r.finished_at, p.id AS p_id, p.name AS p_name, p.asset_id AS p_asset_id,
  coalesce(pa.name, p.asset_name) AS p_asset_name, pa.type AS p_asset_type, p.state AS p_state,
  p.message AS p_message`;

/** Condición SQL de cada origen (`jobRunOrigin`) sobre `JOB_RUN_FROM`. */
const ORIGIN_SQL: Record<JobRunOrigin, string> = {
  bulk: `p.name = '${JOB_NAMES.assetsBulk}'`,
  chain: `r.parent_job_id IS NOT NULL AND p.name IS DISTINCT FROM '${JOB_NAMES.assetsBulk}'`,
  manual: `r.parent_job_id IS NULL AND r.trigger = 'manual'`,
  schedule: `r.parent_job_id IS NULL AND r.trigger = 'schedule'`,
  enrollment: `r.parent_job_id IS NULL AND r.trigger = 'enrollment'`,
};

export function toJobRunSummary(
  row: JobRunRow,
  now: number = Date.now(),
): JobRunSummary {
  const started = row.started_at?.getTime() ?? null;
  const end =
    row.finished_at?.getTime() ?? (row.state === 'active' ? now : null);
  const parent =
    row.p_id && row.p_name && row.p_state
      ? {
          id: row.p_id,
          name: row.p_name,
          assetId: row.p_asset_id,
          assetName: row.p_asset_name,
          assetType: row.p_asset_type,
          state: row.p_state,
          message: row.p_message,
        }
      : null;
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
    parent,
    origin: jobRunOrigin({
      parentJobId: row.parent_job_id,
      parent,
      trigger: row.trigger,
    }),
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
      add(OF_ASSET.replaceAll('$1', '?'), query.assetId);
    if (query.state === 'running')
      where.push(`r.state IN ('queued', 'active')`);
    else if (query.state) add('r.state = ?', query.state);
    if (query.name) add('r.name = ?', query.name);
    if (query.parentJobId) add('r.parent_job_id = ?', query.parentJobId);
    if (query.origin) where.push(ORIGIN_SQL[query.origin]);
    params.push(query.limit ?? DEFAULT_LIMIT, query.offset ?? 0);
    const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows: JobRunRow[] = await this.db.query(
      `SELECT ${JOB_RUN_COLUMNS}, count(*) OVER ()::int AS total,
              EXISTS (SELECT 1 FROM job_run_logs l WHERE l.job_run_id = r.id) AS has_log
         FROM ${JOB_RUN_FROM}
         ${sqlWhere}
        ORDER BY r.created_at DESC, r.id
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    const total =
      rows[0]?.total ??
      (
        (await this.db.query(
          `SELECT count(*)::int AS n FROM ${JOB_RUN_FROM} ${sqlWhere}`,
          params.slice(0, -2),
        )) as { n: number }[]
      )[0]!.n;
    const now = Date.now();
    const children = await this.childrenOf(rows.map((r) => r.id));
    return {
      items: rows.map((r) => {
        const summary = { ...toJobRunSummary(r, now), hasLog: !!r.has_log };
        const counts = children.get(r.id);
        return counts ? { ...summary, children: counts } : summary;
      }),
      total,
    };
  }

  /** Ejecuciones de un asset (404 si no existe), con las mismas reglas que `list`. */
  async listForAsset(
    assetId: string,
    query: Omit<JobRunListQuery, 'assetId' | 'parentJobId'>,
  ): Promise<Page<JobRunSummary>> {
    await this.assertAsset(assetId);
    return this.list({ ...query, assetId });
  }

  /** Una ejecución, como en `list` (404 si no existe o ya se podó): el detalle de la Actividad. */
  async get(runId: string): Promise<JobRunSummary> {
    await this.reconcileOrphans();
    const [row]: JobRunRow[] = await this.db.query(
      `SELECT ${JOB_RUN_COLUMNS},
              EXISTS (SELECT 1 FROM job_run_logs l WHERE l.job_run_id = r.id) AS has_log
         FROM ${JOB_RUN_FROM}
        WHERE r.id = $1`,
      [runId],
    );
    if (!row) throw new NotFoundException('Ejecución no encontrada');
    const summary = { ...toJobRunSummary(row), hasLog: !!row.has_log };
    const counts = (await this.childrenOf([runId])).get(runId);
    return counts ? { ...summary, children: counts } : summary;
  }

  /**
   * Log de una ejecución del asset (DESIGN §20, «Log de cada ejecución»), un bloque por intento.
   * 404 si el asset no existe o la ejecución no es suya (o ya se podó). Sin log (caducado, o un
   * job anterior a esta versión), `attempts` vacío.
   */
  async log(assetId: string, runId: string): Promise<JobRunLog> {
    await this.assertAsset(assetId);
    const [row]: JobRunRow[] = await this.db.query(
      `SELECT ${JOB_RUN_COLUMNS}
         FROM ${JOB_RUN_FROM}
        WHERE r.id = $2 AND ${OF_ASSET}`,
      [assetId, runId],
    );
    if (!row) throw new NotFoundException('Ejecución no encontrada');
    return this.withAttempts(row);
  }

  /** Log de cualquier ejecución (detalle de la Actividad), también de las que no tienen asset. */
  async runLog(runId: string): Promise<JobRunLog> {
    const [row]: JobRunRow[] = await this.db.query(
      `SELECT ${JOB_RUN_COLUMNS} FROM ${JOB_RUN_FROM} WHERE r.id = $1`,
      [runId],
    );
    if (!row) throw new NotFoundException('Ejecución no encontrada');
    return this.withAttempts(row);
  }

  private async withAttempts(row: JobRunRow): Promise<JobRunLog> {
    const logs: JobRunLogRow[] = await this.db.query(
      `SELECT attempt, worker, entries, truncated, dropped, bytes, started_at, updated_at
         FROM job_run_logs WHERE job_run_id = $1 ORDER BY attempt`,
      [row.id],
    );
    return {
      run: { ...toJobRunSummary(row), hasLog: logs.length > 0 },
      attempts: logs.map((l) => ({
        attempt: l.attempt,
        worker: l.worker,
        startedAt: l.started_at.toISOString(),
        updatedAt: l.updated_at.toISOString(),
        truncated: l.truncated,
        dropped: l.dropped,
        bytes: l.bytes,
        entries: l.entries,
      })),
    };
  }

  private async assertAsset(id: string): Promise<void> {
    const [found]: unknown[] = await this.db.query(
      'SELECT 1 FROM assets WHERE id = $1',
      [id],
    );
    if (!found) throw new NotFoundException('Asset no encontrado');
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
