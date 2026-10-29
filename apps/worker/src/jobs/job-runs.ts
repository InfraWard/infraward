import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  clipError,
  clipMessage,
  jobAssetId,
  recordQueuedJob,
  type RecordableJob,
} from '@infraward/domain';
import type { JobRunState } from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { DataSource } from 'typeorm';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Solo los jobs con UUID tienen fila en la Actividad (los que encolan la API y el worker): los
 * de un job scheduler (`repeat:…`) solo disparan otro, y las consultas rápidas llevan prefijo.
 */
export function isTrackedJobId(id: string | undefined): id is string {
  return !!id && UUID.test(id);
}

/** Cambio de una ejecución según un evento de su job. */
export interface JobRunUpdate {
  state: JobRunState;
  progress?: number;
  message?: string | null;
  error?: string | null;
  started?: boolean;
  finished?: boolean;
  /** Réplica que lo ejecuta (`processedBy`). */
  worker?: string | null;
}

/** Tras un fallo: si quedan intentos, el job vuelve a la cola. */
export function failedUpdate(
  job: Pick<Job, 'attemptsMade' | 'opts' | 'failedReason'>,
): JobRunUpdate {
  const retries = (job.opts.attempts ?? 1) > job.attemptsMade;
  return retries
    ? { state: 'queued', error: job.failedReason }
    : { state: 'failed', error: job.failedReason, finished: true };
}

/**
 * Registra en `job_runs` un job que el worker acaba de encolar (cadenas: recolección →
 * descubrimiento → recolecciones y escaneos), con el job que lo encoló. Un fallo aquí no afecta
 * al job: la fila se creará cuando empiece.
 */
export async function recordQueued(
  db: DataSource,
  job: Job,
  parentJobId: string | null | undefined,
  logger: Logger,
): Promise<void> {
  try {
    await recordQueuedJob(db.manager, job, parentJobId ?? null);
  } catch (error) {
    logger.warn(
      `No se pudo registrar el job ${job.id}: ${(error as Error).name}`,
    );
  }
}

/**
 * Escrituras en `job_runs` (la Actividad, DESIGN §20): las hace la réplica que ejecuta el job al
 * empezarlo (con el fencing token) o al devolverlo a la cola, y el líder con los eventos de las
 * colas y el barrido de huérfanos. Nunca lanzan, salvo `start` (sin fencing token el job no
 * debe escribir nada).
 */
@Injectable()
export class JobRuns {
  private readonly logger = new Logger(JobRuns.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  /**
   * El job empieza en `worker`: fila en `active`, con la réplica, y el intento + 1, que es su
   * fencing token. null si el job no tiene fila (sin fencing: recálculos idempotentes).
   */
  async start(job: RecordableJob, worker: string): Promise<number | null> {
    if (!isTrackedJobId(job.id)) return null;
    const assetId = await jobAssetId(this.db.manager, job.name, job.data);
    const [row]: { attempt: number }[] = await this.db.query(
      `INSERT INTO job_runs AS r (id, name, queue, asset_id, asset_name, state, progress,
                                  created_at, started_at, worker, attempt)
       SELECT $1, $2, $3, a.id, a.name, 'active', 0, to_timestamp($5 / 1000.0), now(), $6, 1
         FROM (SELECT 1) one LEFT JOIN assets a ON a.id = $4
       ON CONFLICT (id) DO UPDATE SET
         state = 'active',
         progress = 0,
         worker = EXCLUDED.worker,
         attempt = r.attempt + 1,
         started_at = coalesce(r.started_at, now()),
         finished_at = NULL,
         asset_id = coalesce(r.asset_id, EXCLUDED.asset_id),
         asset_name = coalesce(r.asset_name, EXCLUDED.asset_name)
       RETURNING attempt`,
      [job.id, job.name, job.queueName, assetId, job.timestamp, worker],
    );
    return row?.attempt ?? null;
  }

  /** Aplica el cambio; nunca lanza (el job sigue igual aunque falle el registro). */
  async track(job: RecordableJob, update: JobRunUpdate): Promise<void> {
    if (!isTrackedJobId(job.id)) return;
    try {
      const assetId = await jobAssetId(this.db.manager, job.name, job.data);
      await this.db.query(
        `INSERT INTO job_runs AS r (id, name, queue, asset_id, asset_name, state, progress,
                                    message, error, created_at, started_at, finished_at, worker)
         SELECT $1, $2, $3, a.id, a.name, $5, coalesce($6, 0), $7, $8, to_timestamp($9 / 1000.0),
                CASE WHEN $10 THEN now() END, CASE WHEN $11 THEN now() END, $14
           FROM (SELECT 1) one LEFT JOIN assets a ON a.id = $4
         ON CONFLICT (id) DO UPDATE SET
           state = EXCLUDED.state,
           progress = coalesce($6, r.progress),
           message = CASE WHEN $12 THEN EXCLUDED.message ELSE r.message END,
           error = CASE WHEN $13 THEN EXCLUDED.error ELSE r.error END,
           started_at = CASE WHEN $10 THEN coalesce(r.started_at, now()) ELSE r.started_at END,
           finished_at = CASE WHEN $11 THEN now() ELSE NULL END,
           worker = coalesce($14, r.worker),
           asset_id = coalesce(r.asset_id, EXCLUDED.asset_id),
           asset_name = coalesce(r.asset_name, EXCLUDED.asset_name)
         -- Un evento tardío de progreso nunca reabre una ejecución terminada.
         WHERE NOT (r.state IN ('completed', 'failed') AND EXCLUDED.state = 'active')`,
        [
          job.id,
          job.name,
          job.queueName,
          assetId,
          update.state,
          update.progress ?? null,
          clipMessage(update.message),
          clipError(update.error),
          job.timestamp,
          update.started === true,
          update.finished === true,
          update.message !== undefined,
          update.error !== undefined,
          update.worker ?? null,
        ],
      );
    } catch (error) {
      this.logger.warn(
        `No se pudo registrar el estado del job ${job.id}: ${(error as Error).name}`,
      );
    }
  }

  /**
   * Un job que estaba en curso vuelve a la cola sin el objeto del job a mano (*stalled* o
   * barrido): `queued` con un mensaje que nombra la réplica que lo tenía.
   */
  async requeuedById(id: string, reason: (worker: string) => string): Promise<void> {
    if (!isTrackedJobId(id)) return;
    try {
      const [row]: { worker: string | null }[] = await this.db.query(
        `SELECT worker FROM job_runs WHERE id = $1`,
        [id],
      );
      await this.db.query(
        `UPDATE job_runs SET state = 'queued', message = $2, finished_at = NULL
          WHERE id = $1 AND state IN ('queued', 'active')`,
        [id, clipMessage(reason(row?.worker ?? 'la réplica'))],
      );
    } catch (error) {
      this.logger.warn(
        `No se pudo registrar la vuelta a la cola del job ${id}: ${(error as Error).name}`,
      );
    }
  }

  /** Cierra una fila sin job en BullMQ o con el job ya terminado (barrido de huérfanos). */
  async finishById(
    id: string,
    state: 'completed' | 'failed',
    error: string | null,
  ): Promise<void> {
    await this.db.query(
      `UPDATE job_runs SET state = $2::job_run_state, error = coalesce($3, error),
              progress = CASE WHEN $2::job_run_state = 'completed' THEN 100 ELSE progress END,
              finished_at = now()
        WHERE id = $1 AND state IN ('queued', 'active')`,
      [id, state, clipError(error)],
    );
  }

  async prune(days: number): Promise<void> {
    try {
      const result: [unknown, number] = await this.db.query(
        `DELETE FROM job_runs
          WHERE finished_at IS NOT NULL AND finished_at < now() - make_interval(days => $1)`,
        [days],
      );
      if (result[1] > 0)
        this.logger.log(
          `${result[1]} ejecuciones de más de ${days} días borradas`,
        );
      // Las notificaciones (§10) se conservan lo mismo que la Actividad.
      await this.db.query(
        `DELETE FROM notifications WHERE created_at < now() - make_interval(days => $1)`,
        [days],
      );
    } catch (error) {
      this.logger.warn(
        `No se pudieron limpiar las ejecuciones antiguas: ${(error as Error).name}`,
      );
    }
  }
}
