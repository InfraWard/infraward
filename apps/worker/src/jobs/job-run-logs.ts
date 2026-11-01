import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { isTrackedJobId } from './job-runs.js';
import type { RunLog } from './run-log.js';

/**
 * Guarda y poda los logs de las ejecuciones (`job_run_logs`, DESIGN §20, «Log de cada
 * ejecución»). Una fila por intento (job + `attempt`): la escribe entera la réplica que lo
 * ejecuta, así que un relevo no pisa el log de otra. Nunca lanza: sin log, el job sigue igual.
 */
@Injectable()
export class JobRunLogs {
  private readonly logger = new Logger(JobRunLogs.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async save(
    jobId: string | undefined,
    attempt: number,
    worker: string,
    log: RunLog,
  ): Promise<void> {
    if (!isTrackedJobId(jobId) || !log.dirty) return;
    log.dirty = false;
    try {
      // Sin fila en `job_runs` (podada entretanto) no se inserta nada.
      await this.db.query(
        `INSERT INTO job_run_logs AS l (job_run_id, attempt, asset_id, worker, entries, truncated,
                                        dropped, bytes, started_at, updated_at)
         SELECT r.id, $2, r.asset_id, $3, $4::jsonb, $5, $6, $7, $8, now()
           FROM job_runs r WHERE r.id = $1
         ON CONFLICT (job_run_id, attempt) DO UPDATE SET
           entries = EXCLUDED.entries,
           truncated = EXCLUDED.truncated,
           dropped = EXCLUDED.dropped,
           bytes = EXCLUDED.bytes,
           worker = EXCLUDED.worker,
           asset_id = coalesce(l.asset_id, EXCLUDED.asset_id),
           updated_at = now()`,
        [
          jobId,
          attempt,
          worker,
          JSON.stringify(log.entries),
          log.truncated,
          log.dropped,
          log.bytes,
          log.startedAt,
        ],
      );
    } catch (error) {
      log.dirty = true;
      this.logger.warn(
        `No se pudo guardar el log del job ${jobId}: ${(error as Error).name}`,
      );
    }
  }

  /** Borra los logs de más de `days` días (desde su última escritura). */
  async prune(days: number): Promise<number> {
    try {
      const result: [unknown, number] = await this.db.query(
        `DELETE FROM job_run_logs WHERE updated_at < now() - make_interval(days => $1)`,
        [days],
      );
      if (result[1] > 0)
        this.logger.log(
          `${result[1]} logs de ejecuciones de más de ${days} días borrados`,
        );
      return result[1];
    } catch (error) {
      this.logger.warn(
        `No se pudieron borrar los logs antiguos: ${(error as Error).name}`,
      );
      return 0;
    }
  }
}
