import { Injectable, Logger } from '@nestjs/common';
import type { JobState, QueueName } from '@infraward/shared-types';
import { JobQueues } from './job-queues.js';
import { JobRuns } from './job-runs.js';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

/** Solo se cotejan las filas sin terminar de más de este tiempo (las recientes pueden ir por delante). */
const ORPHAN_AFTER = '2 minutes';
/** Filas revisadas en cada pasada. */
const BATCH = 200;

const WAITING: readonly JobState[] = [
  'waiting',
  'delayed',
  'prioritized',
  'waiting-children',
];

/**
 * Barrido de huérfanos (DESIGN §20), en el líder: las filas de `job_runs` sin terminar se cotejan
 * con el estado real en BullMQ. Recoge lo que el oyente no pudo ver (eventos perdidos sin líder,
 * un job que pasa a fallido por *stalled* repetido) y sobre todo lo que ya no está en la cola: un
 * job `active` que no existe pasa a `failed` con su motivo, en vez de quedarse colgado.
 */
@Injectable()
export class OrphanSweeper {
  private readonly logger = new Logger(OrphanSweeper.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly queues: JobQueues,
    private readonly runs: JobRuns,
  ) {}

  async sweep(): Promise<number> {
    const rows: {
      id: string;
      queue: QueueName;
      state: 'queued' | 'active';
      worker: string | null;
    }[] = await this.db.query(
      `SELECT id, queue, state, worker FROM job_runs
        WHERE state IN ('queued', 'active') AND created_at < now() - $1::interval
        ORDER BY created_at LIMIT $2`,
      [ORPHAN_AFTER, BATCH],
    );
    let fixed = 0;
    for (const row of rows) {
      let queue;
      try {
        queue = this.queues.get(row.queue);
      } catch {
        continue;
      }
      const state = await queue.getJobState(row.id);
      if (state === 'unknown') {
        await this.runs.finishById(
          row.id,
          'failed',
          row.state === 'active'
            ? `El job se perdió: ${row.worker ?? 'la réplica que lo ejecutaba'} dejó de responder y ya no está en la cola`
            : 'El job ya no está en la cola (caducó o se borró)',
        );
        fixed++;
      } else if (state === 'completed') {
        await this.runs.finishById(row.id, 'completed', null);
        fixed++;
      } else if (state === 'failed') {
        const job = await queue.getJob(row.id);
        await this.runs.finishById(
          row.id,
          'failed',
          job?.failedReason || 'El job falló',
        );
        fixed++;
      } else if (row.state === 'active' && WAITING.includes(state)) {
        await this.runs.requeuedById(
          row.id,
          (worker) => `Vuelve a la cola: ${worker} lo soltó sin terminarlo`,
        );
        fixed++;
      }
    }
    if (fixed)
      this.logger.log(`${fixed} ejecuciones de la Actividad conciliadas con la cola`);
    return fixed;
  }
}
