import type { JobLogEntry } from '@infraward/shared-types';
import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';
import { JobRun } from './job-run.entity.js';

/**
 * Log de un intento de una ejecución (DESIGN §20, «Log de cada ejecución»): pasos, comandos con
 * su duración, stderr de lo que falla y el resultado. Lo escribe la réplica que ejecuta el job
 * (ya censurado y con tope de tamaño) y lo borra el líder pasados `COLLECTION_LOG_RETENTION_DAYS`.
 * Uno por intento: un reintento o el relevo de otra réplica no pisa el log del anterior.
 */
@Entity({ name: 'job_run_logs' })
@Index('IDX_job_run_logs_updated', ['updatedAt'])
@Index('IDX_job_run_logs_asset', ['assetId'])
export class JobRunLog {
  @PrimaryColumn({ name: 'job_run_id', type: 'uuid' })
  jobRunId: string;

  /** `job_runs.attempt` del intento (su fencing token). */
  @PrimaryColumn({ type: 'integer' })
  attempt: number;

  // Sin el historial, el log no tiene sentido: se va con él.
  @ManyToOne(() => JobRun, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'job_run_id' })
  run?: JobRun;

  /** Asset de la ejecución (el mismo que `job_runs.asset_id`). */
  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  /** Réplica que ejecutó el intento. */
  @Column({ type: 'varchar', length: 64, nullable: true })
  worker: string | null;

  @Column({ type: 'jsonb', default: () => "'[]'" })
  entries: JobLogEntry[];

  /** Se llegó al tope: faltan `dropped` líneas. */
  @Column({ type: 'boolean', default: false })
  truncated: boolean;

  @Column({ type: 'integer', default: 0 })
  dropped: number;

  /** Tamaño aproximado de `entries` (bytes). */
  @Column({ type: 'integer', default: 0 })
  bytes: number;

  @Column({ name: 'started_at', type: 'timestamptz' })
  startedAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
