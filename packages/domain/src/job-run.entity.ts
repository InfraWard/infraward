import {
  JOB_RUN_STATES,
  type JobName,
  type JobRunState,
  type QueueName,
} from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Ejecución de un job (DESIGN §5). BullMQ borra los jobs terminados (1 h los completados, 24 h los
 * fallidos): esta tabla es el historial de la Actividad. La crea quien encola y la actualiza el
 * worker al empezar, avanzar y terminar. Sin datos ni resultado del job: solo lo que se muestra.
 */
@Entity({ name: 'job_runs' })
@Index('IDX_job_runs_created', { synchronize: false })
@Index('IDX_job_runs_asset_created', { synchronize: false })
@Index('IDX_job_runs_running', { synchronize: false })
@Index('IDX_job_runs_parent', { synchronize: false })
export class JobRun {
  /** El jobId de BullMQ (UUID). */
  @PrimaryColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 64 })
  name: JobName;

  @Column({ type: 'varchar', length: 32 })
  queue: QueueName;

  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  // Sin CASCADE: el historial sobrevive a la purga del asset (queda su nombre).
  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  /** Nombre del asset al encolarse. */
  @Column({ name: 'asset_name', type: 'varchar', length: 255, nullable: true })
  assetName: string | null;

  @Column({
    type: 'enum',
    enum: JOB_RUN_STATES,
    enumName: 'job_run_state',
    default: 'queued',
  })
  state: JobRunState;

  @Column({ type: 'smallint', default: 0 })
  progress: number;

  /** Último mensaje de progreso. */
  @Column({ type: 'varchar', length: 500, nullable: true })
  message: string | null;

  /** `failedReason` del job: el worker solo deja ahí mensajes aptos para mostrarse. */
  @Column({ type: 'varchar', length: 1000, nullable: true })
  error: string | null;

  /**
   * Job que lo encoló (sin FK: puede haberse limpiado antes) o la operación en lote
   * (`assets.bulk`, QoL-6) que lo lanzó.
   */
  @Column({ name: 'parent_job_id', type: 'uuid', nullable: true })
  parentJobId: string | null;

  /** Réplica del worker que lo ejecuta o lo ejecutó por última vez (DESIGN §20). */
  @Column({ type: 'varchar', length: 64, nullable: true })
  worker: string | null;

  /**
   * Veces que una réplica lo ha empezado: es el *fencing token* (DESIGN §20). Las escrituras
   * finales de un job comprueban que sigue siendo el suyo, así que una réplica lenta que perdió el
   * lock no pisa el resultado de la que la sustituyó.
   */
  @Column({ type: 'integer', default: 0 })
  attempt: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'started_at', type: 'timestamptz', nullable: true })
  startedAt: Date | null;

  @Column({ name: 'finished_at', type: 'timestamptz', nullable: true })
  finishedAt: Date | null;
}
