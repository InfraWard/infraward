import type {
  AssetFacts,
  SnapshotDiff,
  SnapshotSource,
} from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Foto de un asset cuando cambia (DESIGN §10): al recogerlo o al descubrirlo, solo si hay cambios
 * reales respecto al anterior, con el diff calculado al guardarla.
 */
@Entity({ name: 'snapshots' })
@Index('IDX_snapshots_asset_collected', { synchronize: false })
export class Snapshot {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @CreateDateColumn({ name: 'collected_at', type: 'timestamptz' })
  collectedAt: Date;

  @Column({ type: 'jsonb', default: () => "'{}'" })
  facts: AssetFacts;

  /** Roles asignados en esta recolección. */
  @Column({ type: 'text', array: true, default: () => "'{}'" })
  roles: string[];

  /** Job del worker que hizo la recolección. */
  @Column({ name: 'job_id', type: 'varchar', length: 64, nullable: true })
  jobId: string | null;

  @Column({ type: 'varchar', length: 16, default: 'collect' })
  source: SnapshotSource;

  /** Snapshot con el que se calculó el diff (null en el primero). */
  @Column({ name: 'previous_id', type: 'uuid', nullable: true })
  previousId: string | null;

  @ManyToOne(() => Snapshot, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'previous_id' })
  previous?: Snapshot | null;

  /** Cambios respecto a `previous` (null en el primero y en los anteriores a la sesión 17). */
  @Column({ type: 'jsonb', nullable: true })
  diff: SnapshotDiff | null;
}
