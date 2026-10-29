import type { DashboardLayout } from '@infraward/shared-types';
import { Project } from '@infraward/domain';
import {
  Check,
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../users/user.entity.js';

/**
 * Panel guardado (QoL-8, DESIGN §15): el personal de un usuario o el de un proyecto, uno de cada
 * como mucho. Sin fila se usa el por defecto (`DEFAULT_DASHBOARD` o la plantilla del proyecto).
 * Los widgets van juntos en `layout` (siempre se leen y se guardan a la vez).
 */
@Entity({ name: 'dashboards' })
@Check(
  'CHK_dashboards_owner',
  `num_nonnulls("owner_user_id", "project_id") = 1`,
)
export class Dashboard {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('UQ_dashboards_owner_user_id', { unique: true })
  @Column({ name: 'owner_user_id', type: 'uuid', nullable: true })
  ownerUserId: string | null;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'owner_user_id' })
  owner?: User;

  @Index('UQ_dashboards_project_id', { unique: true })
  @Column({ name: 'project_id', type: 'uuid', nullable: true })
  projectId: string | null;

  @ManyToOne(() => Project, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'project_id' })
  project?: Project;

  @Column({ type: 'jsonb' })
  layout: DashboardLayout;

  /** Concurrencia optimista: sube con cada guardado. */
  @Column({ type: 'int', default: 1 })
  version: number;

  @Column({ name: 'updated_by_id', type: 'uuid', nullable: true })
  updatedById: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'updated_by_id' })
  updatedBy?: User;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
