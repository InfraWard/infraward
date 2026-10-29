import type { SampleMetric } from '@infraward/shared-types';
import {
  Check,
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Project } from './project.entity.js';

/**
 * Muestra de una métrica para los gráficos de evolución (QoL-8, DESIGN §15): una por día, métrica
 * y ámbito (global, `project_id` null, o un proyecto). Pasado el plazo de las diarias, queda una
 * por semana (`granularity = 'week'`).
 */
@Entity({ name: 'metric_samples' })
// Una por día, ámbito y métrica, también la global (`project_id` null): índice único NULLS NOT
// DISTINCT, que TypeORM no sabe declarar (en la migración).
@Index('UQ_metric_samples_day_project_metric', { synchronize: false })
@Check('CHK_metric_samples_granularity', `"granularity" IN ('day', 'week')`)
export class MetricSample {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Día de la muestra (UTC). */
  @Column({ type: 'date' })
  day: string;

  @Index('IDX_metric_samples_project_id')
  @Column({ name: 'project_id', type: 'uuid', nullable: true })
  projectId: string | null;

  @ManyToOne(() => Project, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'project_id' })
  project?: Project;

  @Column({ type: 'varchar', length: 48 })
  metric: SampleMetric;

  /** Valor de cada serie (`{"urgent":3,"high":12}`). */
  @Column({ type: 'jsonb' })
  values: Record<string, number>;

  @Column({ type: 'varchar', length: 8, default: 'day' })
  granularity: 'day' | 'week';
}
