import {
  AUDIT_OUTCOMES,
  type AuditAction,
  type AuditDetails,
  type AuditOutcome,
} from '@infraward/shared-types';
import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from '../users/user.entity.js';

/**
 * Registro de auditoría (DESIGN §14): solo se añaden filas. Quién (id y email copiados), cuándo,
 * qué, sobre qué (con el nombre copiado: sobrevive a una purga) y desde qué IP. Nunca secretos.
 * Los índices DESC los crea la migración.
 */
@Entity({ name: 'audit_events' })
@Index('IDX_audit_events_occurred_at', { synchronize: false })
@Index('IDX_audit_events_actor', { synchronize: false })
@Index('IDX_audit_events_action', { synchronize: false })
export class AuditEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'occurred_at', type: 'timestamptz', default: () => 'now()' })
  occurredAt: Date;

  @Column({ name: 'actor_id', type: 'uuid', nullable: true })
  actorId: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'actor_id' })
  actor?: User | null;

  @Column({ name: 'actor_email', type: 'varchar', length: 320, nullable: true })
  actorEmail: string | null;

  @Column({ type: 'varchar', length: 64 })
  action: AuditAction;

  @Column({
    type: 'enum',
    enum: AUDIT_OUTCOMES,
    enumName: 'audit_outcome',
    default: 'success',
  })
  outcome: AuditOutcome;

  @Column({ name: 'target_type', type: 'varchar', length: 32, nullable: true })
  targetType: string | null;

  @Index('IDX_audit_events_target_id')
  @Column({ name: 'target_id', type: 'uuid', nullable: true })
  targetId: string | null;

  @Column({
    name: 'target_label',
    type: 'varchar',
    length: 255,
    nullable: true,
  })
  targetLabel: string | null;

  @Column({ type: 'inet', nullable: true })
  ip: string | null;

  @Column({ type: 'jsonb', default: () => "'{}'" })
  details: AuditDetails;
}
