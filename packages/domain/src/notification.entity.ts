import type {
  NotificationItem,
  NotificationKind,
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
 * Aviso del mantenimiento del inventario (DESIGN §10): altas, desapariciones, retiradas y
 * reapariciones de una reconciliación (agrupadas por descubrimiento y padre) y fallos de los
 * nodos raíz. Nunca facts, conexión ni credenciales.
 */
@Entity({ name: 'notifications' })
export class Notification {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 32 })
  kind: NotificationKind;

  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset | null;

  /** Copia del nombre: el aviso sobrevive a la purga. */
  @Column({ name: 'asset_name', type: 'varchar', length: 255, nullable: true })
  assetName: string | null;

  @Column({ type: 'text' })
  message: string;

  @Column({ type: 'jsonb', default: () => "'[]'" })
  items: NotificationItem[];

  @Column({ type: 'int', default: 0 })
  total: number;

  /**
   * Roles que la ven (null = todos). Lo usan los avisos que no son para cualquiera, como un
   * revelado de la caja fuerte (solo admins, QoL-7).
   */
  @Column({
    name: 'audience_roles',
    type: 'varchar',
    length: 16,
    array: true,
    nullable: true,
  })
  audienceRoles: string[] | null;

  /** Usuario que no la ve (quien la provocó: no se avisa a sí mismo). */
  @Column({ name: 'exclude_user_id', type: 'uuid', nullable: true })
  excludeUserId: string | null;

  @Index('IDX_notifications_created')
  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  /**
   * Cuándo la repartió el worker a los canales de alertas (DESIGN §10); null = pendiente. Índice
   * parcial (WHERE dispatched_at IS NULL) en la migración.
   */
  @Index('IDX_notifications_undispatched', { synchronize: false })
  @Column({ name: 'dispatched_at', type: 'timestamptz', nullable: true })
  dispatchedAt: Date | null;
}
