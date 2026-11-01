import type { AlertChannelType, NotificationKind } from '@infraward/shared-types';
import {
  Check,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Destino de un canal. Webhook: el host (para enseñarlo) y la referencia a la URL completa en el
 * gestor de secretos (suele llevar un token). Correo: los destinatarios.
 */
export type AlertChannelConfig =
  | { host: string; urlRef: string }
  | { recipients: string[] };

/**
 * Canal de alertas fuera de la app (DESIGN §10): webhook (POST JSON, firmado con HMAC si tiene
 * secreto) o correo (SMTP del worker). Recibe las notificaciones de la campana que admite su
 * filtro. La URL del webhook y su secreto de firma solo están como referencias `secret://`.
 */
@Entity({ name: 'alert_channels' })
@Check('CHK_alert_channels_type', `"type" IN ('webhook', 'email')`)
export class AlertChannel {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 100 })
  name: string;

  @Column({ type: 'varchar', length: 16 })
  type: AlertChannelType;

  @Column({ type: 'boolean', default: true })
  enabled: boolean;

  /** Tipos de notificación que recibe; null = todos. */
  @Column({ type: 'varchar', length: 32, array: true, nullable: true })
  kinds: NotificationKind[] | null;

  /** También las que solo ven los admins (`audience_roles = {admin}`). */
  @Column({ name: 'include_admin_only', type: 'boolean', default: false })
  includeAdminOnly: boolean;

  @Column({ type: 'jsonb' })
  config: AlertChannelConfig;

  /** Webhook: referencia `secret://…#campo` al secreto de firma. */
  @Column({ name: 'secret_ref', type: 'varchar', length: 512, nullable: true })
  secretRef: string | null;

  @Column({ name: 'last_success_at', type: 'timestamptz', nullable: true })
  lastSuccessAt: Date | null;

  @Column({ name: 'last_error_at', type: 'timestamptz', nullable: true })
  lastErrorAt: Date | null;

  /** Código HTTP o del servidor de correo (nunca el cuerpo ni la URL). */
  @Column({ name: 'last_error', type: 'varchar', length: 255, nullable: true })
  lastError: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
