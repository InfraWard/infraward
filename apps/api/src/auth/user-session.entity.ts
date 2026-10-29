import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from '../users/user.entity.js';

/**
 * `full`: sesión normal. `password_change`: solo sirve para cambiar la contraseña temporal.
 * `mfa`: la contraseña era buena y falta el código TOTP o de recuperación (5 min).
 */
export const SESSION_PURPOSES = ['full', 'password_change', 'mfa'] as const;
export type SessionPurpose = (typeof SESSION_PURPOSES)[number];

/** Cómo se abrió la sesión: con contraseña (y TOTP si lo tiene) o con el proveedor OIDC. */
export const SESSION_AUTH_METHODS = ['password', 'oidc'] as const;
export type SessionAuthMethod = (typeof SESSION_AUTH_METHODS)[number];

/**
 * Sesión web (DESIGN §14). El token solo viaja en la cookie httpOnly; aquí se guarda su sha256.
 * Revocar = borrar la fila (desactivar, restablecer o cambiar la contraseña, cerrar sesión).
 */
@Entity({ name: 'user_sessions' })
export class UserSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('IDX_user_sessions_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user?: User;

  /** sha256 del token de la cookie. */
  @Index('UQ_user_sessions_token_hash', { unique: true })
  @Column({ name: 'token_hash', type: 'bytea' })
  tokenHash: Buffer;

  /** Token CSRF de la sesión (sin la cookie no sirve de nada). */
  @Column({ name: 'csrf_token', type: 'varchar', length: 64 })
  csrfToken: string;

  @Column({
    type: 'enum',
    enum: SESSION_PURPOSES,
    enumName: 'user_session_purpose',
    default: 'full',
  })
  purpose: SessionPurpose;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'last_seen_at', type: 'timestamptz' })
  lastSeenAt: Date;

  /** Caducidad absoluta (la de inactividad se calcula con `last_seen_at`). */
  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({
    name: 'auth_method',
    type: 'enum',
    enum: SESSION_AUTH_METHODS,
    enumName: 'user_session_auth_method',
    default: 'password',
  })
  authMethod: SessionAuthMethod;

  /**
   * Última vez que se confirmó la identidad (login con TOTP, código en el diálogo de
   * reautenticación o `auth_time` de un nuevo login en el proveedor): las acciones sensibles
   * exigen que sea reciente (REAUTH_MAX_AGE). null = nunca en esta sesión.
   */
  @Column({ name: 'reauthenticated_at', type: 'timestamptz', nullable: true })
  reauthenticatedAt: Date | null;

  /** Códigos fallidos en la sesión intermedia `mfa` (a los 5, se borra). */
  @Column({ name: 'mfa_failures', type: 'smallint', default: 0 })
  mfaFailures: number;

  @Column({ type: 'inet', nullable: true })
  ip: string | null;

  @Column({ name: 'user_agent', type: 'varchar', length: 255, nullable: true })
  userAgent: string | null;

  /**
   * ID token de una sesión abierta por OIDC: solo sirve de `id_token_hint` para cerrar también
   * la sesión del proveedor (su audiencia es InfraWard). Nunca sale en respuestas ni logs y se
   * borra con la sesión. `select: false`: solo lo lee el logout.
   */
  @Column({
    name: 'oidc_id_token',
    type: 'text',
    nullable: true,
    select: false,
  })
  oidcIdToken: string | null;
}
