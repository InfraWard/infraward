import {
  USER_ORIGINS,
  USER_ROLES,
  type UserOrigin,
  type UserRole,
} from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity({ name: 'users' })
// Una identidad del proveedor = un usuario: índice único parcial (oidc_issuer, oidc_subject)
// solo de las enlazadas; TypeORM no lo sabe declarar, se crea en la migración.
@Index('UQ_users_oidc_identity', { synchronize: false })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Siempre en minúsculas (lo normaliza UsersService). */
  @Column({ type: 'varchar', length: 320, unique: true })
  email: string;

  /** Nombre visible (editable por el propio usuario y por un admin). */
  @Column({ type: 'varchar', length: 120 })
  name: string;

  /** Hash argon2id. Nunca se devuelve en las respuestas. */
  @Column({ name: 'password_hash', type: 'varchar', length: 255 })
  passwordHash: string;

  @Column({
    type: 'enum',
    enum: USER_ROLES,
    enumName: 'user_role',
    default: 'viewer',
  })
  role: UserRole;

  /** Cómo se creó: `local` (con contraseña) u `oidc` (alta automática, sin contraseña). */
  @Column({
    type: 'enum',
    enum: USER_ORIGINS,
    enumName: 'user_origin',
    default: 'local',
  })
  origin: UserOrigin;

  /** Issuer y `sub` de la identidad OIDC enlazada (null sin enlazar). */
  @Column({ name: 'oidc_issuer', type: 'varchar', length: 512, nullable: true })
  oidcIssuer: string | null;

  @Column({
    name: 'oidc_subject',
    type: 'varchar',
    length: 255,
    nullable: true,
  })
  oidcSubject: string | null;

  /** Desactivado (null = activo): no puede entrar y sus sesiones se borran al desactivarlo. */
  @Column({ name: 'disabled_at', type: 'timestamptz', nullable: true })
  disabledAt: Date | null;

  /**
   * `password_hash` es una contraseña temporal (alta o restablecimiento): el primer login la
   * consume y abre una sesión que solo sirve para elegir una nueva.
   */
  @Column({ name: 'must_change_password', type: 'boolean', default: false })
  mustChangePassword: boolean;

  /** Caducidad de la contraseña temporal (null sin temporal pendiente). */
  @Column({
    name: 'temp_password_expires_at',
    type: 'timestamptz',
    nullable: true,
  })
  tempPasswordExpiresAt: Date | null;

  @Column({ name: 'password_changed_at', type: 'timestamptz', nullable: true })
  passwordChangedAt: Date | null;

  @Column({ name: 'last_login_at', type: 'timestamptz', nullable: true })
  lastLoginAt: Date | null;

  /**
   * Referencia `secret://…` al secreto TOTP activo (DESIGN §14): el secreto vive cifrado en el
   * proveedor de secretos, nunca aquí. null = sin verificación en dos pasos.
   */
  @Column({
    name: 'totp_secret_ref',
    type: 'varchar',
    length: 512,
    nullable: true,
  })
  totpSecretRef: string | null;

  /** Secreto de un alta de TOTP sin confirmar todavía (referencia, como el activo). */
  @Column({
    name: 'totp_pending_ref',
    type: 'varchar',
    length: 512,
    nullable: true,
  })
  totpPendingRef: string | null;

  @Column({ name: 'totp_enabled_at', type: 'timestamptz', nullable: true })
  totpEnabledAt: Date | null;

  /**
   * Último paso de 30 s con el que se aceptó un código TOTP: solo valen los posteriores, así un
   * código no se usa dos veces (ni dentro de su ventana).
   */
  @Column({
    name: 'totp_last_step',
    type: 'bigint',
    nullable: true,
    transformer: {
      to: (v: number | null) => v,
      from: (v: string | null) => (v === null ? null : Number(v)),
    },
  })
  totpLastStep: number | null;

  /**
   * Última vez que marcó como vistos los CVE nuevos de «Vulnerabilidades» (null = nunca entró):
   * el panel de nuevos muestra lo abierto desde entonces.
   */
  @Column({
    name: 'vulnerabilities_seen_at',
    type: 'timestamptz',
    nullable: true,
  })
  vulnerabilitiesSeenAt: Date | null;

  /** Último «Marcar como leídas» de las notificaciones (null = nunca). */
  @Column({
    name: 'notifications_seen_at',
    type: 'timestamptz',
    nullable: true,
  })
  notificationsSeenAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
