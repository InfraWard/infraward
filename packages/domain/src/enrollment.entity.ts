import {
  ENROLLMENT_METHODS,
  ENROLLMENT_PURPOSES,
  ENROLLMENT_STATUSES,
  SSH_AUTH_MODES,
  type EnrollmentMethod,
  type EnrollmentPurpose,
  type EnrollmentStatus,
  type HostKeyFingerprint,
  type AdminAccessRequest,
  type SshAuthMode,
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
 * Proceso de alta (o de actualización del sudoers) de un servidor (DESIGN §7). No se borra al
 * completarse: es el historial de cuándo y cómo se dio de alta. Del token solo se guarda el
 * hash; el token en claro solo existe en el comando que se muestra una vez.
 */
@Entity({ name: 'enrollments' })
@Index('IDX_enrollments_asset_created', { synchronize: false })
@Index('UQ_enrollments_asset_open', { synchronize: false })
export class Enrollment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @Column({
    type: 'enum',
    enum: ENROLLMENT_METHODS,
    enumName: 'enrollment_method',
  })
  method: EnrollmentMethod;

  @Column({
    type: 'enum',
    enum: ENROLLMENT_PURPOSES,
    enumName: 'enrollment_purpose',
  })
  purpose: EnrollmentPurpose;

  @Column({
    type: 'enum',
    enum: ENROLLMENT_STATUSES,
    enumName: 'enrollment_status',
    default: 'pending',
  })
  status: EnrollmentStatus;

  /** SHA-256 (hex) del token de un solo uso; null cuando ya no se puede usar. */
  @Index('UQ_enrollments_token_hash', { unique: true })
  @Column({ name: 'token_hash', type: 'char', length: 64, nullable: true })
  tokenHash: string | null;

  @Column({ name: 'expires_at', type: 'timestamptz', nullable: true })
  expiresAt: Date | null;

  /** Modo de acceso que instala el script de este enrolamiento. */
  @Column({
    name: 'auth_mode',
    type: 'enum',
    enum: SSH_AUTH_MODES,
    enumName: 'ssh_auth_mode',
    default: 'static_key',
  })
  authMode: SshAuthMode;

  /**
   * Acceso interactivo de administración que pide el script (DESIGN §7): `operator` lo instala,
   * `none` lo retira y null no lo toca. Al verificarse, se copia al asset.
   */
  @Column({ name: 'admin_access', type: 'varchar', length: 16, nullable: true })
  adminAccess: AdminAccessRequest | null;

  /**
   * Clave pública instalada (`ssh-ed25519 … inventory@infraward:<asset>`). No es secreta.
   * null en modo CA: no hay clave permanente.
   */
  @Column({ name: 'public_key', type: 'text', nullable: true })
  publicKey: string | null;

  @Column({ name: 'ssh_user', type: 'varchar', length: 32 })
  sshUser: string;

  /** Huellas de las host keys enviadas por el script (vacío en el camino manual). */
  @Column({
    name: 'reported_host_keys',
    type: 'jsonb',
    default: () => "'[]'",
  })
  reportedHostKeys: HostKeyFingerprint[];

  /** Versión del sudoers leída por el worker al verificar (null si no hay). */
  @Column({ name: 'sudoers_version', type: 'int', nullable: true })
  sudoersVersion: number | null;

  /** Motivo del fallo de la verificación (sin secretos). */
  @Column({ type: 'text', nullable: true })
  error: string | null;

  /** Último job de verificación. */
  @Column({ name: 'job_id', type: 'varchar', length: 64, nullable: true })
  jobId: string | null;

  @Column({ name: 'confirmed_at', type: 'timestamptz', nullable: true })
  confirmedAt: Date | null;

  @Column({ name: 'verified_at', type: 'timestamptz', nullable: true })
  verifiedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
