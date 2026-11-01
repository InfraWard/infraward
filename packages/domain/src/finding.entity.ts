import {
  FINDING_STATUSES,
  SEVERITIES,
  type FindingStatus,
  type NoiseReason,
  type PriorityReason,
  type Severity,
} from '@infraward/shared-types';
import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Vulnerabilidad detectada en un asset (DESIGN §5, §9): una imagen (asset `image`, compartida por
 * sus contenedores) o, en el futuro, un servidor. Una por asset y `fingerprint`: un re-escaneo
 * actualiza `lastSeenAt` en lugar de duplicar.
 */
@Entity({ name: 'findings' })
@Index('UQ_findings_asset_fingerprint', ['assetId', 'fingerprint'], {
  unique: true,
})
@Index('IDX_findings_asset_status', ['assetId', 'status'])
@Index('IDX_findings_status_opened_at', ['status', 'openedAt'])
// (status, priority DESC): en la migración (TypeORM no declara DESC).
@Index('IDX_findings_status_priority', { synchronize: false })
// (accept_expires_at) WHERE status = 'accepted': en la migración (índice parcial).
@Index('IDX_findings_accept_expires', { synchronize: false })
export class Finding {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  /** sha256(vuln|paquete|versión|clase|tipo|ruta): identidad del finding en el asset. */
  @Column({ type: 'varchar', length: 64 })
  fingerprint: string;

  @Index('IDX_findings_vulnerability_id')
  @Column({ name: 'vulnerability_id', type: 'varchar', length: 128 })
  vulnerabilityId: string;

  @Column({ name: 'package_name', type: 'varchar', length: 255 })
  packageName: string;

  @Column({ name: 'installed_version', type: 'varchar', length: 255 })
  installedVersion: string;

  @Column({
    name: 'fixed_version',
    type: 'varchar',
    length: 512,
    nullable: true,
  })
  fixedVersion: string | null;

  @Column({ type: 'enum', enum: SEVERITIES, enumName: 'finding_severity' })
  severity: Severity;

  @Column({ type: 'varchar', length: 500, nullable: true })
  title: string | null;

  /** Estado según la distribución (`fixed`, `affected`, `will_not_fix`…). */
  @Column({ name: 'fix_status', type: 'varchar', length: 32, nullable: true })
  fixStatus: string | null;

  @Column({ name: 'pkg_path', type: 'varchar', length: 1024, nullable: true })
  pkgPath: string | null;

  @Column({
    name: 'primary_url',
    type: 'varchar',
    length: 1024,
    nullable: true,
  })
  primaryUrl: string | null;

  @Column({
    type: 'enum',
    enum: FINDING_STATUSES,
    enumName: 'finding_status',
    default: 'open',
  })
  status: FindingStatus;

  @Column({
    name: 'first_seen_at',
    type: 'timestamptz',
    default: () => 'now()',
  })
  firstSeenAt: Date;

  /**
   * Cuándo se abrió por última vez: al aparecer o al reabrirse (`fixed` → `open`). Es lo que
   * cuenta para «CVEs nuevos desde tu última visita».
   */
  @Column({ name: 'opened_at', type: 'timestamptz', default: () => 'now()' })
  openedAt: Date;

  @Column({ name: 'last_seen_at', type: 'timestamptz', default: () => 'now()' })
  lastSeenAt: Date;

  @Column({ name: 'fixed_at', type: 'timestamptz', nullable: true })
  fixedAt: Date | null;

  /** CVSS de Trivy (NVD primero; V3 o V4). null si no da ninguno. */
  @Column({ name: 'cvss_score', type: 'real', nullable: true })
  cvssScore: number | null;

  /**
   * Prioridad 0–100 con contexto (DESIGN §9, `scoreFinding` de shared-types). La calcula el
   * worker (`findings.prioritize`); null hasta la primera vez.
   */
  @Column({ type: 'smallint', nullable: true })
  priority: number | null;

  /** Motivos de la prioridad, en orden (códigos con datos, nunca texto). */
  @Column({ name: 'priority_reasons', type: 'jsonb', nullable: true })
  priorityReasons: PriorityReason[] | null;

  /** Por qué sale de la vista principal (kernel no en uso, sin corrección prevista). */
  @Column({ name: 'noise_reason', type: 'varchar', length: 32, nullable: true })
  noiseReason: NoiseReason | null;

  /** Cuándo se avisó de que es crítico, está en KEV y expuesto (una vez por apertura). */
  @Column({ name: 'kev_alerted_at', type: 'timestamptz', nullable: true })
  kevAlertedAt: Date | null;

  /**
   * Última aceptación del riesgo (`accepted`): quién (email), cuándo, por qué y hasta cuándo. Se
   * conservan al reabrirlo como historial; al caducar, el worker lo vuelve a `open`.
   */
  @Column({ name: 'accepted_at', type: 'timestamptz', nullable: true })
  acceptedAt: Date | null;

  @Column({ name: 'accepted_by', type: 'varchar', length: 320, nullable: true })
  acceptedBy: string | null;

  @Column({ name: 'accept_reason', type: 'text', nullable: true })
  acceptReason: string | null;

  @Column({ name: 'accept_expires_at', type: 'timestamptz', nullable: true })
  acceptExpiresAt: Date | null;
}
