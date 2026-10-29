import { SBOM_SOURCES, type SbomSource } from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * SBOM CycloneDX de un asset (DESIGN §5, §9): un servidor o CT (`trivy rootfs` sobre sus BDs de
 * paquetes) o un asset `image` (una vez para todos sus contenedores). Se guarda para re-evaluarlo
 * con `trivy sbom` sin conectarse a las máquinas; sus paquetes, normalizados, en `packages`.
 */
@Entity({ name: 'sboms' })
export class Sbom {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  // Uno por asset: un escaneo nuevo lo reemplaza.
  @Index('UQ_sboms_asset_id', { unique: true })
  @Column({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @Column({
    type: 'enum',
    enum: SBOM_SOURCES,
    enumName: 'sbom_source',
  })
  source: SbomSource;

  @Column({ name: 'spec_version', type: 'varchar', length: 16 })
  specVersion: string;

  /** CycloneDX JSON (sin las etiquetas de la imagen) comprimido con gzip. */
  @Column({ type: 'bytea', select: false })
  content: Uint8Array;

  /** sha256 de `content`: la re-evaluación comprueba que no lo reemplazó un escaneo entretanto. */
  @Column({ name: 'content_sha256', type: 'varchar', length: 64 })
  contentSha256: string;

  /** sha256 de la lista de paquetes (y el SO): igual ⇒ el SBOM no ha cambiado. */
  @Column({ name: 'packages_sha256', type: 'varchar', length: 64 })
  packagesSha256: string;

  /** Tamaño del JSON sin comprimir. */
  @Column({ name: 'size_bytes', type: 'integer' })
  sizeBytes: number;

  @Column({ name: 'package_count', type: 'integer' })
  packageCount: number;

  @Column({ name: 'os_family', type: 'varchar', length: 64, nullable: true })
  osFamily: string | null;

  @Column({ name: 'os_name', type: 'varchar', length: 64, nullable: true })
  osName: string | null;

  @Column({
    name: 'trivy_version',
    type: 'varchar',
    length: 32,
    nullable: true,
  })
  trivyVersion: string | null;

  @Column({ name: 'generated_at', type: 'timestamptz' })
  generatedAt: Date;

  @Column({ name: 'evaluated_at', type: 'timestamptz', nullable: true })
  evaluatedAt: Date | null;

  /** Fecha de la BD de vulnerabilidades de Trivy de la última evaluación. */
  @Column({ name: 'db_updated_at', type: 'timestamptz', nullable: true })
  dbUpdatedAt: Date | null;

  @Column({ name: 'vulnerability_count', type: 'integer', nullable: true })
  vulnerabilityCount: number | null;

  /** Motivo legible del fallo de la última re-evaluación (sin secretos). */
  @Column({
    name: 'evaluation_error',
    type: 'varchar',
    length: 500,
    nullable: true,
  })
  evaluationError: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
