import {
  IMAGE_SCAN_STATUSES,
  type ImageScanSource,
  type ImageScanStatus,
} from '@infraward/shared-types';
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
 * Estado del escaneo de una imagen de contenedor, identificada por su image ID (DESIGN §9). Es la
 * ficha 1:1 del asset `image`: sus findings cuelgan de ese asset (una vez por imagen) y los
 * contenedores la enlazan con `instance_of`.
 */
@Entity({ name: 'container_images' })
export class ContainerImage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('UQ_container_images_asset_id', { unique: true })
  @Column({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  // 1:1 por el índice único (con OneToOne TypeORM añadiría otra restricción UNIQUE sin nombre).
  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  /** `sha256:…` (config con el almacén clásico; índice o manifiesto con el de containerd). */
  @Index('UQ_container_images_image_id', { unique: true })
  @Column({ name: 'image_id', type: 'varchar', length: 71 })
  imageId: string;

  @Column({
    name: 'repo_digests',
    type: 'text',
    array: true,
    default: () => "'{}'",
  })
  repoDigests: string[];

  @Column({
    name: 'repo_tags',
    type: 'text',
    array: true,
    default: () => "'{}'",
  })
  repoTags: string[];

  /** `linux/amd64`. */
  @Column({ type: 'varchar', length: 64, nullable: true })
  platform: string | null;

  @Column({
    name: 'scan_status',
    type: 'enum',
    enum: IMAGE_SCAN_STATUSES,
    enumName: 'image_scan_status',
    default: 'pending',
  })
  scanStatus: ImageScanStatus;

  /** Motivo legible de `skipped`/`failed` (sin secretos). */
  @Column({ name: 'scan_reason', type: 'varchar', length: 500, nullable: true })
  scanReason: string | null;

  @Column({ name: 'scanned_at', type: 'timestamptz', nullable: true })
  scannedAt: Date | null;

  @Column({ name: 'scan_source', type: 'varchar', length: 32, nullable: true })
  scanSource: ImageScanSource | null;

  /** Host desde el que se sacó la imagen en el último escaneo. */
  @Column({ name: 'source_asset_id', type: 'uuid', nullable: true })
  sourceAssetId: string | null;

  /** Digest del config según Trivy (con containerd difiere del image ID). */
  @Column({
    name: 'config_digest',
    type: 'varchar',
    length: 71,
    nullable: true,
  })
  configDigest: string | null;

  @Column({
    name: 'trivy_version',
    type: 'varchar',
    length: 32,
    nullable: true,
  })
  trivyVersion: string | null;

  /** Fecha de la BD de vulnerabilidades de Trivy usada. */
  @Column({ name: 'db_updated_at', type: 'timestamptz', nullable: true })
  dbUpdatedAt: Date | null;

  /** Vulnerabilidades del último escaneo (null si nunca se escaneó). */
  @Column({ name: 'vulnerability_count', type: 'integer', nullable: true })
  vulnerabilityCount: number | null;

  /**
   * El escaneo de relleno (SBOM de una imagen escaneada antes de los SBOMs) falló o no se pudo
   * hacer: no se vuelve a intentar solo. Un escaneo correcto lo limpia.
   */
  @Column({
    name: 'sbom_backfill_failed_at',
    type: 'timestamptz',
    nullable: true,
  })
  sbomBackfillFailedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
