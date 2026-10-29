import { Asset } from '@infraward/domain';
import {
  VAULT_ENTRY_KINDS,
  VAULT_VERSION_ORIGINS,
  type VaultEntryKind,
  type VaultVersionOrigin,
} from '@infraward/shared-types';
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Unique,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../users/user.entity.js';

/**
 * Entrada de la caja fuerte de credenciales (QoL-7, DESIGN §19): metadatos y la **referencia**
 * al secreto, que vive en el almacén de la caja fuerte (nunca en `SecretsService`, que comparte
 * el worker). Solo la API la conoce: no está en `packages/domain`.
 */
@Entity({ name: 'vault_entries' })
export class VaultEntry {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Asset al que pertenece; al purgarlo la entrada queda suelta (la contraseña no se pierde). */
  @Index('IDX_vault_entries_asset_id')
  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset | null;

  @Column({ type: 'enum', enum: VAULT_ENTRY_KINDS, enumName: 'vault_entry_kind' })
  kind: VaultEntryKind;

  @Column({ type: 'varchar', length: 120 })
  name: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  username: string | null;

  @Column({ type: 'varchar', length: 2000, nullable: true })
  url: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  /** `secret://vault-<almacén>/entries/<id>#password` (null: entrada sin secreto todavía). */
  @Column({ name: 'secret_ref', type: 'text', nullable: true })
  secretRef: string | null;

  @Column({ name: 'current_version', type: 'int', nullable: true })
  currentVersion: number | null;

  @Column({ name: 'last_rotated_at', type: 'timestamptz', nullable: true })
  lastRotatedAt: Date | null;

  /** Plazo propio de rotación (días); null = el de los ajustes. */
  @Column({ name: 'rotation_days', type: 'int', nullable: true })
  rotationDays: number | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'created_by_id', type: 'uuid', nullable: true })
  createdById: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'created_by_id' })
  createdBy?: User | null;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @Column({ name: 'updated_by_id', type: 'uuid', nullable: true })
  updatedById: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'updated_by_id' })
  updatedBy?: User | null;

  /** Borrado lógico: se recupera hasta `deleted_at + deleteRetentionDays`; después se destruye. */
  @Index('IDX_vault_entries_deleted_at')
  @Column({ name: 'deleted_at', type: 'timestamptz', nullable: true })
  deletedAt: Date | null;

  @Column({ name: 'deleted_by_id', type: 'uuid', nullable: true })
  deletedById: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'deleted_by_id' })
  deletedBy?: User | null;
}

/** Historial de versiones del secreto de una entrada: quién y cuándo, **nunca el valor**. */
@Entity({ name: 'vault_entry_versions' })
@Unique('UQ_vault_entry_versions_entry_version', ['entryId', 'version'])
export class VaultEntryVersion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'entry_id', type: 'uuid' })
  entryId: string;

  @ManyToOne(() => VaultEntry, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'entry_id' })
  entry?: VaultEntry;

  /** Número de versión en el almacén. */
  @Column({ type: 'int' })
  version: number;

  @Column({
    type: 'enum',
    enum: VAULT_VERSION_ORIGINS,
    enumName: 'vault_version_origin',
  })
  origin: VaultVersionOrigin;

  @Column({ name: 'restored_from', type: 'int', nullable: true })
  restoredFrom: number | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'created_by_id', type: 'uuid', nullable: true })
  createdById: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'created_by_id' })
  createdBy?: User | null;
}

/** Entidades de la caja fuerte que solo registra la API. */
export const VAULT_API_ENTITIES = [VaultEntry, VaultEntryVersion];
