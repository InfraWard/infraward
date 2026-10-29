import type {
  InventoryPolicyScope,
  ScanExclusions,
} from '@infraward/shared-types';
import {
  Check,
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
import { Project } from './project.entity.js';

/**
 * Regla de la política de inventario (DESIGN §10): la global (una, con todos los campos), la de
 * un asset (se hereda hacia abajo en el árbol), la de una etiqueta o la de un proyecto. null = no
 * fija ese campo.
 */
@Entity({ name: 'inventory_policies' })
@Index('UQ_inventory_policies_global', ['scope'], {
  unique: true,
  where: `"scope" = 'global'`,
})
@Check(
  'CHK_inventory_policies_target',
  `("scope" = 'global' AND "asset_id" IS NULL AND "tag" IS NULL AND "project_id" IS NULL AND "reconcile_interval_minutes" IS NOT NULL AND "scan_enabled" IS NOT NULL AND "scan_periodic" IS NOT NULL)
   OR ("scope" = 'asset' AND "asset_id" IS NOT NULL AND "tag" IS NULL AND "project_id" IS NULL)
   OR ("scope" = 'tag' AND "asset_id" IS NULL AND "tag" IS NOT NULL AND "project_id" IS NULL)
   OR ("scope" = 'project' AND "asset_id" IS NULL AND "tag" IS NULL AND "project_id" IS NOT NULL)`,
)
@Check(
  'CHK_inventory_policies_interval',
  `"reconcile_interval_minutes" IS NULL OR "reconcile_interval_minutes" = 0 OR "reconcile_interval_minutes" BETWEEN 5 AND 43200`,
)
export class InventoryPolicy {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 16 })
  scope: InventoryPolicyScope;

  @Index('UQ_inventory_policies_asset', { unique: true })
  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset | null;

  @Index('UQ_inventory_policies_tag', { unique: true })
  @Column({ type: 'varchar', length: 255, nullable: true })
  tag: string | null;

  @Index('UQ_inventory_policies_project', { unique: true })
  @Column({ name: 'project_id', type: 'uuid', nullable: true })
  projectId: string | null;

  @ManyToOne(() => Project, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'project_id' })
  project?: Project | null;

  /** Minutos entre reconciliaciones de un nodo raíz (0 = nunca). */
  @Column({ name: 'reconcile_interval_minutes', type: 'int', nullable: true })
  reconcileIntervalMinutes: number | null;

  @Column({ name: 'scan_enabled', type: 'boolean', nullable: true })
  scanEnabled: boolean | null;

  @Column({ name: 'scan_periodic', type: 'boolean', nullable: true })
  scanPeriodic: boolean | null;

  /**
   * Lo que excluye del escaneo (tipos, patrones de nombre, assets; QoL-6b): sigue inventariado
   * pero no se escanea. null = nada. Se suman las de todas las reglas que alcanzan al asset.
   */
  @Column({ name: 'scan_exclusions', type: 'jsonb', nullable: true })
  scanExclusions: ScanExclusions | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
