import type { ProjectMembershipMode } from '@infraward/shared-types';
import {
  Check,
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Proyecto o grupo de assets (DESIGN §5). La pertenencia se decide con filas directas
 * (`ProjectMembership`) que se heredan hacia abajo en el árbol `contains`; la efectiva se guarda
 * calculada en `assets.effective_projects`.
 */
@Entity({ name: 'projects' })
// Nombre único sin distinguir mayúsculas: índice de expresión, en la migración.
@Index('UQ_projects_name', { synchronize: false })
@Check('CHK_projects_color', `"color" IS NULL OR "color" ~ '^#[0-9a-fA-F]{6}$'`)
export class Project {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 100 })
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  /** `#rrggbb` (null = sin color). */
  @Column({ type: 'varchar', length: 7, nullable: true })
  color: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}

/**
 * Fila directa de un asset en un proyecto: `include` (entra él y lo que contiene) o `exclude`
 * (excepción: sale él y lo que contiene aunque lo herede). Decide la fila más cercana del camino.
 */
@Entity({ name: 'project_memberships' })
@Check('CHK_project_memberships_mode', `"mode" IN ('include', 'exclude')`)
export class ProjectMembership {
  @PrimaryColumn({ name: 'project_id', type: 'uuid' })
  projectId: string;

  @ManyToOne(() => Project, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'project_id' })
  project?: Project;

  @Index('IDX_project_memberships_asset')
  @PrimaryColumn({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @Column({ type: 'varchar', length: 8 })
  mode: ProjectMembershipMode;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}

/** Color opcional de un tag (los tags siguen siendo texto en `assets.tags`). */
@Entity({ name: 'tag_styles' })
@Check('CHK_tag_styles_color', `"color" ~ '^#[0-9a-fA-F]{6}$'`)
export class TagStyle {
  @PrimaryColumn({ type: 'varchar', length: 255 })
  tag: string;

  @Column({ type: 'varchar', length: 7 })
  color: string;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
