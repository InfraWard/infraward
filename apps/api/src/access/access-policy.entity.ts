import { Asset, Project } from '@infraward/domain';
import {
  USER_ROLES,
  type AccessPermission,
  type AccessScope,
  type AccessSubjectType,
  type UserRole,
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
} from 'typeorm';
import { User } from '../users/user.entity.js';

/**
 * Política de acceso interactivo (sesión 22, DESIGN §5 y §11): concede `terminal.open` a una
 * persona o a un rol en un asset (y lo que contiene), en los assets con una etiqueta o en los de
 * un proyecto. Solo concede; lo que da el rol (admin) no se puede quitar aquí.
 */
@Entity({ name: 'access_policies' })
@Check(
  'CHK_access_policies_subject',
  `("subject_type" = 'user' AND "user_id" IS NOT NULL AND "role" IS NULL)
   OR ("subject_type" = 'role' AND "user_id" IS NULL AND "role" IS NOT NULL)`,
)
@Check(
  'CHK_access_policies_target',
  `("scope" = 'asset' AND "asset_id" IS NOT NULL AND "tag" IS NULL AND "project_id" IS NULL)
   OR ("scope" = 'tag' AND "asset_id" IS NULL AND "tag" IS NOT NULL AND "project_id" IS NULL)
   OR ("scope" = 'project' AND "asset_id" IS NULL AND "tag" IS NULL AND "project_id" IS NOT NULL)`,
)
@Check('CHK_access_policies_permission', `"permission" IN ('terminal.open')`)
// Una regla igual no se repite (índices de expresión parciales, en la migración).
@Index('UQ_access_policies_user_rule', { synchronize: false })
@Index('UQ_access_policies_role_rule', { synchronize: false })
export class AccessPolicy {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 32 })
  permission: AccessPermission;

  @Column({ name: 'subject_type', type: 'varchar', length: 8 })
  subjectType: AccessSubjectType;

  @Index('IDX_access_policies_user_id')
  @Column({ name: 'user_id', type: 'uuid', nullable: true })
  userId: string | null;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user?: User | null;

  @Column({ type: 'enum', enum: USER_ROLES, enumName: 'user_role', nullable: true })
  role: UserRole | null;

  @Column({ type: 'varchar', length: 8 })
  scope: AccessScope;

  @Index('IDX_access_policies_asset_id')
  @Column({ name: 'asset_id', type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  tag: string | null;

  @ManyToOne(() => Project, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'project_id' })
  project?: Project | null;

  @Index('IDX_access_policies_project_id')
  @Column({ name: 'project_id', type: 'uuid', nullable: true })
  projectId: string | null;

  @Column({ name: 'created_by', type: 'uuid', nullable: true })
  createdById: string | null;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'created_by' })
  createdBy?: User | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
