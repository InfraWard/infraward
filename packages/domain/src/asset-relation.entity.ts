import {
  ASSET_RELATION_TYPES,
  type AssetRelationType,
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
import { Asset } from './asset.entity.js';

/**
 * Relación dirigida entre dos assets. `contains` forma el árbol (Proxmox → CT → contenedor):
 * cada hijo tiene como mucho un padre y no hay ciclos (los ciclos los impide el servicio).
 * `instance_of` (contenedor → imagen; el contenedor es el origen): como mucho una imagen por
 * contenedor.
 */
@Entity({ name: 'asset_relations' })
@Index(
  'UQ_asset_relations_parent_child_type',
  ['parentId', 'childId', 'type'],
  {
    unique: true,
  },
)
@Index('UQ_asset_relations_contains_child', ['childId'], {
  unique: true,
  where: `"type" = 'contains'`,
})
@Index('UQ_asset_relations_instance_of_parent', ['parentId'], {
  unique: true,
  where: `"type" = 'instance_of'`,
})
@Index('IDX_asset_relations_child', ['childId'])
@Check('CHK_asset_relations_not_self', '"parent_id" <> "child_id"')
export class AssetRelation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'parent_id', type: 'uuid' })
  parentId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'parent_id' })
  parent?: Asset;

  @Column({ name: 'child_id', type: 'uuid' })
  childId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'child_id' })
  child?: Asset;

  @Column({
    type: 'enum',
    enum: ASSET_RELATION_TYPES,
    enumName: 'asset_relation_type',
  })
  type: AssetRelationType;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
