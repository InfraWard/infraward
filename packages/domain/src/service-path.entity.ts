import type {
  HopConfidence,
  ServiceCutReason,
  ServiceHop,
  ServicePathStatus,
} from '@infraward/shared-types';
import {
  Check,
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToOne,
  PrimaryColumn,
  PrimaryGeneratedColumn,
  Unique,
  UpdateDateColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Camino de un registro DNS hasta el asset que lo sirve (QoL-5b, DESIGN §13). Lo calcula el
 * worker (`ServiceLinker`) con los datos de solo lectura del inventario; el destino fijado a mano
 * (`pinned_asset_id`) gana al calculado, que se sigue guardando para mostrar hasta dónde llegó.
 */
@Entity({ name: 'dns_service_paths' })
@Check(
  'CHK_dns_service_paths_status',
  `"status" IN ('complete', 'partial', 'manual', 'none')`,
)
@Index('IDX_dns_service_paths_final', ['finalAssetId'])
export class DnsServicePath {
  @PrimaryColumn({ name: 'record_id', type: 'uuid' })
  recordId: string;

  @OneToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'record_id' })
  record?: Asset;

  @Column({ type: 'varchar', length: 16 })
  status: ServicePathStatus;

  /** Asset final (el fijado a mano si lo hay); null si la cadena se corta. */
  @Column({ name: 'final_asset_id', type: 'uuid', nullable: true })
  finalAssetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'final_asset_id' })
  finalAsset?: Asset | null;

  /** Eslabones calculados (cada uno con su origen y su confianza). */
  @Column({ type: 'jsonb', default: () => "'[]'" })
  hops: ServiceHop[];

  @Column({ type: 'varchar', length: 16, nullable: true })
  confidence: HopConfidence | null;

  @Column({ name: 'cut_reason', type: 'varchar', length: 32, nullable: true })
  cutReason: ServiceCutReason | null;

  /** Nombre accesible desde Internet (IP pública, proxy de Cloudflare o túnel): prioridad §9. */
  @Column({ type: 'boolean', default: false })
  public: boolean;

  /** Ids de los assets del camino (finales e intermedios), para «Por aquí pasan». */
  @Index('IDX_dns_service_paths_via', { synchronize: false })
  @Column({ name: 'via_asset_ids', type: 'uuid', array: true, default: () => "'{}'" })
  viaAssetIds: string[];

  @Column({ name: 'pinned_asset_id', type: 'uuid', nullable: true })
  pinnedAssetId: string | null;

  @ManyToOne(() => Asset, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'pinned_asset_id' })
  pinnedAsset?: Asset | null;

  @Column({ name: 'pinned_by', type: 'varchar', length: 320, nullable: true })
  pinnedBy: string | null;

  @Column({ name: 'pinned_at', type: 'timestamptz', nullable: true })
  pinnedAt: Date | null;

  @Column({ name: 'computed_at', type: 'timestamptz', nullable: true })
  computedAt: Date | null;
}

/**
 * Reenvío de puertos NAT declarado a mano (Ajustes › Inventario): la IP pública de un router que
 * no está en el inventario, con su puerto, llega a este asset y puerto.
 */
@Entity({ name: 'nat_forwards' })
@Unique('UQ_nat_forwards_public', ['publicIp', 'publicPort', 'proto'])
@Check('CHK_nat_forwards_proto', `"proto" IN ('tcp', 'udp')`)
@Check(
  'CHK_nat_forwards_ports',
  `"public_port" BETWEEN 1 AND 65535 AND "target_port" BETWEEN 1 AND 65535`,
)
export class NatForward {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'public_ip', type: 'inet' })
  publicIp: string;

  @Column({ name: 'public_port', type: 'integer' })
  publicPort: number;

  @Column({ type: 'varchar', length: 3, default: 'tcp' })
  proto: 'tcp' | 'udp';

  @Column({ name: 'target_asset_id', type: 'uuid' })
  targetAssetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'target_asset_id' })
  targetAsset?: Asset;

  @Column({ name: 'target_port', type: 'integer' })
  targetPort: number;

  @Column({ type: 'varchar', length: 255, nullable: true })
  description: string | null;

  @Column({ name: 'created_by', type: 'varchar', length: 320, nullable: true })
  createdBy: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
