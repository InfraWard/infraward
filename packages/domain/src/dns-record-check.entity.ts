import type { DnsCheckLevel, DnsCheckReason } from '@infraward/shared-types';
import {
  Check,
  Column,
  Entity,
  Index,
  JoinColumn,
  OneToOne,
  PrimaryColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Comprobación de un registro DNS A, AAAA o CNAME (DESIGN §13): si es colgante y con qué
 * prioridad. La escribe el worker al enlazar; «Marcar como esperado» guarda el hash del valor
 * que se aceptó: si el registro cambia de valor, el aviso vuelve.
 */
@Entity({ name: 'dns_record_checks' })
@Check('CHK_dns_record_checks_level', `"level" IS NULL OR "level" IN ('high', 'info')`)
@Index('IDX_dns_record_checks_level', ['level'])
export class DnsRecordCheck {
  @PrimaryColumn({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @OneToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @Column({ type: 'varchar', length: 8, nullable: true })
  level: DnsCheckLevel | null;

  @Column({ type: 'varchar', length: 32 })
  reason: DnsCheckReason;

  /** IP o nombre de destino. */
  @Column({ type: 'varchar', length: 255 })
  target: string;

  @Column({ type: 'boolean', default: false })
  ambiguous: boolean;

  @Column({ name: 'takeover_service', type: 'varchar', length: 64, nullable: true })
  takeoverService: string | null;

  /** sha256 de `tipo|valor`: «esperado» solo vale para este valor. */
  @Column({ name: 'value_hash', type: 'varchar', length: 64 })
  valueHash: string;

  @Column({
    name: 'accepted_value_hash',
    type: 'varchar',
    length: 64,
    nullable: true,
  })
  acceptedValueHash: string | null;

  @Column({ name: 'accepted_by', type: 'varchar', length: 320, nullable: true })
  acceptedBy: string | null;

  @Column({ name: 'accepted_at', type: 'timestamptz', nullable: true })
  acceptedAt: Date | null;

  /** Ya se notificó este aviso alto (para este valor). */
  @Column({ name: 'notified_value_hash', type: 'varchar', length: 64, nullable: true })
  notifiedValueHash: string | null;

  @Column({ name: 'checked_at', type: 'timestamptz' })
  checkedAt: Date;
}

/** SQL: el aviso está vigente (con nivel y sin aceptar para el valor actual). */
export function dnsWarningSql(alias: string): string {
  return `(${alias}.level IS NOT NULL AND ${alias}.accepted_value_hash IS DISTINCT FROM ${alias}.value_hash)`;
}
