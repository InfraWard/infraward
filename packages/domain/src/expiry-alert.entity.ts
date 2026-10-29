import {
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { Asset } from './asset.entity.js';

/**
 * Aviso de caducidad ya enviado (DESIGN §13): uno por asset, fecha de caducidad y umbral. Una
 * renovación cambia la fecha y vuelve a avisar en cada umbral.
 */
@Entity({ name: 'expiry_alerts' })
export class ExpiryAlert {
  @PrimaryColumn({ name: 'asset_id', type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Asset, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @PrimaryColumn({ name: 'not_after', type: 'timestamptz' })
  notAfter: Date;

  /** Días del umbral cruzado (0 = ya caducado). */
  @PrimaryColumn({ name: 'threshold_days', type: 'int' })
  thresholdDays: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
