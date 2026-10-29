import {
  DEFAULT_EXPIRY_WARNING_DAYS,
  EXPIRY_WARNING_MAX_DAYS,
  EXPIRY_WARNING_MAX_THRESHOLDS,
} from '@infraward/shared-types';
import { Column, Entity, PrimaryColumn, UpdateDateColumn } from 'typeorm';
import type { EntityManager } from 'typeorm';

/** Ajuste global de la aplicación (clave → JSON). */
@Entity({ name: 'app_settings' })
export class AppSetting {
  @PrimaryColumn({ type: 'varchar', length: 64 })
  key: string;

  @Column({ type: 'jsonb' })
  value: unknown;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}

export const EXPIRY_WARNING_DAYS_KEY = 'expiry_warning_days';

/** Umbrales válidos: enteros 1–365, sin repetir, de mayor a menor; si no, los de por defecto. */
export function normalizeExpiryDays(value: unknown): number[] {
  if (!Array.isArray(value)) return [...DEFAULT_EXPIRY_WARNING_DAYS];
  const days = [
    ...new Set(
      value.filter(
        (d): d is number =>
          Number.isInteger(d) && d >= 1 && d <= EXPIRY_WARNING_MAX_DAYS,
      ),
    ),
  ]
    .sort((a, b) => b - a)
    .slice(0, EXPIRY_WARNING_MAX_THRESHOLDS);
  return days.length > 0 ? days : [...DEFAULT_EXPIRY_WARNING_DAYS];
}

/** Umbrales de aviso de caducidad (días, de mayor a menor). */
export async function expiryWarningDays(m: EntityManager): Promise<number[]> {
  const row = await m.findOne(AppSetting, {
    where: { key: EXPIRY_WARNING_DAYS_KEY },
  });
  return normalizeExpiryDays(row?.value);
}
