import { AppSetting } from '@infraward/domain';
import {
  DEFAULT_VAULT_SETTINGS,
  VAULT_RETENTION_DAYS_MAX,
  VAULT_RETENTION_DAYS_MIN,
  VAULT_ROTATION_DAYS_MAX,
  VAULT_ROTATION_DAYS_MIN,
  type VaultSettings,
} from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';

export const VAULT_SETTINGS_KEY = 'vault_settings';

const intIn = (v: unknown, min: number, max: number, fallback: number) =>
  Number.isInteger(v) && (v as number) >= min && (v as number) <= max
    ? (v as number)
    : fallback;

/** Ajustes válidos (JSON libre en `app_settings`); lo que no valga, el valor por defecto. */
export function normalizeVaultSettings(value: unknown): VaultSettings {
  const v = (value && typeof value === 'object' ? value : {}) as Record<string, unknown>;
  return {
    rotationWarnDays: intIn(
      v.rotationWarnDays,
      VAULT_ROTATION_DAYS_MIN,
      VAULT_ROTATION_DAYS_MAX,
      DEFAULT_VAULT_SETTINGS.rotationWarnDays,
    ),
    notifyOnReveal:
      typeof v.notifyOnReveal === 'boolean'
        ? v.notifyOnReveal
        : DEFAULT_VAULT_SETTINGS.notifyOnReveal,
    deleteRetentionDays: intIn(
      v.deleteRetentionDays,
      VAULT_RETENTION_DAYS_MIN,
      VAULT_RETENTION_DAYS_MAX,
      DEFAULT_VAULT_SETTINGS.deleteRetentionDays,
    ),
  };
}

export async function vaultSettings(m: EntityManager): Promise<VaultSettings> {
  const row = await m.findOne(AppSetting, { where: { key: VAULT_SETTINGS_KEY } });
  return normalizeVaultSettings(row?.value);
}

/**
 * Entradas vigentes con la rotación vencida (`last_rotated_at + plazo <= ahora`; el plazo propio
 * o el de los ajustes). Con proyecto, solo las de sus assets.
 */
export async function vaultRotationOverdue(
  m: EntityManager,
  projectId: string | null,
): Promise<number> {
  const { rotationWarnDays } = await vaultSettings(m);
  const [row] = (await m.query(
    `SELECT count(*)::int AS n
       FROM vault_entries e LEFT JOIN assets a ON a.id = e.asset_id
      WHERE e.deleted_at IS NULL
        AND e.last_rotated_at IS NOT NULL
        AND e.last_rotated_at + make_interval(days => COALESCE(e.rotation_days, $1)) <= now()
        AND ($2::uuid IS NULL OR a.effective_projects @> ARRAY[$2::uuid])`,
    [rotationWarnDays, projectId],
  )) as { n: number }[];
  return row?.n ?? 0;
}
