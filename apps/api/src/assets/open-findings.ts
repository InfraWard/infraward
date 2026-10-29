import { SEVERITIES, type Severity } from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';
import { scanEnabledSql } from '@infraward/domain';

export function emptySeverityCounts(): Record<Severity, number> {
  return Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<
    Severity,
    number
  >;
}

export interface OpenFindingCounts {
  /** Por severidad. */
  open: Record<Severity, number>;
  /** CRITICAL y HIGH con versión corregida. */
  fixable: Record<'CRITICAL' | 'HIGH', number>;
}

export function emptyFindingCounts(): OpenFindingCounts {
  return { open: emptySeverityCounts(), fixable: { CRITICAL: 0, HIGH: 0 } };
}

/**
 * Findings `open` por severidad de cada asset (y cuántos CRITICAL/HIGH tienen parche), en una sola
 * consulta. Un contenedor cuenta los de su imagen (`instance_of`, donde él es el origen); el
 * resto, los suyos. Los assets sin findings no aparecen en el mapa, ni los que tienen el escaneo
 * desactivado por su política (§10): sus findings se conservan, pero no cuentan.
 */
export async function openFindingsBySeverity(
  manager: EntityManager,
  assetIds: string[],
): Promise<Map<string, OpenFindingCounts>> {
  const rows: {
    asset_id: string;
    severity: Severity;
    n: number;
    fixable: number;
  }[] = await manager.query(
    `SELECT a.id AS asset_id, f.severity, count(*)::int AS n,
              count(*) FILTER (WHERE f.fixed_version IS NOT NULL)::int AS fixable
         FROM assets a
         LEFT JOIN asset_relations io
           ON io.parent_id = a.id AND io.type = 'instance_of'
         JOIN findings f
           ON f.asset_id = COALESCE(io.child_id, a.id) AND f.status = 'open'
        WHERE a.id = ANY($1::uuid[]) AND ${scanEnabledSql('a')}
        GROUP BY a.id, f.severity`,
    [assetIds],
  );
  const result = new Map<string, OpenFindingCounts>();
  for (const { asset_id, severity, n, fixable } of rows) {
    let counts = result.get(asset_id);
    if (!counts) result.set(asset_id, (counts = emptyFindingCounts()));
    counts.open[severity] = n;
    if (severity === 'CRITICAL' || severity === 'HIGH')
      counts.fixable[severity] = fixable;
  }
  return result;
}
