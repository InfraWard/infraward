import type { AssetType, ProjectStats } from '@infraward/shared-types';

/** Orden en que se enumeran los tipos de un proyecto. */
const TYPE_ORDER: AssetType[] = [
  'server',
  'vm',
  'lxc',
  'container',
  'image',
  'volume',
  'network',
  'subscription',
  'domain',
  'database',
  'certificate',
  'dns_record',
];

/** «2 C · 5 H con parche» o null. */
export function fixableLabel(stats: ProjectStats): string | null {
  const { CRITICAL, HIGH } = stats.fixableFindings;
  const parts = [CRITICAL ? `${CRITICAL} C` : '', HIGH ? `${HIGH} H` : ''].filter(Boolean);
  return parts.length ? parts.join(' · ') : null;
}

/** Tipos que tiene, con cuántos (en el orden de siempre). */
export function assetTypeCounts(
  stats: ProjectStats,
): { type: AssetType; count: number }[] {
  return TYPE_ORDER.filter((t) => stats.assetsByType[t]).map((t) => ({
    type: t,
    count: stats.assetsByType[t]!,
  }));
}

/** Severidades de más a menos grave, con lo que se pinta en la barra. */
export const SEVERITY_BAR_ORDER = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
] as const;

export function severitySegments(
  open: ProjectStats['openFindings'],
): { severity: (typeof SEVERITY_BAR_ORDER)[number]; count: number; share: number }[] {
  const total = SEVERITY_BAR_ORDER.reduce((n, s) => n + open[s], 0);
  return total
    ? SEVERITY_BAR_ORDER.filter((s) => open[s]).map((s) => ({
        severity: s,
        count: open[s],
        share: open[s] / total,
      }))
    : [];
}
