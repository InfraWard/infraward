import {
  DEFAULT_EXPIRY_WARNING_DAYS,
  expiryLevel,
  type Attention,
  type DnsCheckLevel,
  type AssetRuntimeState,
  type AssetTreeSummaryNode,
  type QuickFilter,
  type Severity,
} from '@infraward/shared-types';
import type { TreeNode } from '@openng/optimus-ui/api';
import {
  ASSET_STATUS_LABELS,
  ASSET_TYPE_LABELS,
  SEVERITY_ORDER,
} from '../../shared/labels';

/** Fila del treeTable: el resumen del asset más lo que se calcula para pintarlo. */
export interface InventoryRow {
  id: string;
  name: string;
  /** Nombre descubierto, solo si está renombrado. */
  discoveredName: string | null;
  type: AssetTreeSummaryNode['type'];
  status: AssetTreeSummaryNode['status'];
  roles: string[];
  tags: string[];
  /** Proyectos (heredados incluidos). */
  projects: string[];
  address: string | null;
  runtimeState: AssetRuntimeState | null;
  runtimeDetail: string | null;
  /** Certificados: «caduca en 12 días» y si avisa (caducado o menos de 30 días). */
  /** Caducidad (certificados y dominios) con su nivel según los umbrales de aviso. */
  expiry: {
    label: string;
    warn: boolean;
    severity: 'danger' | 'warn' | 'success';
    date: string;
  } | null;
  /** Registros DNS: aviso de colgante sin marcar como esperado. */
  dnsWarning: DnsCheckLevel | null;
  /** Peor severidad con findings abiertos (null si no hay). */
  worst: Severity | null;
  /** CRITICAL y HIGH abiertos con parche (lo que hay que atender primero). */
  fixableCritical: number;
  fixableHigh: number;
  /** «791 abiertos: 20 CRITICAL · 183 HIGH · …» para el tooltip. */
  findingsSummary: string;
  /** Escaneo desactivado por su política (§10): sus findings no cuentan. */
  scanDisabled: boolean;
}

/**
 * Árbol de la API → nodos del treeTable. La clave es el id del asset (sirve para conservar qué
 * ramas estaban abiertas al recargar o volver de la ficha).
 */
export function toTreeNodes(
  nodes: readonly AssetTreeSummaryNode[],
  expanded: ReadonlySet<string> = new Set(),
  days: readonly number[] = DEFAULT_EXPIRY_WARNING_DAYS,
): TreeNode<InventoryRow>[] {
  return nodes.map((node) => ({
    key: node.id,
    data: toRow(node, days),
    expanded: expanded.has(node.id),
    leaf: node.children.length === 0,
    children: toTreeNodes(node.children, expanded, days),
  }));
}

export function toRow(
  node: AssetTreeSummaryNode,
  days: readonly number[] = DEFAULT_EXPIRY_WARNING_DAYS,
): InventoryRow {
  const gone = node.status === 'missing' || node.status === 'retired';
  const present = SEVERITY_ORDER.filter((s) => node.openFindings[s] > 0);
  const total = present.reduce((n, s) => n + node.openFindings[s], 0);
  return {
    id: node.id,
    name: node.name,
    discoveredName: node.discoveredName ?? null,
    type: node.type,
    status: node.status,
    roles: node.roles,
    tags: node.tags,
    projects: node.projects ?? [],
    address: node.address,
    // Desaparecido o retirado: el último estado de ejecución que se vio ya no vale.
    runtimeState: gone ? null : node.runtimeState,
    runtimeDetail: gone ? null : node.runtimeDetail,
    expiry: node.expiresAt ? expiryTag(node.expiresAt, days) : null,
    dnsWarning: gone ? null : (node.dnsWarning ?? null),
    worst: present[0] ?? null,
    fixableCritical: node.fixableFindings.CRITICAL,
    fixableHigh: node.fixableFindings.HIGH,
    findingsSummary: total
      ? `${total} abiertas: ${present.map((s) => `${node.openFindings[s]} ${s}`).join(' · ')}`
      : '',
    scanDisabled: node.scanDisabled ?? false,
  };
}

/** «3 C · 12 H» con parche, o null si no hay ninguna CRITICAL/HIGH con parche. */
export function fixableLabel(row: InventoryRow): string | null {
  const parts = [
    row.fixableCritical ? `${row.fixableCritical} C` : '',
    row.fixableHigh ? `${row.fixableHigh} H` : '',
  ].filter(Boolean);
  return parts.length ? parts.join(' · ') : null;
}

/** Claves de todos los nodos con hijos (para «Expandir todo»). */
export function branchKeys(nodes: readonly AssetTreeSummaryNode[]): string[] {
  return nodes.flatMap((n) =>
    n.children.length ? [n.id, ...branchKeys(n.children)] : [],
  );
}

export {
  ATTENTIONS,
  certificateExpiring,
  filterTree,
  matchesQuickFilter,
  prefilter,
  quickFilter,
  type Attention,
  type QuickFilter,
} from '@infraward/shared-types';

const ATTENTION_LABELS: Record<Attention, string> = {
  sudoers: 'Sudoers desactualizado',
  partial: 'Recolección parcial',
  duplicate: 'Duplicados',
  clone: 'machine-id clonado',
  'cert-expiring': 'Certificados que caducan',
  'domain-expiring': 'Dominios que caducan',
  'dns-dangling': 'Registros DNS colgantes',
  'dns-unknown': 'Registros DNS a IPs desconocidas',
  'ssh-ca': 'CA SSH desactualizada',
  'ssh-password': 'SSH con root o contraseña',
};

/** «Proyecto: Homelab · Tipo: Servidor · Pendiente de alta» para el chip del filtro. */
export function quickFilterLabel(f: QuickFilter, projectName?: string): string {
  return [
    f.project ? `Proyecto: ${projectName ?? '…'}` : '',
    f.type ? `Tipo: ${ASSET_TYPE_LABELS[f.type]}` : '',
    f.status ? `Estado: ${ASSET_STATUS_LABELS[f.status]}` : '',
    f.attention ? ATTENTION_LABELS[f.attention] : '',
  ]
    .filter(Boolean)
    .join(' · ');
}

/**
 * Etiqueta de una caducidad: «caduca en 12 días» en rojo si caducó o está por debajo del umbral
 * menor, en ámbar por debajo del mayor y en verde si queda tiempo.
 */
export function expiryTag(
  expiresAt: string,
  days: readonly number[] = DEFAULT_EXPIRY_WARNING_DAYS,
  now: number = Date.now(),
): NonNullable<InventoryRow['expiry']> {
  const level = expiryLevel(expiresAt, days, now);
  return {
    label: certificateExpiryLabel(expiresAt, now),
    warn: level !== null,
    severity: level === null ? 'success' : level === 'warning' ? 'warn' : 'danger',
    date: expiresAt,
  };
}

/** «caduca en 12 días», «caduca hoy», «caducó ayer», «caducó hace 3 días». */
export function certificateExpiryLabel(
  expiresAt: string,
  now: number = Date.now(),
): string {
  const diff = Date.parse(expiresAt) - now;
  const days = Math.floor(Math.abs(diff) / 86_400_000);
  if (diff >= 0)
    return days === 0
      ? 'caduca hoy'
      : days === 1
        ? 'caduca mañana'
        : `caduca en ${days} días`;
  return days === 0
    ? 'caducó hoy'
    : days === 1
      ? 'caducó ayer'
      : `caducó hace ${days} días`;
}
