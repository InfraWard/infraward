import {
  ASSET_STATUSES,
  ASSET_TYPES,
  type AssetStatus,
  type AssetTreeSummaryNode,
  type AssetType,
} from './assets.js';
import { DEFAULT_EXPIRY_WARNING_DAYS, expiryLevel } from './domains.js';
import {
  matchesInventoryQuery,
  parseSearchQuery,
  type InventoryQueryContext,
} from './search-query.js';

/**
 * Filtros del árbol del inventario (DESIGN §15). Los comparten la web (lo que se ve) y la API
 * (lo que se exporta, QoL-6): misma lógica, mismo resultado.
 */

/**
 * Filtro rápido de la URL (`/inventory?type=server`, `?status=…`, `?attention=…`,
 * `?project=<id>`).
 */
export interface QuickFilter {
  type?: AssetType;
  status?: AssetStatus;
  attention?: Attention;
  /** Id de un proyecto: sus assets (heredados incluidos). */
  project?: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const ATTENTIONS = [
  'sudoers',
  'partial',
  'duplicate',
  'clone',
  'ssh-ca',
  'ssh-password',
  'cert-expiring',
  'domain-expiring',
  'dns-dangling',
  'dns-unknown',
] as const;
export type Attention = (typeof ATTENTIONS)[number];

/** Solo los valores válidos; null si no hay ninguno. */
export function quickFilter(params: {
  type?: string;
  status?: string;
  attention?: string;
  project?: string;
}): QuickFilter | null {
  const f: QuickFilter = {};
  if ((ASSET_TYPES as readonly string[]).includes(params.type ?? ''))
    f.type = params.type as AssetType;
  if ((ASSET_STATUSES as readonly string[]).includes(params.status ?? ''))
    f.status = params.status as AssetStatus;
  if ((ATTENTIONS as readonly string[]).includes(params.attention ?? ''))
    f.attention = params.attention as Attention;
  if (UUID.test(params.project ?? '')) f.project = params.project;
  return Object.keys(f).length ? f : null;
}

/**
 * Certificado o dominio caducado o que caduca antes del umbral mayor de aviso (el mismo
 * criterio que el aviso del panel). false sin fecha.
 */
export function certificateExpiring(
  expiresAt: string | null,
  days: readonly number[] = DEFAULT_EXPIRY_WARNING_DAYS,
  now: number = Date.now(),
): boolean {
  return expiryLevel(expiresAt, days, now) !== null;
}

export function matchesQuickFilter(
  node: AssetTreeSummaryNode,
  f: QuickFilter,
  days: readonly number[] = DEFAULT_EXPIRY_WARNING_DAYS,
): boolean {
  if (f.project && !(node.projects ?? []).includes(f.project)) return false;
  if (f.type && node.type !== f.type) return false;
  if (f.status && node.status !== f.status) return false;
  if (f.attention === 'sudoers' && !node.sudoersOutdated) return false;
  if (f.attention === 'partial' && node.collectionWarnings === 0) return false;
  if (f.attention === 'duplicate' && !node.duplicateOf) return false;
  if (f.attention === 'clone' && !node.machineIdClone) return false;
  if (f.attention === 'ssh-password' && !node.sshdRisk) return false;
  if (
    f.attention === 'cert-expiring' &&
    (node.type !== 'certificate' || !certificateExpiring(node.expiresAt, days))
  )
    return false;
  if (
    f.attention === 'domain-expiring' &&
    (node.type !== 'domain' || !certificateExpiring(node.expiresAt, days))
  )
    return false;
  if (f.attention === 'dns-dangling' && node.dnsWarning !== 'high')
    return false;
  if (f.attention === 'dns-unknown' && node.dnsWarning !== 'info') return false;
  if (f.attention === 'ssh-ca' && !node.sshCaOutdated) return false;
  return true;
}

/**
 * Deja los nodos que cumplen el filtro y sus antepasados (para situarlos en el árbol), y devuelve
 * las ramas que hay que abrir para verlos.
 */
export function prefilter(
  nodes: readonly AssetTreeSummaryNode[],
  f: QuickFilter,
  days: readonly number[] = DEFAULT_EXPIRY_WARNING_DAYS,
): { nodes: AssetTreeSummaryNode[]; expand: string[]; matches: number } {
  return filterTree(nodes, (node) => matchesQuickFilter(node, f, days));
}

/** Como `prefilter`, con cualquier condición. */
export function filterTree(
  nodes: readonly AssetTreeSummaryNode[],
  matches: (node: AssetTreeSummaryNode) => boolean,
): { nodes: AssetTreeSummaryNode[]; expand: string[]; matches: number } {
  const expand: string[] = [];
  let count = 0;
  const walk = (
    list: readonly AssetTreeSummaryNode[],
  ): AssetTreeSummaryNode[] =>
    list.flatMap((node) => {
      const children = walk(node.children);
      const self = matches(node);
      if (self) count++;
      if (!self && children.length === 0) return [];
      if (children.length) expand.push(node.id);
      return [{ ...node, children }];
    });
  const kept = walk(nodes);
  return { nodes: kept, expand, matches: count };
}

/**
 * La búsqueda del árbol (`?q=`) con la sintaxis de filtros (`search-query.ts`): el texto sin clave
 * solo busca en el nombre visible y el descubierto.
 */
export function matchesInventoryText(
  node: AssetTreeSummaryNode,
  text: string,
  ctx: InventoryQueryContext = {},
): boolean {
  return matchesInventoryQuery(node, parseSearchQuery(text, 'inventory'), ctx);
}

/**
 * Columnas que se pueden exportar (lista blanca: nada de conexión, credenciales ni facts). La
 * web elige entre ellas con el selector de columnas del árbol.
 */
export const INVENTORY_EXPORT_COLUMNS = [
  'id',
  'name',
  'discoveredName',
  'path',
  'type',
  'status',
  'runtimeState',
  'address',
  'roles',
  'tags',
  'projects',
  'maxSeverity',
  'critical',
  'high',
  'medium',
  'low',
  'fixableCritical',
  'fixableHigh',
  'expiresAt',
] as const;
export type InventoryExportColumn = (typeof INVENTORY_EXPORT_COLUMNS)[number];

/** Las de por defecto (las del árbol: nombre, tipo, dirección, estado y vulnerabilidades). */
export const INVENTORY_DEFAULT_EXPORT_COLUMNS: readonly InventoryExportColumn[] =
  [
    'name',
    'path',
    'type',
    'address',
    'status',
    'maxSeverity',
    'fixableCritical',
    'fixableHigh',
  ];

export const EXPORT_FORMATS = ['csv', 'json'] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/** GET /assets/export: los mismos filtros que el árbol (URL) y las columnas visibles. */
export interface InventoryExportQuery {
  format?: ExportFormat;
  columns?: InventoryExportColumn[];
  q?: string;
  type?: AssetType;
  status?: AssetStatus;
  attention?: Attention;
  project?: string;
  includeRetired?: boolean;
}

/** Agrupación de la exportación de vulnerabilidades. */
export const VULNERABILITY_EXPORT_GROUPS = ['cve', 'asset'] as const;
export type VulnerabilityExportGroup =
  (typeof VULNERABILITY_EXPORT_GROUPS)[number];
