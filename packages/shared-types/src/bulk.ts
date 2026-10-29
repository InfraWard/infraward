import type { CredentialRevocation } from './enrollment.js';
import type { InventoryPolicyFields } from './inventory.js';

/** Operaciones en lote sobre varios assets (QoL-6, DESIGN §15). */
export const BULK_ASSET_ACTIONS = [
  'tags',
  'project',
  'collect',
  'scan',
  'policy',
  'retire',
] as const;
export type BulkAssetAction = (typeof BULK_ASSET_ACTIONS)[number];

/** Assets de una operación: por id (árbol) o los afectados por unos CVE (vulnerabilidades). */
export const BULK_ASSETS_MAX = 500;
export const BULK_VULNERABILITIES_MAX = 200;

export interface BulkAssetTarget {
  assetIds?: string[];
  /**
   * Los assets con findings abiertos de estos CVE (servidores, CT e imágenes; con `projectId`,
   * solo los de ese proyecto). No se combina con `assetIds`.
   */
  vulnerabilityIds?: string[];
  projectId?: string;
}

/**
 * Las acciones que cambian el propio asset (tags, proyecto, política, baja) solo van por id: un
 * CVE no tiene tags, proyecto ni política propios; hereda el contexto del asset afectado.
 */
export interface BulkAssetIds {
  assetIds: string[];
}

/** Las acciones que admiten los afectados por unos CVE (`vulnerabilityIds`). */
export const BULK_VULNERABILITY_ACTIONS = [
  'scan',
] as const satisfies readonly BulkAssetAction[];

export interface BulkTagsRequest extends BulkAssetIds {
  add: string[];
  remove: string[];
}

/** `inherit` quita la fila propia del asset (vuelve a heredar del árbol). */
export const BULK_PROJECT_MODES = ['include', 'exclude', 'inherit'] as const;
export type BulkProjectMode = (typeof BULK_PROJECT_MODES)[number];

export interface BulkProjectRequest extends BulkAssetIds {
  /** El proyecto de destino (no confundir con `projectId`, que filtra los afectados de un CVE). */
  project: string;
  mode: BulkProjectMode;
}

/**
 * Regla propia de cada asset: los campos que vienen se fijan (null = heredar) y los que no, se
 * quedan como estaban. `clear` quita la regla entera.
 */
export interface BulkPolicyRequest extends BulkAssetIds {
  fields?: InventoryPolicyFields;
  clear?: boolean;
}

export interface BulkAssetRef {
  id: string;
  name: string;
  type: string;
}

export interface BulkSkipped extends BulkAssetRef {
  reason: string;
}

export interface BulkOperationResult {
  /** Id de la fila `assets.bulk` en la Actividad (padre de los jobs que lanzó). */
  operationId: string;
  action: BulkAssetAction;
  /** Los que cambiaron (o para los que se encoló un job). */
  applied: BulkAssetRef[];
  /** Los que no se pudieron (con el motivo) o ya estaban así. */
  skipped: BulkSkipped[];
  /** Jobs encolados (recolectar, escanear). */
  jobs: string[];
  /** Dar de baja: comandos para quitar el acceso de los servidores. */
  revocations?: CredentialRevocation[];
}

/** POST /assets/bulk/preview: qué assets entrarían (y, al dar de baja, todo su subárbol). */
export interface BulkPreviewResponse {
  assets: BulkAssetRef[];
  /** Subárbol `contains` completo (seleccionados + descendientes), sin los ya retirados. */
  retire: { total: number; descendants: BulkAssetRef[] };
}

/** Mismo mensaje en la Actividad y en la web. */
export const BULK_ACTION_LABELS: Record<BulkAssetAction, string> = {
  tags: 'Etiquetar',
  project: 'Mover a un proyecto',
  collect: 'Recolectar',
  scan: 'Escanear',
  policy: 'Aplicar una política',
  retire: 'Dar de baja',
};
