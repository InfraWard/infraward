// Mantenimiento del inventario (DESIGN §10): política de inventario, reconciliación periódica,
// diffs entre snapshots y notificaciones.

import type { AssetType } from './assets.js';
import { byCodeUnit } from './sort.js';

// --- Política de inventario ---

/** Valores de una política: todos fijados (la global y la efectiva de cada asset). */
export interface InventoryPolicyValues {
  /** Cada cuánto se reconcilia un nodo raíz, en minutos (0 = nunca). */
  reconcileIntervalMinutes: number;
  /** Escanear vulnerabilidades (SBOM y Trivy). Desactivado: ni automático ni bajo demanda. */
  scanEnabled: boolean;
  /** Escaneos automáticos (tras recoger y descubrir). Desactivado: solo bajo demanda. */
  scanPeriodic: boolean;
}

export type InventoryPolicyField = keyof InventoryPolicyValues;

export const INVENTORY_POLICY_FIELDS = [
  'reconcileIntervalMinutes',
  'scanEnabled',
  'scanPeriodic',
] as const satisfies readonly InventoryPolicyField[];

/** Valores de partida de la política global (la migración los siembra). */
export const DEFAULT_INVENTORY_POLICY: InventoryPolicyValues = {
  reconcileIntervalMinutes: 360,
  scanEnabled: true,
  scanPeriodic: true,
};

/** Límites del intervalo (minutos): 0 = nunca; si no, entre 5 min y 30 días. */
export const RECONCILE_INTERVAL_MIN = 5;
export const RECONCILE_INTERVAL_MAX = 43_200;

export const INVENTORY_POLICY_SCOPES = [
  'global',
  'asset',
  'tag',
  'project',
] as const;
export type InventoryPolicyScope = (typeof INVENTORY_POLICY_SCOPES)[number];

/**
 * De dónde sale el valor efectivo de un campo:
 * - `own`: regla del propio asset;
 * - `inherited`: regla del antepasado `contains` más cercano que lo fija (`assetId`);
 * - `tag`: regla de una etiqueta del asset (la más restrictiva si hay varias);
 * - `project`: regla de un proyecto del asset (la más restrictiva si hay varios);
 * - `holders`: imagen sin regla propia: lo que tengan los hosts y contenedores que la usan;
 * - `global`: la política global.
 */
export type InventoryPolicySource =
  | { kind: 'own' }
  | { kind: 'inherited'; assetId: string; assetName?: string }
  | { kind: 'tag'; tag: string }
  | { kind: 'project'; projectId: string; projectName?: string }
  | { kind: 'holders' }
  | { kind: 'global' }
  | ExcludedPolicySource;

/**
 * Escaneo desactivado por una **exclusión** (QoL-6b): la regla que la tiene (`by`), qué la hizo
 * coincidir (`match`) y, en una imagen, el host o contenedor que la usa por cuya regla queda
 * fuera (`holderId`; con varios, el primero).
 */
export interface ExcludedPolicySource {
  kind: 'excluded';
  by: ScanExclusionOrigin;
  match: ScanExclusionMatch;
  holderId?: string;
  holderName?: string;
}

/** Regla de la que sale una exclusión (como los orígenes de un campo). */
export type ScanExclusionOrigin =
  | { kind: 'own' }
  | { kind: 'inherited'; assetId: string; assetName?: string }
  | { kind: 'tag'; tag: string }
  | { kind: 'project'; projectId: string; projectName?: string }
  | { kind: 'global' };

// --- Exclusiones del escaneo (QoL-6b) ---

/**
 * Tipos que se pueden excluir: los que se escanean (SBOM de servidores y CT, Trivy de imágenes).
 * Volúmenes, redes y el resto no se escanean nunca: excluirlos no cambiaría nada.
 */
export const SCAN_EXCLUDABLE_TYPES = [
  'image',
  'server',
  'lxc',
] as const satisfies readonly AssetType[];
export type ScanExcludableType = (typeof SCAN_EXCLUDABLE_TYPES)[number];

export const SCAN_EXCLUSION_PATTERNS_MAX = 20;
export const SCAN_EXCLUSION_PATTERN_MAX = 100;
export const SCAN_EXCLUSION_ASSETS_MAX = 200;
/** Patrón glob (`*` y `?`) sobre el nombre visible o el descubierto, sin mayúsculas. */
export const SCAN_EXCLUSION_PATTERN = /^[\p{L}\p{N}._:@/*?+\- ]+$/u;

/**
 * Lo que una regla excluye del escaneo: sigue inventariado, pero no se escanea. Se suman las de
 * todas las reglas que alcanzan al asset (propia, antepasados, etiquetas, proyectos y global).
 */
export interface ScanExclusions {
  types?: ScanExcludableType[];
  namePatterns?: string[];
  assetIds?: string[];
}

export type ScanExclusionMatch =
  | { kind: 'type'; type: ScanExcludableType }
  | { kind: 'pattern'; pattern: string }
  | { kind: 'asset'; assetId: string };

/** Sin repetidos ni listas vacías y ordenadas; null si no excluye nada. */
export function normalizeScanExclusions(
  ex: ScanExclusions | null | undefined,
): ScanExclusions | null {
  if (!ex) return null;
  const out: ScanExclusions = {};
  const types = [...new Set(ex.types ?? [])]
    .filter((t) => (SCAN_EXCLUDABLE_TYPES as readonly string[]).includes(t))
    .sort(byCodeUnit);
  const patterns = [
    ...new Set((ex.namePatterns ?? []).map((p) => p.trim()).filter(Boolean)),
  ].sort(byCodeUnit);
  const assetIds = [...new Set(ex.assetIds ?? [])].sort(byCodeUnit);
  if (types.length) out.types = types;
  if (patterns.length) out.namePatterns = patterns;
  if (assetIds.length) out.assetIds = assetIds;
  return Object.keys(out).length ? out : null;
}

/** Mismo carácter sin distinguir mayúsculas (como la `i` de una regex con `u`). */
function sameChar(a: string, b: string): boolean {
  return (
    a === b ||
    a.toLowerCase() === b.toLowerCase() ||
    a.toUpperCase() === b.toUpperCase()
  );
}

/**
 * ¿Casa `name` entero con el glob (`*` = cualquier secuencia, `?` = un carácter), sin mayúsculas?
 * Iterativo, de dos punteros y sin regex: O(n·m) en el peor caso. Una regex con un `.*` por
 * estrella hace backtracking exponencial con patrones como `*a*a*a…*b` y congelaba la API con el
 * candado de la política tomado (revisión #3, A1).
 */
export function globMatch(pattern: string, name: string): boolean {
  const p = Array.from(pattern);
  const s = Array.from(name);
  let pi = 0;
  let si = 0;
  // Última estrella vista y desde qué carácter del nombre se probó: al fallar, se le da uno más.
  let star = -1;
  let mark = 0;
  while (si < s.length) {
    if (pi < p.length && p[pi] === '*') {
      star = pi++;
      mark = si;
    } else if (pi < p.length && (p[pi] === '?' || sameChar(p[pi]!, s[si]!))) {
      pi++;
      si++;
    } else if (star !== -1) {
      pi = star + 1;
      si = ++mark;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

/** Si la exclusión alcanza al asset y por qué (tipo, patrón de nombre o el propio asset). */
export function scanExclusionMatch(
  asset: {
    id: string;
    type: AssetType;
    name: string;
    discoveredName?: string | null;
  },
  ex: ScanExclusions | null | undefined,
): ScanExclusionMatch | null {
  if (!ex) return null;
  if (ex.assetIds?.includes(asset.id))
    return { kind: 'asset', assetId: asset.id };
  const type = ex.types?.find((t) => t === asset.type);
  if (type) return { kind: 'type', type };
  const names = [asset.name, asset.discoveredName ?? ''].filter(Boolean);
  for (const pattern of ex.namePatterns ?? []) {
    if (names.some((n) => globMatch(pattern, n)))
      return { kind: 'pattern', pattern };
  }
  return null;
}

/** Nombre en plural de un tipo excluible, para los motivos. */
export const SCAN_EXCLUDABLE_TYPE_LABELS: Record<ScanExcludableType, string> = {
  image: 'imágenes de contenedor',
  server: 'servidores',
  lxc: 'CT',
};

/** Política efectiva de un asset (se guarda calculada en `assets.effective_policy`). */
export interface EffectiveInventoryPolicy {
  values: InventoryPolicyValues;
  sources: Record<InventoryPolicyField, InventoryPolicySource>;
}

/** Regla de política: global, de un asset (se hereda hacia abajo), de una etiqueta o de un proyecto. */
export interface InventoryPolicyRule {
  id: string;
  scope: InventoryPolicyScope;
  /** Solo `asset`. */
  assetId: string | null;
  /** Solo `asset`: nombre del asset (para listarla). */
  assetName?: string | null;
  /** Solo `tag`. */
  tag: string | null;
  /** Solo `project`. */
  projectId: string | null;
  /** Solo `project`: nombre del proyecto (para listarla). */
  projectName?: string | null;
  /** null = no lo fija (se hereda). En la global, nunca null. */
  reconcileIntervalMinutes: number | null;
  scanEnabled: boolean | null;
  scanPeriodic: boolean | null;
  /** Lo que excluye del escaneo (null = nada). */
  scanExclusions: ScanExclusions | null;
  createdAt: string;
  updatedAt: string;
}

/** Campos de una regla de asset, etiqueta o proyecto (null = no lo fija). Al menos uno fijado. */
export interface InventoryPolicyFields {
  reconcileIntervalMinutes?: number | null;
  scanEnabled?: boolean | null;
  scanPeriodic?: boolean | null;
  /** null o vacío = no excluye nada. */
  scanExclusions?: ScanExclusions | null;
}

/** Los campos de una regla: los de la política efectiva y las exclusiones. */
export const INVENTORY_RULE_FIELDS = [
  ...INVENTORY_POLICY_FIELDS,
  'scanExclusions',
] as const satisfies readonly (keyof InventoryPolicyFields)[];
export type InventoryRuleField = (typeof INVENTORY_RULE_FIELDS)[number];

/**
 * Plantillas del alta de un servidor (QoL-6b): solo rellenan el formulario de la regla propia
 * (luego se puede retocar). «Estándar» no fija nada: hereda.
 */
export const INVENTORY_POLICY_PRESETS: readonly {
  id: string;
  label: string;
  description: string;
  fields: InventoryPolicyFields;
}[] = [
  {
    id: 'standard',
    label: 'Estándar',
    description: 'Hereda la política global, de sus etiquetas y de sus proyectos',
    fields: {},
  },
  {
    id: 'inventory-only',
    label: 'Solo inventario',
    description: 'Se inventaría, pero nada se escanea',
    fields: { scanEnabled: false },
  },
  {
    id: 'no-images',
    label: 'Sin imágenes',
    description:
      'Escanea el sistema, pero no las imágenes de sus contenedores',
    fields: { scanExclusions: { types: ['image'] } },
  },
  {
    id: 'on-demand',
    label: 'Escaneo bajo demanda',
    description: 'Solo se escanea cuando se pide',
    fields: { scanPeriodic: false },
  },
];

export interface CreateInventoryPolicyRequest extends InventoryPolicyFields {
  scope: 'asset' | 'tag' | 'project';
  assetId?: string;
  tag?: string;
  projectId?: string;
}

export type UpdateInventoryPolicyRequest = InventoryPolicyFields;

/** `PUT /inventory-policies/global`: los tres campos (siempre fijados) y las exclusiones. */
export interface UpdateGlobalPolicyRequest extends Partial<InventoryPolicyValues> {
  scanExclusions?: ScanExclusions | null;
}

export interface InventoryPolicyList {
  global: InventoryPolicyRule;
  rules: InventoryPolicyRule[];
}

/** `GET /assets/:id/policy`. */
export interface AssetPolicy {
  effective: EffectiveInventoryPolicy;
  /** Regla propia del asset (null si no tiene). */
  rule: InventoryPolicyRule | null;
  /** Nodo raíz que lo reconcilia (el propio asset si es raíz; null si no tiene ninguno). */
  reconcileRoot: { id: string; name: string } | null;
  /** Solo raíces: última reconciliación encolada y la siguiente prevista (null = nunca). */
  reconciledAt: string | null;
  nextReconcileAt: string | null;
}

// --- Reconciliación (DESIGN §10) ---

/** Qué lanzó un job de la cadena de recolección y descubrimiento. */
export type InventoryTrigger = 'manual' | 'reconcile';

export interface InventoryReconcileJobData {
  /** Reconciliar solo este nodo raíz, ahora (sin mirar el intervalo). */
  assetId?: string;
}

export interface InventoryReconcileJobResult {
  /** Nodos raíz cuya recolección se encoló. */
  queued: number;
  assetIds: string[];
  /** Raíces con el intervalo sin vencer o desactivado. */
  notDue: number;
}

export interface ReconcileRequest {
  /** Solo este nodo raíz; sin él, todos los que tienen el intervalo vencido. */
  assetId?: string;
}

// --- Diff entre snapshots ---

export const SNAPSHOT_SOURCES = ['collect', 'discover'] as const;
export type SnapshotSource = (typeof SNAPSHOT_SOURCES)[number];

export type SnapshotChangeKind = 'added' | 'removed' | 'changed';

/**
 * Un cambio entre dos snapshots. `path` usa puntos y, en las listas con clave, `[clave]`:
 * `packages[openssl:amd64].version`, `ports[tcp 0.0.0.0:80]`, `proxmox.config.memory`.
 */
export interface SnapshotChange {
  path: string;
  kind: SnapshotChangeKind;
  before?: unknown;
  after?: unknown;
}

/** Cambios por sección (primer nivel de los facts, o `roles`). */
export interface SnapshotChangeSummary {
  section: string;
  added: number;
  removed: number;
  changed: number;
}

export interface SnapshotDiff {
  changes: SnapshotChange[];
  summary: SnapshotChangeSummary[];
  /** Se cortó la lista de cambios (el resumen sí cuenta todos). */
  truncated: boolean;
}

// --- Notificaciones ---

export const NOTIFICATION_KINDS = [
  'asset_created',
  'asset_missing',
  'asset_reactivated',
  'asset_retired',
  'reconcile_failed',
  /** Un dominio o certificado ha cruzado un umbral de aviso de caducidad (QoL-5). */
  'expiry_warning',
  /** Registros DNS colgantes nuevos de prioridad alta (QoL-5). */
  'dns_dangling',
  /** CVE críticos, en KEV y expuestos en un asset (sesión 19): `items` son los CVE. */
  'vulnerability_kev',
  /** Un admin reveló una credencial de la caja fuerte (QoL-7): solo la ven los demás admins. */
  'vault_revealed',
  /** Caducó la aceptación del riesgo de findings de un asset: vuelven a abiertos. */
  'finding_acceptance_expired',
] as const;
export type NotificationKind = (typeof NOTIFICATION_KINDS)[number];

/** Asset al que se refiere una notificación. Nunca facts, conexión ni credenciales. */
export interface NotificationItem {
  id: string;
  name: string;
  /** `vulnerability`: un CVE (`id` = su identificador), en `vulnerability_kev`. */
  type: AssetType | 'vulnerability';
}

export interface Notification {
  id: string;
  kind: NotificationKind;
  /** Asset principal (el padre de lo descubierto o la raíz que falló); null si se purgó. */
  assetId: string | null;
  assetName: string | null;
  message: string;
  /** Hasta `NOTIFICATION_MAX_ITEMS` assets afectados. */
  items: NotificationItem[];
  /** Cuántos assets afectó en total (puede ser más que `items`). */
  total: number;
  createdAt: string;
  /** Posterior al último «Marcar como leídas» del usuario. */
  unread: boolean;
}

export const NOTIFICATION_MAX_ITEMS = 20;

export interface NotificationPage {
  items: Notification[];
  total: number;
  unread: number;
}

export interface NotificationUnreadCount {
  unread: number;
}

/** Motivo de no escanear un asset con `scanEnabled = false` (worker y API). */
export const SCAN_DISABLED_REASON =
  'Escaneo desactivado por la política de inventario';

/** El motivo concreto: el genérico o, con una exclusión, cuál y de qué regla (QoL-6b). */
export function scanDisabledReason(
  policy: Partial<EffectiveInventoryPolicy> | null | undefined,
): string {
  const source = policy?.sources?.scanEnabled;
  return source?.kind === 'excluded'
    ? `Excluido del escaneo por ${scanExclusionText(source)}`
    : SCAN_DISABLED_REASON;
}

/** «la regla del proyecto Clientes (tipo: imágenes de contenedor)». */
export function scanExclusionText(source: ExcludedPolicySource): string {
  const { by, match } = source;
  const rule =
    by.kind === 'global'
      ? 'la política global'
      : by.kind === 'tag'
        ? `la regla de la etiqueta ${by.tag}`
        : by.kind === 'project'
          ? `la regla del proyecto ${by.projectName ?? by.projectId}`
          : by.kind === 'inherited'
            ? `la regla de ${by.assetName ?? 'un antepasado'}`
            : source.holderId
              ? `la regla de ${source.holderName ?? 'quien la usa'}`
              : 'su regla propia';
  const via =
    source.holderId && by.kind !== 'own'
      ? `, que alcanza a ${source.holderName ?? 'quien la usa'}`
      : '';
  const what =
    match.kind === 'type'
      ? `tipo: ${SCAN_EXCLUDABLE_TYPE_LABELS[match.type]}`
      : match.kind === 'pattern'
        ? `nombre: ${match.pattern}`
        : 'excluido por asset';
  return `${rule}${via} (${what})`;
}

/** Id del job scheduler de BullMQ que lanza `inventory.reconcile` cada `RECONCILE_TICK`. */
export const INVENTORY_RECONCILE_ID = 'inventory-reconcile';
