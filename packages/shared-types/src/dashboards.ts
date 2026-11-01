// Paneles personalizables (QoL-8, DESIGN §15): catálogo de widgets, diseño guardado y validación.
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  type AssetStatus,
  type AssetSummary,
  type AssetType,
} from './assets.js';
import type { DashboardVulnerability } from './dashboard.js';
import type { JobRunSummary } from './jobs.js';
import type { PriorityBand } from './priority.js';
import type { Severity } from './findings.js';

/** Columnas de la rejilla. */
export const DASHBOARD_COLUMNS = 12;
/** Filas que puede ocupar un widget como mucho. */
export const DASHBOARD_MAX_HEIGHT = 12;
export const DASHBOARD_MAX_WIDGETS = 24;
export const DASHBOARD_TITLE_MAX = 80;
export const DASHBOARD_TAGS_MAX = 10;
/** Versión del formato del diseño guardado (`layout.schema`). */
export const DASHBOARD_SCHEMA = 1;

export const WIDGET_TYPES = [
  'asset-summary',
  'fixable-vulnerabilities',
  'vulnerability-counts',
  'asset-counts',
  'pending-enrollment',
  'running-jobs',
  'top-vulnerabilities',
  'new-vulnerabilities',
  'attention',
  'expirations',
  'recent-activity',
  'trend',
] as const;
export type WidgetType = (typeof WIDGET_TYPES)[number];

/** Filtros de un widget: tags (O entre ellos), tipos (O) y proyecto; filtros distintos, Y. */
export interface WidgetFilters {
  projectId?: string;
  tags?: string[];
  types?: AssetType[];
  /** Se guarda, pero aún no tiene efecto: no hay sitios (DESIGN §18). */
  site?: string;
}
export type WidgetFilterKey = keyof WidgetFilters;

export interface DashboardWidget {
  /** Único dentro del panel. */
  id: string;
  type: WidgetType;
  x: number;
  y: number;
  w: number;
  h: number;
  /** Título propio (si no, el del catálogo). */
  title?: string;
  filters: WidgetFilters;
  /** Opciones del tipo (`DASHBOARD_WIDGETS[type].options`), ya con los valores por defecto. */
  options: Record<string, unknown>;
}

export interface DashboardLayout {
  schema: typeof DASHBOARD_SCHEMA;
  widgets: DashboardWidget[];
}

// --- Opciones ---

export interface WidgetChoice {
  value: string;
  label: string;
}

/** Una opción de un tipo de widget: un valor de una lista, varios o un número. */
export type WidgetOptionSpec =
  | { kind: 'select'; label: string; choices: WidgetChoice[]; default: string }
  | { kind: 'multi'; label: string; choices: WidgetChoice[]; default: string[] }
  | {
      kind: 'number';
      label: string;
      min: number;
      max: number;
      default: number | null;
      hint?: string;
    };

/** Avisos del widget `attention` (los mismos que el panel de antes). */
export const ATTENTION_KINDS = [
  'duplicates',
  'certificatesExpiring',
  'domainsExpiring',
  'dnsDangling',
  'dnsUnknown',
  'clones',
  'sshCaOutdated',
  'sshdPasswordLogin',
  'vaultRotationOverdue',
  'sudoersOutdated',
  'partialCollection',
  'failedJobs',
] as const;
export type AttentionKind = (typeof ATTENTION_KINDS)[number];

export const ATTENTION_KIND_LABELS: Record<AttentionKind, string> = {
  duplicates: 'Servidores duplicados',
  certificatesExpiring: 'Certificados que caducan',
  domainsExpiring: 'Dominios que caducan',
  dnsDangling: 'Registros DNS colgantes',
  dnsUnknown: 'DNS a IPs desconocidas',
  clones: 'Clones sin regenerar el machine-id',
  sshCaOutdated: 'CA SSH desactualizada',
  sshdPasswordLogin: 'sshd con root o contraseñas',
  vaultRotationOverdue: 'Credenciales sin rotar',
  sudoersOutdated: 'Sudoers desactualizado',
  partialCollection: 'Recolección parcial',
  failedJobs: 'Tareas fallidas (24 h)',
};

export const TREND_METRICS = [
  'open-findings',
  'new-vs-fixed',
  'cves-by-band',
  'assets-by-status',
] as const;
export type TrendMetric = (typeof TREND_METRICS)[number];

/** Las métricas que salen de las muestras diarias (`metric_samples`): solo filtran por proyecto. */
export const SAMPLED_TREND_METRICS = [
  'cves-by-band',
  'assets-by-status',
] as const satisfies readonly TrendMetric[];

export const TREND_RANGES = ['30d', '90d', '1y'] as const;
export type TrendRange = (typeof TREND_RANGES)[number];
export const TREND_RANGE_DAYS: Record<TrendRange, number> = {
  '30d': 30,
  '90d': 90,
  '1y': 365,
};

const PRIORITY_CHOICES: WidgetChoice[] = [
  { value: 'medium', label: 'Media o más' },
  { value: 'high', label: 'Alta o más' },
  { value: 'urgent', label: 'Solo urgentes' },
];
const LIMIT_CHOICES = ['5', '10', '20'].map((v) => ({ value: v, label: v }));

export interface WidgetSize {
  w: number;
  h: number;
}

export interface WidgetDefinition {
  label: string;
  description: string;
  /** Clase de Bootstrap Icons. */
  icon: string;
  size: WidgetSize;
  min: WidgetSize;
  /** Filtros que admite (`site` se acepta siempre y no tiene efecto). */
  filters: readonly WidgetFilterKey[];
  options: Record<string, WidgetOptionSpec>;
  /** Tiempo de la caché de sus datos en la API (s); null = `DASHBOARD_CACHE_TTL`. */
  ttl: number | null;
}

const ALL_FILTERS = ['projectId', 'tags', 'types', 'site'] as const;

/** Catálogo de widgets (DESIGN §15). */
export const DASHBOARD_WIDGETS: Record<WidgetType, WidgetDefinition> = {
  'asset-summary': {
    label: 'Resumen de assets',
    description:
      'Cuántos assets hay (sin retirados) y de qué tipos, como la tarjeta de un proyecto.',
    icon: 'bi-diagram-3',
    size: { w: 4, h: 3 },
    min: { w: 3, h: 2 },
    filters: ALL_FILTERS,
    options: {},
    ttl: null,
  },
  'fixable-vulnerabilities': {
    label: 'Vulnerabilidades con parche',
    description:
      'Hallazgos críticos y altos con parche, CVE abiertos y hallazgos por severidad.',
    icon: 'bi-bandaid',
    size: { w: 4, h: 3 },
    min: { w: 3, h: 2 },
    filters: ALL_FILTERS,
    options: {},
    ttl: null,
  },
  'vulnerability-counts': {
    label: 'Vulnerabilidades prioritarias',
    description:
      'CVE urgentes, altos y medios de la vista principal, y cuántos están en KEV.',
    icon: 'bi-shield-exclamation',
    size: { w: 4, h: 2 },
    min: { w: 3, h: 2 },
    filters: ALL_FILTERS,
    options: {},
    ttl: null,
  },
  'asset-counts': {
    label: 'Assets por tipo o estado',
    description:
      'Cuántos assets hay de cada tipo o en cada estado, enlazados al inventario.',
    icon: 'bi-diagram-3',
    size: { w: 4, h: 5 },
    min: { w: 3, h: 2 },
    filters: ALL_FILTERS,
    options: {
      groupBy: {
        kind: 'select',
        label: 'Agrupar por',
        choices: [
          { value: 'type', label: 'Tipo' },
          { value: 'status', label: 'Estado' },
        ],
        default: 'type',
      },
    },
    ttl: null,
  },
  'pending-enrollment': {
    label: 'Pendientes de alta',
    description: 'Servidores esperando al script de alta.',
    icon: 'bi-hourglass-split',
    size: { w: 4, h: 2 },
    min: { w: 3, h: 2 },
    filters: ['projectId', 'tags', 'site'],
    options: {
      limit: {
        kind: 'select',
        label: 'Mostrar',
        choices: [{ value: '0', label: 'Solo el número' }, ...LIMIT_CHOICES],
        default: '0',
      },
    },
    ttl: null,
  },
  'running-jobs': {
    label: 'Tareas en curso',
    description:
      'Recolecciones, descubrimientos y escaneos en cola o en marcha.',
    icon: 'bi-arrow-repeat',
    size: { w: 4, h: 2 },
    min: { w: 3, h: 2 },
    filters: ['projectId', 'site'],
    options: {},
    ttl: 5,
  },
  'top-vulnerabilities': {
    label: 'Lo más prioritario',
    description: 'Los CVE más prioritarios con su puntuación y su porqué.',
    icon: 'bi-list-ol',
    size: { w: 4, h: 5 },
    min: { w: 3, h: 3 },
    filters: ALL_FILTERS,
    options: {
      limit: {
        kind: 'select',
        label: 'Cuántos',
        choices: LIMIT_CHOICES,
        default: '5',
      },
      minPriority: {
        kind: 'select',
        label: 'Prioridad',
        choices: PRIORITY_CHOICES,
        default: 'medium',
      },
    },
    ttl: null,
  },
  'new-vulnerabilities': {
    label: 'CVE nuevos',
    description:
      'Los CVE que han aparecido desde tu última visita o en los últimos días.',
    icon: 'bi-stars',
    size: { w: 6, h: 5 },
    min: { w: 3, h: 3 },
    filters: ALL_FILTERS,
    options: {
      since: {
        kind: 'select',
        label: 'Desde',
        choices: [
          { value: 'lastVisit', label: 'Tu última visita' },
          { value: '7d', label: 'Últimos 7 días' },
          { value: '30d', label: 'Últimos 30 días' },
        ],
        default: 'lastVisit',
      },
      limit: {
        kind: 'select',
        label: 'Cuántos',
        choices: LIMIT_CHOICES,
        default: '5',
      },
    },
    ttl: null,
  },
  attention: {
    label: 'Avisos',
    description:
      'Duplicados, caducidades, DNS colgantes, sshd, sudoers, fallos… con los primeros assets.',
    icon: 'bi-exclamation-triangle',
    size: { w: 4, h: 5 },
    min: { w: 3, h: 3 },
    filters: ALL_FILTERS,
    options: {
      kinds: {
        kind: 'multi',
        label: 'Avisos',
        choices: ATTENTION_KINDS.map((k) => ({
          value: k,
          label: ATTENTION_KIND_LABELS[k],
        })),
        default: [...ATTENTION_KINDS],
      },
    },
    ttl: null,
  },
  expirations: {
    label: 'Caducidades',
    description: 'Dominios y certificados ordenados por fecha de caducidad.',
    icon: 'bi-calendar-x',
    size: { w: 6, h: 5 },
    min: { w: 3, h: 3 },
    filters: ['projectId', 'tags', 'site'],
    options: {
      kinds: {
        kind: 'multi',
        label: 'Qué',
        choices: [
          { value: 'domain', label: 'Dominios' },
          { value: 'certificate', label: 'Certificados' },
        ],
        default: ['domain', 'certificate'],
      },
      horizonDays: {
        kind: 'number',
        label: 'Que caduquen en menos de (días)',
        min: 1,
        max: 730,
        default: null,
        hint: 'Vacío: el umbral mayor de los avisos de caducidad',
      },
      limit: {
        kind: 'select',
        label: 'Cuántos',
        choices: LIMIT_CHOICES,
        default: '10',
      },
    },
    ttl: null,
  },
  'recent-activity': {
    label: 'Actividad reciente',
    description: 'Las últimas ejecuciones del worker.',
    icon: 'bi-clock-history',
    size: { w: 12, h: 4 },
    min: { w: 4, h: 3 },
    filters: ['projectId', 'tags', 'types', 'site'],
    options: {
      limit: {
        kind: 'select',
        label: 'Cuántas',
        choices: ['5', '8', '15'].map((v) => ({ value: v, label: v })),
        default: '8',
      },
      state: {
        kind: 'select',
        label: 'Estado',
        choices: [
          { value: 'all', label: 'Todas' },
          { value: 'failed', label: 'Fallidas' },
          { value: 'running', label: 'En curso' },
        ],
        default: 'all',
      },
    },
    ttl: 5,
  },
  trend: {
    label: 'Evolución',
    description:
      'Gráfico de hallazgos abiertos, nuevos y corregidos, CVE prioritarios o assets en el tiempo.',
    icon: 'bi-graph-up',
    size: { w: 6, h: 4 },
    min: { w: 4, h: 3 },
    filters: ALL_FILTERS,
    options: {
      metric: {
        kind: 'select',
        label: 'Qué',
        choices: [
          { value: 'open-findings', label: 'Hallazgos abiertos por severidad' },
          { value: 'new-vs-fixed', label: 'Hallazgos nuevos y corregidos' },
          {
            value: 'cves-by-band',
            label: 'CVE por prioridad (muestras diarias)',
          },
          {
            value: 'assets-by-status',
            label: 'Assets por estado (muestras diarias)',
          },
        ],
        default: 'open-findings',
      },
      range: {
        kind: 'select',
        label: 'Periodo',
        choices: [
          { value: '30d', label: '30 días' },
          { value: '90d', label: '90 días' },
          { value: '1y', label: 'Un año' },
        ],
        default: '90d',
      },
    },
    ttl: null,
  },
};

/** Las opciones de un widget con los valores por defecto donde falten o no valgan. */
export function widgetOptions(
  type: WidgetType,
  options: Record<string, unknown> = {},
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, spec] of Object.entries(DASHBOARD_WIDGETS[type].options)) {
    const value = options[key];
    out[key] =
      optionError(spec, value) === null
        ? normalizeOption(spec, value)
        : spec.default;
  }
  return out;
}

function normalizeOption(spec: WidgetOptionSpec, value: unknown): unknown {
  if (spec.kind === 'multi') {
    const set = new Set(value as string[]);
    return spec.choices.map((c) => c.value).filter((v) => set.has(v));
  }
  return value;
}

/** null si el valor vale para la opción; si no, el motivo. */
function optionError(spec: WidgetOptionSpec, value: unknown): string | null {
  switch (spec.kind) {
    case 'select':
      return typeof value === 'string' &&
        spec.choices.some((c) => c.value === value)
        ? null
        : 'valor no permitido';
    case 'multi':
      return Array.isArray(value) &&
        value.length > 0 &&
        value.every(
          (v) =>
            typeof v === 'string' && spec.choices.some((c) => c.value === v),
        )
        ? null
        : 'valores no permitidos';
    case 'number':
      return value === null ||
        (typeof value === 'number' &&
          Number.isInteger(value) &&
          value >= spec.min &&
          value <= spec.max)
        ? null
        : `entero entre ${spec.min} y ${spec.max}`;
  }
}

// --- Validación del diseño ---

export type DashboardValidation =
  { ok: true; layout: DashboardLayout } | { ok: false; error: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const WIDGET_ID = /^[A-Za-z0-9_-]{1,40}$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isInt(v: unknown, min: number, max: number): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
}

/**
 * Comprueba un diseño (el que manda la web) y lo devuelve normalizado: sin claves desconocidas,
 * con las opciones por defecto, los filtros que el tipo no admite quitados y, si hay
 * `lockedProject` (el panel de un proyecto), todos los widgets fijados a él. Nunca lanza.
 */
export function validateDashboardLayout(
  input: unknown,
  lockedProject?: string,
): DashboardValidation {
  const fail = (error: string): DashboardValidation => ({ ok: false, error });
  if (!isRecord(input)) return fail('El diseño no es un objeto');
  if (input['schema'] !== DASHBOARD_SCHEMA)
    return fail(
      `Versión del diseño no soportada (se espera ${DASHBOARD_SCHEMA})`,
    );
  const raw = input['widgets'];
  if (!Array.isArray(raw)) return fail('Faltan los widgets');
  if (raw.length > DASHBOARD_MAX_WIDGETS)
    return fail(`Como mucho ${DASHBOARD_MAX_WIDGETS} widgets`);
  const ids = new Set<string>();
  const widgets: DashboardWidget[] = [];
  for (const [i, w] of raw.entries()) {
    const at = `Widget ${i + 1}`;
    if (!isRecord(w)) return fail(`${at}: no es un objeto`);
    const { id, type, x, y, w: width, h, title, filters, options } = w;
    if (typeof id !== 'string' || !WIDGET_ID.test(id))
      return fail(`${at}: id no válido`);
    if (ids.has(id)) return fail(`${at}: id repetido`);
    ids.add(id);
    if (
      typeof type !== 'string' ||
      !(WIDGET_TYPES as readonly string[]).includes(type)
    )
      return fail(`${at}: tipo desconocido`);
    const def = DASHBOARD_WIDGETS[type as WidgetType];
    if (!isInt(width, def.min.w, DASHBOARD_COLUMNS))
      return fail(`${at}: ancho entre ${def.min.w} y ${DASHBOARD_COLUMNS}`);
    if (!isInt(h, def.min.h, DASHBOARD_MAX_HEIGHT))
      return fail(`${at}: alto entre ${def.min.h} y ${DASHBOARD_MAX_HEIGHT}`);
    if (!isInt(x, 0, DASHBOARD_COLUMNS - width))
      return fail(`${at}: se sale de la rejilla`);
    if (!isInt(y, 0, 1000)) return fail(`${at}: fila no válida`);
    if (
      title !== undefined &&
      title !== null &&
      (typeof title !== 'string' || title.length > DASHBOARD_TITLE_MAX)
    )
      return fail(`${at}: título de hasta ${DASHBOARD_TITLE_MAX} caracteres`);
    const f = filters ?? {};
    if (!isRecord(f)) return fail(`${at}: filtros no válidos`);
    const parsedFilters = parseFilters(f, def.filters, lockedProject);
    if (typeof parsedFilters === 'string')
      return fail(`${at}: ${parsedFilters}`);
    const o = options ?? {};
    if (!isRecord(o)) return fail(`${at}: opciones no válidas`);
    for (const [key, spec] of Object.entries(def.options)) {
      if (o[key] === undefined) continue;
      const err = optionError(spec, o[key]);
      if (err) return fail(`${at}: ${spec.label}: ${err}`);
    }
    const trimmed = typeof title === 'string' ? title.trim() : '';
    widgets.push({
      id,
      type: type as WidgetType,
      x,
      y,
      w: width,
      h,
      ...(trimmed ? { title: trimmed } : {}),
      filters: parsedFilters,
      options: widgetOptions(type as WidgetType, o),
    });
  }
  const overlap = findOverlap(widgets);
  if (overlap)
    return fail(`Los widgets ${overlap[0]} y ${overlap[1]} se solapan`);
  return {
    ok: true,
    layout: { schema: DASHBOARD_SCHEMA, widgets: sortWidgets(widgets) },
  };
}

function parseFilters(
  f: Record<string, unknown>,
  allowed: readonly WidgetFilterKey[],
  lockedProject: string | undefined,
): WidgetFilters | string {
  const out: WidgetFilters = {};
  const { projectId, tags, types, site } = f;
  if (lockedProject) out.projectId = lockedProject;
  else if (projectId !== undefined && projectId !== null) {
    if (typeof projectId !== 'string' || !UUID.test(projectId))
      return 'proyecto no válido';
    if (allowed.includes('projectId')) out.projectId = projectId.toLowerCase();
  }
  if (tags !== undefined && tags !== null) {
    if (
      !Array.isArray(tags) ||
      tags.length > DASHBOARD_TAGS_MAX ||
      !tags.every((t) => typeof t === 'string' && t.trim() && t.length <= 255)
    )
      return `hasta ${DASHBOARD_TAGS_MAX} tags`;
    const clean = [...new Set((tags as string[]).map((t) => t.trim()))];
    if (clean.length && allowed.includes('tags')) out.tags = clean;
  }
  if (types !== undefined && types !== null) {
    if (
      !Array.isArray(types) ||
      !types.every((t) => (ASSET_TYPES as readonly unknown[]).includes(t))
    )
      return 'tipo de asset no válido';
    const clean = [...new Set(types as AssetType[])];
    if (clean.length && allowed.includes('types')) out.types = clean;
  }
  if (site !== undefined && site !== null) {
    if (typeof site !== 'string' || site.length > 100) return 'sitio no válido';
    if (site.trim()) out.site = site.trim();
  }
  return out;
}

/** Los dos primeros widgets que se solapan, o null. */
export function findOverlap(
  widgets: readonly DashboardWidget[],
): [string, string] | null {
  for (let i = 0; i < widgets.length; i++)
    for (let j = i + 1; j < widgets.length; j++) {
      const a = widgets[i]!;
      const b = widgets[j]!;
      if (
        a.x < b.x + b.w &&
        b.x < a.x + a.w &&
        a.y < b.y + b.h &&
        b.y < a.y + a.h
      )
        return [a.id, b.id];
    }
  return null;
}

/** En orden de lectura: por fila y luego por columna (el orden del panel en una columna). */
export function sortWidgets(
  widgets: readonly DashboardWidget[],
): DashboardWidget[] {
  return [...widgets].sort(
    (a, b) => a.y - b.y || a.x - b.x || a.id.localeCompare(b.id),
  );
}

/**
 * Coloca los widgets en el orden dado de izquierda a derecha y de arriba abajo, sin huecos ni
 * solapes (para «Mover antes/después» y «Tamaño» sin arrastrar).
 */
export function packWidgets(
  ordered: readonly DashboardWidget[],
): DashboardWidget[] {
  const heights = new Array<number>(DASHBOARD_COLUMNS).fill(0);
  let cursorX = 0;
  let rowY = 0;
  return ordered.map((widget) => {
    const w = Math.min(widget.w, DASHBOARD_COLUMNS);
    if (cursorX + w > DASHBOARD_COLUMNS) {
      cursorX = 0;
      rowY = Math.max(...heights);
    }
    const y = Math.max(rowY, ...heights.slice(cursorX, cursorX + w));
    for (let c = cursorX; c < cursorX + w; c++) heights[c] = y + widget.h;
    const placed = { ...widget, x: cursorX, y, w };
    cursorX += w;
    return placed;
  });
}

/** Un widget nuevo del tipo, con su tamaño y opciones por defecto, debajo de todo. */
export function newWidget(
  type: WidgetType,
  existing: readonly DashboardWidget[],
  id: string,
): DashboardWidget {
  const def = DASHBOARD_WIDGETS[type];
  const bottom = existing.reduce((max, w) => Math.max(max, w.y + w.h), 0);
  return {
    id,
    type,
    x: 0,
    y: bottom,
    ...def.size,
    filters: {},
    options: widgetOptions(type),
  };
}

/** El título que se ve: el propio o el del catálogo. */
export function widgetTitle(
  widget: Pick<DashboardWidget, 'type' | 'title'>,
): string {
  return widget.title || DASHBOARD_WIDGETS[widget.type].label;
}

// --- Paneles por defecto ---

/** Posición y tamaño en la rejilla: `[x, y, w, h]`. */
type WidgetBox = readonly [x: number, y: number, w: number, h: number];

function widget(
  id: string,
  type: WidgetType,
  [x, y, w, h]: WidgetBox,
  options: Record<string, unknown> = {},
  filters: WidgetFilters = {},
): DashboardWidget {
  return {
    id,
    type,
    x,
    y,
    w,
    h,
    filters,
    options: widgetOptions(type, options),
  };
}

/** El panel de inicio de quien no lo ha personalizado: el panel de antes, hecho con widgets. */
export const DEFAULT_DASHBOARD: DashboardLayout = {
  schema: DASHBOARD_SCHEMA,
  widgets: [
    widget('vulns', 'vulnerability-counts', [0, 0, 4, 2]),
    widget('pending', 'pending-enrollment', [4, 0, 4, 2]),
    widget('running', 'running-jobs', [8, 0, 4, 2]),
    widget('top', 'top-vulnerabilities', [0, 2, 4, 5]),
    widget('types', 'asset-counts', [4, 2, 4, 5]),
    widget('attention', 'attention', [8, 2, 4, 5]),
    widget('activity', 'recent-activity', [0, 7, 12, 4]),
  ],
};

/** El panel de un proyecto que aún no tiene el suyo, fijado a ese proyecto. */
export function projectDashboardTemplate(projectId: string): DashboardLayout {
  const p = { projectId };
  return {
    schema: DASHBOARD_SCHEMA,
    widgets: [
      widget('assets', 'asset-summary', [0, 0, 4, 3], {}, p),
      widget('fixable', 'fixable-vulnerabilities', [4, 0, 4, 3], {}, p),
      widget('vulns', 'vulnerability-counts', [8, 0, 4, 3], {}, p),
      widget('top', 'top-vulnerabilities', [0, 3, 6, 6], { limit: '10' }, p),
      widget('expirations', 'expirations', [6, 3, 6, 6], {}, p),
      widget(
        'trend',
        'trend',
        [0, 9, 6, 4],
        { metric: 'open-findings', range: '90d' },
        p,
      ),
      widget('attention', 'attention', [6, 9, 6, 4], {}, p),
      widget('activity', 'recent-activity', [0, 13, 12, 4], {}, p),
    ],
  };
}

// --- API ---

/** GET /dashboards/me, GET /projects/:id/dashboard. */
export interface DashboardDocument {
  layout: DashboardLayout;
  /** No hay panel guardado: es el por defecto (o la plantilla del proyecto). */
  isDefault: boolean;
  /** Para la concurrencia optimista (0 si es el por defecto). */
  version: number;
  updatedAt: string | null;
  updatedBy: string | null;
}

/** PUT: el diseño y la versión que se editó (409 si alguien guardó otra antes). */
export interface SaveDashboardRequest {
  layout: DashboardLayout;
  version: number;
}

/**
 * Parámetros de la petición de datos de un widget (`GET /dashboard/widgets/<tipo>`). `project`
 * sustituye al proyecto del widget (el selector de la página o el panel de un proyecto). Las
 * listas van repetidas (`tag=a&tag=b`).
 */
export function widgetRequestParams(
  widget: Pick<DashboardWidget, 'type' | 'filters' | 'options'>,
  project?: string,
): Record<string, string | string[]> {
  const def = DASHBOARD_WIDGETS[widget.type];
  const params: Record<string, string | string[]> = {};
  const projectId = project ?? widget.filters.projectId;
  if (projectId && def.filters.includes('projectId'))
    params['projectId'] = projectId;
  if (widget.filters.tags?.length && def.filters.includes('tags'))
    params['tag'] = widget.filters.tags;
  if (widget.filters.types?.length && def.filters.includes('types'))
    params['type'] = widget.filters.types;
  const options = widgetOptions(widget.type, widget.options);
  for (const [key, value] of Object.entries(options)) {
    if (value === null || value === undefined) continue;
    params[key] = Array.isArray(value) ? value.map(String) : String(value);
  }
  return params;
}

/** Filtros comunes de las peticiones de datos. */
export interface WidgetDataQuery {
  projectId?: string;
  tag?: string[];
  type?: AssetType[];
}

/**
 * Hallazgos abiertos de dueños no retirados que escanean (con ruido incluido: el mismo criterio que
 * la tarjeta de un proyecto, `ProjectStats`), con los tags y tipos aplicados al dueño.
 */
export interface FixableVulnerabilitiesData {
  openFindings: Record<Severity, number>;
  fixableFindings: Record<'CRITICAL' | 'HIGH', number>;
  /** CVE distintos con algún hallazgo abierto. */
  openVulnerabilities: number;
}

export interface VulnerabilityCountsData {
  urgent: number;
  high: number;
  medium: number;
  kev: number;
  /** CVE distintos (prioridad ≥ media). */
  cves: number;
}

export interface AssetCountsData {
  groupBy: 'type' | 'status';
  /** Por tipo (sin retirados) o por estado (todos). */
  counts: Partial<Record<AssetType | AssetStatus, number>>;
  total: number;
}

export interface PendingEnrollmentData {
  count: number;
  assets: AssetSummary[];
}

export interface RunningJobsData {
  count: number;
}

export interface TopVulnerabilitiesData {
  /** CVE que cumplen (para «Ver los N»). */
  total: number;
  items: DashboardVulnerability[];
}

export interface NewVulnerabilitiesData extends TopVulnerabilitiesData {
  /** Desde cuándo cuenta. */
  since: string;
  /** De los nuevos, cuántos están en KEV. */
  kev: number;
}

export interface AttentionItem {
  kind: AttentionKind;
  count: number;
  /** Los primeros (como mucho 5); vacío en los que no son assets (caja fuerte). */
  assets: AssetSummary[];
}

export interface AttentionData {
  /** Solo los que tienen algo, en el orden del catálogo. */
  items: AttentionItem[];
  /** Umbrales de aviso de caducidad (días, de mayor a menor). */
  expiryWarningDays: number[];
}

export interface ExpirationItem {
  asset: AssetSummary;
  kind: 'domain' | 'certificate';
  expiresAt: string;
  /** Negativo si ya caducó. */
  daysLeft: number;
}

export interface ExpirationsData {
  horizonDays: number;
  expiryWarningDays: number[];
  total: number;
  items: ExpirationItem[];
}

export interface RecentActivityData {
  items: JobRunSummary[];
  /** Jobs en cola o en curso (para refrescar mientras haya). */
  running: number;
}

export interface TrendSeries {
  key: string;
  label: string;
  /** Severidad o banda (para el color); null en las demás. */
  severity?: Severity;
  band?: PriorityBand;
}

export interface TrendPoint {
  /** Día (`YYYY-MM-DD`; en semanas, el último de la semana o hoy). */
  day: string;
  values: Record<string, number>;
}

export interface TrendData {
  metric: TrendMetric;
  bucket: 'day' | 'week';
  /** Reconstruido de las fechas de los findings: aproximado (ver el tooltip de la web). */
  approximate: boolean;
  /** Desde cuándo hay datos (null: ninguno); antes de esa fecha no hay puntos. */
  since: string | null;
  /** El widget tiene filtros (tags, tipos) que esta métrica no aplica. */
  ignoredFilters: boolean;
  series: TrendSeries[];
  points: TrendPoint[];
}

/** Estados de asset en el orden de las muestras y los gráficos. */
export const TREND_ASSET_STATUSES: readonly AssetStatus[] = ASSET_STATUSES;
