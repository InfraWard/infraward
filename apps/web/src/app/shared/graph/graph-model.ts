import type {
  AssetGraph,
  AssetType,
  GraphNode,
} from '@infraward/shared-types';
import type { ElementDefinition, StylesheetJson } from 'cytoscape';
import { ASSET_TYPE_LABELS, RELATION_LABELS } from '../labels';
import { assetTypeIconUri } from './graph-icons';

/** Color de cada tipo: una paleta primitiva de Aura (`--p-<color>-500`, o 400 en oscuro). */
export const ASSET_TYPE_COLORS: Record<AssetType, string> = {
  server: 'indigo',
  vm: 'violet',
  lxc: 'teal',
  container: 'sky',
  domain: 'emerald',
  dns_record: 'lime',
  database: 'amber',
  image: 'fuchsia',
  volume: 'orange',
  network: 'cyan',
  subscription: 'purple',
  certificate: 'green',
  dns_provider: 'orange',
};

/** Filtro de estado de la topología (el de ejecución «parado» cuenta aparte). */
export const GRAPH_STATUS_FILTERS = [
  'active',
  'stopped',
  'missing',
  'pending_enrollment',
  'retired',
] as const;
export type GraphStatusFilter = (typeof GRAPH_STATUS_FILTERS)[number];

export const GRAPH_STATUS_LABELS: Record<GraphStatusFilter, string> = {
  active: 'En marcha / activo',
  stopped: 'Parado',
  missing: 'Desaparecido',
  pending_enrollment: 'Pendiente de alta',
  retired: 'Retirado',
};

export function statusFilterOf(node: GraphNode): GraphStatusFilter {
  if (node.status !== 'active') return node.status;
  return node.runtimeState === 'stopped' ? 'stopped' : 'active';
}

export interface GraphElementOptions {
  /** Dibujar cada nodo dentro de su padre (`parentId`): la topología. */
  compound?: boolean;
  /** Tipos que no se muestran. */
  hiddenTypes?: ReadonlySet<AssetType>;
  /** Estados que se muestran (todos si no se indica). */
  statuses?: ReadonlySet<GraphStatusFilter>;
  /** Atenuar lo que no tiene (ni contiene sin cargar) CVE críticos. */
  highlightCritical?: boolean;
}

export function hiddenTotal(node: GraphNode): number {
  return Object.values(node.hidden).reduce((a, b) => a + (b ?? 0), 0);
}

const PLURALS: Partial<Record<AssetType, [string, string]>> = {
  container: ['contenedor', 'contenedores'],
  volume: ['volumen', 'volúmenes'],
  network: ['red', 'redes'],
  image: ['imagen', 'imágenes'],
  lxc: ['CT', 'CT'],
  vm: ['VM', 'VM'],
  domain: ['dominio', 'dominios'],
  dns_record: ['registro DNS', 'registros DNS'],
  database: ['base de datos', 'bases de datos'],
  certificate: ['certificado', 'certificados'],
  subscription: ['suscripción', 'suscripciones'],
};

/** «3 contenedores · 1 volumen · 1 red» (lo que hay sin cargar), con los críticos. */
export function hiddenSummary(node: GraphNode): string {
  const parts = Object.entries(node.hidden)
    .filter(([, n]) => n)
    .map(([type, n]) => {
      const [one, many] = PLURALS[type as AssetType] ?? [
        ASSET_TYPE_LABELS[type as AssetType].toLowerCase(),
        ASSET_TYPE_LABELS[type as AssetType].toLowerCase(),
      ];
      return `${n} ${n === 1 ? one : many}`;
    });
  if (node.hiddenCritical)
    parts.push(
      `${node.hiddenCritical} ${node.hiddenCritical === 1 ? 'crítica' : 'críticas'}`,
    );
  return parts.join(' · ');
}

/**
 * Elementos de Cytoscape a partir del grafo de la API, con los filtros aplicados. Un nodo filtrado
 * se lleva sus aristas; si era un grupo, sus hijos quedan sueltos.
 */
export function toElements(
  graph: AssetGraph,
  options: GraphElementOptions = {},
): ElementDefinition[] {
  const kept = graph.nodes.filter(
    (n) =>
      n.id === graph.centerId ||
      (!options.hiddenTypes?.has(n.type) &&
        (!options.statuses || options.statuses.has(statusFilterOf(n)))),
  );
  const keptIds = new Set(kept.map((n) => n.id));
  const parentOf = new Map(kept.map((n) => [n.id, n.parentId]));
  const groups = new Set(
    options.compound
      ? kept.flatMap((n) =>
          n.parentId && keptIds.has(n.parentId) ? [n.parentId] : [],
        )
      : [],
  );

  // Con «resaltar críticas», lo que tiene críticos y los grupos que lo contienen.
  const hot = new Set<string>();
  if (options.highlightCritical)
    for (const n of kept) {
      if (!n.critical && !n.hiddenCritical) continue;
      for (let id: string | null = n.id; id && !hot.has(id); ) {
        hot.add(id);
        id = parentOf.get(id) ?? null;
      }
    }
  const dim = (id: string) => options.highlightCritical && !hot.has(id);

  // Camino de un registro DNS hasta el servicio (QoL-5b): sus nodos y las aristas entre eslabones
  // seguidos (y «servido por» desde el registro), resaltados.
  const path = graph.servicePath ?? [];
  const onPath = new Set(path.length > 1 ? path : []);
  const steps = new Set(path.slice(1).map((id, i) => `${path[i]}>${id}`));
  // Solo las aristas del tráfico: «contiene» entre dos eslabones seguidos no es el camino.
  const pathEdge = (e: AssetGraph['edges'][number]) =>
    (e.type !== 'contains' && steps.has(`${e.source}>${e.target}`)) ||
    (e.type === 'served_by' && e.source === path[0] && onPath.has(e.target));

  const nodes: ElementDefinition[] = kept.map((n) => {
    const total = hiddenTotal(n);
    const summary = total || n.hiddenCritical ? hiddenSummary(n) : '';
    const classes = [
      `type-${n.type}`,
      `status-${statusFilterOf(n)}`,
      n.id === graph.centerId ? 'center' : '',
      n.critical ? 'critical' : '',
      groups.has(n.id) ? 'group' : '',
      dim(n.id) ? 'dim' : '',
      onPath.has(n.id) ? 'on-path' : '',
    ].filter(Boolean);
    const label = options.compound
      ? summary
        ? `${n.name}\n${summary}`
        : n.name
      : total
        ? `${n.name}\n+${total} más`
        : n.name;
    return {
      group: 'nodes',
      data: {
        id: n.id,
        label,
        type: n.type,
        depth: n.depth,
        ...(options.compound && n.parentId && keptIds.has(n.parentId)
          ? { parent: n.parentId }
          : {}),
      },
      classes,
    };
  });
  const edges: ElementDefinition[] = graph.edges
    .filter((e) => keptIds.has(e.source) && keptIds.has(e.target))
    // En la topología, «contiene» ya lo dice el grupo.
    .filter(
      (e) =>
        !(
          options.compound &&
          e.type === 'contains' &&
          parentOf.get(e.target) === e.source
        ),
    )
    .map((e) => ({
      group: 'edges',
      data: {
        id: `e:${e.id}`,
        source: e.source,
        target: e.target,
        type: e.type,
        label:
          e.count > 1
            ? `${RELATION_LABELS[e.type]} ×${e.count}`
            : RELATION_LABELS[e.type],
      },
      classes: [
        `rel-${e.type}`,
        dim(e.source) || dim(e.target) ? 'dim' : '',
        pathEdge(e) ? 'on-path' : '',
      ]
        .filter(Boolean)
        .join(' '),
    }));
  return [...nodes, ...edges];
}

/** Colores ya resueltos del tema (claro u oscuro) para el estilo del lienzo. */
export interface GraphPalette {
  text: string;
  muted: string;
  surface: string;
  groupBackground: string;
  border: string;
  primary: string;
  danger: string;
  warn: string;
  types: Record<AssetType, string>;
}

/** Lee los tokens de OptimusNG del documento (cambian con el modo claro/oscuro). */
export function readPalette(dark: boolean, el: Element): GraphPalette {
  const css = getComputedStyle(el);
  const v = (name: string, fallback: string) =>
    css.getPropertyValue(name).trim() || fallback;
  const shade = dark ? 400 : 500;
  return {
    text: v('--p-text-color', dark ? '#e5e7eb' : '#1f2937'),
    muted: v('--p-text-muted-color', '#6b7280'),
    surface: v('--p-content-background', dark ? '#18181b' : '#ffffff'),
    groupBackground: v('--p-app-background', dark ? '#09090b' : '#f8fafc'),
    border: v('--p-content-border-color', dark ? '#3f3f46' : '#e2e8f0'),
    primary: v('--p-primary-color', '#14b8a6'),
    danger: v('--p-app-danger-color', '#dc2626'),
    warn: v('--p-app-warn-color', '#ea580c'),
    types: Object.fromEntries(
      Object.entries(ASSET_TYPE_COLORS).map(([type, color]) => [
        type,
        v(`--p-${color}-${shade}`, '#64748b'),
      ]),
    ) as Record<AssetType, string>,
  };
}

/** Hoja de estilo de Cytoscape para la paleta dada. */
export function graphStylesheet(p: GraphPalette): StylesheetJson {
  const typeRules = (Object.keys(p.types) as AssetType[]).map((type) => ({
    selector: `node.type-${type}`,
    style: {
      'background-color': p.types[type],
      'background-image': assetTypeIconUri(type, '#ffffff'),
    },
  }));
  return [
    {
      selector: 'node',
      style: {
        shape: 'round-rectangle',
        width: 34,
        height: 34,
        'background-image-containment': 'inside',
        'background-width': '58%',
        'background-height': '58%',
        'border-width': 0,
        label: 'data(label)',
        color: p.text,
        'font-size': 11,
        'font-family': 'Inter, system-ui, sans-serif',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 5,
        'text-wrap': 'wrap',
        'text-max-width': '140px',
        'text-background-color': p.surface,
        'text-background-opacity': 0.85,
        'text-background-padding': '2px',
        'text-background-shape': 'round-rectangle',
        'min-zoomed-font-size': 7,
      },
    },
    ...typeRules,
    {
      selector: 'node.center',
      style: {
        width: 46,
        height: 46,
        'font-weight': 'bold',
        'font-size': 12,
        'border-width': 3,
        'border-color': p.primary,
        'border-style': 'double',
      },
    },
    {
      selector: 'node.status-stopped',
      style: { 'background-opacity': 0.55 },
    },
    {
      selector: 'node.status-missing, node.status-retired',
      style: {
        'background-opacity': 0.35,
        'border-width': 2,
        'border-style': 'dashed',
        'border-color': p.muted,
        color: p.muted,
      },
    },
    {
      selector: 'node.critical',
      style: {
        'border-width': 3,
        'border-style': 'solid',
        'border-color': p.danger,
        'outline-width': 2,
        'outline-color': p.danger,
        'outline-opacity': 0.35,
        'outline-offset': 2,
      },
    },
    {
      selector: 'node.group',
      style: {
        shape: 'round-rectangle',
        'background-color': p.groupBackground,
        'background-opacity': 0.6,
        'background-image': 'none',
        'border-width': 1.5,
        'border-style': 'solid',
        'border-color': p.border,
        'text-valign': 'top',
        'text-halign': 'center',
        'text-margin-y': -4,
        'font-weight': 'bold',
        padding: '14px',
      },
    },
    {
      selector: 'node.group.critical',
      style: { 'border-color': p.danger, 'border-width': 2 },
    },
    {
      selector: 'edge',
      style: {
        width: 1.5,
        'curve-style': 'bezier',
        'line-color': p.border,
        'target-arrow-color': p.border,
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.8,
        label: 'data(label)',
        'font-size': 9,
        color: p.muted,
        'text-rotation': 'autorotate',
        'text-background-color': p.surface,
        'text-background-opacity': 0.9,
        'text-background-padding': '1px',
        'min-zoomed-font-size': 8,
      },
    },
    {
      selector: 'edge.rel-contains',
      style: { 'line-style': 'solid', width: 2 },
    },
    {
      selector: 'edge.rel-instance_of',
      style: {
        'line-color': p.types.image,
        'target-arrow-color': p.types.image,
      },
    },
    {
      selector: 'edge.rel-mounts',
      style: {
        'line-color': p.types.volume,
        'target-arrow-color': p.types.volume,
        'line-style': 'dashed',
      },
    },
    {
      selector: 'edge.rel-attached_to',
      style: {
        'line-color': p.types.network,
        'target-arrow-color': p.types.network,
        'line-style': 'dashed',
      },
    },
    {
      selector: 'edge.rel-stores',
      style: { 'line-style': 'dotted' },
    },
    {
      selector: 'edge.rel-resolves_to',
      style: {
        'line-color': p.types.dns_record,
        'target-arrow-color': p.types.dns_record,
        'line-style': 'dashed',
        'line-dash-pattern': [6, 3],
      },
    },
    {
      selector: 'edge.rel-secured_by',
      style: {
        'line-color': p.types.certificate,
        'target-arrow-color': p.types.certificate,
        'line-style': 'dotted',
      },
    },
    {
      selector: 'edge.rel-served_by',
      style: {
        'line-color': p.types.dns_record,
        'target-arrow-color': p.types.dns_record,
        width: 2.5,
      },
    },
    {
      selector: 'edge.rel-routes_to',
      style: {
        'line-color': p.primary,
        'target-arrow-color': p.primary,
        'target-arrow-shape': 'triangle-backcurve',
      },
    },
    { selector: '.dim', style: { opacity: 0.22 } },
    {
      selector: 'edge.on-path',
      style: {
        width: 3.5,
        'line-color': p.primary,
        'target-arrow-color': p.primary,
        'line-style': 'solid',
        'z-index': 10,
      },
    },
    {
      selector: 'node.on-path',
      style: { 'border-color': p.primary, 'border-width': 3 },
    },
    {
      selector: 'node:selected',
      style: {
        'overlay-color': p.primary,
        'overlay-opacity': 0.18,
        'overlay-padding': 6,
      },
    },
  ] as StylesheetJson;
}
