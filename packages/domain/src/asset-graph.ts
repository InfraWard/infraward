import {
  GRAPH_MAX_NEIGHBORS,
  GRAPH_MAX_NODES,
  TOPOLOGY_MAX_NODES,
  type AssetRelationType,
  type AssetType,
  type GraphEdge,
} from '@infraward/shared-types';

/** Relación con el tipo de sus dos extremos (lo que necesita la expansión del mapa). */
export interface GraphRelationRow {
  id: string;
  parentId: string;
  childId: string;
  type: AssetRelationType;
  parentType: AssetType;
  childType: AssetType;
}

/**
 * Orden en que se cargan los vecinos de un nodo cuando hay más que el tope: primero la jerarquía y
 * lo que define a un contenedor (imagen, volúmenes, redes); `stores` (todas las imágenes de un
 * host, las use o no) lo último.
 */
const RELATION_PRIORITY: readonly AssetRelationType[] = [
  'contains',
  'instance_of',
  'mounts',
  'attached_to',
  'served_by',
  'routes_to',
  'secured_by',
  'resolves_to',
  'depends_on',
  'stores',
];

export interface ExpandGraphOptions {
  depth: number;
  maxNeighbors?: number;
  maxNodes?: number;
}

export interface ExpandedGraph {
  /** Id → saltos desde el centro. */
  depths: Map<string, number>;
  edges: GraphEdge[];
  /** Vecinos sin cargar de cada nodo, por tipo (los del borde incluidos: el siguiente salto). */
  hidden: Map<string, Partial<Record<AssetType, number>>>;
  truncated: boolean;
}

/**
 * Recorre las relaciones desde `centerId` en los dos sentidos, salto a salto (`fetchLevel` da las
 * relaciones que tocan a los nodos de un nivel). Cada nodo carga como mucho `maxNeighbors` vecinos
 * nuevos y el grafo, `maxNodes`; lo que no entra se cuenta en `hidden`. Tras el último salto se
 * pide una vez más el borde para unir los nodos ya cargados entre sí y contar lo que queda fuera.
 */
export async function expandGraph(
  centerId: string,
  fetchLevel: (ids: string[]) => Promise<GraphRelationRow[]>,
  options: ExpandGraphOptions,
): Promise<ExpandedGraph> {
  const maxNeighbors = options.maxNeighbors ?? GRAPH_MAX_NEIGHBORS;
  const maxNodes = options.maxNodes ?? GRAPH_MAX_NODES;
  const depths = new Map<string, number>([[centerId, 0]]);
  const edges = new Map<string, GraphEdge>();
  // Nodo → vecinos que no cupieron (con su tipo).
  const left = new Map<string, Map<string, AssetType>>();
  let truncated = false;
  let frontier = [centerId];

  for (let level = 1; level <= options.depth + 1 && frontier.length; level++) {
    const last = level > options.depth;
    const rows = (await fetchLevel(frontier)).toSorted(
      (a, b) =>
        RELATION_PRIORITY.indexOf(a.type) - RELATION_PRIORITY.indexOf(b.type),
    );
    const next: string[] = [];
    for (const id of frontier) {
      const peersSeen = new Set<string>();
      let added = 0;
      for (const row of rows) {
        if (row.parentId !== id && row.childId !== id) continue;
        const outgoing = row.parentId === id;
        const peer = outgoing ? row.childId : row.parentId;
        if (depths.has(peer)) {
          edges.set(row.id, toEdge(row));
          continue;
        }
        if (peersSeen.has(peer)) continue;
        peersSeen.add(peer);
        const full = depths.size >= maxNodes;
        if (!last && !full && added < maxNeighbors) {
          depths.set(peer, level);
          next.push(peer);
          added++;
          edges.set(row.id, toEdge(row));
        } else {
          if (!last && full) truncated = true;
          const peers = left.get(id) ?? new Map<string, AssetType>();
          peers.set(peer, outgoing ? row.childType : row.parentType);
          left.set(id, peers);
        }
      }
    }
    frontier = next;
  }
  // Un vecino que no cupo desde un nodo pudo cargarse luego desde otro: ese ya no está oculto.
  const hidden = new Map<string, Partial<Record<AssetType, number>>>();
  for (const [id, peers] of left) {
    const counts: Partial<Record<AssetType, number>> = {};
    for (const [peer, type] of peers)
      if (!depths.has(peer)) counts[type] = (counts[type] ?? 0) + 1;
    if (Object.keys(counts).length) hidden.set(id, counts);
  }
  return { depths, edges: [...edges.values()], hidden, truncated };
}

function toEdge(row: GraphRelationRow): GraphEdge {
  return {
    id: row.id,
    source: row.parentId,
    target: row.childId,
    type: row.type,
    count: 1,
  };
}

// --- Topología ---

/** Tipos que forman el «nivel host» de la topología bajo una raíz (lo demás es su contenido). */
export const TOPOLOGY_HOST_TYPES: readonly AssetType[] = [
  /** Dominio de un conector: grupo con sus registros y certificados. */
  'domain',
  'server',
  'vm',
  'lxc',
  'subscription',
];

export interface TopologyAsset {
  id: string;
  type: AssetType;
  /** Padre `contains` dentro del conjunto (null en las raíces y en las imágenes). */
  parentId: string | null;
}

export interface TopologyRelation {
  id: string;
  parentId: string;
  childId: string;
  type: AssetRelationType;
}

export interface TopologyInput {
  assets: TopologyAsset[];
  /** Relaciones entre assets del conjunto que no son `contains`. */
  relations: TopologyRelation[];
  /** Findings CRITICAL abiertos por asset (un contenedor, los de su imagen). */
  critical: Map<string, number>;
  /** Assets cuyo contenido se muestra. */
  expand: ReadonlySet<string>;
  maxNodes?: number;
}

export interface TopologyNode {
  id: string;
  /** Grupo en el que se dibuja (su padre `contains`, o el host de una imagen de un solo host). */
  parentId: string | null;
  hidden: Partial<Record<AssetType, number>>;
  hiddenCritical: number;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

/**
 * Qué se ve de la topología: las raíces y sus hijos de tipo host; el contenido de cada asset
 * expandido (hijos `contains` y, en un host Docker, sus imágenes); y las imágenes de los
 * contenedores visibles. Lo que no se ve se resume en su antepasado visible (`hidden`,
 * `hiddenCritical`) y sus relaciones se agregan entre los antepasados visibles.
 */
export function buildTopology(input: TopologyInput): Topology {
  const maxNodes = input.maxNodes ?? TOPOLOGY_MAX_NODES;
  const byId = new Map(input.assets.map((a) => [a.id, a]));
  const children = new Map<string, TopologyAsset[]>();
  for (const a of input.assets) {
    if (!a.parentId || !byId.has(a.parentId)) continue;
    const list = children.get(a.parentId) ?? [];
    list.push(a);
    children.set(a.parentId, list);
  }
  const rootOf = (a: TopologyAsset) => !a.parentId || !byId.has(a.parentId);

  // Árbol visible, por niveles (así el tope deja fuera lo más profundo).
  const visible = new Set<string>();
  let truncated = false;
  const show = (id: string) => {
    if (visible.has(id)) return;
    if (visible.size >= maxNodes) {
      truncated = true;
      return;
    }
    visible.add(id);
  };
  let level = input.assets.filter((a) => a.type !== 'image' && rootOf(a));
  while (level.length) {
    const next: TopologyAsset[] = [];
    for (const a of level) {
      show(a.id);
      if (!visible.has(a.id)) continue;
      for (const child of children.get(a.id) ?? []) {
        const hostLevel = rootOf(a) && TOPOLOGY_HOST_TYPES.includes(child.type);
        if (hostLevel || input.expand.has(a.id)) next.push(child);
      }
    }
    level = next;
  }

  // Imágenes: las de un host expandido (`stores`) y las de los contenedores visibles.
  const imageHosts = new Map<string, Set<string>>();
  for (const r of input.relations) {
    if (r.type !== 'stores' && r.type !== 'instance_of') continue;
    if (byId.get(r.childId)?.type !== 'image') continue;
    const fromExpandedHost =
      r.type === 'stores' && input.expand.has(r.parentId);
    const fromContainer = r.type === 'instance_of' && visible.has(r.parentId);
    if (visible.has(r.parentId) && (fromExpandedHost || fromContainer))
      show(r.childId);
    if (r.type === 'stores') {
      const hosts = imageHosts.get(r.childId) ?? new Set<string>();
      hosts.add(r.parentId);
      imageHosts.set(r.childId, hosts);
    }
  }

  // Antepasado visible más cercano (por `contains`); null si no hay.
  const representative = (id: string): string | null => {
    for (let cur = byId.get(id), n = 0; cur && n < 64; n++) {
      if (visible.has(cur.id)) return cur.id;
      cur = cur.parentId ? byId.get(cur.parentId) : undefined;
    }
    return null;
  };

  const nodes = new Map<string, TopologyNode>();
  for (const id of visible) {
    const asset = byId.get(id)!;
    let parentId =
      asset.parentId && visible.has(asset.parentId) ? asset.parentId : null;
    if (asset.type === 'image') {
      const hosts = [...(imageHosts.get(id) ?? [])];
      const [host] = hosts;
      parentId =
        hosts.length === 1 &&
        host &&
        input.expand.has(host) &&
        visible.has(host)
          ? host
          : null;
    }
    nodes.set(id, { id, parentId, hidden: {}, hiddenCritical: 0 });
  }
  // Contenido oculto: se cuenta en su antepasado visible.
  for (const a of input.assets) {
    if (visible.has(a.id) || a.type === 'image') continue;
    const rep = representative(a.id);
    if (!rep) continue;
    const node = nodes.get(rep)!;
    node.hidden[a.type] = (node.hidden[a.type] ?? 0) + 1;
    node.hiddenCritical += input.critical.get(a.id) ?? 0;
  }
  // Imágenes de un host sin expandir.
  for (const [imageId, hosts] of imageHosts) {
    if (visible.has(imageId)) continue;
    for (const host of hosts) {
      const node = nodes.get(host);
      if (node) node.hidden.image = (node.hidden.image ?? 0) + 1;
    }
  }

  // Relaciones entre lo visible; las de lo oculto, agregadas en sus antepasados visibles.
  const edges = new Map<string, GraphEdge>();
  for (const r of input.relations) {
    if (r.type === 'contains') continue;
    const source =
      byId.get(r.parentId)?.type === 'image'
        ? visible.has(r.parentId)
          ? r.parentId
          : null
        : representative(r.parentId);
    const target =
      byId.get(r.childId)?.type === 'image'
        ? visible.has(r.childId)
          ? r.childId
          : null
        : representative(r.childId);
    if (!source || !target || source === target) continue;
    // La imagen dibujada dentro de su host ya dice que la guarda.
    if (r.type === 'stores' && nodes.get(target)?.parentId === source) continue;
    const real = source === r.parentId && target === r.childId;
    const key = real ? r.id : `${source}:${target}:${r.type}`;
    const edge = edges.get(key);
    if (edge) edge.count++;
    else edges.set(key, { id: key, source, target, type: r.type, count: 1 });
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], truncated };
}
