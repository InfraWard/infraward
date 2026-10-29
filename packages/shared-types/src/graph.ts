// Contratos de los grafos de relaciones (DESIGN §5 y §15, QoL-4): mapa de un asset y topología.
import type {
  AssetRelationType,
  AssetRuntimeState,
  AssetSummary,
  AssetType,
} from './assets.js';
import type { Severity } from './findings.js';

/** Saltos que puede recorrer el mapa de un asset. */
export const GRAPH_MAX_DEPTH = 3;
/** Vecinos nuevos que se cargan como mucho desde cada nodo del mapa (el resto, en `hidden`). */
export const GRAPH_MAX_NEIGHBORS = 25;
/** Nodos como mucho en el mapa de un asset. */
export const GRAPH_MAX_NODES = 150;
/** Nodos como mucho en una respuesta de la topología. */
export const TOPOLOGY_MAX_NODES = 500;

/**
 * Nodo resumido de un grafo: nunca facts, conexión ni credenciales (lo mismo que el árbol).
 */
export interface GraphNode extends AssetSummary {
  address: string | null;
  runtimeState: AssetRuntimeState | null;
  /** Findings CRITICAL abiertos (un contenedor cuenta los de su imagen). */
  critical: number;
  /** Severidad máxima abierta, o null. */
  maxSeverity: Severity | null;
  /** Padre `contains` si también está en el grafo (agrupa por host en la topología). */
  parentId: string | null;
  /** Mapa: saltos desde el centro. Topología: 0. */
  depth: number;
  /**
   * Vecinos (mapa) o descendientes (topología) que no se han cargado, por tipo: el nodo dibuja
   * «+N». Vacío si no queda nada por cargar.
   */
  hidden: Partial<Record<AssetType, number>>;
  /** Topología: CRITICAL abiertos de lo que tiene debajo sin cargar. */
  hiddenCritical: number;
}

export interface GraphEdge {
  /** Id de la relación, o `<origen>:<destino>:<tipo>` en las agregadas. */
  id: string;
  /** Origen (el `parent` de la relación). */
  source: string;
  target: string;
  type: AssetRelationType;
  /** Relaciones reales que representa (> 1 si se agregaron entre grupos de la topología). */
  count: number;
}

export interface AssetGraph {
  /** Mapa: el asset del centro. */
  centerId: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Se llegó al tope de nodos: hay más de lo que se muestra. */
  truncated: boolean;
  /**
   * Mapa de un registro DNS: los assets de su camino hasta el que lo sirve, en orden y empezando
   * por el registro (QoL-5b). Siempre están en `nodes`, aunque queden lejos del centro.
   */
  servicePath?: string[];
}

export interface AssetGraphQuery {
  depth?: number;
  includeRetired?: boolean;
}

export interface TopologyQuery {
  projectId?: string;
  /** Solo el subárbol `contains` de este asset. */
  rootId?: string;
  /** Assets cuyo contenido se carga (además del nivel host). */
  expand?: string[];
  includeRetired?: boolean;
}
