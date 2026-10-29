import {
  portExposure,
  type AffectedNode,
  type AffectedPackage,
  type AssetStatus,
  type AssetType,
  type ExposedPort,
  type NoiseReason,
  type PriorityInfo,
} from '@infraward/shared-types';
import { runtimeState } from '../assets/tree-extras.js';

/** Lo que el árbol necesita de cada asset (leído con rutas de JSONB concretas). */
export interface TreeAsset {
  id: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
  /** `facts.docker.state` o `facts.proxmox.status`. */
  state: unknown;
  /** `facts.ports` (servidor/CT) o `facts.docker.ports` (contenedor). */
  ports: unknown;
  /** Nombres públicos que sirve o que pasan por él (QoL-5b; hasta 3). */
  public_domains?: string[] | null;
}

export interface AffectedTreeInput {
  assets: ReadonlyMap<string, TreeAsset>;
  /** Hijo → padre `contains`. */
  parents: ReadonlyMap<string, string>;
  /** Paquetes con el CVE de cada dueño de findings (servidor, CT o imagen). */
  packages: ReadonlyMap<string, AffectedPackage[]>;
  /** Imagen → contenedores no retirados que la usan (`instance_of`). */
  containers: ReadonlyMap<string, string[]>;
  /** Imagen → hosts que la guardan (`stores`), para situar las imágenes sin uso. */
  stores: ReadonlyMap<string, string[]>;
  /** Dueño → prioridad de su finding más prioritario de este CVE (y si es ruido). */
  priorities?: ReadonlyMap<
    string,
    { priority: PriorityInfo | null; noiseReason: NoiseReason | null }
  >;
}

/**
 * Árbol de afectados de un CVE con la jerarquía real (nodo → CT → contenedor → imagen):
 * - un servidor o CT con findings es afectado y la acción es actualizar el paquete;
 * - una imagen cuelga, como hoja, de cada contenedor que la usa (el contenedor es afectado a
 *   través de ella) y la acción es reconstruirla; si ningún contenedor activo la usa, cuelga del
 *   host que la guarda, marcada «sin uso»;
 * - los antepasados por `contains` que no tienen el CVE son solo contexto.
 */
export function buildAffectedTree(input: AffectedTreeInput): AffectedNode[] {
  const nodes = new Map<string, AffectedNode>();
  const node = (id: string): AffectedNode | null => {
    const existing = nodes.get(id);
    if (existing) return existing;
    const a = input.assets.get(id);
    if (!a) return null;
    const n = baseNode(a);
    nodes.set(id, n);
    return n;
  };

  for (const [ownerId, packages] of input.packages) {
    const owner = input.assets.get(ownerId);
    if (!owner) continue;
    const priority = input.priorities?.get(ownerId);
    if (owner.type !== 'image') {
      const n = node(ownerId)!;
      n.affected = true;
      n.packages = packages;
      n.action = 'update_package';
      if (priority) Object.assign(n, priority);
      continue;
    }
    const containers = (input.containers.get(ownerId) ?? []).filter((id) =>
      input.assets.has(id),
    );
    const active = containers.some(
      (id) => input.assets.get(id)!.status === 'active',
    );
    for (const id of containers) {
      const c = node(id)!;
      c.affected = true;
      if (priority) Object.assign(c, priority);
      c.children.push(imageLeaf(owner, packages, false, priority));
    }
    if (active) continue;
    // Sin contenedor activo: también bajo los hosts que la guardan, como «sin uso».
    const hosts = (input.stores.get(ownerId) ?? []).filter((id) =>
      input.assets.has(id),
    );
    for (const id of hosts)
      node(id)!.children.push(imageLeaf(owner, packages, true, priority));
    if (!containers.length && !hosts.length)
      nodes.set(`image:${ownerId}`, imageLeaf(owner, packages, true, priority));
  }

  // Subir por `contains` hasta las raíces, creando los nodos de contexto.
  const childOf = new Set<string>();
  for (const id of [...nodes.keys()]) {
    let current = id;
    const seen = new Set([current]);
    for (;;) {
      const parentId = input.parents.get(current);
      if (!parentId || seen.has(parentId)) break;
      const parent = node(parentId);
      if (!parent) break;
      const child = nodes.get(current)!;
      if (!parent.children.includes(child)) parent.children.push(child);
      childOf.add(current);
      seen.add(parentId);
      current = parentId;
    }
  }
  const roots = [...nodes.entries()]
    .filter(([id]) => !childOf.has(id))
    .map(([, n]) => n);
  sortTree(roots);
  return roots;
}

function baseNode(a: TreeAsset): AffectedNode {
  return {
    id: a.id,
    name: a.name,
    type: a.type,
    status: a.status,
    runtimeState: typeof a.state === 'string' && a.state ? runtimeState(a.state) : null,
    affected: false,
    packages: [],
    exposedPorts: exposedPorts(a),
    ...(a.public_domains?.length && { publicDomains: a.public_domains }),
    action: null,
    children: [],
  };
}

function imageLeaf(
  image: TreeAsset,
  packages: AffectedPackage[],
  unused: boolean,
  priority?: { priority: PriorityInfo | null; noiseReason: NoiseReason | null },
): AffectedNode {
  return {
    ...baseNode(image),
    affected: true,
    packages,
    action: 'rebuild_image',
    ...(unused ? { unused: true } : {}),
    ...priority,
  };
}

/**
 * Activos antes que los desaparecidos; luego afectados antes que el contexto, los de más
 * prioridad primero, y por nombre.
 */
function sortTree(list: AffectedNode[]): void {
  list.sort(
    (a, b) =>
      Number(b.status === 'active') - Number(a.status === 'active') ||
      Number(b.affected) - Number(a.affected) ||
      (b.priority?.score ?? -1) - (a.priority?.score ?? -1) ||
      a.name.localeCompare(b.name),
  );
  for (const n of list) sortTree(n.children);
}

/**
 * Puertos por los que se llega desde fuera: en un servidor o CT, los que escuchan fuera de
 * loopback; en un contenedor, los publicados en el host (sin los publicados solo en loopback).
 */
export function exposedPorts(a: Pick<TreeAsset, 'type' | 'ports'>): ExposedPort[] {
  if (!Array.isArray(a.ports)) return [];
  const byKey = new Map<string, ExposedPort>();
  for (const p of a.ports as unknown[]) {
    if (!p || typeof p !== 'object') continue;
    const r = p as Record<string, unknown>;
    let port: unknown, address: string, process: string | null = null;
    if (a.type === 'container') {
      port = r['hostPort'];
      // Publicado sin IP = en todas las interfaces.
      address = typeof r['hostIp'] === 'string' && r['hostIp'] ? r['hostIp'] : '0.0.0.0';
    } else {
      port = r['port'];
      address = typeof r['address'] === 'string' ? r['address'] : '';
      process = typeof r['process'] === 'string' ? r['process'] : null;
    }
    if (typeof port !== 'number' || portExposure(address) === 'local') continue;
    const proto = typeof r['proto'] === 'string' ? r['proto'] : 'tcp';
    const key = `${port}/${proto}/${process ?? ''}`;
    const prev = byKey.get(key);
    // De IPv4 e IPv6 queda una fila; la de todas las interfaces si la hay.
    if (!prev || (portExposure(address) === 'all' && portExposure(prev.address) !== 'all'))
      byKey.set(key, { port, proto, address, process });
  }
  return [...byKey.values()].sort(
    (x, y) => x.port - y.port || x.proto.localeCompare(y.proto),
  );
}
