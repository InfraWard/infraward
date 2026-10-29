import type {
  AssetType,
  ProxmoxGuestFacts,
  ProxmoxInterface,
} from '@infraward/shared-types';
import {
  DiscoveryError,
  seenKey,
  type ChildAsset,
  type CollectTarget,
  type DiscoveredAsset,
  type Discoverer,
  type DiscoveryListing,
  type DiscoveryParent,
  type HostCommandResult,
  type HostExec,
} from '../discoverer.js';
import {
  expandQuery,
  QueryRejectedError,
  type PrivilegedQuery,
} from '../privileged.js';

/** Nombres de nodo y clúster de Proxmox (van en argumentos de pvesh y en claves naturales). */
const NODE_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const CLUSTER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MACHINE_ID = /^[0-9a-f]{32}$/;
/** Proxmox admite vmid de 100 a 999999999. */
const isVmid = (v: unknown): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= 100 && v <= 999_999_999;

/**
 * Claves de la configuración de un guest que nunca se guardan: contraseñas y claves de
 * cloud-init (`cipassword` es un hash, `sshkeys`), tokens y la descripción (notas libres de la
 * UI de Proxmox, donde la gente apunta contraseñas).
 */
const SENSITIVE_CONFIG_KEY = /pass|secret|token|key|cred|^description$/i;
/** Ruido que cambia en cada lectura. */
const NOISY_CONFIG_KEY = /^digest$/;

export type ProxmoxGuestKind = 'lxc' | 'qemu';

export interface ProxmoxClusterStatus {
  localNode: string;
  /** null en un nodo sin clúster. */
  cluster: string | null;
}

/** Entrada de `pvesh get /cluster/resources --type vm`. */
export interface ProxmoxResource {
  kind: ProxmoxGuestKind;
  vmid: number;
  node: string;
  name: string | null;
  status: string;
  template: boolean;
  maxcpu: number | null;
  maxmem: number | null;
  maxdisk: number | null;
  uptime: number | null;
  tags: string[];
}

/**
 * Clave natural de un CT o VM (§8): ID de clúster + vmid. En un nodo sin clúster, el machine-id
 * del nodo hace de ID de clúster.
 */
export function proxmoxNaturalKey(
  scope: { cluster: string | null; machineId: string },
  vmid: number,
): string {
  return scope.cluster
    ? `proxmox:cluster:${scope.cluster}:${vmid}`
    : `proxmox:node:${scope.machineId}:${vmid}`;
}

/** Nodo local y nombre del clúster a partir de `pvesh get /cluster/status`. */
export function parseClusterStatus(json: string): ProxmoxClusterStatus {
  const entries = parseJsonArray(json, '/cluster/status');
  const local = entries.find(
    (e) => e.type === 'node' && (e.local === 1 || e.local === true),
  );
  if (!local || typeof local.name !== 'string' || !NODE_NAME.test(local.name))
    throw new DiscoveryError(
      'pvesh no indica el nodo local en /cluster/status',
    );
  const cluster = entries.find((e) => e.type === 'cluster');
  let clusterName: string | null = null;
  if (cluster) {
    if (typeof cluster.name !== 'string' || !CLUSTER_NAME.test(cluster.name))
      throw new DiscoveryError('Nombre de clúster de Proxmox no válido');
    clusterName = cluster.name;
  }
  return { localNode: local.name, cluster: clusterName };
}

/**
 * CT y VMs de `pvesh get /cluster/resources --type vm`. Las entradas que no se entienden se
 * descartan con un aviso (y el listado deja de considerarse completo).
 */
export function parseClusterResources(json: string): {
  resources: ProxmoxResource[];
  invalid: number;
} {
  const entries = parseJsonArray(json, '/cluster/resources');
  const resources: ProxmoxResource[] = [];
  let invalid = 0;
  for (const e of entries) {
    if (e.type !== 'lxc' && e.type !== 'qemu') continue;
    if (
      !isVmid(e.vmid) ||
      typeof e.node !== 'string' ||
      !NODE_NAME.test(e.node)
    ) {
      invalid++;
      continue;
    }
    resources.push({
      kind: e.type,
      vmid: e.vmid,
      node: e.node,
      name: typeof e.name === 'string' && e.name ? e.name.slice(0, 255) : null,
      status: typeof e.status === 'string' ? e.status : 'unknown',
      template: e.template === 1 || e.template === true,
      maxcpu: num(e.maxcpu),
      maxmem: num(e.maxmem),
      maxdisk: num(e.maxdisk),
      uptime: num(e.uptime),
      tags:
        typeof e.tags === 'string'
          ? e.tags.split(/[;,\s]+/).filter(Boolean)
          : [],
    });
  }
  return { resources, invalid };
}

/** Configuración de un guest sin contraseñas, claves, tokens ni notas libres. */
export function sanitizeGuestConfig(
  config: Record<string, unknown>,
): Record<string, string | number> {
  const clean: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(config)) {
    if (SENSITIVE_CONFIG_KEY.test(key) || NOISY_CONFIG_KEY.test(key)) continue;
    if (typeof value === 'string' || typeof value === 'number')
      clean[key] = value;
  }
  return clean;
}

/** Interfaces de `pvesh get /nodes/<n>/lxc/<vmid>/interfaces` (formato antiguo y nuevo). */
export function parseInterfaces(json: string): ProxmoxInterface[] {
  const entries = parseJsonArray(json, 'interfaces');
  return entries
    .filter((e) => typeof e.name === 'string' && e.name !== 'lo')
    .map((e) => {
      const ipv4: string[] = [];
      const ipv6: string[] = [];
      if (typeof e.inet === 'string') ipv4.push(e.inet);
      if (typeof e.inet6 === 'string') ipv6.push(e.inet6);
      const addresses = e['ip-addresses'];
      if (Array.isArray(addresses)) {
        for (const a of addresses as Record<string, unknown>[]) {
          const ip = a['ip-address'];
          if (typeof ip !== 'string') continue;
          const cidr =
            a.prefix !== undefined ? `${ip}/${String(a.prefix)}` : ip;
          // PVE 9 usa `inet`/`inet6`; el agente de QEMU, `ipv4`/`ipv6`. Ante la duda, por la forma.
          const kind = String(a['ip-address-type'] ?? '');
          const v6 = /6$/.test(kind) || (!kind && ip.includes(':'));
          (v6 ? ipv6 : ipv4).push(cidr);
        }
      }
      const mac = typeof e.hwaddr === 'string' ? e.hwaddr : null;
      return {
        name: e.name as string,
        mac,
        ipv4: [...new Set(ipv4)],
        ipv6: [...new Set(ipv6)],
      };
    });
}

/**
 * Descubridor de Proxmox (§8): lista los CT y VMs del nodo con `pvesh get` (consultas `pve-*` del
 * ayudante de root, rutas fijas) y los recoge desde el nodo con `pct exec`.
 */
export class ProxmoxDiscoverer implements Discoverer {
  readonly role = 'proxmox-node';
  readonly childTypes: readonly AssetType[] = ['lxc', 'vm'];

  constructor(private readonly now: () => Date = () => new Date()) {}

  async discover(
    parent: DiscoveryParent,
    host: HostExec,
  ): Promise<DiscoveryListing> {
    const machineId = parent.facts.machineId;
    if (typeof machineId !== 'string' || !MACHINE_ID.test(machineId))
      throw new DiscoveryError(
        'El nodo no tiene machine-id: recógelo antes de descubrir sus CT y VMs',
      );
    const warnings: string[] = [];
    const status = parseClusterStatus(
      await pvesh(host, { name: 'pve-cluster-status' }, true),
    );
    const { resources, invalid } = parseClusterResources(
      await pvesh(host, { name: 'pve-cluster-resources' }, true),
    );
    if (invalid)
      warnings.push(
        `${invalid} entradas de /cluster/resources no válidas: no se marca nada como desaparecido`,
      );

    const scope = { cluster: status.cluster, machineId };
    const discoveredAt = this.now().toISOString();
    const seen = new Set<string>();
    const children: DiscoveredAsset[] = [];
    for (const r of resources) {
      const type: AssetType = r.kind === 'lxc' ? 'lxc' : 'vm';
      const naturalKey = proxmoxNaturalKey(scope, r.vmid);
      seen.add(seenKey(type, naturalKey));
      if (r.node !== status.localNode) continue;

      const guest = [r.node, String(r.vmid)];
      let config: ProxmoxGuestFacts['config'] = null;
      try {
        config = sanitizeGuestConfig(
          parseJsonObject(
            await pvesh(host, {
              name: 'pve-guest-config',
              args: [r.kind, ...guest],
            }),
            'config',
          ),
        );
      } catch (error) {
        warnings.push(`${r.kind} ${r.vmid}: ${describe(error)}`);
      }
      let interfaces: ProxmoxInterface[] | null = null;
      if (r.kind === 'lxc' && r.status === 'running') {
        try {
          interfaces = parseInterfaces(
            await pvesh(host, { name: 'pve-lxc-interfaces', args: guest }),
          );
        } catch (error) {
          warnings.push(`lxc ${r.vmid}: ${describe(error)}`);
        }
      }

      const proxmox: ProxmoxGuestFacts = {
        vmid: r.vmid,
        kind: r.kind,
        node: r.node,
        cluster: status.cluster,
        status: r.status,
        template: r.template,
        cpus: r.maxcpu,
        maxMemBytes: r.maxmem,
        maxDiskBytes: r.maxdisk,
        uptime: r.uptime,
        tags: r.tags,
        config,
        interfaces,
        discoveredAt,
      };
      children.push({
        type,
        name: r.name ?? `${r.kind}-${r.vmid}`,
        naturalKey,
        // Nodo que se ha unido a un clúster: sus CT se guardaron con la clave del nodo.
        aliases: status.cluster
          ? [proxmoxNaturalKey({ cluster: null, machineId }, r.vmid)]
          : [],
        facts: { proxmox },
        collect: r.kind === 'lxc' && r.status === 'running' && !r.template,
      });
    }
    return { children, seen, complete: invalid === 0, warnings };
  }

  collectTarget(
    child: ChildAsset,
  ): { target: CollectTarget } | { target: null; reason: string } {
    const proxmox = child.facts.proxmox as
      Partial<ProxmoxGuestFacts> | undefined;
    if (child.type === 'vm')
      return {
        target: null,
        reason:
          'Las VMs solo tienen los datos de Proxmox: no se recogen por dentro',
      };
    if (child.type !== 'lxc' || !proxmox || !isVmid(proxmox.vmid))
      return {
        target: null,
        reason: 'El asset no es un CT descubierto en un nodo Proxmox',
      };
    if (proxmox.template)
      return { target: null, reason: 'El CT es una plantilla' };
    if (proxmox.status !== 'running')
      return {
        target: null,
        reason: `El CT no está en marcha (${String(proxmox.status)})`,
      };
    return { target: { kind: 'pct', vmid: proxmox.vmid } };
  }
}

/** `pvesh get … --output-format json` por el ayudante; un fallo es un `DiscoveryError`. */
async function pvesh(
  host: HostExec,
  query: PrivilegedQuery,
  required = false,
): Promise<string> {
  let path: string;
  try {
    path = expandQuery(query)[2] ?? query.name;
  } catch (error) {
    if (error instanceof QueryRejectedError)
      throw new DiscoveryError(
        `Consulta de pvesh no válida (${error.message})`,
      );
    throw error;
  }
  const result = await host.query(query);
  if (result.code !== 0)
    throw new DiscoveryError(
      `${required ? 'No se pudo listar Proxmox: ' : ''}pvesh get ${path} falló${failure(result)}`,
    );
  return result.stdout;
}

function failure(result: HostCommandResult): string {
  if (result.code === null) return ' (tiempo agotado)';
  const line = result.stderr
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .at(-1);
  return ` (código ${result.code})${line ? `: ${line.slice(0, 200)}` : ''}`;
}

function describe(error: unknown): string {
  return error instanceof DiscoveryError ? error.message : 'error inesperado';
}

function parseJsonArray(json: string, what: string): Record<string, unknown>[] {
  const parsed = parseJson(json, what);
  if (!Array.isArray(parsed))
    throw new DiscoveryError(`Respuesta de pvesh no válida (${what})`);
  return parsed.filter(
    (e): e is Record<string, unknown> => typeof e === 'object' && e !== null,
  );
}

function parseJsonObject(json: string, what: string): Record<string, unknown> {
  const parsed = parseJson(json, what);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
    throw new DiscoveryError(`Respuesta de pvesh no válida (${what})`);
  return parsed as Record<string, unknown>;
}

function parseJson(json: string, what: string): unknown {
  try {
    return JSON.parse(json);
  } catch {
    throw new DiscoveryError(`Respuesta de pvesh no es JSON (${what})`);
  }
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
