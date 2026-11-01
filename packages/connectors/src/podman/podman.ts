import type {
  AssetRelationType,
  AssetType,
  DockerContainerFacts,
} from '@infraward/shared-types';
import {
  DiscoveryError,
  type DiscoveryListing,
  type DiscoveryParent,
  type Discoverer,
  type HostCommandResult,
  type HostExec,
  type HostImage,
} from '../discoverer.js';
import {
  EngineLister,
  type ContainerEngine,
  type EngineQueries,
} from '../docker/docker.js';
import { isSudoDenial, QUERY_ARG } from '../privileged.js';
import { parsePodmanUsers, type PodmanUser } from './podman-users.js';

export * from './formats.js';
export * from './podman-users.js';

/** Dueño de lo que corre como root en las claves naturales (un usuario rootless nunca es root). */
const ROOTFUL = 'root';

/**
 * Clave natural de un contenedor de Podman (§8): host + dueño (`root` o el usuario rootless) +
 * nombre. Distinta de la de Docker: un host puede tener los dos motores.
 */
export function podmanNaturalKey(
  hostAssetId: string,
  owner: string,
  name: string,
): string {
  return `podman:${hostAssetId}:${owner}:${name}`;
}

export function podmanVolumeKey(
  hostAssetId: string,
  owner: string,
  name: string,
): string {
  return `podman-volume:${hostAssetId}:${owner}:${name}`;
}

export function podmanNetworkKey(
  hostAssetId: string,
  owner: string,
  name: string,
): string {
  return `podman-network:${hostAssetId}:${owner}:${name}`;
}

const PODMAN_QUERIES: EngineQueries = {
  ps: 'podman-ps',
  inspect: 'podman-inspect-containers',
  images: 'podman-images',
  imageInspect: 'podman-image-inspect',
  volumes: 'podman-volumes',
  volumeInspect: 'podman-volume-inspect',
  networks: 'podman-networks',
  networkInspect: 'podman-network-inspect',
  nginxRoutes: 'podman-nginx-routes',
};

/** Nombre de unidad de systemd (`web.service`, `app-pod.service`). */
const SYSTEMD_UNIT = /^[A-Za-z0-9:_.@-]{1,255}$/;
const POD_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/;

/**
 * Descubridor de Podman (DESIGN §8, sudoers v8). Lo mismo que `DockerDiscoverer` (contenedores en
 * marcha y parados, volúmenes, redes, imágenes del host y rutas de nginx), con las consultas
 * `podman-*` del ayudante y en varios ámbitos:
 * - rootful: el CLI `podman` como root (Podman no tiene demonio: no hace falta `podman.socket`
 *   ni el CLI de Docker; con o sin `podman-docker`);
 * - rootless: cada usuario de `/etc/infraward/podman-users` por SU socket, en modo remoto y solo
 *   con consultas de lectura. Sus hijos llevan `rootlessUser` y el usuario delante del nombre.
 * Los contenedores de un pod llevan el nombre del pod y el contenedor «infra» del pod no se
 * inventaría; los de Quadlet (o `podman generate systemd`), su unidad de systemd. Si un usuario de
 * la lista no responde, el listado deja de ser completo (nada suyo pasa a `missing`).
 */
export class PodmanDiscoverer implements Discoverer {
  readonly role = 'podman-host';
  readonly childTypes: readonly AssetType[] = [
    'container',
    'volume',
    'network',
  ];
  readonly linkTypes: readonly AssetRelationType[] = ['mounts', 'attached_to'];

  constructor(private readonly now: () => Date = () => new Date()) {}

  async discover(
    parent: DiscoveryParent,
    host: HostExec,
  ): Promise<DiscoveryListing> {
    const warnings: string[] = [];
    let complete = true;

    // Rootful primero: si no responde, el descubridor falla (como Docker sin `docker ps`).
    const listings = [await this.listScope(parent, host, null, warnings)];

    const users = await host.query({ name: 'podman-users' });
    if (users.code !== 0) {
      // Sin la lista no se sabe qué rootless había: nada pasa a `missing`.
      complete = false;
      if (!isSudoDenial(users.stderr, users.code))
        warnings.push(`no se pudo leer la lista de usuarios de Podman${failure(users)}`);
    }
    for (const user of users.code === 0 ? parsePodmanUsers(users.stdout).users : []) {
      if (!user.socket) {
        complete = false;
        warnings.push(
          `Podman rootless de ${user.name}: sin socket activo, sus contenedores no se ven (vuelve a habilitarlo desde la ficha)`,
        );
        continue;
      }
      try {
        listings.push(await this.listScope(parent, host, user, warnings));
      } catch (error) {
        if (!(error instanceof DiscoveryError)) throw error;
        complete = false;
        warnings.push(error.message);
      }
    }
    return merge(listings, complete, warnings);
  }

  collectTarget(): { target: null; reason: string } {
    return {
      target: null,
      reason:
        'Los contenedores, volúmenes y redes no se recogen con Ansible: sus datos vienen del host Podman',
    };
  }

  /** Un ámbito (root o un usuario rootless): sus pods y, con ellos, el listado. */
  private async listScope(
    parent: DiscoveryParent,
    host: HostExec,
    user: PodmanUser | null,
    warnings: string[],
  ): Promise<DiscoveryListing> {
    const scope = user ? String(user.uid) : ROOTFUL;
    const pods = new Map<string, string>();
    const r = await host.query({ name: 'podman-pods', args: [scope] });
    if (r.code === 0) {
      for (const line of r.stdout.split('\n')) {
        const e = parseObject(line.trim());
        if (
          e &&
          typeof e.id === 'string' &&
          QUERY_ARG.containerId.test(e.id) &&
          typeof e.name === 'string' &&
          POD_NAME.test(e.name)
        )
          pods.set(e.id, e.name);
      }
    } else if (!isSudoDenial(r.stderr, r.code))
      warnings.push(`${label(user)} pod ps falló${failure(r)}`);
    return new EngineLister(podmanEngine(parent.id, user, pods), this.now).list(
      host,
    );
  }
}

function label(user: PodmanUser | null): string {
  return user ? `podman (${user.name})` : 'podman';
}

/** Un ámbito de Podman como motor de `EngineLister`. */
export function podmanEngine(
  hostAssetId: string,
  user: PodmanUser | null,
  pods: ReadonlyMap<string, string> = new Map(),
): ContainerEngine {
  const owner = user?.name ?? ROOTFUL;
  return {
    title: user ? `Podman de ${user.name}` : 'Podman',
    label: label(user),
    queries: PODMAN_QUERIES,
    args: [user ? String(user.uid) : ROOTFUL],
    containerKey: (name) => podmanNaturalKey(hostAssetId, owner, name),
    volumeKey: (name) => podmanVolumeKey(hostAssetId, owner, name),
    networkKey: (name) => podmanNetworkKey(hostAssetId, owner, name),
    childName: (name) => (user ? `${user.name}/${name}` : name),
    marker: {
      engine: 'podman',
      ...(user && { rootlessUser: user.name, rootlessUid: user.uid }),
    },
    // El contenedor «infra» de un pod solo sostiene sus namespaces (imagen de pausa).
    skip: (raw) => raw.infra === true,
    extra: (raw) => {
      const out: Partial<DockerContainerFacts> = {};
      const pod = typeof raw.pod === 'string' ? pods.get(raw.pod) : undefined;
      if (pod) out.pod = pod;
      if (typeof raw.systemdUnit === 'string' && SYSTEMD_UNIT.test(raw.systemdUnit))
        out.systemdUnit = raw.systemdUnit;
      return out;
    },
  };
}

/** Junta los listados de los ámbitos (las claves naturales llevan el dueño: no se pisan). */
function merge(
  listings: DiscoveryListing[],
  complete: boolean,
  warnings: string[],
): DiscoveryListing {
  const images = new Map<string, HostImage>();
  let imagesComplete = true;
  for (const l of listings) {
    for (const i of l.hostImages?.images ?? [])
      if (!images.has(i.imageId)) images.set(i.imageId, i);
    imagesComplete &&= l.hostImages?.complete === true;
  }
  return {
    children: listings.flatMap((l) => l.children),
    seen: new Set(listings.flatMap((l) => [...l.seen])),
    complete: complete && listings.every((l) => l.complete),
    partialTypes: [...new Set(listings.flatMap((l) => l.partialTypes ?? []))],
    links: listings.flatMap((l) => l.links ?? []),
    // Una imagen que solo está en el almacén de un usuario que no respondió no se da por borrada.
    hostImages: { images: [...images.values()], complete: imagesComplete && complete },
    warnings: [...listings.flatMap((l) => l.warnings), ...warnings],
  };
}

function parseObject(line: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(line);
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function failure(result: HostCommandResult): string {
  if (result.code === null) return ' (tiempo agotado)';
  const line = result.stderr.trim().split('\n').at(-1);
  return ` (código ${result.code})${line ? `: ${line.slice(0, 200)}` : ''}`;
}
