import {
  byCodeUnit,
  type AssetRelationType,
  type AssetType,
  type DockerContainerFacts,
  type DockerContainerNetwork,
  type DockerMount,
  type DockerNetworkFacts,
  type DockerNetworkSubnet,
  type DockerPortBinding,
  type DockerVolumeFacts,
} from '@infraward/shared-types';
import {
  DiscoveryError,
  seenKey,
  type DiscoveredAsset,
  type DiscoveredLink,
  type Discoverer,
  type DiscoveryListing,
  type DiscoveryParent,
  type HostCommandResult,
  type HostExec,
  type HostImage,
} from '../discoverer.js';
import { nginxImageKind, parseProxyLabels, proxyLabelPairs } from '../proxies/labels.js';
import { parseNginxRoutes } from '../proxies/nginx-filter.js';
import {
  chunks,
  isSudoDenial,
  QUERY_ARG,
  type PrivilegedQueryName,
} from '../privileged.js';

const CONTAINER_ID = QUERY_ARG.containerId;
/** Identidad de una imagen: `sha256:` + 64 hex (config, índice o manifiesto). */
export const IMAGE_ID = QUERY_ARG.imageId;
/** Nombres de contenedor de Docker (`[a-zA-Z0-9][a-zA-Z0-9_.-]+`). */
const CONTAINER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/;
const PORT_KEY = /^(\d{1,5})\/(tcp|udp|sctp)$/;
/** Nombres de volumen (`[a-zA-Z0-9][a-zA-Z0-9_.-]+`; los anónimos son 64 hex). */
const VOLUME_NAME = QUERY_ARG.dockerName;
/** Nombres de red (`bridge`, `host`, `none`, los de compose…). */
const NETWORK_NAME = QUERY_ARG.dockerName;

export {
  CONTAINER_FORMAT,
  IMAGE_FORMAT,
  NETWORK_FORMAT,
  VOLUME_FORMAT,
} from './formats.js';

/** Clave natural de un contenedor (§8): host + nombre (el id cambia al recrearlo). */
export function dockerNaturalKey(hostAssetId: string, name: string): string {
  return `docker:${hostAssetId}:${name}`;
}

/** Clave natural de un volumen: host + nombre. */
export function dockerVolumeKey(hostAssetId: string, name: string): string {
  return `docker-volume:${hostAssetId}:${name}`;
}

/** Clave natural de una red: host + nombre (su id cambia con `compose down/up`). */
export function dockerNetworkKey(hostAssetId: string, name: string): string {
  return `docker-network:${hostAssetId}:${name}`;
}

type ImageInfo = Omit<HostImage, 'imageId'>;
type ParsedContainer = NonNullable<ReturnType<typeof parseContainer>>;

/**
 * Descubridor de Docker (DESIGN §8). Hijos `container` (en marcha y parados), `volume` y `network`
 * del host, enlaces `mounts` y `attached_to` desde los contenedores, y las imágenes del host (las
 * registra el worker con `stores`). Solo lectura y siempre con los subcomandos que permite el
 * ayudante de root (consultas `docker-*`, sudoers v4). Si no deja listar volúmenes o redes, son los que
 * usan los contenedores y su listado es parcial (nada de ellos pasa a `missing`). El listado lo
 * hace `EngineLister`, que comparte con Podman.
 */
export class DockerDiscoverer implements Discoverer {
  readonly role = 'docker-host';
  readonly childTypes: readonly AssetType[] = [
    'container',
    'volume',
    'network',
  ];
  readonly linkTypes: readonly AssetRelationType[] = ['mounts', 'attached_to'];

  constructor(private readonly now: () => Date = () => new Date()) {}

  discover(parent: DiscoveryParent, host: HostExec): Promise<DiscoveryListing> {
    return new EngineLister(dockerEngine(parent.id), this.now).list(host);
  }

  collectTarget(): { target: null; reason: string } {
    return {
      target: null,
      reason:
        'Los contenedores, volúmenes y redes no se recogen con Ansible: sus datos vienen del host Docker',
    };
  }

}

/** Consultas del ayudante que usa `EngineLister`, por su papel. */
export interface EngineQueries {
  ps: PrivilegedQueryName;
  inspect: PrivilegedQueryName;
  images: PrivilegedQueryName;
  imageInspect: PrivilegedQueryName;
  volumes: PrivilegedQueryName;
  volumeInspect: PrivilegedQueryName;
  networks: PrivilegedQueryName;
  networkInspect: PrivilegedQueryName;
  nginxRoutes: PrivilegedQueryName;
}

/**
 * Un motor de contenedores tal como lo lista `EngineLister`: Docker o un ámbito de Podman (root o
 * un usuario rootless). Las plantillas de cada motor dan el mismo JSON, así que el listado y el
 * análisis son los mismos; cambian las consultas, sus argumentos fijos y las claves naturales.
 */
export interface ContainerEngine {
  /** Para los mensajes: «No se pudo listar Docker». */
  title: string;
  /** Para los avisos: `docker`, `podman`, `podman (alice)`. */
  label: string;
  queries: EngineQueries;
  /** Argumentos fijos delante de los de cada consulta (en Podman, el ámbito: `root` o un uid). */
  args: readonly string[];
  containerKey(name: string): string;
  volumeKey(name: string): string;
  networkKey(name: string): string;
  /** Nombre del hijo en el inventario (en Podman rootless lleva delante el usuario). */
  childName(name: string): string;
  /** Campos que se añaden a `facts.docker` de cada hijo (motor y usuario de Podman). */
  marker: Record<string, unknown>;
  /** Contenedores que no se inventarían (el contenedor «infra» de un pod de Podman). */
  skip?(line: Record<string, unknown>): boolean;
  /** Campos propios del motor para `facts.docker` de un contenedor (pod, unidad de systemd). */
  extra?(line: Record<string, unknown>): Partial<DockerContainerFacts>;
}

/** Docker: las consultas `docker-*` sin argumentos fijos. */
export function dockerEngine(hostAssetId: string): ContainerEngine {
  return {
    title: 'Docker',
    label: 'docker',
    queries: {
      ps: 'docker-ps',
      inspect: 'docker-inspect-containers',
      images: 'docker-images',
      imageInspect: 'docker-image-inspect',
      volumes: 'docker-volumes',
      volumeInspect: 'docker-volume-inspect',
      networks: 'docker-networks',
      networkInspect: 'docker-network-inspect',
      nginxRoutes: 'docker-nginx-routes',
    },
    args: [],
    containerKey: (name) => dockerNaturalKey(hostAssetId, name),
    volumeKey: (name) => dockerVolumeKey(hostAssetId, name),
    networkKey: (name) => dockerNetworkKey(hostAssetId, name),
    childName: (name) => name,
    marker: {},
  };
}

/** Listado de un motor de contenedores (Docker o un ámbito de Podman): ver `DockerDiscoverer`. */
export class EngineLister {
  constructor(
    private readonly engine: ContainerEngine,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async list(host: HostExec): Promise<DiscoveryListing> {
    const { engine } = this;
    const warnings: string[] = [];
    let complete = true;

    const ps = await this.query(host, 'ps');
    if (ps.code !== 0)
      throw new DiscoveryError(
        `No se pudo listar ${engine.title}: ${engine.label} ps falló${failure(ps)}`,
      );
    const ids = lines(ps.stdout);
    if (ids.some((id) => !CONTAINER_ID.test(id)))
      throw new DiscoveryError(`Respuesta de ${engine.label} ps no válida`);

    const containers: ParsedContainer[] = [];
    const extras = new Map<string, Partial<DockerContainerFacts>>();
    let skipped = 0;
    if (ids.length > 0) {
      const inspect = await this.inspectAll(host, 'inspect', ids);
      // Un contenedor borrado entre `ps` e `inspect` hace fallar el comando pero el resto sale:
      // se usa lo que haya y el listado deja de ser completo (no se marca nada como missing).
      if (inspect.code !== 0) {
        complete = false;
        warnings.push(`${engine.label} inspect falló${failure(inspect)}`);
      }
      for (const line of lines(inspect.stdout)) {
        const raw = parseObject(line);
        if (raw && engine.skip?.(raw)) {
          skipped++;
          continue;
        }
        const parsed = parseContainer(line);
        if (!parsed) {
          complete = false;
          warnings.push(
            `${engine.label} inspect devolvió un contenedor que no se entiende`,
          );
          continue;
        }
        containers.push(parsed);
        if (raw && engine.extra) extras.set(parsed.id, engine.extra(raw));
      }
      if (containers.length + skipped < ids.length) complete = false;
    }

    const hostImages = await this.hostImages(
      host,
      containers.map((c) => c.imageId),
      warnings,
    );
    const images = new Map(hostImages.images.map((i) => [i.imageId, i]));

    const proxies = await this.nginxProxies(host, containers, warnings);

    const discoveredAt = this.now().toISOString();
    const children: DiscoveredAsset[] = [];
    const links: DiscoveredLink[] = [];
    const seen = new Set<string>();
    const partialTypes: AssetType[] = [];
    for (const c of containers) {
      const image = images.get(c.imageId);
      const facts: DockerContainerFacts = {
        ...c,
        repoDigests: image?.repoDigests ?? [],
        repoTags: image?.repoTags ?? [],
        platform: image?.platform ?? null,
        imageSizeBytes: image?.size ?? null,
        ...(proxies.has(c.id) && { proxy: proxies.get(c.id) ?? null }),
        ...extras.get(c.id),
        discoveredAt,
      };
      const naturalKey = engine.containerKey(c.name);
      seen.add(seenKey('container', naturalKey));
      children.push({
        type: 'container',
        name: engine.childName(c.name),
        naturalKey,
        aliases: [],
        facts: { docker: { ...facts, ...engine.marker } },
        collect: false,
      });
      const from = { type: 'container' as const, naturalKey };
      for (const m of c.mounts)
        if (m.type === 'volume' && m.name)
          links.push({
            type: 'mounts',
            from,
            to: {
              type: 'volume',
              naturalKey: engine.volumeKey(m.name),
            },
          });
      for (const n of c.networks)
        links.push({
          type: 'attached_to',
          from,
          to: {
            type: 'network',
            naturalKey: engine.networkKey(n.name),
          },
        });
    }

    // Volúmenes y redes: todos los del host (v3) o, si sudo no deja listarlos, los que usan los
    // contenedores (listado parcial).
    const used = {
      volume: containers.flatMap((c) =>
        c.mounts
          .filter((m) => m.type === 'volume' && m.name)
          .map((m) => m.name!),
      ),
      network: containers.flatMap((c) => c.networks.map((n) => n.name)),
    };
    for (const kind of ['volume', 'network'] as const) {
      const listed = await this.listNames(host, kind, warnings);
      if (!listed.complete) partialTypes.push(kind);
      const names = [...new Set([...listed.names, ...used[kind]])].sort(byCodeUnit);
      const details = await this.inspectNames(host, kind, names, warnings);
      if (details.size < names.length && !partialTypes.includes(kind))
        partialTypes.push(kind);
      for (const name of names) {
        const facts = details.get(name);
        if (!facts) continue;
        const naturalKey =
          kind === 'volume'
            ? engine.volumeKey(name)
            : engine.networkKey(name);
        seen.add(seenKey(kind, naturalKey));
        children.push({
          type: kind,
          name: engine.childName(name),
          naturalKey,
          aliases: [],
          facts: { docker: { ...facts, ...engine.marker, discoveredAt } },
          collect: false,
        });
      }
    }
    // Un enlace a un volumen o una red que no se pudo leer no se crea (no existe el asset).
    const known = new Set(children.map((c) => seenKey(c.type, c.naturalKey)));
    const resolvable = links.filter((l) =>
      known.has(seenKey(l.to.type, l.to.naturalKey)),
    );

    return {
      children,
      seen,
      complete,
      partialTypes,
      links: resolvable,
      hostImages,
      warnings,
    };
  }

  /**
   * Rutas de los contenedores de nginx o Nginx Proxy Manager en marcha (QoL-5b, sudoers v5):
   * `docker exec <id> nginx -T` (o `podman exec`) filtrado en el servidor. Sin la v5 (denegado) o si falla, null:
   * el listado sigue completo y el camino de los dominios se corta ahí.
   */
  private async nginxProxies(
    host: HostExec,
    containers: ParsedContainer[],
    warnings: string[],
  ): Promise<Map<string, DockerContainerFacts['proxy']>> {
    const out = new Map<string, DockerContainerFacts['proxy']>();
    for (const c of containers) {
      const kind = nginxImageKind(c.image);
      if (!kind || c.state !== 'running') continue;
      const r = await this.query(host, 'nginxRoutes', [c.id]);
      if (r.code === 0) {
        out.set(c.id, parseNginxRoutes(r.stdout, kind, this.now()));
        continue;
      }
      out.set(c.id, null);
      if (!deniedBySudo(r))
        warnings.push(`no se pudo leer nginx de ${c.name}${failure(r)}`);
    }
    return out;
  }

  /**
   * Imágenes del host (`docker images`) con sus metadatos, más las de los contenedores (por si
   * alguna no sale en el listado). `complete` solo si `docker images` respondió y se leyeron todas.
   */
  private async hostImages(
    host: HostExec,
    containerImages: string[],
    warnings: string[],
  ): Promise<{ images: HostImage[]; complete: boolean }> {
    const ls = await this.query(host, 'images');
    let complete = ls.code === 0;
    if (!complete) warnings.push(`${this.engine.label} images falló${failure(ls)}`);
    const listed = ls.code === 0 ? lines(ls.stdout) : [];
    if (listed.some((id) => !IMAGE_ID.test(id))) {
      complete = false;
      warnings.push(`Respuesta de ${this.engine.label} images no válida`);
    }
    const ids = [
      ...new Set([
        ...listed.filter((id) => IMAGE_ID.test(id)),
        ...containerImages,
      ]),
    ];
    const info = await this.images(host, ids, warnings);
    if (info.size < ids.length) complete = false;
    return {
      images: [...info].map(([imageId, i]) => ({ imageId, ...i })),
      complete,
    };
  }

  /** Metadatos de las imágenes; un fallo es un aviso (no afecta a la lista de contenedores). */
  private async images(
    host: HostExec,
    imageIds: string[],
    warnings: string[],
  ): Promise<Map<string, ImageInfo>> {
    const images = new Map<string, ImageInfo>();
    if (imageIds.length === 0) return images;
    const result = await this.inspectAll(host, 'imageInspect', imageIds);
    if (result.code !== 0)
      warnings.push(`${this.engine.label} image inspect falló${failure(result)}`);
    for (const line of lines(result.stdout)) {
      const e = parseObject(line);
      if (!e || typeof e.id !== 'string' || !IMAGE_ID.test(e.id)) continue;
      images.set(e.id, {
        repoDigests: strings(e.repoDigests),
        repoTags: strings(e.repoTags),
        platform:
          typeof e.os === 'string' && typeof e.architecture === 'string'
            ? `${e.os}/${e.architecture}`.slice(0, 64)
            : null,
        size:
          typeof e.size === 'number' && Number.isSafeInteger(e.size)
            ? e.size
            : null,
      });
    }
    return images;
  }

  /**
   * Nombres de volúmenes o redes del host. Si sudo no lo permite (sudoers antiguo) no es un error:
   * el listado es parcial y la nota la da la tabla de capacidades del sudoers.
   */
  private async listNames(
    host: HostExec,
    kind: 'volume' | 'network',
    warnings: string[],
  ): Promise<{ names: string[]; complete: boolean }> {
    const result = await this.query(
      host,
      kind === 'volume' ? 'volumes' : 'networks',
    );
    if (result.code !== 0) {
      if (!deniedBySudo(result))
        warnings.push(`${this.engine.label} ${kind} ls falló${failure(result)}`);
      return { names: [], complete: false };
    }
    const names = lines(result.stdout);
    const pattern = kind === 'volume' ? VOLUME_NAME : NETWORK_NAME;
    if (names.some((n) => !pattern.test(n))) {
      warnings.push(`Respuesta de ${this.engine.label} ${kind} ls no válida`);
      return { names: names.filter((n) => pattern.test(n)), complete: false };
    }
    return { names, complete: true };
  }

  /** `docker inspect --type volume|network` de los nombres (ya validados). */
  private async inspectNames(
    host: HostExec,
    kind: 'volume' | 'network',
    names: string[],
    warnings: string[],
  ): Promise<
    Map<string, Omit<DockerVolumeFacts | DockerNetworkFacts, 'discoveredAt'>>
  > {
    const found = new Map<
      string,
      Omit<DockerVolumeFacts | DockerNetworkFacts, 'discoveredAt'>
    >();
    if (names.length === 0) return found;
    const result = await this.inspectAll(
      host,
      kind === 'volume' ? 'volumeInspect' : 'networkInspect',
      names,
    );
    // Uno borrado entretanto hace fallar el comando; el resto sale.
    if (result.code !== 0)
      warnings.push(`${this.engine.label} inspect --type ${kind} falló${failure(result)}`);
    for (const line of lines(result.stdout)) {
      const parsed = kind === 'volume' ? parseVolume(line) : parseNetwork(line);
      if (parsed) found.set(parsed.name, parsed);
    }
    return found;
  }

  private query(
    host: HostExec,
    role: keyof EngineQueries,
    args: readonly string[] = [],
  ): Promise<HostCommandResult> {
    return host.query({
      name: this.engine.queries[role],
      args: [...this.engine.args, ...args],
    });
  }

  private inspectAll(
    host: HostExec,
    role: keyof EngineQueries,
    args: readonly string[],
  ): Promise<HostCommandResult> {
    return inspectAll(host, this.engine.queries[role], args, this.engine.args);
  }
}

/**
 * `docker inspect` de muchos ids o nombres por el ayudante, en trozos de `MAX_INSPECT_ARGS`:
 * la salida de todos junta y el primer código de error (los demás trozos se usan igual).
 */
async function inspectAll(
  host: HostExec,
  name: PrivilegedQueryName,
  args: readonly string[],
  fixed: readonly string[] = [],
): Promise<HostCommandResult> {
  const all: HostCommandResult = { code: 0, stdout: '', stderr: '' };
  for (const part of chunks(args)) {
    const r = await host.query({ name, args: [...fixed, ...part] });
    all.stdout += r.stdout;
    all.stderr += r.stderr;
    if (all.code === 0) all.code = r.code;
  }
  return all;
}

/** Una línea de `docker inspect --format CONTAINER_FORMAT`; null si no es válida. */
export function parseContainer(
  line: string,
):
  | (Omit<
      DockerContainerFacts,
      | 'repoDigests'
      | 'repoTags'
      | 'platform'
      | 'imageSizeBytes'
      | 'discoveredAt'
      | 'mounts'
      | 'networks'
    > & { mounts: DockerMount[]; networks: DockerContainerNetwork[] })
  | null {
  const e = parseObject(line);
  if (!e) return null;
  const name = typeof e.name === 'string' ? e.name.replace(/^\//, '') : '';
  if (
    typeof e.id !== 'string' ||
    !CONTAINER_ID.test(e.id) ||
    !CONTAINER_NAME.test(name) ||
    typeof e.imageId !== 'string' ||
    !IMAGE_ID.test(e.imageId)
  )
    return null;
  const running = parsePorts(e.ports);
  return {
    id: e.id,
    name,
    image: typeof e.image === 'string' ? e.image.slice(0, 512) : '',
    imageId: e.imageId,
    state: typeof e.state === 'string' ? e.state.slice(0, 32) : 'unknown',
    // Parado, `NetworkSettings.Ports` va vacío: se usan los puertos configurados.
    ports: running.length ? running : parsePorts(e.bindings),
    composeProject:
      typeof e.composeProject === 'string' && e.composeProject
        ? e.composeProject.slice(0, 255)
        : null,
    composeService:
      typeof e.composeService === 'string' && e.composeService
        ? e.composeService.slice(0, 255)
        : null,
    // Solo con un ayudante v5 (antes, el campo no existe): nada si no declara rutas.
    ...proxyRoutesOf(e.proxyLabels),
    createdAt: date(e.createdAt),
    startedAt: date(e.startedAt),
    mounts: objects(e.mounts)
      .map(parseMount)
      .filter((m): m is DockerMount => m !== null),
    networks: objects(e.networks)
      .map(parseContainerNetwork)
      .filter((n): n is DockerContainerNetwork => n !== null),
  };
}

function parseMount(e: Record<string, unknown>): DockerMount | null {
  if (typeof e.type !== 'string' || typeof e.destination !== 'string')
    return null;
  const name =
    e.type === 'volume' &&
    typeof e.name === 'string' &&
    VOLUME_NAME.test(e.name)
      ? e.name
      : null;
  if (e.type === 'volume' && !name) return null;
  return {
    type: e.type.slice(0, 16),
    name,
    // La ruta del host solo en los bind (en un volumen es la de su almacén: no aporta).
    source:
      e.type === 'bind' && typeof e.source === 'string'
        ? e.source.slice(0, 1024)
        : null,
    destination: e.destination.slice(0, 1024),
    readOnly: e.rw === false,
  };
}

function parseContainerNetwork(
  e: Record<string, unknown>,
): DockerContainerNetwork | null {
  if (typeof e.name !== 'string' || !NETWORK_NAME.test(e.name)) return null;
  const aliases = strings(e.aliases)
    .filter((a) => CONTAINER_NAME.test(a))
    .slice(0, 20);
  return {
    name: e.name,
    ipv4: typeof e.ipv4 === 'string' && e.ipv4 ? e.ipv4.slice(0, 64) : null,
    ipv6: typeof e.ipv6 === 'string' && e.ipv6 ? e.ipv6.slice(0, 64) : null,
    ...(aliases.length && { aliases }),
  };
}

function proxyRoutesOf(value: unknown): { proxyRoutes?: DockerContainerFacts['proxyRoutes'] } {
  const routes = parseProxyLabels(proxyLabelPairs(value));
  return routes.length ? { proxyRoutes: routes } : {};
}

/** Una línea de `docker inspect --type volume --format VOLUME_FORMAT`; null si no es válida. */
export function parseVolume(
  line: string,
): Omit<DockerVolumeFacts, 'discoveredAt'> | null {
  const e = parseObject(line);
  if (!e || typeof e.name !== 'string' || !VOLUME_NAME.test(e.name))
    return null;
  return {
    name: e.name,
    driver: typeof e.driver === 'string' ? e.driver.slice(0, 128) : 'local',
    scope: typeof e.scope === 'string' ? e.scope.slice(0, 32) : null,
    mountpoint:
      typeof e.mountpoint === 'string' && e.mountpoint
        ? e.mountpoint.slice(0, 1024)
        : null,
    createdAt: date(e.createdAt),
  };
}

/** Una línea de `docker inspect --type network --format NETWORK_FORMAT`; null si no es válida. */
export function parseNetwork(
  line: string,
): Omit<DockerNetworkFacts, 'discoveredAt'> | null {
  const e = parseObject(line);
  if (
    !e ||
    typeof e.name !== 'string' ||
    !NETWORK_NAME.test(e.name) ||
    typeof e.id !== 'string' ||
    !/^[0-9a-f]{64}$/.test(e.id)
  )
    return null;
  return {
    id: e.id,
    name: e.name,
    driver: typeof e.driver === 'string' ? e.driver.slice(0, 128) : 'unknown',
    scope: typeof e.scope === 'string' ? e.scope.slice(0, 32) : null,
    internal: e.internal === true,
    subnets: objects(e.subnets)
      .filter((n) => typeof n.subnet === 'string' && n.subnet)
      .map((n): DockerNetworkSubnet => ({
        subnet: (n.subnet as string).slice(0, 64),
        gateway:
          typeof n.gateway === 'string' && n.gateway
            ? n.gateway.slice(0, 64)
            : null,
      })),
    createdAt: date(e.createdAt),
  };
}

/** `{"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}] | null}`. */
function parsePorts(value: unknown): DockerPortBinding[] {
  if (!value || typeof value !== 'object') return [];
  const ports: DockerPortBinding[] = [];
  for (const [key, bindings] of Object.entries(value)) {
    const m = PORT_KEY.exec(key);
    if (!m) continue;
    const containerPort = Number(m[1]);
    const proto = m[2] as DockerPortBinding['proto'];
    const list = Array.isArray(bindings) ? bindings : [];
    if (list.length === 0)
      ports.push({ containerPort, proto, hostIp: null, hostPort: null });
    for (const b of list) {
      if (!b || typeof b !== 'object') continue;
      const { HostIp, HostPort } = b as Record<string, unknown>;
      const hostPort = Number(HostPort);
      ports.push({
        containerPort,
        proto,
        // Vacío = todas las interfaces.
        hostIp: typeof HostIp === 'string' && HostIp ? HostIp : '0.0.0.0',
        hostPort:
          Number.isInteger(hostPort) && hostPort > 0 && hostPort < 65536
            ? hostPort
            : null,
      });
    }
  }
  const ip = (p: DockerPortBinding) => p.hostIp ?? '';
  return ports.sort(
    (a, b) =>
      a.containerPort - b.containerPort ||
      (ip(a) < ip(b) ? -1 : ip(a) > ip(b) ? 1 : 0),
  );
}

function lines(output: string): string[] {
  return output
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

/** Elementos objeto de una lista JSON (las plantillas terminan la lista con `null`). */
function objects(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value
        .filter(
          (v): v is Record<string, unknown> =>
            !!v && typeof v === 'object' && !Array.isArray(v),
        )
        .slice(0, 200)
    : [];
}

/** sudo (o el ayudante) rechazó el comando: sudoers antiguo o alta manual. */
function deniedBySudo(result: HostCommandResult): boolean {
  return isSudoDenial(result.stderr, result.code);
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

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value
        .filter((v): v is string => typeof v === 'string')
        .map((v) => v.slice(0, 512))
        .slice(0, 50)
    : [];
}

/** Fechas de Docker; la cero (`0001-01-01…`, nunca arrancado) es null. */
function date(value: unknown): string | null {
  if (typeof value !== 'string' || value.startsWith('0001-')) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

function failure(result: HostCommandResult): string {
  if (result.code === null) return ' (tiempo agotado)';
  const line = lines(result.stderr).at(-1);
  return ` (código ${result.code})${line ? `: ${line.slice(0, 200)}` : ''}`;
}
