import {
  PROXY_SELF_HOST,
  SERVICE_MAX_HOPS,
  portExposure,
  type AssetType,
  type CloudflareTunnel,
  type CollectedPort,
  type DockerContainerNetwork,
  type DockerPortBinding,
  type HopConfidence,
  type ProxyFacts,
  type ProxyRoute,
  type ProxyUpstream,
  type ServiceCutReason,
  type ServiceHop,
  type ServicePathStatus,
  type ServiceResolverKind,
} from '@infraward/shared-types';
import { isPrivateIp } from '../domains/link.js';

// --- Entrada ---

/** Asset que puede ser un eslabón: servidor, VM o CT (con `ss`) y contenedores. */
export interface ServiceAsset {
  id: string;
  name: string;
  type: AssetType;
  /** Padre `contains` (el host de un contenedor). */
  parentId: string | null;
  /** IPs del asset: las de `assetIps` en un host, las de sus redes en un contenedor. */
  ips: string[];
  /** Puertos en escucha (`ss`) de un host; null si no se recogieron. */
  ports: CollectedPort[] | null;
  /** nginx/NPM del host o del contenedor: undefined = no hay; null = no se pudo leer. */
  proxy?: ProxyFacts | null;
  /** Solo contenedores. */
  docker?: {
    image: string;
    state: string;
    ports: DockerPortBinding[];
    networks: DockerContainerNetwork[];
    composeService: string | null;
    proxyRoutes: ProxyRoute[];
  };
}

export interface ServiceRecord {
  id: string;
  /** Nombre completo del registro (el Host que llega a los proxies). */
  name: string;
  type: 'A' | 'AAAA' | 'CNAME';
  content: string;
  /** Con el proxy de Cloudflare (nube naranja): accesible desde Internet. */
  proxied?: boolean;
  /** Destinos `resolves_to`: hosts (A/AAAA) o registros/dominios (CNAME interno). */
  targets: string[];
}

export interface NatForwardRule {
  publicIp: string;
  publicPort: number;
  proto: 'tcp' | 'udp';
  targetAssetId: string;
  targetPort: number;
}

export interface ServicePathInput {
  records: ServiceRecord[];
  assets: ServiceAsset[];
  natForwards: NatForwardRule[];
  tunnels: CloudflareTunnel[];
}

export interface ResolvedServicePath {
  recordId: string;
  status: Exclude<ServicePathStatus, 'manual'>;
  hops: ServiceHop[];
  finalAssetId: string | null;
  confidence: HopConfidence | null;
  cutReason: ServiceCutReason | null;
  /**
   * Nombre accesible desde Internet: IP pública, proxy de Cloudflare o túnel (prioridad de las
   * vulnerabilidades del servicio, §9).
   */
  public: boolean;
}

// --- Contexto y plugins ---

/** Un punto de la cadena: un asset y el puerto al que llega el tráfico para un nombre. */
export interface Endpoint {
  assetId: string;
  port: number;
  hostname: string;
  /** Llega desde el propio asset (loopback): cuenta lo que escucha solo en 127.0.0.1. */
  local?: boolean;
  /**
   * Un proxy ya eligió este destino por el nombre (etiqueta, `server_name`, regla del túnel):
   * todo lo que llega aquí es para ese nombre, y el `server_name` del propio destino da igual.
   */
  routed?: boolean;
}

/** Siguiente paso de un resolutor: un salto más (o el final) o un corte con su motivo. */
export type Step =
  | { hop: ServiceHop | null; next: Endpoint | null }
  | { cut: ServiceCutReason; detail: string };

/** Resolutor de un tipo de eslabón (plugin): decide si se encarga y da el siguiente salto. */
export interface ServiceResolver {
  readonly kind: ServiceResolverKind;
  applies(at: Endpoint, asset: ServiceAsset, ctx: ResolveContext): boolean;
  next(at: Endpoint, asset: ServiceAsset, ctx: ResolveContext): Step;
}

/** Índices de la entrada que comparten los resolutores. */
export class ResolveContext {
  readonly byId = new Map<string, ServiceAsset>();
  readonly byIp = new Map<string, ServiceAsset[]>();
  readonly children = new Map<string, ServiceAsset[]>();

  constructor(readonly input: ServicePathInput) {
    for (const a of input.assets) {
      this.byId.set(a.id, a);
      if (a.parentId)
        this.children.set(a.parentId, [
          ...(this.children.get(a.parentId) ?? []),
          a,
        ]);
      for (const ip of a.ips) {
        const key = normIp(ip);
        this.byIp.set(key, [...(this.byIp.get(key) ?? []), a]);
      }
    }
  }

  get(id: string): ServiceAsset | undefined {
    return this.byId.get(id);
  }

  containersOf(hostId: string): ServiceAsset[] {
    return (this.children.get(hostId) ?? []).filter((c) => c.docker);
  }

  /** Hosts (no contenedores) con esa IP. */
  hostsWithIp(ip: string): ServiceAsset[] {
    return (this.byIp.get(normIp(ip)) ?? []).filter((a) => !a.docker);
  }
}

const hop = (
  asset: ServiceAsset | null,
  port: number | null,
  resolver: ServiceResolverKind,
  source: string,
  confidence: HopConfidence,
  label?: string,
): ServiceHop => ({
  assetId: asset?.id ?? null,
  label: (label ?? `${asset?.name ?? '?'}${port ? `:${port}` : ''}`).slice(0, 255),
  port,
  resolver,
  source: source.slice(0, 512),
  confidence,
});

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '0.0.0.0']);
const TRAEFIK_IMAGE = /(?:^|\/)traefik(?:[:@]|$)/i;
const CADDY_IMAGE = /caddy/i;
const CLOUDFLARED = /cloudflared/i;

/**
 * docker-proxy: un puerto del host publicado por un contenedor. Confirmado si `ss` muestra
 * `docker-proxy` (o el contenedor con red de host) escuchando; deducido si solo lo dice Docker
 * (sin proxy de usuario: iptables).
 */
const dockerProxy: ServiceResolver = {
  kind: 'docker-proxy',
  applies: (at, asset, ctx) =>
    !asset.docker && publishedBy(at, asset, ctx) !== null,
  next(at, asset, ctx) {
    const { container, binding } = publishedBy(at, asset, ctx)!;
    const listener = listenerOn(asset, at);
    const confirmed = listener?.process === 'docker-proxy';
    return {
      hop: hop(
        container,
        binding.containerPort,
        'docker-proxy',
        `${asset.name}:${at.port} publicado → ${container.name}:${binding.containerPort}`,
        confirmed ? 'confirmed' : 'deduced',
      ),
      next: {
        assetId: container.id,
        port: binding.containerPort,
        hostname: at.hostname,
      },
    };
  },
};

function publishedBy(
  at: Endpoint,
  host: ServiceAsset,
  ctx: ResolveContext,
): { container: ServiceAsset; binding: DockerPortBinding } | null {
  for (const c of ctx.containersOf(host.id)) {
    if (c.docker!.state !== 'running') continue;
    const binding = c.docker!.ports.find(
      (p) => p.proto === 'tcp' && p.hostPort === at.port,
    );
    if (binding) return { container: c, binding };
  }
  return null;
}

/** Proceso de `ss` que escucha en ese puerto del host (desde fuera, o desde dentro si `local`). */
function listenerOn(
  asset: ServiceAsset,
  at: Endpoint,
): CollectedPort | null {
  return (
    asset.ports?.find(
      (p) =>
        p.proto === 'tcp' &&
        p.port === at.port &&
        (at.local || portExposure(p.address) !== 'local'),
    ) ?? null
  );
}

/** Traefik: el contenedor con su etiqueta `Host(...)` en el mismo host Docker. */
const traefik: ServiceResolver = {
  kind: 'traefik',
  applies: (_at, asset) =>
    !!asset.docker && TRAEFIK_IMAGE.test(asset.docker.image),
  next: (at, asset, ctx) => labelRoute('traefik', at, asset, ctx),
};

/** caddy-docker-proxy: etiquetas `caddy`/`caddy.reverse_proxy` en el mismo host Docker. */
const caddy: ServiceResolver = {
  kind: 'caddy',
  applies: (_at, asset, ctx) =>
    !!asset.docker &&
    CADDY_IMAGE.test(asset.docker.image) &&
    siblings(asset, ctx).some((c) =>
      c.docker!.proxyRoutes.some((r) => r.source === 'caddy'),
    ),
  next: (at, asset, ctx) => labelRoute('caddy', at, asset, ctx),
};

function siblings(asset: ServiceAsset, ctx: ResolveContext): ServiceAsset[] {
  return asset.parentId ? ctx.containersOf(asset.parentId) : [];
}

function labelRoute(
  source: 'traefik' | 'caddy',
  at: Endpoint,
  proxy: ServiceAsset,
  ctx: ResolveContext,
): Step {
  for (const c of siblings(proxy, ctx)) {
    if (c.docker!.state !== 'running') continue;
    const route = c.docker!.proxyRoutes.find(
      (r) => r.source === source && hostMatches(r.hosts, at.hostname),
    );
    if (!route) continue;
    const upstream = route.upstreams[0];
    if (!upstream) continue;
    const self = upstream.host === PROXY_SELF_HOST;
    const target = self
      ? { asset: c, confidence: 'confirmed' as HopConfidence }
      : resolveName(upstream.host, proxy, ctx);
    if (!target)
      return {
        cut: 'unknown_upstream',
        detail: `${source}: ${at.hostname} → ${upstream.host}`,
      };
    let port = upstream.port;
    let confidence: HopConfidence = target.confidence;
    if (port === null) {
      // Sin puerto en la etiqueta: Traefik usa el único expuesto.
      const exposed = [
        ...new Set(
          (target.asset.docker?.ports ?? [])
            .filter((p) => p.proto === 'tcp')
            .map((p) => p.containerPort),
        ),
      ];
      port = exposed.length === 1 ? exposed[0] : 80;
      confidence = 'deduced';
    }
    return {
      hop: hop(
        target.asset,
        port,
        source,
        `${source}: ${route.hosts.join(', ')} → ${target.asset.name}:${port}${self ? ' (etiquetas del contenedor)' : ''}`,
        confidence,
      ),
      next: { assetId: target.asset.id, port, hostname: at.hostname, routed: true },
    };
  }
  return {
    cut: 'no_route_for_host',
    detail: `${source} en ${proxy.name}: ninguna etiqueta con ${at.hostname}`,
  };
}

/** nginx (y Nginx Proxy Manager): rutas filtradas de `nginx -T` del host o del contenedor. */
const nginx: ServiceResolver = {
  kind: 'nginx',
  applies: (at, asset) =>
    asset.proxy !== undefined &&
    (asset.proxy === null || asset.proxy.source !== 'npm') &&
    servesPort(asset, at),
  next: (at, asset, ctx) => nginxRoute('nginx', at, asset, ctx),
};

const npm: ServiceResolver = {
  kind: 'npm',
  applies: (_at, asset) => asset.proxy?.source === 'npm',
  next: (at, asset, ctx) => nginxRoute('npm', at, asset, ctx),
};

/** ¿El nginx de este asset es quien atiende ese puerto? En un host, `ss` lo dice. */
function servesPort(asset: ServiceAsset, at: Endpoint): boolean {
  if (asset.docker) return true;
  const l = listenerOn(asset, at);
  return !!l && /nginx|openresty/i.test(l.process ?? '');
}

function nginxRoute(
  kind: 'nginx' | 'npm',
  at: Endpoint,
  asset: ServiceAsset,
  ctx: ResolveContext,
): Step {
  if (!asset.proxy)
    return {
      cut: 'proxy_unreadable',
      detail: `no se pudo leer la configuración de ${kind === 'npm' ? 'Nginx Proxy Manager' : 'nginx'} en ${asset.name} (¿sudoers anterior a la v5?)`,
    };
  const picked = pickRoute(asset.proxy.routes, at);
  const { route } = picked;
  // Ya enrutado por nombre: el default_server del destino es quien lo sirve, sin duda.
  const confidence: HopConfidence = at.routed ? 'confirmed' : picked.confidence;
  if (!route)
    return {
      cut: 'no_route_for_host',
      detail: `${kind}: ningún server de ${asset.name} atiende ${at.hostname}:${at.port}`,
    };
  const label = route.hosts.length ? route.hosts.join(', ') : 'por defecto';
  const upstream = route.upstreams[0];
  if (!upstream) {
    // Ya enrutado por nombre hasta aquí: este asset es el destino, sin otro eslabón.
    if (at.routed && picked.confidence === 'deduced') return { hop: null, next: null };
    // Sin proxy_pass: lo sirve el propio nginx (estático, redirección).
    return {
      hop: hop(
        asset,
        at.port,
        kind,
        `${kind}: server_name ${label} lo sirve el propio nginx`,
        confidence,
      ),
      next: null,
    };
  }
  const target = resolveUpstream(upstream, asset, ctx);
  if (!target)
    return {
      cut: 'unknown_upstream',
      detail: `${kind}: ${label} → ${upstream.host}${upstream.port ? `:${upstream.port}` : ''} (no está en el inventario)`,
    };
  const port = upstream.port ?? 80;
  return {
    hop: hop(
      target.asset,
      port,
      kind,
      `${kind}: server_name ${label} → ${upstream.host}:${port}`,
      worst(confidence, target.confidence),
    ),
    next: {
      assetId: target.asset.id,
      port,
      hostname: at.hostname,
      local: target.local,
      routed: picked.confidence === 'confirmed' || at.routed,
    },
  };
}

/**
 * Ruta de nginx para un nombre y un puerto: el server con ese nombre (exacto, luego comodín) y,
 * si no hay, el `default_server` o el primero del puerto (lo que hace nginx: deducido).
 */
function pickRoute(
  routes: ProxyRoute[],
  at: Endpoint,
): { route: ProxyRoute | null; confidence: HopConfidence } {
  const onPort = routes.filter(
    (r) => r.listen.length === 0 || r.listen.includes(at.port),
  );
  const byPath = (list: ProxyRoute[]) =>
    list.find((r) => r.path === null || r.path === '/') ?? list[0] ?? null;
  const exact = onPort.filter((r) => r.hosts.includes(at.hostname));
  if (exact.length) return { route: byPath(exact), confidence: 'confirmed' };
  const wild = onPort.filter((r) => hostMatches(r.hosts, at.hostname));
  if (wild.length) return { route: byPath(wild), confidence: 'confirmed' };
  const fallback = onPort.filter((r) => r.isDefault);
  return {
    route: byPath(fallback.length ? fallback : onPort),
    confidence: 'deduced',
  };
}

/** Un proceso cualquiera en escucha: el destino final es el propio host o CT. */
const listener: ServiceResolver = {
  kind: 'listener',
  applies: (at, asset) => !asset.docker && listenerOn(asset, at) !== null,
  next(at, asset, ctx) {
    const l = listenerOn(asset, at)!;
    // Un contenedor con la red del host (`network_mode: host`) cuyo proceso escucha aquí.
    const hostNet = ctx
      .containersOf(asset.id)
      .find(
        (c) =>
          c.docker!.state === 'running' &&
          c.docker!.networks.some((n) => n.name === 'host') &&
          !!l.process &&
          c.docker!.image.toLowerCase().includes(l.process.toLowerCase()),
      );
    if (hostNet)
      return {
        hop: hop(
          hostNet,
          at.port,
          'listener',
          `${l.process} en ${asset.name}:${at.port} (contenedor con la red del host)`,
          'deduced',
        ),
        next: { ...at, assetId: hostNet.id },
      };
    return {
      hop: hop(
        asset,
        at.port,
        'listener',
        `${l.process ?? 'proceso'} escucha en ${l.address}:${at.port}`,
        'confirmed',
        `${asset.name}:${at.port}${l.process ? ` (${l.process})` : ''}`,
      ),
      next: null,
    };
  },
};

/** Resolutores de los eslabones, en orden (el primero que se encarga da el salto). */
export const SERVICE_RESOLVERS: readonly ServiceResolver[] = [
  dockerProxy,
  traefik,
  caddy,
  npm,
  nginx,
  listener,
];

// --- Destinos de un proxy ---

interface Target {
  asset: ServiceAsset;
  confidence: HopConfidence;
  local?: boolean;
}

/** Destino de un upstream visto desde el asset del proxy. */
function resolveUpstream(
  u: ProxyUpstream,
  from: ServiceAsset,
  ctx: ResolveContext,
): Target | null {
  if (u.host === PROXY_SELF_HOST) return { asset: from, confidence: 'confirmed' };
  return resolveName(u.host, from, ctx);
}

/** Un nombre o IP de un upstream: loopback, contenedor vecino, puerta de enlace o asset por IP. */
function resolveName(
  name: string,
  from: ServiceAsset,
  ctx: ResolveContext,
): Target | null {
  const host = name.toLowerCase();
  const parent = from.parentId ? ctx.get(from.parentId) : undefined;
  const hostNet = from.docker?.networks.some((n) => n.name === 'host');
  if (LOOPBACK.has(host)) {
    // Desde un contenedor, 127.0.0.1 es él mismo (salvo con la red del host).
    if (from.docker && hostNet && parent)
      return { asset: parent, confidence: 'confirmed', local: true };
    return { asset: from, confidence: 'confirmed', local: true };
  }
  if (host === 'host.docker.internal' && parent)
    return { asset: parent, confidence: 'deduced', local: true };
  const docker = from.docker ? parent : from;
  const neighbours = docker ? ctx.containersOf(docker.id) : [];
  if (isIp(host)) {
    // IP de un contenedor del mismo host (red de Docker).
    const c = neighbours.find((n) =>
      n.docker!.networks.some((net) => net.ipv4 === host || net.ipv6 === host),
    );
    if (c) return { asset: c, confidence: 'confirmed' };
    // Puerta de enlace de una red de Docker (172.17.0.1): el host.
    if (from.docker && parent && /^172\.(1[6-9]|2\d|3[01])\.\d+\.1$/.test(host))
      return { asset: parent, confidence: 'deduced' };
    const hosts = ctx.hostsWithIp(host);
    if (hosts.length)
      return {
        asset: hosts[0],
        confidence: hosts.length === 1 ? 'confirmed' : 'deduced',
      };
    return null;
  }
  // Nombre: un contenedor del mismo host (nombre, servicio de compose o alias en una red
  // compartida con el proxy si es un contenedor).
  const shared = new Set(from.docker?.networks.map((n) => n.name) ?? []);
  const matches = neighbours.filter((c) => {
    const d = c.docker!;
    const names = [
      c.name.toLowerCase(),
      d.composeService?.toLowerCase(),
      ...d.networks
        .filter((n) => !from.docker || shared.has(n.name))
        .flatMap((n) => n.aliases ?? [])
        .map((a) => a.toLowerCase()),
    ];
    return names.includes(host);
  });
  if (matches.length)
    return {
      asset: matches.find((m) => m.docker!.state === 'running') ?? matches[0],
      confidence: matches.length === 1 ? 'confirmed' : 'deduced',
    };
  return null;
}

// --- Cadena ---

/** Caminos de todos los registros A/AAAA/CNAME. Pura: no toca la BD ni la red. */
export function resolveServicePaths(
  input: ServicePathInput,
  resolvers: readonly ServiceResolver[] = SERVICE_RESOLVERS,
): ResolvedServicePath[] {
  const ctx = new ResolveContext(input);
  const records = new Map(input.records.map((r) => [r.id, r]));
  return input.records.map((r) => resolveRecord(r, records, ctx, resolvers));
}

function resolveRecord(
  record: ServiceRecord,
  records: Map<string, ServiceRecord>,
  ctx: ResolveContext,
  resolvers: readonly ServiceResolver[],
): ResolvedServicePath {
  const hostname = record.name;
  const prefix: ServiceHop[] = [];
  // CNAME internos: hasta el registro A/AAAA al que llevan (el Host sigue siendo este nombre).
  let current = record;
  for (let i = 0; i < 5 && current.type === 'CNAME'; i++) {
    if (/\.cfargotunnel\.com\.?$/i.test(current.content)) {
      const tunnel = tunnelEntry(current, hostname, ctx, resolvers);
      return finish(record, [...prefix, ...tunnel.hops], tunnel.cut, true);
    }
    const next = current.targets
      .map((t) => records.get(t))
      .find((t): t is ServiceRecord => !!t);
    if (!next) return finish(record, prefix, 'no_target', !!record.proxied);
    prefix.push(
      hop(null, null, 'dns', `CNAME ${current.name} → ${next.name}`, 'confirmed', next.name),
    );
    current = next;
  }
  if (current.type === 'CNAME')
    return finish(record, prefix, 'no_target', !!record.proxied);
  const isPublic =
    !!record.proxied ||
    !!current.proxied ||
    (!isPrivateIp(current.content) && !/^(127\.|0\.|::1$)/.test(current.content));

  // A/AAAA: un reenvío NAT declarado para esa IP gana (la IP pública de un router); si no, el
  // host del inventario con esa IP.
  // 443 y 80: gana el primer camino completo y confirmado; si no hay, el primero completo
  // (p. ej. el `default_server` de un proxy, deducido) y, si ninguno llega, el que más avanza.
  const attempts: { hops: ServiceHop[]; cut: ServiceCutReason | null }[] = [];
  for (const port of [443, 80]) {
    const entry = entryFor(current, port, ctx);
    if (!entry) continue;
    const walked = walk(
      { assetId: entry.asset.id, port: entry.port, hostname },
      ctx,
      resolvers,
    );
    attempts.push({ hops: [...prefix, ...entry.hops, ...walked.hops], cut: walked.cut });
  }
  const complete = attempts.filter((a) => !a.cut);
  const best =
    complete.find((a) => a.hops.every((h) => h.confidence === 'confirmed')) ??
    complete[0] ??
    attempts.toSorted((a, b) => b.hops.length - a.hops.length)[0];
  if (best) return finish(record, best.hops, best.cut, isPublic);
  return finish(record, prefix, 'no_target', isPublic);
}

/** Primer eslabón de un A/AAAA en un puerto: reenvío NAT o host con esa IP. */
function entryFor(
  record: ServiceRecord,
  port: number,
  ctx: ResolveContext,
): { asset: ServiceAsset; port: number; hops: ServiceHop[] } | null {
  const ip = normIp(record.content);
  const nat = ctx.input.natForwards.find(
    (n) => normIp(n.publicIp) === ip && n.publicPort === port && n.proto === 'tcp',
  );
  if (nat) {
    const target = ctx.get(nat.targetAssetId);
    if (!target) return null;
    return {
      asset: target,
      port: nat.targetPort,
      hops: [
        hop(null, port, 'dns', `${record.type} ${record.name} → ${record.content}`, 'confirmed', `${record.content}:${port}`),
        hop(target, nat.targetPort, 'nat', `reenvío NAT ${record.content}:${port} → ${target.name}:${nat.targetPort}`, 'confirmed'),
      ],
    };
  }
  const hosts = record.targets
    .map((t) => ctx.get(t))
    .filter((a): a is ServiceAsset => !!a && !a.docker);
  if (!hosts.length) return null;
  const host = hosts[0];
  return {
    asset: host,
    port,
    hops: [
      hop(
        host,
        port,
        'dns',
        `${record.type} ${record.name} → ${record.content}${hosts.length > 1 ? ` (${hosts.length} assets con esa IP)` : ''}`,
        hosts.length > 1 ? 'deduced' : 'confirmed',
      ),
    ],
  };
}

/** CNAME a `<id>.cfargotunnel.com`: regla de entrada del túnel → quien ejecuta cloudflared. */
function tunnelEntry(
  record: ServiceRecord,
  hostname: string,
  ctx: ResolveContext,
  resolvers: readonly ServiceResolver[],
): { hops: ServiceHop[]; cut: ServiceCutReason | null } {
  const id = record.content.toLowerCase().split('.')[0];
  const tunnel = ctx.input.tunnels.find((t) => t.id === id);
  if (!tunnel) return { hops: [], cut: 'tunnel_unknown' };
  const tunnelHop = hop(null, null, 'tunnel', `túnel de Cloudflare ${tunnel.name}`, 'confirmed', `túnel ${tunnel.name}`);
  if (!tunnel.ingress) return { hops: [tunnelHop], cut: 'tunnel_no_config' };
  const rule = tunnel.ingress.find(
    (r) => r.hostname === null || hostMatches([r.hostname], hostname),
  );
  const url = rule && /^(https?|tcp):\/\/([^/:]+|\[[^\]]+\])(?::(\d+))?/.exec(rule.service);
  if (!rule || !url) return { hops: [tunnelHop], cut: 'no_route_for_host' };
  const runners = ctx.input.assets.filter(
    (a) =>
      (a.docker?.state === 'running' && CLOUDFLARED.test(a.docker.image)) ||
      (!a.docker && a.ports?.some((p) => CLOUDFLARED.test(p.process ?? ''))),
  );
  if (!runners.length) return { hops: [tunnelHop], cut: 'no_cloudflared' };
  const port = url[3] ? Number(url[3]) : url[1] === 'https' ? 443 : 80;
  const host = url[2].replace(/^\[|\]$/g, '');
  for (const runner of runners) {
    const target = resolveName(host, runner, ctx);
    if (!target) continue;
    const confidence: HopConfidence =
      runners.length === 1 ? target.confidence : 'deduced';
    const ruleHop = hop(
      target.asset,
      port,
      'tunnel',
      `túnel ${tunnel.name}: ${rule.hostname ?? '*'} → ${rule.service} (cloudflared en ${runner.name})`,
      confidence,
    );
    const walked = walk(
      { assetId: target.asset.id, port, hostname, local: target.local, routed: true },
      ctx,
      resolvers,
    );
    return { hops: [tunnelHop, ruleHop, ...walked.hops], cut: walked.cut };
  }
  return { hops: [tunnelHop], cut: 'unknown_upstream' };
}

/** Recorre los eslabones desde un punto hasta el destino final, un corte, un ciclo o el tope. */
function walk(
  start: Endpoint,
  ctx: ResolveContext,
  resolvers: readonly ServiceResolver[],
): { hops: ServiceHop[]; cut: ServiceCutReason | null } {
  const hops: ServiceHop[] = [];
  const seen = new Set<string>();
  let at: Endpoint = start;
  for (;;) {
    const key = `${at.assetId}:${at.port}`;
    if (seen.has(key)) return { hops, cut: 'cycle' };
    seen.add(key);
    if (hops.length >= SERVICE_MAX_HOPS) return { hops, cut: 'max_hops' };
    const asset = ctx.get(at.assetId);
    if (!asset) return { hops, cut: 'unknown_upstream' };
    const resolver = resolvers.find((r) => r.applies(at, asset, ctx));
    if (!resolver) {
      // Un contenedor sin proxy es el destino final; un host sin nada escuchando, un corte.
      if (asset.docker) return { hops, cut: null };
      return { hops, cut: 'no_listener' };
    }
    const step = resolver.next(at, asset, ctx);
    if ('cut' in step) return { hops, cut: step.cut };
    if (step.hop) hops.push(step.hop);
    if (!step.next) return { hops, cut: null };
    at = step.next;
  }
}

function finish(
  record: ServiceRecord,
  hops: ServiceHop[],
  cut: ServiceCutReason | null,
  isPublic: boolean,
): ResolvedServicePath {
  const last = hops.findLast((h) => h.assetId) ?? null;
  const status: ResolvedServicePath['status'] = !hops.length
    ? 'none'
    : cut || !last
      ? 'partial'
      : 'complete';
  return {
    recordId: record.id,
    status,
    hops,
    finalAssetId: cut ? null : (last?.assetId ?? null),
    confidence: hops.length
      ? hops.every((h) => h.confidence === 'confirmed')
        ? 'confirmed'
        : 'deduced'
      : null,
    cutReason: cut ?? (hops.length && !last ? 'no_target' : null),
    public: isPublic,
  };
}

// --- Utilidades ---

/** ¿Algún nombre (exacto o comodín `*.x`) cubre este host? */
export function hostMatches(names: readonly string[], host: string): boolean {
  const h = host.toLowerCase();
  return names.some((n) => {
    const name = n.toLowerCase();
    if (name === h) return true;
    if (name.startsWith('*.')) {
      const base = name.slice(1);
      return h.endsWith(base) && !h.slice(0, -base.length).includes('.');
    }
    // server_name .example.com (nginx): el dominio y sus subdominios.
    if (name.startsWith('.')) return h === name.slice(1) || h.endsWith(name);
    return false;
  });
}

function worst(a: HopConfidence, b: HopConfidence): HopConfidence {
  return a === 'confirmed' && b === 'confirmed' ? 'confirmed' : 'deduced';
}

function isIp(v: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v);
}

function normIp(v: string): string {
  return v.trim().toLowerCase().replace(/^\[|\]$/g, '');
}
