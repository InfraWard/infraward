// Qué servicio sirve cada dominio (QoL-5b, DESIGN §13): rutas de los proxies y caminos de
// registro DNS → asset final.
import type { AssetSummary } from './assets.js';

/** De dónde sale una ruta de proxy. */
export const PROXY_SOURCES = [
  'nginx',
  'npm',
  'traefik',
  'caddy',
  'tunnel',
] as const;
export type ProxySource = (typeof PROXY_SOURCES)[number];

/**
 * Host de un upstream que es el propio contenedor que declara la ruta (etiquetas de Traefik y
 * Caddy: el proxy envía al contenedor etiquetado).
 */
export const PROXY_SELF_HOST = '@self';

/** Topes de lo que se guarda de un proxy. */
export const PROXY_MAX_ROUTES = 500;
export const PROXY_MAX_HOSTS = 20;
export const PROXY_MAX_UPSTREAMS = 10;

export interface ProxyUpstream {
  /** `http`, `https`, `grpc`, `fastcgi`, `uwsgi`, `tcp`… (null si no se sabe). */
  scheme: string | null;
  /** Nombre, IP o `PROXY_SELF_HOST`. */
  host: string;
  /** null = el puerto por defecto del esquema. */
  port: number | null;
}

/**
 * Una ruta de un proxy: SOLO nombres de host y destinos. Nunca cabeceras, credenciales ni el
 * resto de la configuración (nginx -T se filtra en el propio servidor, DESIGN §7).
 */
export interface ProxyRoute {
  source: ProxySource;
  /** Nombres que atiende (`server_name`, `Host(...)`); vacío = cualquiera (por defecto). */
  hosts: string[];
  /** Puertos en los que escucha (vacío = los del proxy). */
  listen: number[];
  /** `default_server` en alguno de sus `listen`. */
  isDefault: boolean;
  /** Prefijo de ruta (`location`), null = `/`. */
  path: string | null;
  /** Destinos; vacío = lo sirve el propio proxy (estático, redirección). */
  upstreams: ProxyUpstream[];
}

/** Configuración leída de un proxy (nginx, NPM) de un host, CT o contenedor. */
export interface ProxyFacts {
  source: ProxySource;
  routes: ProxyRoute[];
  readAt: string;
  /** Había más rutas de las que se guardan. */
  truncated?: boolean;
}

/** Regla de entrada de un túnel de Cloudflare (solo nombre, ruta y servicio). */
export interface TunnelIngress {
  hostname: string | null;
  path: string | null;
  /** `http://localhost:8080`, `http_status:404`… */
  service: string;
}

export interface CloudflareTunnel {
  id: string;
  name: string;
  status: string | null;
  /** null = túnel gestionado localmente (config.yml): su configuración no está en la API. */
  ingress: TunnelIngress[] | null;
}

// --- Caminos ---

export const SERVICE_RESOLVER_KINDS = [
  'dns',
  'tunnel',
  'nat',
  'docker-proxy',
  'traefik',
  'caddy',
  'nginx',
  'npm',
  'listener',
  'manual',
] as const;
export type ServiceResolverKind = (typeof SERVICE_RESOLVER_KINDS)[number];

/** `confirmed`: lo dicen los datos (ss, configuración, publicación); `deduced`: inferido. */
export type HopConfidence = 'confirmed' | 'deduced';

export interface ServiceHop {
  /** Asset de este eslabón (null si no está en el inventario, p. ej. una IP pública). */
  assetId: string | null;
  /** Lo que se muestra: `nginx-proxy:443`, `203.0.113.7:443`… */
  label: string;
  port: number | null;
  /** Quién ha dado el salto hasta aquí. */
  resolver: ServiceResolverKind;
  /** De dónde sale (p. ej. `nginx: server_name app.x → 127.0.0.1:8080`). */
  source: string;
  confidence: HopConfidence;
}

export const SERVICE_PATH_STATUSES = [
  'complete',
  'partial',
  'manual',
  'none',
] as const;
/**
 * `complete`: llega a un asset final. `partial`: la cadena se corta (`cutReason`). `manual`:
 * destino fijado a mano. `none`: no hay por dónde empezar (registro sin destino).
 */
export type ServicePathStatus = (typeof SERVICE_PATH_STATUSES)[number];

export const SERVICE_CUT_REASONS = [
  'no_target',
  'no_listener',
  'no_route_for_host',
  'unknown_upstream',
  'proxy_unreadable',
  'tunnel_unknown',
  'tunnel_no_config',
  'no_cloudflared',
  'max_hops',
  'cycle',
] as const;
export type ServiceCutReason = (typeof SERVICE_CUT_REASONS)[number];

/** Máximo de saltos de un camino. */
export const SERVICE_MAX_HOPS = 10;

/** Resumen de un asset de un camino (para la web). */
export type ServicePathAsset = AssetSummary;

export interface ServiceHopView extends ServiceHop {
  asset: ServicePathAsset | null;
}

/** Camino de un registro DNS (`GET /assets/:id/service-path`). */
export interface ServicePathView {
  recordId: string;
  record: string;
  status: ServicePathStatus;
  confidence: HopConfidence | null;
  cutReason: ServiceCutReason | null;
  final: ServicePathAsset | null;
  hops: ServiceHopView[];
  /** Destino fijado a mano (gana al calculado, que sigue en `hops`). */
  pinned: { asset: ServicePathAsset; by: string | null; at: string } | null;
  computedAt: string | null;
}

/** Registro que sirve o atraviesa un asset (`GET /assets/:id/served-domains`). */
export interface ServedDomain {
  record: ServicePathAsset;
  /** `final`: el asset sirve el nombre; `via`: el tráfico pasa por él. */
  role: 'final' | 'via';
  status: ServicePathStatus;
  confidence: HopConfidence | null;
  final: ServicePathAsset | null;
}

/** Caminos de los registros de un dominio (`GET /assets/:id/service-paths`). */
export interface DomainServicePaths {
  paths: ServicePathView[];
}

/** `GET /assets/:id/served-domains`. */
export interface ServedDomains {
  records: ServedDomain[];
}

export interface ServicePinRequest {
  targetAssetId: string;
}

/** Tipos de asset que pueden ser el destino fijado a mano de un camino. */
export const SERVICE_PIN_TARGET_TYPES = [
  'server',
  'vm',
  'lxc',
  'container',
  'database',
] as const;

// --- Reenvíos NAT (Ajustes) ---

export interface NatForward {
  id: string;
  publicIp: string;
  publicPort: number;
  proto: 'tcp' | 'udp';
  target: ServicePathAsset;
  targetPort: number;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface NatForwardInput {
  publicIp: string;
  publicPort: number;
  proto?: 'tcp' | 'udp';
  targetAssetId: string;
  targetPort: number;
  description?: string | null;
}

/** Exposición pública de un asset con findings (priorización §9). */
export interface PublicExposure {
  /** Registros DNS públicos cuyo camino llega a él o pasa por él. */
  publicDomains: number;
  /** Uno de ellos, para mostrar. */
  sample: string | null;
}
