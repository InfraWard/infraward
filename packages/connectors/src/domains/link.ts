import type {
  AssetStatus,
  AssetType,
  DnsCheckLevel,
  DnsCheckReason,
} from '@infraward/shared-types';
import { isIP } from 'node:net';
import { inZone } from './domain-provider.js';

// --- IPs de los assets del inventario ---

/** Tipos a los que puede apuntar un A/AAAA (los contenedores llegan a través de su host). */
export const IP_TARGET_TYPES = [
  'server',
  'vm',
  'lxc',
] as const satisfies readonly AssetType[];

/** Interfaces virtuales: sus IPs se repiten entre hosts (172.17.0.1 en todo host Docker). */
const VIRTUAL_IFACE =
  /^(lo|docker\d*|br-[0-9a-f]+|veth|virbr|cni|flannel|cali|tailscale|wg)/;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** IP en forma canónica (IPv6 comprimida y en minúsculas), sin prefijo; null si no es una IP. */
export function normalizeIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const ip = value.trim().split('/')[0].replace(/^\[|\]$/g, '');
  const version = isIP(ip);
  if (version === 4) return ip.split('.').map((o) => String(Number(o))).join('.');
  if (version === 6) {
    try {
      return new URL(`http://[${ip}]/`).hostname.slice(1, -1);
    } catch {
      return null;
    }
  }
  return null;
}

/** Loopback, sin especificar o de enlace local: nunca identifican a un asset. */
function unusable(ip: string): boolean {
  return (
    ip.startsWith('127.') ||
    ip === '0.0.0.0' ||
    ip.startsWith('169.254.') ||
    ip === '::1' ||
    ip === '::' ||
    /^fe[89ab][0-9a-f]:/.test(ip)
  );
}

/** IP privada: RFC 1918, CGNAT (100.64/10) o IPv6 ULA (fc00::/7). */
export function isPrivateIp(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  return /^f[cd][0-9a-f]{2}:/.test(ip);
}

/**
 * IPs con las que se identifica un servidor, VM o CT: sus interfaces reales (recogidas o de
 * Proxmox), las fijas de `net0`…`net9` y el host de conexión si es una IP (p. ej. la pública de
 * un NAT). Sin loopback, enlace local ni interfaces virtuales.
 */
export function assetIps(
  facts: Record<string, unknown>,
  connection: unknown,
): string[] {
  const out = new Set<string>();
  const add = (v: unknown): void => {
    const ip = normalizeIp(v);
    if (ip && !unusable(ip)) out.add(ip);
  };
  const interfaces = (list: unknown): void => {
    if (!Array.isArray(list)) return;
    for (const iface of list) {
      if (!isObj(iface)) continue;
      if (VIRTUAL_IFACE.test(String(iface.name ?? ''))) continue;
      for (const key of ['ipv4', 'ipv6'] as const) {
        const ips = iface[key];
        if (Array.isArray(ips)) ips.forEach(add);
      }
    }
  };
  if (isObj(facts.network)) {
    interfaces(facts.network.interfaces);
    add(facts.network.defaultIpv4);
  }
  if (isObj(facts.proxmox)) {
    interfaces(facts.proxmox.interfaces);
    const config = facts.proxmox.config;
    if (isObj(config))
      for (let i = 0; i < 10; i++) {
        const net = config[`net${i}`];
        if (typeof net !== 'string') continue;
        for (const m of net.matchAll(/(?:^|,)ip6?=([^,]+)/g)) add(m[1]);
      }
  }
  if (isObj(connection)) add(connection.host);
  return [...out];
}

// --- Enlazado y registros colgantes ---

export interface LinkTarget {
  id: string;
  type: AssetType;
  status: AssetStatus;
}

/** Registro A, AAAA o CNAME a comprobar. */
export interface LinkRecord {
  id: string;
  type: 'A' | 'AAAA' | 'CNAME';
  name: string;
  content: string;
}

/** Resultado DNS de un CNAME externo. */
export type CnameLookup = 'exists' | 'nxdomain' | 'error';

export interface LinkInput {
  records: LinkRecord[];
  /** IP canónica → assets (`IP_TARGET_TYPES`) con esa IP, de cualquier estado. */
  ips: ReadonlyMap<string, readonly LinkTarget[]>;
  /** Zonas inventariadas (nombre → id del asset `domain`). */
  zones: ReadonlyMap<string, string>;
  /** Nombre → ids de los registros activos con ese nombre (también los comodín, `*.x`). */
  names: ReadonlyMap<string, readonly string[]>;
  /** Resultados DNS de los destinos CNAME externos (si falta, «sin comprobar»). */
  cnames: ReadonlyMap<string, CnameLookup>;
}

export interface RecordLink {
  recordId: string;
  /** Destinos de `resolves_to` (assets, registros o el dominio). */
  targets: string[];
  level: DnsCheckLevel | null;
  reason: DnsCheckReason;
  target: string;
  ambiguous: boolean;
  takeoverService: string | null;
}

/**
 * Servicios en los que un CNAME a un nombre que ya no existe se puede reclamar (subdomain
 * takeover). Solo añade contexto al aviso: el aviso lo da el NXDOMAIN.
 */
const TAKEOVER_SERVICES: readonly [RegExp, string][] = [
  [/\.herokuapp\.com$|\.herokudns\.com$/, 'Heroku'],
  [/\.github\.io$/, 'GitHub Pages'],
  [/\.azurewebsites\.net$|\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azureedge\.net$/, 'Azure'],
  [/\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$|\.s3-website[.-]/, 'Amazon S3'],
  [/\.elasticbeanstalk\.com$/, 'AWS Elastic Beanstalk'],
  [/\.cloudfront\.net$/, 'Amazon CloudFront'],
  [/\.netlify\.(app|com)$/, 'Netlify'],
  [/\.vercel\.app$|\.vercel-dns\.com$/, 'Vercel'],
  [/\.pantheonsite\.io$/, 'Pantheon'],
  [/\.ghost\.io$/, 'Ghost'],
  [/\.myshopify\.com$/, 'Shopify'],
  [/\.surge\.sh$/, 'Surge'],
  [/\.readthedocs\.io$/, 'Read the Docs'],
  [/\.fly\.dev$/, 'Fly.io'],
  [/\.bitbucket\.io$/, 'Bitbucket'],
  [/\.wordpress\.com$/, 'WordPress.com'],
  [/\.zendesk\.com$/, 'Zendesk'],
];

const TUNNEL = /\.cfargotunnel\.com$/;

/** Servicio susceptible de takeover al que apunta un nombre, o null. */
export function takeoverService(name: string): string | null {
  return TAKEOVER_SERVICES.find(([re]) => re.test(name))?.[1] ?? null;
}

const ACTIVE: readonly AssetStatus[] = ['active', 'pending_enrollment'];

/**
 * Enlaces `resolves_to` y estado de cada registro (DESIGN §13), sin efectos:
 * - A/AAAA → los assets activos con esa IP (varios: todos, `ambiguous`). Si solo la tienen
 *   assets retirados o desaparecidos, se enlazan igual y el aviso es **alto**; si nadie la tiene,
 *   **alto** si es privada (debería estar en el inventario) e **informativo** si es pública.
 * - CNAME a un nombre de una zona inventariada → sus registros (o un comodín que lo cubra, o el
 *   dominio si es la raíz); sin ninguno, **alto**. Externo: NXDOMAIN ⇒ **alto** (takeover); si
 *   resuelve pero es un servicio con DNS comodín (Heroku…), **informativo**; túnel de Cloudflare,
 *   sin aviso; error del resolutor ⇒ sin comprobar.
 */
export function linkDnsRecords(input: LinkInput): RecordLink[] {
  return input.records.map((r) =>
    r.type === 'CNAME' ? linkCname(r, input) : linkAddress(r, input),
  );
}

function linkAddress(r: LinkRecord, input: LinkInput): RecordLink {
  const ip = normalizeIp(r.content);
  const base = {
    recordId: r.id,
    target: ip ?? r.content.slice(0, 255),
    ambiguous: false,
    takeoverService: null,
  };
  if (!ip) return { ...base, targets: [], level: null, reason: 'unchecked' };
  const owners = (input.ips.get(ip) ?? []).filter((o) =>
    (IP_TARGET_TYPES as readonly string[]).includes(o.type),
  );
  const active = owners.filter((o) => ACTIVE.includes(o.status));
  if (active.length > 0)
    return {
      ...base,
      targets: active.map((o) => o.id).sort(),
      level: null,
      reason: 'linked',
      ambiguous: active.length > 1,
    };
  if (owners.length > 0)
    return {
      ...base,
      targets: owners.map((o) => o.id).sort(),
      level: 'high',
      reason: 'retired_target',
      ambiguous: owners.length > 1,
    };
  return isPrivateIp(ip)
    ? { ...base, targets: [], level: 'high', reason: 'private_unknown' }
    : { ...base, targets: [], level: 'info', reason: 'public_unknown' };
}

function linkCname(r: LinkRecord, input: LinkInput): RecordLink {
  const target = r.content.trim().toLowerCase().replace(/\.$/, '');
  const base = {
    recordId: r.id,
    target: target.slice(0, 255),
    ambiguous: false,
    takeoverService: null,
  };
  const zone = [...input.zones.keys()]
    .filter((z) => inZone(target, z))
    .sort((a, b) => b.length - a.length)[0];
  if (zone !== undefined) {
    const exact = (input.names.get(target) ?? []).filter((id) => id !== r.id);
    const wildcard =
      exact.length > 0 ? [] : (input.names.get(wildcardOf(target)) ?? []);
    const targets = [...exact, ...wildcard];
    if (targets.length === 0 && target === zone)
      targets.push(input.zones.get(zone)!);
    return targets.length > 0
      ? { ...base, targets: targets.sort(), level: null, reason: 'cname_internal' }
      : { ...base, targets: [], level: 'high', reason: 'cname_internal_missing' };
  }
  if (TUNNEL.test(target))
    return { ...base, targets: [], level: null, reason: 'cname_tunnel' };
  const lookup = input.cnames.get(target);
  if (lookup === 'nxdomain')
    return {
      ...base,
      targets: [],
      level: 'high',
      reason: 'cname_nxdomain',
      takeoverService: takeoverService(target),
    };
  if (lookup === 'exists') {
    // Heroku, GitHub Pages o S3 responden a cualquier nombre (DNS comodín): que resuelva no dice
    // que la app siga siendo tuya. Informativo, para revisarlo (y marcarlo como esperado).
    const service = takeoverService(target);
    return service
      ? { ...base, targets: [], level: 'info', reason: 'cname_takeover_service', takeoverService: service }
      : { ...base, targets: [], level: null, reason: 'cname_external' };
  }
  return { ...base, targets: [], level: null, reason: 'unchecked' };
}

/** `a.b.c` → `*.b.c`. */
function wildcardOf(name: string): string {
  const dot = name.indexOf('.');
  return dot < 0 ? name : `*${name.slice(dot)}`;
}

/** Destinos CNAME externos (fuera de las zonas inventariadas y sin túneles) que hay que resolver. */
export function externalCnameTargets(
  records: readonly { type: string; content: string }[],
  zones: Iterable<string>,
): string[] {
  const zoneList = [...zones];
  const out = new Set<string>();
  for (const r of records) {
    if (r.type !== 'CNAME') continue;
    const target = r.content.trim().toLowerCase().replace(/\.$/, '');
    if (!target || TUNNEL.test(target)) continue;
    if (zoneList.some((z) => inZone(target, z))) continue;
    out.add(target);
  }
  return [...out].sort();
}
