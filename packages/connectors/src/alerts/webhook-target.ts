import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isPrivateIp } from '../domains/link.js';

/** Qué destinos admite un webhook de alertas (DESIGN §10, SECURITY-NOTES). */
export interface WebhookTargetPolicy {
  /** Permitir `http:` (por defecto solo `https:`). */
  allowHttp?: boolean;
  /** Permitir IPs privadas (RFC 1918, CGNAT, ULA): un homelab con su ntfy o n8n. */
  allowPrivate?: boolean;
}

export type WebhookLookup = (
  hostname: string,
) => Promise<readonly { address: string; family: number }[]>;

const defaultLookup: WebhookLookup = (hostname) =>
  dnsLookup(hostname, { all: true, verbatim: true });

/** URL de webhook rechazada: el motivo es apto para enseñarlo (sin la URL). */
export class WebhookTargetError extends Error {
  override readonly name = 'WebhookTargetError';
}

/** Forma canónica de una IP (sin corchetes; IPv4 mapeada en IPv6 → IPv4). */
function canonicalIp(ip: string): string {
  const bare = ip.replace(/^\[|\]$/g, '').toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(bare);
  return mapped ? mapped[1]! : bare;
}

/**
 * Los 8 grupos de 16 bits de una IPv6 (con `::`, una IPv4 al final y zona `%eth0`); null si no es
 * una IPv6 válida.
 */
export function ipv6Groups(ip: string): number[] | null {
  let addr = ip.replace(/%.*$/, '');
  if (isIP(addr) !== 6) return null;
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(addr);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number];
    addr = `${addr.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = addr.split('::') as [string, string | undefined];
  const parse = (part: string) => (part ? part.split(':').map((g) => parseInt(g, 16)) : []);
  const left = parse(head);
  const right = tail === undefined ? [] : parse(tail);
  const zeros = tail === undefined ? 0 : 8 - left.length - right.length;
  const groups = [...left, ...Array<number>(zeros).fill(0), ...right];
  return groups.length === 8 ? groups : null;
}

/**
 * Nunca, aunque se permitan las privadas: loopback, sin especificar, enlace local (incluidos los
 * metadatos de las nubes, 169.254.169.254), multicast y reservadas. En IPv6, además, los rangos que
 * llevan una IPv4 dentro o la traducen (IPv4 compatible `::/96` y mapeada `::ffff:0:0/96`, NAT64
 * `64:ff9b::/96` y `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`): sirven para llegar a
 * una IPv4 interna sin que lo parezca. También `100::/64` (descarte) y `fec0::/10` (site-local).
 */
export function isForbiddenWebhookIp(ip: string): boolean {
  const addr = canonicalIp(ip);
  if (isIP(addr) === 4) {
    const [a, b] = addr.split('.').map(Number) as [number, number];
    return (
      a === 0 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      a >= 224 ||
      (a === 192 && b === 0 && addr.startsWith('192.0.0.')) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }
  const g = ipv6Groups(addr);
  // Lo que no se entiende, fuera.
  if (!g) return true;
  const [g0, g1, g2, g3, g4, g5] = g as [number, number, number, number, number, number];
  const zeroTo = (n: number) => g.slice(0, n).every((x) => x === 0);
  return (
    // ::/96: sin especificar, loopback e IPv4 compatible (`::7f00:1` = 127.0.0.1).
    zeroTo(6) ||
    // ::ffff:0:0/96 (mapeada; la de puntos ya se trató como IPv4) y ::ffff:0:0:0/96 (traducida).
    (zeroTo(5) && g5 === 0xffff) ||
    (zeroTo(4) && g4 === 0xffff && g5 === 0) ||
    // NAT64.
    (g0 === 0x64 && g1 === 0xff9b && (g2 === 1 || (g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0))) ||
    // 6to4 y Teredo.
    g0 === 0x2002 ||
    (g0 === 0x2001 && g1 === 0) ||
    // Descarte.
    (g0 === 0x100 && g1 === 0 && g2 === 0 && g3 === 0) ||
    // Enlace local fe80::/10, site-local fec0::/10 y multicast ff00::/8.
    (g0 & 0xffc0) === 0xfe80 ||
    (g0 & 0xffc0) === 0xfec0 ||
    (g0 & 0xff00) === 0xff00
  );
}

/**
 * Comprueba la forma de la URL de un webhook: `https:` (o `http:` si se permite), sin usuario ni
 * contraseña en la URL. Devuelve la URL normalizada.
 */
export function parseWebhookUrl(raw: string, policy: WebhookTargetPolicy = {}): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new WebhookTargetError('URL no válida');
  }
  if (url.protocol !== 'https:' && !(policy.allowHttp && url.protocol === 'http:'))
    throw new WebhookTargetError(
      policy.allowHttp ? 'La URL tiene que ser http(s)' : 'La URL tiene que ser https',
    );
  if (url.username || url.password)
    throw new WebhookTargetError('La URL no puede llevar usuario ni contraseña');
  if (!url.hostname) throw new WebhookTargetError('La URL no tiene host');
  return url;
}

/**
 * Resuelve el host del webhook y devuelve la dirección con la que conectar (la primera admitida).
 * Rechaza el destino si **alguna** de sus direcciones está prohibida (o es privada sin permitirlo):
 * así un nombre con una IP pública y otra interna no sirve para llegar dentro. Conectar a la
 * dirección devuelta (y no volver a resolver) evita el DNS rebinding.
 */
export async function resolveWebhookTarget(
  url: URL,
  policy: WebhookTargetPolicy = {},
  lookup: WebhookLookup = defaultLookup,
): Promise<{ address: string; family: 4 | 6 }> {
  const host = url.hostname.replace(/^\[|\]$/g, '');
  let addresses: { address: string; family: number }[];
  if (isIP(host)) addresses = [{ address: host, family: isIP(host) }];
  else {
    try {
      addresses = [...(await lookup(host))];
    } catch {
      throw new WebhookTargetError('No se pudo resolver el host');
    }
  }
  if (!addresses.length) throw new WebhookTargetError('El host no tiene direcciones');
  for (const { address } of addresses) {
    const ip = canonicalIp(address);
    if (isForbiddenWebhookIp(ip))
      throw new WebhookTargetError(
        'El host resuelve a una dirección no permitida (loopback, enlace local o reservada)',
      );
    if (!policy.allowPrivate && isPrivateIp(ip))
      throw new WebhookTargetError(
        'El host resuelve a una IP privada (permítelas con ALERTS_WEBHOOK_ALLOW_PRIVATE)',
      );
  }
  const first = addresses[0]!;
  return { address: canonicalIp(first.address), family: first.family === 6 ? 6 : 4 };
}
