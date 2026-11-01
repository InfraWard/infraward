import type { CnameLookup } from '@infraward/connectors';
import { Resolver } from 'node:dns/promises';
import type { LookupFunction } from 'node:net';

/**
 * Resultado de comprobar un nombre a partir de los códigos de error de sus consultas A, AAAA y
 * CNAME (null = respondió con datos). NXDOMAIN (`ENOTFOUND`) en todas ⇒ no existe; si alguna dice
 * «sin datos de este tipo» (`ENODATA`, p. ej. un nombre de DKIM que solo tiene TXT), el nombre
 * existe; cualquier otro error ⇒ no se sabe.
 */
export function classifyLookup(codes: readonly (string | null)[]): CnameLookup {
  if (codes.includes(null)) return 'exists';
  if (codes.every((c) => c === 'ENOTFOUND')) return 'nxdomain';
  if (codes.every((c) => c === 'ENOTFOUND' || c === 'ENODATA')) return 'exists';
  return 'error';
}

/**
 * Resolución DNS de los dominios: comprobar si existe el destino de un CNAME externo y, si se
 * configuran servidores propios (`DOMAINS_DNS_SERVERS`), resolver los nombres del 443.
 */
export class DomainResolver {
  private readonly resolver: Resolver;

  constructor(
    servers: string[] | null,
    timeoutMs: number,
  ) {
    this.resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
    if (servers?.length) this.resolver.setServers(servers);
    this.custom = !!servers?.length;
  }

  /** Hay servidores propios: el 443 también resuelve con ellos. */
  readonly custom: boolean;

  /**
   * ¿Existe `name`? Ver `classifyLookup`: solo un NXDOMAIN en todas las consultas dice que no.
   */
  async cname(name: string): Promise<CnameLookup> {
    const results = await Promise.allSettled([
      this.resolver.resolve4(name),
      this.resolver.resolve6(name),
      this.resolver.resolveCname(name),
    ]);
    return classifyLookup(
      results.map((r) =>
        r.status === 'fulfilled'
          ? r.value.length > 0
            ? null
            : 'ENODATA'
          : ((r.reason as NodeJS.ErrnoException).code ?? 'EUNKNOWN'),
      ),
    );
  }

  /** `lookup` para `tls.connect` con estos servidores (IPv4 primero). */
  lookup(): LookupFunction {
    return (hostname, options, callback) => {
      void (async () => {
        let address: string | undefined;
        let family = 4;
        try {
          address = (await this.resolver.resolve4(hostname))[0];
        } catch {
          // probamos IPv6
        }
        if (!address) {
          try {
            address = (await this.resolver.resolve6(hostname))[0];
            family = 6;
          } catch {
            // sin dirección
          }
        }
        if (!address) {
          const error = Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), {
            code: 'ENOTFOUND',
          });
          callback(error, '', 4);
          return;
        }
        if (options.all) callback(null, [{ address, family }]);
        else callback(null, address, family);
      })();
    };
  }
}

/** `DOMAINS_DNS_SERVERS` → lista para `setServers` (o null). */
export function dnsServers(value: string | undefined): string[] | null {
  const list = (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length ? list : null;
}
