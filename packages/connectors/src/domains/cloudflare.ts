import {
  DNS_RECORD_TYPES,
  type CloudflareTunnel,
  type DnsRecordType,
  type TunnelIngress,
  byCodeUnit,
} from '@infraward/shared-types';
import {
  DomainApiError,
  dnsName,
  type DomainApi,
  type DomainProvider,
  type ProviderListing,
  type ProviderRecord,
  type ProviderTunnels,
  type ProviderVerification,
  type ProviderZone,
} from './domain-provider.js';

/** Máximo de zonas por página que admite Cloudflare. */
const ZONES_PER_PAGE = 50;
/** Registros por página (Cloudflare admite muchos más; así una página no pesa demasiado). */
const RECORDS_PER_PAGE = 1000;
/** Tope de páginas por listado (50 000 zonas o un millón de registros por zona). */
const MAX_PAGES = 1000;

const ZONE_ID = /^[0-9a-f]{32}$/;
const ACCOUNT_ID = /^[0-9a-f]{32}$/;
const TUNNEL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Túneles por página y tope por cuenta. */
const TUNNELS_PER_PAGE = 50;
const MAX_TUNNELS = 200;
const MAX_INGRESS = 200;
/** Servicio de una regla de entrada: `http://host:puerto`, `tcp://…`, `http_status:404`… */
const TUNNEL_SERVICE =
  /^(?:(?:https?|tcp|ssh|rdp|smb|unix|unix\+tls|socks5|h2mux):\/\/[A-Za-z0-9_.:[\]/-]+|http_status:\d{3}|hello_world|bastion)$/;
const RECORD_ID = /^[0-9a-f]{32}$/;

interface Envelope {
  success?: unknown;
  result?: unknown;
  result_info?: { total_pages?: unknown };
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null =>
  typeof v === 'string' && v.length > 0 ? v : null;

/**
 * Conector de Cloudflare (DESIGN §13): zonas y registros DNS con un API token de **solo
 * lectura** (permisos *Zone:Read* y *DNS:Read*). Nunca escribe nada.
 */
export class CloudflareProvider implements DomainProvider {
  readonly kind = 'cloudflare' as const;

  async verify(api: DomainApi): Promise<ProviderVerification> {
    const warnings: string[] = [];
    // Token de usuario; uno de cuenta no vale aquí (lo comprueba su cuenta, abajo).
    type Token = { status: string | null; expiresOn: string | null };
    let token: Token | Error = await this.verifyAt(
      api,
      '/user/tokens/verify',
    ).catch((e: unknown) => asError(e));
    let zones: ProviderZone[] = [];
    let zonesError: unknown = null;
    try {
      zones = await this.zones(api);
    } catch (e) {
      zonesError = e;
    }
    if (token instanceof Error && zones.length > 0) {
      const account = zones.find((z) => z.account)?.account?.id;
      if (account)
        token = await this.verifyAt(
          api,
          `/accounts/${encodeURIComponent(account)}/tokens/verify`,
        ).catch((e: unknown) => asError(e));
    }
    if (token instanceof Error) {
      return failure(message(token), zones.length);
    }
    if (zonesError) {
      return {
        ...failure(
          `el token es válido pero no puede listar las zonas (${message(zonesError)}): necesita el permiso Zone:Read`,
          0,
        ),
        tokenStatus: token.status,
        tokenExpiresAt: token.expiresOn,
      };
    }
    if (token.status !== 'active') {
      return {
        ...failure(`el token está ${token.status ?? 'inactivo'}`, zones.length),
        tokenStatus: token.status,
        tokenExpiresAt: token.expiresOn,
      };
    }
    if (zones.length === 0)
      warnings.push(
        'el token no ve ninguna zona: revisa el permiso Zone:Read y las zonas que incluye',
      );
    else {
      try {
        await api.getJson(`/zones/${zones[0].id}/dns_records`, {
          page: 1,
          per_page: 1,
        });
      } catch (e) {
        warnings.push(
          `no puede leer los registros DNS (${message(e)}): necesita el permiso DNS:Read`,
        );
      }
      // Opcional (QoL-5b): sin él no se sigue el camino de los nombres servidos por un túnel.
      const account = zones.find((z) => z.account)?.account?.id;
      if (account && ACCOUNT_ID.test(account))
        try {
          await api.getJson(`/accounts/${account}/cfd_tunnel`, {
            page: 1,
            per_page: 1,
          });
        } catch {
          warnings.push(
            'sin el permiso opcional Account · Cloudflare Tunnel · Read: no se verá qué sirve los nombres de un túnel',
          );
        }
    }
    return {
      ok: true,
      error: null,
      tokenStatus: token.status,
      tokenExpiresAt: token.expiresOn,
      accounts: [
        ...new Set(
          zones.map((z) => z.account?.name ?? z.account?.id).filter(isString),
        ),
      ].sort(byCodeUnit),
      zones: zones.length,
      warnings,
    };
  }

  async list(api: DomainApi): Promise<ProviderListing> {
    const warnings: string[] = [];
    const zones = await this.zones(api, warnings);
    let complete = true;
    const records: ProviderRecord[] = [];
    for (const zone of zones) {
      try {
        const rows = await this.pages(
          api,
          `/zones/${zone.id}/dns_records`,
          RECORDS_PER_PAGE,
        );
        for (const row of rows) {
          const record = parseRecord(row, zone.id);
          if (record === 'skip') continue;
          if (!record) {
            complete = false;
            warnings.push(`${zone.name}: registro que no se entiende`);
            continue;
          }
          records.push(record);
        }
      } catch (e) {
        complete = false;
        warnings.push(`${zone.name}: no se pudieron listar los registros (${message(e)})`);
      }
    }
    if (warnings.some((w) => w.startsWith('zona que no se entiende')))
      complete = false;
    return { zones, records, complete, warnings };
  }

  private async verifyAt(
    api: DomainApi,
    path: string,
  ): Promise<{ status: string | null; expiresOn: string | null }> {
    const body = envelope(await api.getJson(path));
    const result = isObj(body.result) ? body.result : {};
    return { status: str(result.status), expiresOn: str(result.expires_on) };
  }

  private async zones(
    api: DomainApi,
    warnings: string[] = [],
  ): Promise<ProviderZone[]> {
    const rows = await this.pages(api, '/zones', ZONES_PER_PAGE);
    const zones: ProviderZone[] = [];
    for (const row of rows) {
      const zone = parseZone(row);
      if (zone) zones.push(zone);
      else warnings.push('zona que no se entiende');
    }
    return zones;
  }

  /**
   * Túneles de Cloudflare de las cuentas (permiso opcional *Account · Cloudflare Tunnel · Read*).
   * De cada regla de entrada solo el nombre, la ruta y el servicio: nunca `originRequest`
   * (cabeceras, Access…). Un túnel gestionado localmente (config.yml) no tiene reglas en la API.
   */
  async tunnels(api: DomainApi, accounts: string[]): Promise<ProviderTunnels> {
    const items: CloudflareTunnel[] = [];
    let complete = true;
    let error: string | null = null;
    for (const account of [...new Set(accounts)].filter((a) => ACCOUNT_ID.test(a))) {
      let rows: unknown[];
      try {
        rows = await this.pages(
          api,
          `/accounts/${account}/cfd_tunnel`,
          TUNNELS_PER_PAGE,
          { is_deleted: 'false' },
        );
      } catch (e) {
        complete = false;
        error =
          e instanceof DomainApiError && (e.status === 403 || e.status === 401)
            ? 'el token no tiene el permiso Account · Cloudflare Tunnel · Read (opcional)'
            : message(e);
        continue;
      }
      for (const row of rows.slice(0, MAX_TUNNELS)) {
        if (!isObj(row) || !str(row.id) || !TUNNEL_ID.test(row.id as string))
          continue;
        const id = row.id as string;
        const remote =
          row.remote_config === true || row.config_src === 'cloudflare';
        let ingress: TunnelIngress[] | null = null;
        if (remote) {
          try {
            const body = envelope(
              await api.getJson(`/accounts/${account}/cfd_tunnel/${id}/configurations`),
            );
            ingress = parseIngress(body.result);
          } catch (e) {
            complete = false;
            error ??= `túnel ${str(row.name) ?? id}: ${message(e)}`;
          }
        }
        items.push({
          id,
          name: (str(row.name) ?? id).slice(0, 255),
          status: str(row.status)?.slice(0, 32) ?? null,
          ingress,
        });
      }
    }
    return { items, complete, error };
  }

  /** Todas las páginas de un listado (`result_info.total_pages`). */
  private async pages(
    api: DomainApi,
    path: string,
    perPage: number,
    extra: Record<string, string> = {},
  ): Promise<unknown[]> {
    const out: unknown[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const body = envelope(
        await api.getJson(path, { ...extra, page, per_page: perPage }),
      );
      if (!Array.isArray(body.result))
        throw new DomainApiError('respuesta sin lista de resultados', null);
      out.push(...body.result);
      const total = Number(body.result_info?.total_pages ?? 1);
      if (!Number.isFinite(total) || page >= total || body.result.length === 0)
        return out;
    }
    throw new DomainApiError(`más de ${MAX_PAGES} páginas`, null);
  }
}

function envelope(value: unknown): Envelope {
  if (!isObj(value) || value.success !== true)
    throw new DomainApiError('respuesta de Cloudflare sin éxito', null);
  return value as Envelope;
}

/** Reglas de entrada de `…/configurations`: solo nombre, ruta y servicio. */
export function parseIngress(result: unknown): TunnelIngress[] | null {
  const config = isObj(result) && isObj(result.config) ? result.config : null;
  if (!config || !Array.isArray(config.ingress)) return null;
  const out: TunnelIngress[] = [];
  for (const rule of config.ingress.slice(0, MAX_INGRESS)) {
    if (!isObj(rule) || typeof rule.service !== 'string') continue;
    // Sin `usuario:contraseña@` si alguien lo puso en la URL del servicio.
    const service = rule.service.trim().replace(/:\/\/[^/@]*@/, '://');
    if (!TUNNEL_SERVICE.test(service) || service.length > 256) continue;
    const hostname =
      rule.hostname === undefined || rule.hostname === null
        ? null
        : dnsName(rule.hostname);
    if (rule.hostname && !hostname) continue;
    const path =
      typeof rule.path === 'string' && /^[A-Za-z0-9._~/^$*+?()|\\-]{1,256}$/.test(rule.path)
        ? rule.path
        : null;
    out.push({ hostname, path, service });
  }
  return out;
}

function parseZone(row: unknown): ProviderZone | null {
  if (!isObj(row)) return null;
  const id = str(row.id);
  const name = dnsName(row.name);
  if (!id || !ZONE_ID.test(id) || !name || name.startsWith('*')) return null;
  const account = isObj(row.account)
    ? { id: str(row.account.id) ?? '', name: str(row.account.name) }
    : null;
  return {
    id,
    name,
    status: str(row.status),
    paused: row.paused === true,
    nameServers: Array.isArray(row.name_servers)
      ? row.name_servers.map(dnsName).filter(isString).slice(0, 20)
      : [],
    plan: isObj(row.plan) ? str(row.plan.name) : null,
    account: account?.id ? account : null,
  };
}

/** Un registro, `skip` si es de un tipo que no se inventaría o null si no se entiende. */
function parseRecord(row: unknown, zoneId: string): ProviderRecord | 'skip' | null {
  if (!isObj(row)) return null;
  const type = str(row.type);
  if (!type) return null;
  if (!(DNS_RECORD_TYPES as readonly string[]).includes(type)) return 'skip';
  const id = str(row.id);
  const name = dnsName(row.name);
  const content = typeof row.content === 'string' ? row.content : null;
  if (!id || !RECORD_ID.test(id) || !name || content === null) return null;
  const ttl = Number(row.ttl);
  const priority = Number(row.priority);
  return {
    id,
    zoneId,
    name,
    type: type as DnsRecordType,
    content,
    ttl: Number.isInteger(ttl) ? ttl : null,
    proxied: row.proxied === true,
    priority: row.priority === undefined || !Number.isInteger(priority) ? null : priority,
  };
}

function failure(error: string, zones: number): ProviderVerification {
  return {
    ok: false,
    error,
    tokenStatus: null,
    tokenExpiresAt: null,
    accounts: [],
    zones,
    warnings: [],
  };
}

function message(e: unknown): string {
  return e instanceof DomainApiError ? e.message : 'error inesperado';
}

function asError(e: unknown): Error {
  return e instanceof Error ? e : new Error('error inesperado');
}

function isString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}
