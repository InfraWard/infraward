import type {
  CloudflareTunnel,
  ConnectorVerification,
  DnsRecordType,
  DomainProviderKind,
} from '@infraward/shared-types';

/**
 * Acceso de solo lectura a la API de un proveedor de dominios, ya autenticado. Lo da el worker
 * (que resuelve el token con `SecretsService`): el conector no ve nunca el token.
 * `getJson` devuelve el cuerpo JSON de una respuesta 2xx y, si no, lanza `DomainApiError`.
 */
export interface DomainApi {
  getJson(
    path: string,
    query?: Record<string, string | number>,
  ): Promise<unknown>;
}

/**
 * Error de la API del proveedor con un mensaje apto para guardarse y mostrarse: el estado HTTP y
 * el código del proveedor, nunca el cuerpo completo ni las cabeceras (llevan el token).
 */
export class DomainApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly providerCode: number | null = null,
  ) {
    super(message);
  }
}

/** Zona (dominio) tal como la da el proveedor. */
export interface ProviderZone {
  id: string;
  /** En minúsculas y sin punto final. */
  name: string;
  status: string | null;
  paused: boolean;
  nameServers: string[];
  plan: string | null;
  account: { id: string; name: string | null } | null;
}

/** Registro DNS tal como lo da el proveedor. */
export interface ProviderRecord {
  id: string;
  zoneId: string;
  /** Nombre completo, en minúsculas y sin punto final. */
  name: string;
  type: DnsRecordType;
  content: string;
  ttl: number | null;
  proxied: boolean;
  priority: number | null;
}

export interface ProviderListing {
  zones: ProviderZone[];
  records: ProviderRecord[];
  /** false si falló alguna zona o página: entonces no se marca nada como desaparecido. */
  complete: boolean;
  warnings: string[];
}

/** Prueba del token, sin la fecha (la pone el worker). */
export type ProviderVerification = Omit<ConnectorVerification, 'checkedAt'>;

/**
 * Conector de un proveedor de dominios (DESIGN §13). De SOLO LECTURA: solo lista zonas y
 * registros. El worker compone el listado de assets, añade RDAP y certificados y reconcilia.
 */
export interface DomainProvider {
  readonly kind: DomainProviderKind;
  verify(api: DomainApi): Promise<ProviderVerification>;
  list(api: DomainApi): Promise<ProviderListing>;
  /**
   * Túneles de las cuentas (QoL-5b), si el proveedor los tiene. Solo nombres y servicios de sus
   * reglas de entrada; `error` si el token no tiene el permiso (opcional).
   */
  tunnels?(api: DomainApi, accounts: string[]): Promise<ProviderTunnels>;
}

export interface ProviderTunnels {
  items: CloudflareTunnel[];
  complete: boolean;
  error: string | null;
}

/** Nombre DNS válido (ASCII/punycode; un comodín inicial `*.`), en minúsculas y sin punto final. */
const DNS_NAME =
  /^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** Normaliza un nombre DNS (minúsculas, sin punto final); null si no es válido. */
export function dnsName(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const name = value.trim().toLowerCase().replace(/\.$/, '');
  return name.length > 0 && name.length <= 253 && DNS_NAME.test(name)
    ? name
    : null;
}

/** ¿`name` está en la zona `zone` (o es ella)? */
export function inZone(name: string, zone: string): boolean {
  return name === zone || name.endsWith(`.${zone}`);
}
