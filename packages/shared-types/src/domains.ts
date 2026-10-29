// Inventario de dominios (DESIGN §13, QoL-5): conectores, facts, comprobaciones y caducidades.
import type { AssetStatus, AssetSummary, AssetType } from './assets.js';
import type { CloudflareTunnel } from './service-paths.js';
import type { InventoryTrigger } from './inventory.js';

// --- Conectores ---

/** Proveedores de dominios con conector. */
export const DOMAIN_PROVIDER_KINDS = ['cloudflare'] as const;
export type DomainProviderKind = (typeof DOMAIN_PROVIDER_KINDS)[number];

/**
 * Catálogo de proveedores de dominios para la interfaz: qué se le pide al usuario y con qué
 * permisos. Añadir un proveedor = una entrada aquí (y su `DomainProvider` en el backend); la
 * pantalla de Ajustes > Conectores sale de esta tabla.
 */
export interface DomainProviderInfo {
  kind: DomainProviderKind;
  label: string;
  /** Icono de Bootstrap Icons (`bi-…`). */
  icon: string;
  /** Qué inventaría (en la lista de proveedores del alta). */
  description: string;
  /** Etiqueta del campo de la credencial. */
  credentialLabel: string;
  /** Dónde se crea la credencial. */
  credentialWhere: string;
  /** Permisos mínimos (de solo lectura) que necesita. */
  permissions: string[];
  /** Documentación del proveedor sobre la credencial. */
  docsUrl: string;
  /** Permisos que amplían lo que se ve, sin ser necesarios. */
  optionalPermissions?: string[];
}

export const DOMAIN_PROVIDERS: Record<DomainProviderKind, DomainProviderInfo> = {
  cloudflare: {
    kind: 'cloudflare',
    label: 'Cloudflare',
    icon: 'bi-cloud',
    description: 'Zonas y registros DNS de una cuenta (o de las zonas que permita el token).',
    credentialLabel: 'API token',
    credentialWhere: 'Mi perfil › API Tokens › Create Custom Token',
    permissions: ['Zone · Zone · Read', 'Zone · DNS · Read'],
    optionalPermissions: [
      'Account · Cloudflare Tunnel · Read (qué servicio sirve los nombres de un túnel)',
    ],
    docsUrl: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/',
  },
};

/** Campo del secreto de un conector (`secret://<proveedor>/connectors/<id>/<kind>#apiToken`). */
export const CONNECTOR_TOKEN_FIELD = 'apiToken';

/** Longitudes admitidas del token de API (Cloudflare: 40 caracteres; margen para otros). */
export const CONNECTOR_TOKEN_MIN_LENGTH = 20;
export const CONNECTOR_TOKEN_MAX_LENGTH = 512;

/** Resultado de la última prueba del token (`facts.connector.verify`). */
export interface ConnectorVerification {
  ok: boolean;
  checkedAt: string;
  /** Mensaje apto para mostrarse (estado HTTP y código del proveedor; nunca el token). */
  error: string | null;
  /** Estado del token según el proveedor (`active`, `disabled`, `expired`). */
  tokenStatus: string | null;
  /** Caducidad del token si la tiene. */
  tokenExpiresAt: string | null;
  /** Cuentas a las que dan acceso las zonas visibles. */
  accounts: string[];
  /** Zonas que puede leer. */
  zones: number;
  warnings: string[];
}

/** Facts del asset `dns_provider` (`facts.connector`). */
export interface ConnectorFacts {
  kind: DomainProviderKind;
  verify: ConnectorVerification | null;
  /** Última sincronización completa o parcial. */
  lastSync: {
    at: string;
    zones: number;
    records: number;
    complete: boolean;
    warnings: string[];
  } | null;
  /**
   * Túneles de Cloudflare de las cuentas de sus zonas (QoL-5b): solo nombre, estado y reglas de
   * entrada (nombre → servicio). Requiere el permiso opcional *Account · Cloudflare Tunnel ·
   * Read*; sin él, `error`. Ausente antes de la primera sincronización.
   */
  tunnels?: {
    at: string;
    items: CloudflareTunnel[];
    complete: boolean;
    error: string | null;
  } | null;
}

/** Conector tal como lo ve la web (`GET /connectors`). Nunca el token. */
export interface Connector {
  /** Id del asset `dns_provider`. */
  id: string;
  name: string;
  kind: DomainProviderKind;
  status: AssetStatus;
  /** Proveedor de secretos donde está el token (`local`, `openbao`), o null si no hay. */
  secretProvider: string | null;
  hasToken: boolean;
  verify: ConnectorVerification | null;
  lastSync: ConnectorFacts['lastSync'];
  /** Dominios no retirados. */
  domains: number;
  /** Registros DNS no retirados. */
  records: number;
  createdAt: string;
}

export interface CreateConnectorRequest {
  kind: DomainProviderKind;
  name: string;
  /** Solo viaja en esta petición; se guarda en el proveedor de secretos y no vuelve a salir. */
  apiToken: string;
}

export interface ReplaceConnectorTokenRequest {
  apiToken: string;
}

export interface ConnectorTestResponse {
  /** null si el worker no respondió a tiempo. */
  verify: ConnectorVerification | null;
}

// --- Jobs ---

export interface DomainsTestJobData {
  assetId: string;
}

export type DomainsTestJobResult = ConnectorVerification;

export interface DomainsSyncJobData {
  assetId: string;
  trigger?: InventoryTrigger;
}

export interface DomainsSyncJobResult {
  assetId: string;
  zones: number;
  records: number;
  certificates: number;
  created: number;
  updated: number;
  missing: number;
  reactivated: number;
  retired: number;
  /** Relaciones `resolves_to` tras enlazar. */
  links: number;
  /** Registros con aviso alto sin marcar como esperados. */
  dangling: number;
  complete: boolean;
  /** Caminos hasta el servicio (QoL-5b): completos y cortados. */
  services?: { complete: number; partial: number };
  warnings: string[];
}

/** Id de deduplicación de `domains.sync` (distinto del de `asset.collect`). */
export function domainsSyncDeduplicationId(assetId: string): string {
  return `domains:${assetId}`;
}

// --- Facts de dominios y registros ---

/** `facts.zone` de un `domain` de un conector. */
export interface ZoneFacts {
  provider: DomainProviderKind;
  id: string;
  name: string;
  /** `active`, `pending`, `moved`… */
  status: string | null;
  paused: boolean;
  nameServers: string[];
  plan: string | null;
  account: string | null;
  discoveredAt: string;
}

/** `facts.registration`: datos del registro del dominio (RDAP). */
export interface RegistrationFacts {
  source: 'rdap';
  /** `ok`, sin servidor RDAP para el TLD (`unsupported`) o error al consultarlo. */
  state: 'ok' | 'unsupported' | 'error';
  expiresAt: string | null;
  registeredAt: string | null;
  registrar: string | null;
  statuses: string[];
  error: string | null;
  checkedAt: string;
}

/** Tipos de registro DNS que se inventarían. */
export const DNS_RECORD_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'TXT',
  'NS',
  'SRV',
  'CAA',
  'HTTPS',
  'SVCB',
  'PTR',
  'LOC',
  'CERT',
  'DNSKEY',
  'DS',
  'NAPTR',
  'SMIMEA',
  'SSHFP',
  'TLSA',
  'URI',
] as const;
export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];

/** Longitud máxima del valor de un registro que se guarda (los TXT largos se cortan). */
export const DNS_CONTENT_MAX_LENGTH = 2048;

/** `facts.dns` de un `dns_record`. */
export interface DnsRecordFacts {
  provider: DomainProviderKind;
  id: string;
  zone: string;
  name: string;
  type: DnsRecordType;
  content: string;
  /** El valor se cortó a `DNS_CONTENT_MAX_LENGTH`. */
  truncated: boolean;
  /** 1 = automático. */
  ttl: number | null;
  /** Pasa por el proxy de Cloudflare (lo que ve el público es su borde, no el origen). */
  proxied: boolean;
  priority: number | null;
  discoveredAt: string;
}

/** `facts.tls`: la lectura del certificado en el 443 del registro. */
export interface DnsTlsFacts {
  status: 'ok' | 'error' | 'skipped';
  /** Mensaje apto para mostrarse (timeout, conexión rechazada…). */
  error: string | null;
  /** La cadena es válida para el sistema del worker. */
  authorized: boolean | null;
  authorizationError: string | null;
  /** El certificado cubre el nombre del registro. */
  hostnameMatch: boolean | null;
  fingerprint256: string | null;
  checkedAt: string;
}

// --- Comprobaciones de registros (colgantes) ---

/**
 * - `high`: apunta a un asset retirado o desaparecido, a una IP privada que no está en el
 *   inventario, o es un CNAME a un nombre interno inexistente o a uno externo que no resuelve
 *   (riesgo de subdomain takeover).
 * - `info`: apunta a una IP pública que no está en el inventario (un tercero, quizá esperado).
 */
export const DNS_CHECK_LEVELS = ['high', 'info'] as const;
export type DnsCheckLevel = (typeof DNS_CHECK_LEVELS)[number];

export const DNS_CHECK_REASONS = [
  /** A/AAAA a un asset del inventario activo. */
  'linked',
  /** A/AAAA cuyos únicos assets con esa IP están retirados o desaparecidos. */
  'retired_target',
  /** A/AAAA a una IP privada (RFC 1918, ULA, CGNAT) que no está en el inventario. */
  'private_unknown',
  /** A/AAAA a una IP pública que no está en el inventario. */
  'public_unknown',
  /** CNAME a un nombre de una zona inventariada que no tiene ningún registro. */
  'cname_internal_missing',
  /** CNAME a un nombre interno con registro. */
  'cname_internal',
  /** CNAME externo que no existe (NXDOMAIN o sin datos). */
  'cname_nxdomain',
  /** CNAME externo que resuelve. */
  'cname_external',
  /**
   * CNAME externo que resuelve, a un servicio con DNS comodín donde un nombre abandonado se puede
   * reclamar (Heroku, GitHub Pages, S3…): el DNS no basta para saber si sigue siendo tuyo.
   */
  'cname_takeover_service',
  /** CNAME a un túnel de Cloudflare (`*.cfargotunnel.com`, no resuelve en público). */
  'cname_tunnel',
  /** No se pudo comprobar (timeout o error del resolutor). */
  'unchecked',
] as const;
export type DnsCheckReason = (typeof DNS_CHECK_REASONS)[number];

/** Estado de comprobación de un registro (A, AAAA o CNAME). */
export interface DnsRecordCheck {
  level: DnsCheckLevel | null;
  reason: DnsCheckReason;
  /** IP o nombre de destino. */
  target: string;
  /** Varios assets tienen esa IP: se enlaza con todos. */
  ambiguous: boolean;
  /** CNAME externo a un servicio conocido por ser susceptible de takeover (p. ej. Heroku). */
  takeoverService: string | null;
  checkedAt: string;
  /**
   * Avisos informativos sin aceptar con el mismo destino (este incluido): «marcar como esperados
   * todos los que apuntan a esta IP» (p. ej. la IP pública de casa).
   */
  sameTarget: number;
  /** Marcado como esperado (silencia el aviso mientras el valor no cambie). */
  accepted: {
    at: string;
    by: string | null;
  } | null;
}

/** «Marcar como esperados» todos los avisos informativos con un destino (`POST /dns-checks/acceptance`). */
export interface AcceptDnsTargetRequest {
  target: string;
}

export interface AcceptDnsTargetResponse {
  accepted: number;
}

/** Un registro que llega a un asset (`GET /assets/:id/domains`). */
export interface AssetDomainRecord {
  record: AssetSummary;
  /** Dominio del registro (su zona). */
  domain: AssetSummary | null;
  dns: Pick<DnsRecordFacts, 'name' | 'type' | 'content' | 'proxied'>;
  /** Saltos hasta el asset: 1 = directo; más = a través de CNAME. */
  hops: number;
  /** Registros intermedios (CNAME) desde este hasta el que apunta al asset. */
  via: AssetSummary[];
  /** Certificado que sirve en el 443 y su caducidad. */
  certificate: { id: string; name: string; notAfter: string | null } | null;
}

export interface AssetDomains {
  records: AssetDomainRecord[];
}

// --- Avisos de caducidad ---

/** Días antes de la caducidad (dominios y certificados) en los que se avisa, de mayor a menor. */
export const DEFAULT_EXPIRY_WARNING_DAYS = [30, 7] as const;
export const EXPIRY_WARNING_MAX_THRESHOLDS = 4;
export const EXPIRY_WARNING_MAX_DAYS = 365;

export interface ExpiryWarningSettings {
  /** De mayor a menor, sin repetir (1–365). El mayor marca «caduca pronto». */
  days: number[];
}

/** Nivel de una caducidad según los umbrales: caducado, por debajo del menor, o de otro. */
export type ExpiryLevel = 'expired' | 'critical' | 'warning';

/**
 * Nivel de aviso de una caducidad: `expired` si ya pasó, `critical` si está por debajo del
 * umbral menor, `warning` si está por debajo del mayor; null si no hay que avisar.
 */
export function expiryLevel(
  expiresAt: string | null,
  days: readonly number[],
  now: number = Date.now(),
): ExpiryLevel | null {
  if (!expiresAt || days.length === 0) return null;
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return null;
  if (t <= now) return 'expired';
  const max = Math.max(...days);
  const min = Math.min(...days);
  if (t < now + min * 86_400_000 && days.length > 1) return 'critical';
  if (t < now + max * 86_400_000) return days.length > 1 ? 'warning' : 'critical';
  return null;
}

/** Tipos con caducidad visible (árbol, panel y avisos). */
export const EXPIRING_ASSET_TYPES = [
  'domain',
  'certificate',
] as const satisfies readonly AssetType[];
