import type { RegistrationFacts } from '@infraward/shared-types';
import { DomainApiError } from './domain-provider.js';

/** Bootstrap de IANA: qué servidor RDAP sirve cada TLD (RFC 9224). */
export const IANA_RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';

/** Cuánto vale el bootstrap en memoria. */
const BOOTSTRAP_TTL_MS = 24 * 3_600_000;

/**
 * GET de un JSON público (sin credenciales). Lo da el worker con su timeout; un estado no 2xx
 * lanza `DomainApiError` con el estado (404 = el registro no tiene ese dominio).
 */
export type FetchJson = (url: string) => Promise<unknown>;

export type RdapResult = Omit<RegistrationFacts, 'checkedAt'>;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Caducidad, alta, registrador y estados de un dominio por RDAP (DESIGN §13), válido para
 * cualquier registrador. Sin servidor RDAP para el TLD (p. ej. `.es`), `unsupported`.
 */
export class RdapClient {
  private bootstrap: { at: number; services: Map<string, string> } | null =
    null;

  constructor(
    private readonly fetchJson: FetchJson,
    private readonly bootstrapUrl: string = IANA_RDAP_BOOTSTRAP,
    private readonly now: () => number = Date.now,
  ) {}

  async lookup(domain: string): Promise<RdapResult> {
    let base: string | null;
    try {
      base = await this.serverFor(domain);
    } catch (e) {
      return error(`no se pudo leer el bootstrap de IANA (${reason(e)})`);
    }
    if (!base) return { ...empty(), state: 'unsupported' };
    let body: unknown;
    try {
      body = await this.fetchJson(
        `${base}domain/${encodeURIComponent(domain)}`,
      );
    } catch (e) {
      if (e instanceof DomainApiError && e.status === 404)
        return error('el registro no encuentra el dominio');
      return error(reason(e));
    }
    return parseRdapDomain(body);
  }

  /** URL base (con `/` final) del servidor RDAP del TLD más largo que casa. */
  private async serverFor(domain: string): Promise<string | null> {
    if (!this.bootstrap || this.now() - this.bootstrap.at > BOOTSTRAP_TTL_MS) {
      this.bootstrap = {
        at: this.now(),
        // Un bootstrap en http (solo en pruebas) admite servidores http.
        services: parseBootstrap(
          await this.fetchJson(this.bootstrapUrl),
          this.bootstrapUrl.startsWith('http://'),
        ),
      };
    }
    const labels = domain.toLowerCase().split('.');
    for (let i = 1; i < labels.length; i++) {
      const url = this.bootstrap.services.get(labels.slice(i).join('.'));
      if (url) return url;
    }
    return null;
  }
}

/** `{ services: [[["com","net"], ["https://…/"]], …] }` → TLD → URL https (con `/` final). */
export function parseBootstrap(
  value: unknown,
  allowHttp = false,
): Map<string, string> {
  const map = new Map<string, string>();
  if (!isObj(value) || !Array.isArray(value.services))
    throw new DomainApiError('bootstrap RDAP sin servicios', null);
  for (const service of value.services) {
    if (!Array.isArray(service) || service.length < 2) continue;
    const [tlds, urls] = service as [unknown, unknown];
    if (!Array.isArray(tlds) || !Array.isArray(urls)) continue;
    const url = urls.find(
      (u): u is string =>
        typeof u === 'string' &&
        (u.startsWith('https://') || (allowHttp && u.startsWith('http://'))),
    );
    if (!url) continue;
    for (const tld of tlds)
      if (typeof tld === 'string')
        map.set(tld.toLowerCase(), url.endsWith('/') ? url : `${url}/`);
  }
  return map;
}

/** Datos del registro de una respuesta RDAP de dominio (RFC 9083). */
export function parseRdapDomain(value: unknown): RdapResult {
  if (!isObj(value)) return error('respuesta RDAP que no se entiende');
  const events = Array.isArray(value.events) ? value.events.filter(isObj) : [];
  const date = (action: string): string | null => {
    const event = events.find((e) => e.eventAction === action);
    const t = Date.parse(typeof event?.eventDate === 'string' ? event.eventDate : '');
    return Number.isNaN(t) ? null : new Date(t).toISOString();
  };
  return {
    source: 'rdap',
    state: 'ok',
    expiresAt: date('expiration'),
    registeredAt: date('registration'),
    registrar: registrar(value.entities),
    statuses: Array.isArray(value.status)
      ? value.status
          .filter((s): s is string => typeof s === 'string')
          .slice(0, 20)
      : [],
    error: null,
  };
}

/** Nombre (`fn` del vCard) de la entidad con el rol `registrar`. */
function registrar(entities: unknown): string | null {
  if (!Array.isArray(entities)) return null;
  for (const entity of entities) {
    if (
      !isObj(entity) ||
      !Array.isArray(entity.roles) ||
      !entity.roles.includes('registrar')
    )
      continue;
    const vcard = Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : null;
    if (!Array.isArray(vcard)) continue;
    for (const prop of vcard) {
      if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string')
        return prop[3].slice(0, 200);
    }
  }
  return null;
}

function empty(): RdapResult {
  return {
    source: 'rdap',
    state: 'ok',
    expiresAt: null,
    registeredAt: null,
    registrar: null,
    statuses: [],
    error: null,
  };
}

function error(message: string): RdapResult {
  return { ...empty(), state: 'error', error: message };
}

function reason(e: unknown): string {
  return e instanceof DomainApiError ? e.message : 'error inesperado';
}
