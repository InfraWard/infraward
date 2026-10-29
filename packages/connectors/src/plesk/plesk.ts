import type {
  AssetRelationType,
  AssetType,
  CertificateFacts,
  PleskDatabaseFacts,
  PleskDomainFacts,
  PleskDomainKind,
  PleskSubscriptionFacts,
} from '@infraward/shared-types';
import {
  DiscoveryError,
  seenKey,
  type AssetRef,
  type DiscoveredAsset,
  type DiscoveredLink,
  type Discoverer,
  type DiscoveryListing,
  type DiscoveryParent,
  type HostCommandResult,
  type HostExec,
} from '../discoverer.js';
import {
  hasPemCertificate,
  parseCertificate,
  tlsCertificateKey,
} from './certificate.js';
import type { PleskQuery } from './queries.js';

/** Nombres de dominio de Plesk (`name` es ASCII: los IDN van en punycode). */
const DOMAIN_NAME =
  /^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$/;
/** Nombres de base de datos y de certificado: texto razonable, sin caracteres de control. */
const PLAIN_NAME = /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]{1,255}$/u;

export const pleskSubscriptionKey = (host: string, name: string) =>
  `plesk:${host}:subscription:${name}`;
export const pleskDomainKey = (host: string, name: string) =>
  `plesk:${host}:domain:${name}`;
export const pleskDatabaseKey = (host: string, server: string, name: string) =>
  `plesk:${host}:db:${server}:${name}`;
export const pleskCertificateKey = (
  host: string,
  repository: string,
  name: string,
) => `plesk:${host}:cert:${repository}:${name}`;

interface DomainRow {
  id: number;
  name: string;
  status: number;
  htype: string | null;
  webspace: number;
  parent: number;
  created: string | null;
  owner: string | null;
  certificate: number | null;
}
interface AliasRow {
  id: number;
  name: string;
  status: number;
  domain: number;
}
interface DatabaseRow {
  id: number;
  name: string;
  type: string;
  domain: number;
  host: string | null;
  port: number | null;
}
interface CertificateRow {
  id: number;
  name: string;
  cert: string | null;
  domain: number | null;
}

/**
 * Descubridor de Plesk (DESIGN §8), de solo lectura: con consultas FIJAS a la base de datos
 * `psa` (consultas `plesk-*` del ayudante de root, `PRIVILEGED_QUERIES`) lista suscripciones, dominios
 * (principales, adicionales, subdominios y alias), bases de datos y certificados TLS con su
 * caducidad, como árbol servidor → suscripción → dominio → (base de datos, certificado), más
 * `secured_by` dominio → certificado en uso. Nunca lee contraseñas ni claves privadas.
 * Si el servidor tiene Docker, sus contenedores los descubre el de Docker.
 */
export class PleskDiscoverer implements Discoverer {
  readonly role = 'plesk';
  readonly childTypes: readonly AssetType[] = [
    'subscription',
    'domain',
    'database',
    'certificate',
  ];
  readonly linkTypes: readonly AssetRelationType[] = ['secured_by'];

  constructor(private readonly now: () => Date = () => new Date()) {}

  async discover(
    parent: DiscoveryParent,
    host: HostExec,
  ): Promise<DiscoveryListing> {
    const warnings: string[] = [];
    let complete = true;
    const rows = async <T>(
      query: PleskQuery,
      parse: (e: Record<string, unknown>) => T | null,
    ): Promise<T[]> => {
      const result = await host.query({ name: `plesk-${query}` });
      if (result.code !== 0)
        throw new DiscoveryError(
          `No se pudo leer Plesk: plesk db (${query}) falló${failure(result)}`,
        );
      const out: T[] = [];
      for (const line of lines(result.stdout)) {
        const e = parseObject(line);
        const parsed = e ? parse(e) : null;
        if (parsed) out.push(parsed);
        else {
          complete = false;
          warnings.push(
            `plesk db (${query}) devolvió una fila que no se entiende`,
          );
        }
      }
      return out;
    };

    const domains = await rows('domains', parseDomain);
    const aliases = await rows('aliases', parseAlias);
    const databases = await rows('databases', parseDatabase);
    const certificates = await rows('certificates', parseCertificateRow);

    const at = this.now().toISOString();
    const h = parent.id;
    const byId = new Map(domains.map((d) => [d.id, d]));
    const children: DiscoveredAsset[] = [];
    const links: DiscoveredLink[] = [];
    const add = (child: Omit<DiscoveredAsset, 'aliases' | 'collect'>) =>
      children.push({ ...child, aliases: [], collect: false });
    const domainRef = (name: string): AssetRef => ({
      type: 'domain',
      naturalKey: pleskDomainKey(h, name),
    });
    const lost = (what: string) => {
      complete = false;
      warnings.push(what);
    };

    // Suscripciones: los dominios sin webspace (son su propio espacio web).
    const subscriptionOf = (d: DomainRow): DomainRow | undefined =>
      d.webspace === 0 ? d : byId.get(d.webspace);
    for (const d of domains.filter((x) => x.webspace === 0)) {
      const facts: PleskSubscriptionFacts = {
        name: d.name,
        status: d.status,
        active: d.status === 0,
        owner: d.owner,
        createdAt: d.created,
        discoveredAt: at,
      };
      add({
        type: 'subscription',
        name: d.name,
        naturalKey: pleskSubscriptionKey(h, d.name),
        facts: { plesk: facts },
      });
    }

    const addDomain = (
      name: string,
      kind: PleskDomainKind,
      status: number,
      subscription: DomainRow,
      extra: Pick<PleskDomainFacts, 'hostingType' | 'parent' | 'createdAt'>,
    ) => {
      const facts: PleskDomainFacts = {
        name,
        kind,
        status,
        active: status === 0,
        subscription: subscription.name,
        discoveredAt: at,
        ...extra,
      };
      add({
        type: 'domain',
        name,
        naturalKey: pleskDomainKey(h, name),
        facts: { plesk: facts },
        parent: {
          type: 'subscription',
          naturalKey: pleskSubscriptionKey(h, subscription.name),
        },
      });
    };
    for (const d of [...domains].sort(
      (a, b) =>
        Number(a.webspace !== 0) - Number(b.webspace !== 0) || a.id - b.id,
    )) {
      const subscription = subscriptionOf(d);
      if (!subscription) {
        lost(`${d.name}: su suscripción (${d.webspace}) no aparece en Plesk`);
        continue;
      }
      const kind: PleskDomainKind =
        d.webspace === 0
          ? 'subscription'
          : d.parent > 0
            ? 'subdomain'
            : 'addon';
      addDomain(d.name, kind, d.status, subscription, {
        hostingType: d.htype,
        parent: d.parent > 0 ? (byId.get(d.parent)?.name ?? null) : null,
        createdAt: d.created,
      });
    }
    for (const a of aliases) {
      const target = byId.get(a.domain);
      const subscription = target && subscriptionOf(target);
      if (!target || !subscription) {
        lost(`alias ${a.name}: su dominio (${a.domain}) no aparece en Plesk`);
        continue;
      }
      addDomain(a.name, 'alias', a.status, subscription, {
        hostingType: null,
        parent: target.name,
        createdAt: null,
      });
    }

    for (const b of databases) {
      const d = byId.get(b.domain);
      if (!d) {
        lost(
          `base de datos ${b.name}: su dominio (${b.domain}) no aparece en Plesk`,
        );
        continue;
      }
      const server = b.host
        ? `${b.host}:${b.port ?? defaultPort(b.type)}`
        : null;
      const facts: PleskDatabaseFacts = {
        name: b.name,
        engine: b.type,
        server,
        domain: d.name,
        discoveredAt: at,
      };
      add({
        type: 'database',
        name: b.name,
        naturalKey: pleskDatabaseKey(h, server ?? b.type, b.name),
        facts: { plesk: facts },
        parent: domainRef(d.name),
      });
    }

    // Certificados: hijos del dominio de cuyo repositorio son (o del servidor: pool del admin).
    const certKeys = new Map<number, string>();
    const seenCert = new Set<number>();
    for (const c of certificates) {
      if (seenCert.has(c.id)) continue;
      seenCert.add(c.id);
      // Claves públicas sueltas o solicitudes sin certificado: no son certificados.
      if (!c.cert || !hasPemCertificate(c.cert)) continue;
      const owner = c.domain === null ? undefined : byId.get(c.domain);
      const parsed = parseCertificate(c.cert);
      if (!parsed)
        warnings.push(
          `certificado ${c.name}: no se pudo leer la parte pública`,
        );
      const repository = owner?.name ?? 'admin';
      const naturalKey = pleskCertificateKey(h, repository, c.name);
      certKeys.set(c.id, naturalKey);
      const facts: CertificateFacts = {
        name: c.name,
        subject: parsed?.subject ?? null,
        subjectAltNames: parsed?.subjectAltNames ?? [],
        issuer: parsed?.issuer ?? null,
        notBefore: parsed?.notBefore ?? null,
        notAfter: parsed?.notAfter ?? null,
        fingerprint256: parsed?.fingerprint256 ?? null,
        selfSigned: parsed?.selfSigned ?? false,
        letsEncrypt: parsed?.letsEncrypt ?? false,
        usedBy: domains
          .filter((d) => d.certificate === c.id)
          .map((d) => d.name)
          .sort(),
        repository,
        discoveredAt: at,
      };
      children.push({
        type: 'certificate',
        name: c.name,
        naturalKey,
        // Si el mismo certificado ya se leyó en el 443 de un registro DNS (QoL-5), es este:
        // se adopta (mismo asset) en lugar de duplicarlo.
        aliases: facts.fingerprint256
          ? [tlsCertificateKey(facts.fingerprint256)]
          : [],
        collect: false,
        facts: { certificate: facts },
        ...(owner ? { parent: domainRef(owner.name) } : {}),
      });
    }
    for (const d of domains) {
      const cert =
        d.certificate === null ? undefined : certKeys.get(d.certificate);
      if (
        cert &&
        children.some((c) => c.type === 'domain' && c.name === d.name)
      )
        links.push({
          type: 'secured_by',
          from: domainRef(d.name),
          to: { type: 'certificate', naturalKey: cert },
        });
    }

    return {
      children,
      seen: new Set(children.map((c) => seenKey(c.type, c.naturalKey))),
      complete,
      links,
      warnings,
    };
  }

  collectTarget(): { target: null; reason: string } {
    return {
      target: null,
      reason:
        'Las suscripciones, dominios, bases de datos y certificados de Plesk no se recogen con Ansible: sus datos vienen del servidor Plesk',
    };
  }
}

function defaultPort(type: string): number | string {
  return type === 'postgresql' ? 5432 : type === 'mysql' ? 3306 : '?';
}

function parseDomain(e: Record<string, unknown>): DomainRow | null {
  const id = int(e.id);
  if (id === null || typeof e.name !== 'string' || !DOMAIN_NAME.test(e.name))
    return null;
  return {
    id,
    name: e.name.toLowerCase(),
    status: int(e.status) ?? -1,
    htype: typeof e.htype === 'string' ? e.htype.slice(0, 32) : null,
    webspace: int(e.webspace) ?? 0,
    parent: int(e.parent) ?? 0,
    created: date(e.created),
    owner:
      typeof e.owner === 'string' && PLAIN_NAME.test(e.owner)
        ? e.owner.slice(0, 255)
        : null,
    certificate: int(e.certificate),
  };
}

function parseAlias(e: Record<string, unknown>): AliasRow | null {
  const id = int(e.id);
  const domain = int(e.domain);
  if (
    id === null ||
    domain === null ||
    typeof e.name !== 'string' ||
    !DOMAIN_NAME.test(e.name)
  )
    return null;
  return {
    id,
    name: e.name.toLowerCase(),
    status: int(e.status) ?? -1,
    domain,
  };
}

function parseDatabase(e: Record<string, unknown>): DatabaseRow | null {
  const id = int(e.id);
  const domain = int(e.domain);
  if (
    id === null ||
    domain === null ||
    typeof e.name !== 'string' ||
    !PLAIN_NAME.test(e.name) ||
    typeof e.type !== 'string'
  )
    return null;
  return {
    id,
    name: e.name,
    type: e.type.slice(0, 32),
    domain,
    host:
      typeof e.host === 'string' && /^[A-Za-z0-9_.:-]{1,255}$/.test(e.host)
        ? e.host
        : null,
    port: int(e.port),
  };
}

function parseCertificateRow(
  e: Record<string, unknown>,
): CertificateRow | null {
  const id = int(e.id);
  if (id === null || typeof e.name !== 'string' || !PLAIN_NAME.test(e.name))
    return null;
  return {
    id,
    name: e.name,
    cert: typeof e.cert === 'string' && e.cert ? e.cert : null,
    domain: int(e.domain),
  };
}

function int(value: unknown): number | null {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isSafeInteger(n) ? n : null;
}

/** `2026-10-11` o `2026-10-11 10:00:00` (hora del servidor, sin zona). */
function date(value: unknown): string | null {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(value))
    return null;
  const t = Date.parse(
    value.replace(' ', 'T') + (value.length > 10 ? 'Z' : ''),
  );
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

function lines(output: string): string[] {
  return output
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
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

function failure(result: HostCommandResult): string {
  if (result.code === null) return ' (tiempo agotado)';
  const line = lines(result.stderr).at(-1);
  return ` (código ${result.code})${line ? `: ${line.slice(0, 200)}` : ''}`;
}
