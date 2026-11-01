import {
  DNS_CONTENT_MAX_LENGTH,
  type AssetType,
  type CertificateFacts,
  type DnsRecordFacts,
  type DnsTlsFacts,
  type DomainProviderKind,
  type RegistrationFacts,
  type ZoneFacts,
  byCodeUnit,
} from '@infraward/shared-types';
import {
  seenKey,
  type AssetRef,
  type DiscoveredAsset,
  type DiscoveredLink,
  type DiscoveryListing,
} from '../discoverer.js';
import { tlsCertificateKey, type ParsedCertificate } from '../plesk/certificate.js';
import type { ProviderListing, ProviderRecord } from './domain-provider.js';

/** Tipos que crea la sincronización de un conector de dominios bajo su `dns_provider`. */
export const DOMAIN_CHILD_TYPES = [
  'domain',
  'dns_record',
  'certificate',
] as const satisfies readonly AssetType[];

/** Relaciones que mantiene el listado (se sustituyen en cada sincronización). */
export const DOMAIN_LINK_TYPES = ['secured_by'] as const;

/** Tipos cuyo 443 se lee. */
export const TLS_RECORD_TYPES = ['A', 'AAAA', 'CNAME'] as const;

export const zoneKey = (kind: DomainProviderKind, id: string): string =>
  `${kind}:zone:${id}`;
export const recordKey = (kind: DomainProviderKind, id: string): string =>
  `${kind}:record:${id}`;

/** Lectura del 443 de un nombre. */
export interface TlsObservation {
  facts: DnsTlsFacts;
  /** Datos públicos del certificado si se leyó. */
  certificate: (ParsedCertificate & { fingerprint256: string }) | null;
}

export interface DomainListingInput {
  kind: DomainProviderKind;
  listing: ProviderListing;
  /** Nombre de la zona → registro por RDAP (ya decidido: nuevo o el anterior). */
  registrations: ReadonlyMap<string, RegistrationFacts>;
  /** Nombre del registro → lectura de su 443 (solo los que se leyeron). */
  tls: ReadonlyMap<string, TlsObservation>;
  /** false si alguna lectura del 443 falló: los certificados no pasan a `missing`. */
  tlsComplete: boolean;
  /**
   * Huella → clave natural de un certificado que ya existe fuera de este conector (p. ej. de
   * Plesk): se enlaza ese, no se crea otro.
   */
  knownCertificates: ReadonlyMap<string, string>;
  now: string;
}

/** Nombres cuyo 443 tiene sentido leer: A/AAAA/CNAME no comodín, sin repetir. */
export function tlsCandidates(records: readonly ProviderRecord[]): string[] {
  return [
    ...new Set(
      records
        .filter(
          (r) =>
            (TLS_RECORD_TYPES as readonly string[]).includes(r.type) &&
            !r.name.startsWith('*'),
        )
        .map((r) => r.name),
    ),
  ].sort(byCodeUnit);
}

/** Nombre visible de un registro: `www.ejemplo.dev · A`. */
export function recordName(r: Pick<ProviderRecord, 'name' | 'type'>): string {
  return `${r.name} · ${r.type}`;
}

/**
 * Listado del conector como hijos de su `dns_provider` (DESIGN §13): dominio → registros y
 * certificados del 443 (hijos del primer dominio en el que se ven; uno por huella), con
 * `secured_by` registro → certificado. Pura.
 */
export function buildDomainListing(input: DomainListingInput): DiscoveryListing {
  const { kind, listing, now } = input;
  const children: DiscoveredAsset[] = [];
  const links: DiscoveredLink[] = [];
  const zones = new Map(listing.zones.map((z) => [z.id, z]));
  const certs = new Map<string, DiscoveredAsset>();

  for (const z of listing.zones) {
    const facts: ZoneFacts = {
      provider: kind,
      id: z.id,
      name: z.name,
      status: z.status,
      paused: z.paused,
      nameServers: z.nameServers,
      plan: z.plan,
      account: z.account?.name ?? z.account?.id ?? null,
      discoveredAt: now,
    };
    const registration = input.registrations.get(z.name);
    children.push({
      type: 'domain',
      name: z.name,
      naturalKey: zoneKey(kind, z.id),
      aliases: [],
      collect: false,
      facts: { zone: facts, ...(registration ? { registration } : {}) },
    });
  }

  for (const r of listing.records) {
    const zone = zones.get(r.zoneId);
    if (!zone) continue;
    const zoneRef: AssetRef = { type: 'domain', naturalKey: zoneKey(kind, zone.id) };
    const truncated = r.content.length > DNS_CONTENT_MAX_LENGTH;
    const dns: DnsRecordFacts = {
      provider: kind,
      id: r.id,
      zone: zone.name,
      name: r.name,
      type: r.type,
      content: truncated ? r.content.slice(0, DNS_CONTENT_MAX_LENGTH) : r.content,
      truncated,
      ttl: r.ttl,
      proxied: r.proxied,
      priority: r.priority,
      discoveredAt: now,
    };
    const tls =
      (TLS_RECORD_TYPES as readonly string[]).includes(r.type)
        ? input.tls.get(r.name)
        : undefined;
    const ref: AssetRef = { type: 'dns_record', naturalKey: recordKey(kind, r.id) };
    children.push({
      ...ref,
      name: recordName(r),
      aliases: [],
      collect: false,
      parent: zoneRef,
      facts: { dns, tls: tls?.facts ?? null },
    });

    const cert = tls?.certificate;
    if (!cert) continue;
    const known = input.knownCertificates.get(cert.fingerprint256);
    const certKey = known ?? tlsCertificateKey(cert.fingerprint256);
    links.push({ type: 'secured_by', from: ref, to: { type: 'certificate', naturalKey: certKey } });
    if (known) continue;
    const existing = certs.get(certKey);
    if (existing) {
      const facts = existing.facts.certificate as CertificateFacts;
      if (!facts.usedBy.includes(r.name)) facts.usedBy.push(r.name);
      continue;
    }
    const facts: CertificateFacts = {
      name: certificateName(cert),
      subject: cert.subject,
      subjectAltNames: cert.subjectAltNames,
      issuer: cert.issuer,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      fingerprint256: cert.fingerprint256,
      selfSigned: cert.selfSigned,
      letsEncrypt: cert.letsEncrypt,
      usedBy: [r.name],
      repository: 'tls',
      discoveredAt: now,
    };
    const child: DiscoveredAsset = {
      type: 'certificate',
      name: facts.name,
      naturalKey: certKey,
      aliases: [],
      collect: false,
      parent: zoneRef,
      facts: { certificate: facts },
    };
    certs.set(certKey, child);
  }
  for (const c of certs.values()) {
    (c.facts.certificate as CertificateFacts).usedBy.sort();
    children.push(c);
  }

  return {
    children,
    seen: new Set(children.map((c) => seenKey(c.type, c.naturalKey))),
    complete: listing.complete,
    ...(input.tlsComplete ? {} : { partialTypes: ['certificate'] }),
    links,
    warnings: [...listing.warnings],
  };
}

/** CN del sujeto o, si no, el primer SAN DNS; si no, la huella corta. */
function certificateName(cert: TlsObservation['certificate'] & object): string {
  const cn = /(?:^|, )CN=([^,]+)/.exec(cert.subject ?? '')?.[1];
  const san = cert.subjectAltNames
    .find((s) => s.startsWith('DNS:'))
    ?.slice(4);
  return (cn ?? san ?? cert.fingerprint256.slice(0, 23)).slice(0, 200);
}
