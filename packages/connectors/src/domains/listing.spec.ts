import type { CertificateFacts, DnsRecordFacts } from '@infraward/shared-types';
import { describe, expect, it } from 'vitest';
import { seenKey } from '../discoverer.js';
import { tlsCertificateKey } from '../plesk/certificate.js';
import { planReconcile } from '../reconcile.js';
import type { ProviderListing } from './domain-provider.js';
import {
  buildDomainListing,
  DOMAIN_CHILD_TYPES,
  recordKey,
  tlsCandidates,
  zoneKey,
  type TlsObservation,
} from './listing.js';

const Z = 'z'.repeat(32);
const NOW = '2026-10-14T10:00:00.000Z';
const FP = 'AA:BB:CC';

const LISTING: ProviderListing = {
  zones: [
    {
      id: Z,
      name: 'ejemplo.dev',
      status: 'active',
      paused: false,
      nameServers: ['ada.ns.cloudflare.com'],
      plan: 'Free',
      account: { id: 'acc', name: 'Pruebas' },
    },
  ],
  records: [
    { id: '1', zoneId: Z, name: 'ejemplo.dev', type: 'A', content: '203.0.113.10', ttl: 1, proxied: true, priority: null },
    { id: '2', zoneId: Z, name: 'www.ejemplo.dev', type: 'CNAME', content: 'ejemplo.dev', ttl: 1, proxied: true, priority: null },
    { id: '3', zoneId: Z, name: '*.ejemplo.dev', type: 'A', content: '203.0.113.10', ttl: 1, proxied: false, priority: null },
    { id: '4', zoneId: Z, name: 'ejemplo.dev', type: 'TXT', content: 'x'.repeat(3000), ttl: 300, proxied: false, priority: null },
    { id: '5', zoneId: 'otra', name: 'huerfano.net', type: 'A', content: '1.1.1.1', ttl: 1, proxied: false, priority: null },
  ],
  complete: true,
  warnings: [],
};

const observed = (fp = FP): TlsObservation => ({
  facts: {
    status: 'ok',
    error: null,
    authorized: true,
    authorizationError: null,
    hostnameMatch: true,
    fingerprint256: fp,
    checkedAt: NOW,
  },
  certificate: {
    subject: 'CN=ejemplo.dev',
    subjectAltNames: ['DNS:ejemplo.dev', 'DNS:*.ejemplo.dev'],
    issuer: 'C=US, O=Google Trust Services, CN=WE1',
    notBefore: '2026-09-01T00:00:00.000Z',
    notAfter: '2026-12-01T00:00:00.000Z',
    fingerprint256: fp,
    selfSigned: false,
    letsEncrypt: false,
  },
});

const base = {
  kind: 'cloudflare' as const,
  listing: LISTING,
  registrations: new Map(),
  tls: new Map([
    ['ejemplo.dev', observed()],
    ['www.ejemplo.dev', observed()],
  ]),
  tlsComplete: true,
  knownCertificates: new Map<string, string>(),
  now: NOW,
};

describe('buildDomainListing', () => {
  it('dominio → registros y un certificado por huella (compartido), con secured_by', () => {
    const l = buildDomainListing(base);
    expect(l.complete).toBe(true);
    expect(l.partialTypes).toBeUndefined();
    expect(l.children.map((c) => [c.type, c.name, c.parent?.naturalKey ?? null])).toEqual([
      ['domain', 'ejemplo.dev', null],
      ['dns_record', 'ejemplo.dev · A', zoneKey('cloudflare', Z)],
      ['dns_record', 'www.ejemplo.dev · CNAME', zoneKey('cloudflare', Z)],
      ['dns_record', '*.ejemplo.dev · A', zoneKey('cloudflare', Z)],
      ['dns_record', 'ejemplo.dev · TXT', zoneKey('cloudflare', Z)],
      ['certificate', 'ejemplo.dev', zoneKey('cloudflare', Z)],
    ]);
    const cert = l.children.at(-1)!;
    expect(cert.naturalKey).toBe(tlsCertificateKey(FP));
    expect((cert.facts.certificate as CertificateFacts).usedBy).toEqual(['ejemplo.dev', 'www.ejemplo.dev']);
    expect(l.links).toEqual(
      ['1', '2'].map((id) => ({
        type: 'secured_by',
        from: { type: 'dns_record', naturalKey: recordKey('cloudflare', id) },
        to: { type: 'certificate', naturalKey: tlsCertificateKey(FP) },
      })),
    );
    const txt = l.children[4].facts.dns as DnsRecordFacts;
    expect(txt.content).toHaveLength(2048);
    expect(txt.truncated).toBe(true);
    expect(l.children[4].facts.tls).toBeNull();
    expect(l.seen.has(seenKey('dns_record', recordKey('cloudflare', '5')))).toBe(false);
  });

  it('una huella que ya es de otro asset (Plesk) se enlaza, no se crea', () => {
    const l = buildDomainListing({
      ...base,
      knownCertificates: new Map([[FP, 'plesk:h:cert:ejemplo.dev:le']]),
    });
    expect(l.children.some((c) => c.type === 'certificate')).toBe(false);
    expect(l.links?.[0].to).toEqual({ type: 'certificate', naturalKey: 'plesk:h:cert:ejemplo.dev:le' });
  });

  it('lecturas del 443 fallidas: los certificados son parciales (nada a missing)', () => {
    const l = buildDomainListing({ ...base, tlsComplete: false });
    expect(l.partialTypes).toEqual(['certificate']);
    const plan = planReconcile({
      parentId: 'prov',
      childTypes: DOMAIN_CHILD_TYPES,
      listing: { ...l, children: l.children.filter((c) => c.type !== 'certificate') },
      existing: [
        { id: 'c-old', type: 'certificate', naturalKey: tlsCertificateKey('OLD'), status: 'active', parentId: 'dom' , inScope: true },
      ],
    });
    expect(plan.missing).toEqual([]);
  });

  it('candidatos del 443: A/AAAA/CNAME no comodín, sin repetir', () => {
    expect(tlsCandidates(LISTING.records)).toEqual(['ejemplo.dev', 'huerfano.net', 'www.ejemplo.dev']);
  });
});

describe('adopción de certificados entre Plesk y el 443', () => {
  it('Plesk descubre la huella que ya era un `tls:`: el mismo asset pasa a ser suyo', () => {
    const plan = planReconcile({
      parentId: 'plesk',
      childTypes: ['certificate'],
      listing: {
        children: [
          {
            type: 'certificate',
            name: 'le',
            naturalKey: 'plesk:plesk:cert:ejemplo.dev:le',
            aliases: [tlsCertificateKey(FP)],
            collect: false,
            facts: {},
          },
        ],
        seen: new Set([seenKey('certificate', 'plesk:plesk:cert:ejemplo.dev:le')]),
        complete: true,
        warnings: [],
      },
      existing: [
        { id: 'c1', type: 'certificate', naturalKey: tlsCertificateKey(FP), status: 'active', parentId: 'dom', inScope: false },
      ],
    });
    expect(plan.create).toEqual([]);
    expect(plan.update).toMatchObject([
      { id: 'c1', rename: 'plesk:plesk:cert:ejemplo.dev:le', attach: true },
    ]);
  });
});
