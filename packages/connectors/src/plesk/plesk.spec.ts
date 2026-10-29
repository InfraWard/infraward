import type {
  CertificateFacts,
  PleskDatabaseFacts,
  PleskDomainFacts,
} from '@infraward/shared-types';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DiscoveryError,
  type DiscoveredAsset,
  type HostCommandResult,
  type HostExec,
} from '../discoverer.js';
import { createDiscoverers } from '../index.js';
import {
  expandQuery,
  helperArgv,
  INFRAWARD_QUERY_HELPER,
} from '../privileged.js';
import { parseCertificate, tlsCertificateKey } from './certificate.js';
import {
  PleskDiscoverer,
  pleskCertificateKey,
  pleskDomainKey,
  pleskSubscriptionKey,
} from './plesk.js';
import {
  PLESK_QUERIES,
  type PleskQuery,
} from './queries.js';

// Filas con la forma de `plesk db -B -N -r -e <consulta>` (JSON_OBJECT de MariaDB, que separa
// con `, ` y `: `). Datos sintéticos: los certificados son reales (generados con openssl).
const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
const NOW = new Date('2026-10-11T00:00:00Z');
const H = 'plesk-1';
const PARENT = { id: H, name: 'plesk', facts: {} };

type Reply = HostCommandResult | string;

function host(replies: Partial<Record<PleskQuery, Reply>> = {}) {
  const calls: { argv: string[]; sudo?: boolean }[] = [];
  const exec: HostExec = {
    run: (argv) => {
      throw new Error(`comando sin el ayudante: ${argv.join(' ')}`);
    },
    query: (q) => {
      calls.push({ argv: helperArgv(q), sudo: true });
      const query = (Object.keys(PLESK_QUERIES) as PleskQuery[]).find(
        (name) => q.name === `plesk-${name}` && !q.args?.length,
      );
      if (!query) throw new Error(`consulta inesperada: ${q.name}`);
      const r = replies[query] ?? fixture(`${query}.jsonl`);
      return Promise.resolve(
        typeof r === 'string' ? { code: 0, stdout: r, stderr: '' } : r,
      );
    },
  };
  return { exec, calls };
}

const discoverer = new PleskDiscoverer(() => NOW);
const byName = (children: DiscoveredAsset[], type: string, name: string) =>
  children.find((c) => c.type === type && c.name === name)!;

describe('PleskDiscoverer', () => {
  it('árbol suscripción → dominio → (base de datos, certificado)', async () => {
    const listing = await discoverer.discover(PARENT, host().exec);
    expect(listing.complete).toBe(true);
    expect(listing.warnings).toEqual([]);
    const tree = listing.children.map((c) => [
      c.type,
      c.name,
      c.parent?.naturalKey ?? null,
    ]);
    expect(tree).toEqual([
      ['subscription', 'ejemplo.com', null],
      ['subscription', 'tienda.example.org', null],
      ['domain', 'ejemplo.com', pleskSubscriptionKey(H, 'ejemplo.com')],
      ['domain', 'tienda.example.org', pleskSubscriptionKey(H, 'tienda.example.org')],
      ['domain', 'blog.ejemplo.com', pleskSubscriptionKey(H, 'ejemplo.com')],
      ['domain', 'otro-ejemplo.net', pleskSubscriptionKey(H, 'ejemplo.com')],
      ['domain', 'redireccion.example.org', pleskSubscriptionKey(H, 'tienda.example.org')],
      ['domain', 'ejemplo.es', pleskSubscriptionKey(H, 'ejemplo.com')],
      ['database', 'wp_ejemplo', pleskDomainKey(H, 'ejemplo.com')],
      ['database', 'blog_db', pleskDomainKey(H, 'blog.ejemplo.com')],
      ['database', 'tienda', pleskDomainKey(H, 'tienda.example.org')],
      ['certificate', 'Lets Encrypt ejemplo.com', pleskDomainKey(H, 'ejemplo.com')],
      ['certificate', 'tienda autofirmado', pleskDomainKey(H, 'tienda.example.org')],
      // Del pool del servidor: cuelga del propio servidor Plesk.
      ['certificate', 'default certificate', null],
    ]);
    // Los padres salen antes que sus hijos (el worker los crea en orden).
    const index = new Map(listing.children.map((c, i) => [c.naturalKey, i]));
    for (const [i, c] of listing.children.entries())
      if (c.parent) expect(index.get(c.parent.naturalKey)).toBeLessThan(i);
    expect(listing.seen.size).toBe(listing.children.length);
    expect(listing.children.every((c) => !c.collect)).toBe(true);
  });

  it('tipos de dominio, estado y suscripción', async () => {
    const { children } = await discoverer.discover(PARENT, host().exec);
    const plesk = (name: string) =>
      byName(children, 'domain', name).facts.plesk as PleskDomainFacts;
    expect(plesk('ejemplo.com')).toEqual({
      name: 'ejemplo.com',
      kind: 'subscription',
      hostingType: 'vrt_hst',
      status: 0,
      active: true,
      subscription: 'ejemplo.com',
      parent: null,
      createdAt: '2026-01-15T00:00:00.000Z',
      discoveredAt: NOW.toISOString(),
    });
    expect(plesk('blog.ejemplo.com')).toMatchObject({
      kind: 'subdomain',
      parent: 'ejemplo.com',
    });
    expect(plesk('otro-ejemplo.net').kind).toBe('addon');
    expect(plesk('ejemplo.es')).toMatchObject({
      kind: 'alias',
      parent: 'ejemplo.com',
      subscription: 'ejemplo.com',
    });
    expect(plesk('redireccion.example.org').hostingType).toBe('std_fwd');
    expect(
      byName(children, 'subscription', 'tienda.example.org').facts.plesk,
    ).toMatchObject({ status: 2, active: false, owner: 'admin' });
    expect(
      byName(children, 'database', 'tienda').facts.plesk as PleskDatabaseFacts,
    ).toEqual({
      name: 'tienda',
      engine: 'postgresql',
      server: 'localhost:5432',
      domain: 'tienda.example.org',
      discoveredAt: NOW.toISOString(),
    });
  });

  it('certificados: parte pública, caducidad, quién los usa y secured_by', async () => {
    const listing = await discoverer.discover(PARENT, host().exec);
    const le = byName(listing.children, 'certificate', 'Lets Encrypt ejemplo.com');
    expect(le.naturalKey).toBe(
      pleskCertificateKey(H, 'ejemplo.com', 'Lets Encrypt ejemplo.com'),
    );
    const facts = le.facts.certificate as CertificateFacts;
    expect(facts).toMatchObject({
      subject: 'CN=ejemplo.com',
      subjectAltNames: ['DNS:ejemplo.com', 'DNS:www.ejemplo.com'],
      issuer: "C=US, O=Let's Encrypt, CN=R11",
      notAfter: '2027-01-09T00:36:49.000Z',
      fingerprint256:
        '46:91:3E:DB:0A:30:88:9C:D6:4E:EF:7C:B8:E6:88:C3:88:5D:02:22:AB:75:DA:2C:7A:C7:F1:27:14:52:8D:1A',
      selfSigned: false,
      letsEncrypt: true,
      usedBy: ['ejemplo.com', 'otro-ejemplo.net'],
      repository: 'ejemplo.com',
    });
    // La misma huella leída antes en el 443 de un registro DNS es este asset (se adopta).
    expect(le.aliases).toEqual([tlsCertificateKey(facts.fingerprint256!)]);
    const self = byName(listing.children, 'certificate', 'tienda autofirmado')
      .facts.certificate as CertificateFacts;
    expect(self).toMatchObject({ selfSigned: true, letsEncrypt: false });
    expect(
      byName(listing.children, 'certificate', 'default certificate').facts
        .certificate,
    ).toMatchObject({ repository: 'admin', usedBy: [] });

    expect(listing.links).toEqual(
      [
        ['ejemplo.com', 'ejemplo.com', 'Lets Encrypt ejemplo.com'],
        ['otro-ejemplo.net', 'ejemplo.com', 'Lets Encrypt ejemplo.com'],
        ['tienda.example.org', 'tienda.example.org', 'tienda autofirmado'],
      ].map(([from, repo, cert]) => ({
        type: 'secured_by',
        from: { type: 'domain', naturalKey: pleskDomainKey(H, from!) },
        to: {
          type: 'certificate',
          naturalKey: pleskCertificateKey(H, repo!, cert!),
        },
      })),
    );
  });

  it('nunca guarda el PEM ni una clave privada pegada al certificado', async () => {
    const leaky = fixture('certificates.jsonl')
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const row = JSON.parse(l) as { cert: string };
        row.cert +=
          '-----BEGIN PRIVATE KEY-----\nCENTINELA-CLAVE-PRIVADA\n-----END PRIVATE KEY-----\n';
        return JSON.stringify(row);
      })
      .join('\n');
    const listing = await discoverer.discover(
      PARENT,
      host({ certificates: leaky }).exec,
    );
    const text = JSON.stringify(listing);
    expect(text).not.toContain('CENTINELA');
    expect(text).not.toContain('BEGIN');
    expect(
      byName(listing.children, 'certificate', 'tienda autofirmado').facts
        .certificate,
    ).toMatchObject({ selfSigned: true });
  });

  it('solo lanza las cuatro consultas fijas, con sudo', async () => {
    const { exec, calls } = host();
    await discoverer.discover(PARENT, exec);
    expect(calls).toEqual(
      (['domains', 'aliases', 'databases', 'certificates'] as const).map(
        (q) => ({ argv: [INFRAWARD_QUERY_HELPER, `plesk-${q}`], sudo: true }),
      ),
    );
  });

  it('si una consulta falla, el descubrimiento de Plesk falla entero (no toca estados)', async () => {
    await expect(
      discoverer.discover(
        PARENT,
        host({
          databases: {
            code: 1,
            stdout: '',
            stderr: "ERROR 1054 (42S22): Unknown column 'b.type'",
          },
        }).exec,
      ),
    ).rejects.toThrow(
      new DiscoveryError(
        "No se pudo leer Plesk: plesk db (databases) falló (código 1): ERROR 1054 (42S22): Unknown column 'b.type'",
      ),
    );
  });

  it('filas que no se entienden o huérfanas: aviso y listado incompleto', async () => {
    const listing = await discoverer.discover(
      PARENT,
      host({
        domains: `${fixture('domains.jsonl')}{"id": 9, "name": "../../etc"}\nbasura\n`,
        databases: `${fixture('databases.jsonl')}{"id": 9, "name": "huerfana", "type": "mysql", "domain": 77}\n`,
      }).exec,
    );
    expect(listing.complete).toBe(false);
    expect(listing.warnings).toEqual([
      'plesk db (domains) devolvió una fila que no se entiende',
      'plesk db (domains) devolvió una fila que no se entiende',
      'base de datos huerfana: su dominio (77) no aparece en Plesk',
    ]);
  });

  it('las consultas no piden contraseñas, claves privadas ni CSR', () => {
    for (const q of Object.values(PLESK_QUERIES)) {
      expect(q).not.toMatch(
        /pass|pvt_key|csr|accounts|db_users|admin_password|secret|token/i,
      );
      expect(q).toMatch(/^SELECT JSON_OBJECT\(/);
      // Nada que rompa las comillas dobles del ayudante que instala el script de alta.
      expect(q).not.toMatch(/["$`\\\n]/);
    }
  });

  it('el ayudante recibe solo el nombre de la consulta y ejecuta plesk db con la consulta fija', () => {
    expect(helperArgv({ name: 'plesk-domains' })).toEqual([
      '/usr/local/libexec/infraward/infraward-query',
      'plesk-domains',
    ]);
    expect(expandQuery({ name: 'plesk-domains' })).toEqual([
      'plesk',
      'db',
      '-B',
      '-N',
      '-r',
      '-e',
      PLESK_QUERIES.domains,
    ]);
  });

  it('certificados de Plesk codificados como formulario; las claves públicas sueltas no son certificados', async () => {
    // Así los guarda Plesk 18.0.81 (comprobado en un servidor real): %2D…BEGIN+CERTIFICATE…
    const formEncoded = (pem: string) =>
      encodeURIComponent(pem).replace(/%20/g, '+').replace(/-/g, '%2D');
    const rows = fixture('certificates.jsonl')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { id: number; cert: string });
    const encoded = [
      ...rows.map((r) => ({ ...r, cert: formEncoded(r.cert) })),
      {
        id: 9,
        name: 'Backup sign certificate',
        cert: '\n-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMo=\n-----END RSA PUBLIC KEY-----\n',
        domain: null,
      },
      { id: 10, name: 'solicitud sin certificado', cert: null, domain: null },
    ];
    expect(encoded[0]!.cert).toMatch(/^%2D%2D%2D%2D%2DBEGIN\+CERTIFICATE%2D/);
    const listing = await discoverer.discover(
      PARENT,
      host({ certificates: encoded.map((r) => JSON.stringify(r)).join('\n') }).exec,
    );
    expect(listing.warnings).toEqual([]);
    expect(
      listing.children.filter((c) => c.type === 'certificate').map((c) => c.name),
    ).toEqual(['Lets Encrypt ejemplo.com', 'tienda autofirmado', 'default certificate']);
    expect(
      byName(listing.children, 'certificate', 'Lets Encrypt ejemplo.com').facts
        .certificate,
    ).toMatchObject({ notAfter: '2027-01-09T00:36:49.000Z', letsEncrypt: true });
  });

  it('parseCertificate: null si no hay certificado', () => {
    expect(parseCertificate('')).toBeNull();
    expect(
      parseCertificate('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'),
    ).toBeNull();
  });

  it('está registrado para el rol plesk y no recoge con Ansible', () => {
    expect(createDiscoverers().get('plesk')).toBeInstanceOf(PleskDiscoverer);
    expect(discoverer.collectTarget().target).toBeNull();
  });
});
