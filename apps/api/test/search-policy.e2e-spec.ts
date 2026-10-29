import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  QUEUE_NAMES,
  type AssetPolicy,
  type AssetTreeSummaryNode,
  type Page,
  type VulnerabilitySummary,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { DataSource } from 'typeorm';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { seedInventory, type SeededInventory } from './support/inventory-seed.js';

const ids = (nodes: readonly AssetTreeSummaryNode[]): string[] =>
  nodes.flatMap((n) => [n.name, ...ids(n.children)]);

/**
 * QoL-6b: búsqueda con sintaxis en el árbol, la exportación y vulnerabilidades (nunca 500), el
 * lote de vulnerabilidades sin tags/proyecto/política y las exclusiones del escaneo.
 */
describe('Búsqueda con filtros, lote de vulnerabilidades y exclusiones (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let inv: SeededInventory;

  beforeAll(async () => {
    await prepareEnv('e2e_search');
    app = await createTestApp();
    db = app.get(DataSource);
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    inv = await seedInventory(db);
    for (const [id, tags] of [
      [inv.web, ['prueba']],
      [inv.cache, ['prueba-2']],
      [inv.db, ['prueba']],
    ] as const) {
      const res = await request('PATCH', `/assets/${id}`, { tags });
      expect(res.statusCode).toBe(200);
    }
    // `db` se llama ahora «hola-db»; el descubierto sigue siendo «db».
    await request('PATCH', `/assets/${inv.db}`, { displayName: 'hola-db' });
    await request('PATCH', `/assets/${inv.web}`, { displayName: 'hola-web' });
  });

  afterAll(async () => {
    for (const name of Object.values(QUEUE_NAMES))
      await app?.get<Queue>(getQueueToken(name)).obliterate({ force: true });
    await app?.close();
  });

  function request(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH',
    url: string,
    payload?: object,
  ) {
    return app.inject({ method, url, payload, headers: authHeaders(admin) });
  }
  const tree = async (q: string) => {
    const res = await request('GET', `/assets/tree?q=${encodeURIComponent(q)}`);
    expect(res.statusCode).toBe(200);
    return ids(res.json<AssetTreeSummaryNode[]>());
  };
  const cves = async (q: string) => {
    const res = await request('GET', `/vulnerabilities?q=${encodeURIComponent(q)}`);
    expect(res.statusCode).toBe(200);
    return res
      .json<Page<VulnerabilitySummary>>()
      .items.map((v) => v.vulnerabilityId)
      .sort();
  };

  it('tag:prueba nombre:hola: tag exacto y nombre parcial, con sus antepasados', async () => {
    expect(await tree('tag:prueba nombre:hola')).toEqual(['pve-lab', 'ct-docker', 'hola-db', 'hola-web']);
    // `prueba-2` no es `prueba`; el texto suelto no busca en tags.
    expect(await tree('tag:prueba nombre:hola -nombre:web')).toEqual(['pve-lab', 'ct-docker', 'hola-db']);
    expect(await tree('prueba')).toEqual([]);
    // Nombre descubierto, O entre la misma clave, tipo e IP.
    expect(await tree('db')).toEqual(['pve-lab', 'ct-docker', 'hola-db']);
    expect(await tree('tag:prueba-2 tag:nada')).toEqual(['pve-lab', 'ct-docker', 'cache']);
    expect(await tree('tipo:ct')).toEqual(['pve-lab', 'ct-docker']);
    expect(await tree('ip:10.9.9.0/24')).toEqual(['pve-lab']);
  });

  it('nunca 500: claves desconocidas, comillas sin cerrar y valores raros se ignoran', async () => {
    for (const q of ['foo:bar', 'nombre:"sin cerrar', '-', '"', 'tipo:foo ip:999.1.1.1', 'sitio:x', "'; DROP TABLE assets; --", 'ñ'.repeat(2000)])
      await tree(q);
    expect((await request('GET', `/assets/tree?q=${'a'.repeat(2001)}`)).statusCode).toBe(400);
    // Lo ignorado no filtra.
    expect(await tree('tipo:foo sitio:madrid')).toContain('cache');
  });

  it('la exportación usa la misma búsqueda', async () => {
    const res = await request(
      'GET',
      `/assets/export?format=json&columns=name&q=${encodeURIComponent('tag:prueba nombre:hola')}`,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json<{ name: string }[]>().map((r) => r.name).sort()).toEqual(['hola-db', 'hola-web']);
  });

  it('vulnerabilidades: claves del CVE y del asset afectado (la imagen, por quien la usa)', async () => {
    // nginx (CVE-0001, 0002) la usa hola-web; pg (CVE-0003), hola-db.
    expect(await cves('tag:prueba')).toEqual(['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']);
    expect(await cves('nombre:hola-web')).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
    expect(await cves('severidad:crítica tipo:ct')).toEqual(['CVE-2026-0001']);
    expect(await cves('cve:CVE-2026-000 -tag:prueba')).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
    expect(await cves('paquete:openssl severidad:high')).toEqual(['CVE-2026-0002']);
    expect(await cves('CVE-2026-0003')).toEqual(['CVE-2026-0003']);
    for (const q of ['cve:"sin cerrar', 'severidad:x prioridad:alta foo:bar', 'ip:10.9.9.0/24', 'ip:10.', "'; --"])
      await cves(q);
  });

  it('el lote de vulnerabilidades no acepta etiquetar, mover a proyecto, política ni baja', async () => {
    const vulnerabilityIds = ['CVE-2026-0001'];
    for (const [url, extra] of [
      ['/assets/bulk/tags', { add: ['x'], remove: [] }],
      ['/assets/bulk/project', { project: '11111111-1111-4111-8111-111111111111', mode: 'include' }],
      ['/assets/bulk/policy', { fields: { scanEnabled: false } }],
      ['/assets/bulk/retire', {}],
    ] as const) {
      const res = await request('POST', url, { vulnerabilityIds, ...extra });
      expect(res.statusCode, url).toBe(400);
    }
    const scan = await request('POST', '/assets/bulk/scan', { vulnerabilityIds });
    expect(scan.statusCode).toBe(202);
    // Nada cambió en los afectados.
    const [{ tags }] = await db.query(`SELECT tags FROM assets WHERE id = $1`, [inv.ct]);
    expect(tags).toEqual([]);
  });

  it('exclusiones: por tipo en un nodo, heredadas; lo excluido no se escanea y se explica', async () => {
    const set = await request('PUT', `/assets/${inv.node}/policy`, {
      scanExclusions: { types: ['image'] },
    });
    expect(set.statusCode).toBe(200);
    const nginx = (await request('GET', `/assets/${inv.images.nginx}/policy`)).json<AssetPolicy>();
    expect(nginx.effective.values.scanEnabled).toBe(false);
    expect(nginx.effective.sources.scanEnabled).toMatchObject({
      kind: 'excluded',
      by: { kind: 'inherited', assetName: 'pve-lab' },
      match: { kind: 'type', type: 'image' },
    });
    // El CT y los contenedores siguen escaneando; sus imágenes, no.
    const ct = (await request('GET', `/assets/${inv.ct}/policy`)).json<AssetPolicy>();
    expect(ct.effective.values.scanEnabled).toBe(true);
    const scan = await request('POST', `/assets/${inv.images.nginx}/scan`);
    expect(scan.statusCode).toBe(409);
    expect(scan.json<{ message: string }>().message).toContain('Excluido del escaneo por la regla de pve-lab');
    // Siguen en el inventario, pero sus CVE salen de las listas.
    expect(await cves('tag:prueba')).toEqual([]);
    // Quitar la exclusión lo devuelve todo.
    await request('PUT', `/assets/${inv.node}/policy`, { scanExclusions: null });
    expect((await request('GET', `/assets/${inv.images.nginx}/policy`)).json<AssetPolicy>().effective.values.scanEnabled).toBe(true);
  });

  it('exclusiones por patrón en la global y por asset en una regla de etiqueta; validación', async () => {
    expect(
      (await request('PUT', '/inventory-policies/global', { scanExclusions: { namePatterns: ['REDIS*'] } })).statusCode,
    ).toBe(200);
    const redis = (await request('GET', `/assets/${inv.images.redis}/policy`)).json<AssetPolicy>();
    expect(redis.effective.sources.scanEnabled).toMatchObject({
      kind: 'excluded',
      by: { kind: 'global' },
      match: { kind: 'pattern', pattern: 'REDIS*' },
    });
    // Solo con exclusiones ya es una regla válida.
    const rule = await request('POST', '/inventory-policies', {
      scope: 'tag',
      tag: 'prueba',
      scanExclusions: { assetIds: [inv.ct] },
    });
    expect(rule.statusCode).toBe(201);
    for (const scanExclusions of [{ types: ['volume'] }, { namePatterns: ['$(rm -rf /)'] }, { assetIds: ['x'] }])
      expect((await request('POST', '/inventory-policies', { scope: 'tag', tag: 'otra', scanExclusions })).statusCode).toBe(400);
    await request('PUT', '/inventory-policies/global', { scanExclusions: null });
  });
});
