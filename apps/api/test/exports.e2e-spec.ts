import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { DataSource } from 'typeorm';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import {
  SECRET_SENTINELS,
  seedInventory,
  type SeededInventory,
} from './support/inventory-seed.js';

/** Filas de un CSV sencillo (sin comillas con saltos de línea dentro), sin el BOM. */
function csvRows(body: string): string[][] {
  return body
    .replace(/^\uFEFF/, '')
    .split('\r\n')
    .filter(Boolean)
    .map((line) => line.split(','));
}

/**
 * Exportaciones a CSV y JSON (QoL-6): el inventario con los filtros del árbol y sus columnas, y
 * las vulnerabilidades con los filtros de la lista, por CVE o por asset. Sin secretos y con las
 * fórmulas neutralizadas.
 */
describe('Exportaciones (e2e)', () => {
  let app: NestFastifyApplication;
  let admin: string;
  let inv: SeededInventory;
  let project: string;
  const bodies: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_exports');
    app = await createTestApp();
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    inv = await seedInventory(app.get(DataSource));
    project = (await get('/projects', 'POST', { name: 'Lab' })).json<{ id: string }>().id;
    // Solo `web` (y su imagen nginx) entra en el proyecto.
    await get(`/projects/${project}/members/${inv.web}`, 'PUT', { mode: 'include' });
  });

  afterAll(async () => {
    await app?.close();
  });

  async function get(url: string, method: 'GET' | 'POST' | 'PUT' = 'GET', payload?: object) {
    const res = await app.inject({ method, url, payload, headers: authHeaders(admin) });
    bodies.push(res.body);
    return res;
  }

  it('inventario a CSV: columnas por defecto, ruta y cabeceras de descarga', async () => {
    const res = await get('/assets/export');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(res.headers['content-disposition']).toMatch(
      /^attachment; filename="infraward-inventario-\d{4}-\d{2}-\d{2}\.csv"$/,
    );
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body.startsWith('\uFEFF')).toBe(true);
    const [header, ...rows] = csvRows(res.body);
    expect(header).toEqual([
      'name',
      'path',
      'type',
      'address',
      'status',
      'maxSeverity',
      'fixableCritical',
      'fixableHigh',
    ]);
    const web = rows.find((r) => r[0] === 'web')!;
    expect(web[1]).toBe('pve-lab › ct-docker › web');
    expect(web[5]).toBe('CRITICAL');
    expect(res.headers['x-export-rows']).toBe(String(rows.length));
  });

  it('inventario con filtros del árbol y columnas elegidas (CSV y JSON)', async () => {
    const csv = await get('/assets/export?type=container&columns=name,tags,projects,critical');
    const [header, ...rows] = csvRows(csv.body);
    expect(header).toEqual(['name', 'tags', 'projects', 'critical']);
    expect(rows.map((r) => r[0]).sort()).toEqual(['cache', 'db', 'web']);
    expect(rows.find((r) => r[0] === 'web')![2]).toBe('Lab');

    const json = await get(`/assets/export?format=json&project=${project}&columns=name,type`);
    expect(json.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(json.headers['content-disposition']).toContain('.json"');
    // Del proyecto, lo que enseña el árbol: el contenedor (las imágenes no salen en el árbol) y
    // no sus antepasados, que solo lo sitúan.
    expect(json.json()).toEqual([{ name: 'web', type: 'container' }]);

    const text = await get('/assets/export?format=json&q=CT-DOCK&columns=name');
    expect(text.json()).toEqual([{ name: 'ct-docker' }]);
  });

  it('valida las columnas: nunca conexión, credenciales ni facts', async () => {
    for (const column of ['connection', 'credentials', 'facts', 'sshAuth'])
      expect((await get(`/assets/export?columns=name,${column}`)).statusCode).toBe(400);
    expect((await get('/assets/export?format=xml')).statusCode).toBe(400);
  });

  it('vulnerabilidades críticas de un proyecto a CSV, por CVE', async () => {
    const res = await get(
      `/vulnerabilities/export?status=open&minSeverity=CRITICAL&projectId=${project}`,
    );
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-disposition']).toContain('infraward-vulnerabilidades-');
    const lines = res.body.replace(/^\uFEFF/, '').split('\r\n').filter(Boolean);
    expect(lines[0]).toBe(
      'vulnerabilityId,priority,band,reasons,severity,cvss,kev,epss,title,fixable,packages,images,containers,otherAssets,unusedImages,publicDomains,url',
    );
    // Solo la crítica de nginx (la de pg no es del proyecto).
    expect(lines).toHaveLength(2);
    expect(lines[1]!.startsWith('CVE-2026-0001,')).toBe(true);
    expect(lines[1]).toContain(',CRITICAL,');
    // El título con forma de fórmula sale neutralizado.
    expect(lines[1]).toContain(`"'=HYPERLINK(""http://x"")"`);
  });

  it('vulnerabilidades por asset (CSV y JSON)', async () => {
    const csv = await get('/vulnerabilities/export?status=open&groupBy=asset');
    expect(csv.headers['content-disposition']).toContain('vulnerabilidades-por-asset');
    const [header, ...rows] = csvRows(csv.body);
    expect(header!.slice(0, 6)).toEqual(['assetId', 'asset', 'type', 'projects', 'containers', 'cves']);
    // Los más graves primero.
    expect(rows[0]![1]).toBe('nginx:latest');
    const nginx = rows.find((r) => r[1] === 'nginx:latest')!;
    expect(nginx[4]).toBe('web');
    expect(nginx.at(-1)).toBe('CVE-2026-0001; CVE-2026-0002');

    const json = await get(
      `/vulnerabilities/export?status=open&groupBy=asset&format=json&projectId=${project}`,
    );
    const items = json.json<{ name: string; critical: number; findings: { id: string }[] }[]>();
    expect(items.map((i) => i.name)).toEqual(['nginx:latest']);
    expect(items[0]!.critical).toBe(1);
    expect(items[0]!.findings.map((f) => f.id)).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
  });

  it('sin sesión, 401', async () => {
    expect((await app.inject({ method: 'GET', url: '/assets/export' })).statusCode).toBe(401);
  });

  it('0 fugas: ningún fichero lleva referencias a secretos ni facts', () => {
    const all = bodies.join('\n');
    for (const sentinel of SECRET_SENTINELS) expect(all).not.toContain(sentinel);
    expect(all).not.toContain('secret://');
    expect(all).not.toContain('10.9.9.1:22');
  });
});
