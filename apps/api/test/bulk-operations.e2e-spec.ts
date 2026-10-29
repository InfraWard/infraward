import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  QUEUE_NAMES,
  SCAN_DISABLED_REASON,
  type AuditPage,
  type BulkOperationResult,
  type BulkPreviewResponse,
  type JobRunSummary,
  type Page,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
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

const OPERATOR = { email: 'operador-lote@infraward.test', password: 'contraseña-del-operador' };
const VIEWER = { email: 'lector-lote@infraward.test', password: 'contraseña-del-lector' };

/**
 * Operaciones en lote (QoL-6): una llamada para N assets, una fila en la Actividad con sus jobs
 * colgando, un evento de auditoría, omitidos con su motivo y permisos por acción. Sin worker: los
 * jobs se quedan en cola (se vacían al terminar).
 */
describe('Operaciones en lote (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let operator: string;
  let viewer: string;
  let inv: SeededInventory;
  const responses: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_bulk');
    app = await createTestApp();
    db = app.get(DataSource);
    const users = app.get(UsersService);
    await users.create(OPERATOR.email, OPERATOR.password, 'operator');
    await users.create(VIEWER.email, VIEWER.password, 'viewer');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    operator = await loginToken(app, OPERATOR.email, OPERATOR.password);
    viewer = await loginToken(app, VIEWER.email, VIEWER.password);
    inv = await seedInventory(db);
  });

  afterAll(async () => {
    // Que los jobs encolados no los recoja el worker de otro e2e (mismo Redis).
    for (const name of Object.values(QUEUE_NAMES))
      await app?.get<Queue>(getQueueToken(name)).obliterate({ force: true });
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'PUT',
    url: string,
    payload?: object,
    token = admin,
  ) {
    const res = await app.inject({ method, url, payload, headers: authHeaders(token) });
    responses.push(res.body);
    return res;
  }

  const audit = async (action: string) =>
    (await request('GET', `/audit?action=${action}`)).json<AuditPage>().items;

  const tagsOf = async (ids: string[]) =>
    (
      (await db.query(`SELECT id, tags FROM assets WHERE id = ANY($1)`, [ids])) as {
        id: string;
        tags: string[];
      }[]
    ).map((r) => r.tags);

  it('etiqueta 3 assets en una sola llamada: una auditoría y una fila en la Actividad', async () => {
    const ids = [inv.web, inv.cache, inv.db];
    const res = await request('POST', '/assets/bulk/tags', {
      assetIds: ids,
      add: ['lab', 'qol6'],
      remove: [],
    });
    expect(res.statusCode).toBe(200);
    const out = res.json<BulkOperationResult>();
    expect(out.action).toBe('tags');
    expect(out.applied.map((a) => a.name).sort()).toEqual(['cache', 'db', 'web']);
    expect(out.skipped).toEqual([]);
    expect(await tagsOf(ids)).toEqual([
      ['lab', 'qol6'],
      ['lab', 'qol6'],
      ['lab', 'qol6'],
    ]);

    const events = await audit('asset.bulk_tags');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      actorEmail: ADMIN.email,
      targetType: 'bulk_operation',
      targetId: out.operationId,
      details: { count: 3, added: ['lab', 'qol6'], removed: [], skipped: 0 },
    });
    expect((events[0]!.details['assets'] as string[]).sort()).toEqual(['cache', 'db', 'web']);
    // Nada de un evento por asset.
    expect(await audit('asset.tags_changed')).toHaveLength(0);

    const runs = (await request('GET', '/jobs?name=assets.bulk')).json<Page<JobRunSummary>>();
    expect(runs.items).toHaveLength(1);
    expect(runs.items[0]).toMatchObject({
      id: out.operationId,
      state: 'completed',
      assetId: null,
    });
    expect(runs.items[0]!.message).toContain('Etiquetar · 3 assets');
    expect(runs.items[0]!.assetName).toMatch(/web|cache|db/);
  });

  it('quitar y añadir a la vez; los que ya estaban así salen omitidos', async () => {
    const res = await request('POST', '/assets/bulk/tags', {
      assetIds: [inv.web, inv.cache],
      add: [],
      remove: ['qol6'],
    });
    expect(res.json<BulkOperationResult>().applied).toHaveLength(2);
    const again = await request('POST', '/assets/bulk/tags', {
      assetIds: [inv.web, inv.db],
      add: ['lab'],
      remove: ['qol6'],
    });
    const out = again.json<BulkOperationResult>();
    expect(out.applied.map((a) => a.name)).toEqual(['db']);
    expect(out.skipped).toEqual([
      expect.objectContaining({ name: 'web', reason: 'Ya estaba así' }),
    ]);
    expect(
      (await request('POST', '/assets/bulk/tags', { assetIds: [inv.web], add: ['x'], remove: ['x'] }))
        .statusCode,
    ).toBe(400);
  });

  it('escanea 3 assets en una sola acción: los jobs cuelgan de la operación', async () => {
    const res = await request('POST', '/assets/bulk/scan', {
      assetIds: [inv.web, inv.cache, inv.db, inv.pending],
    });
    expect(res.statusCode).toBe(202);
    const out = res.json<BulkOperationResult>();
    expect(out.applied.map((a) => a.name)).toEqual(['web', 'cache', 'db']);
    expect(out.jobs).toHaveLength(3);
    expect(out.skipped).toEqual([
      expect.objectContaining({ name: 'pendiente', reason: expect.stringMatching(/escanean/) }),
    ]);

    const children = (
      await request('GET', `/jobs?parentJobId=${out.operationId}`)
    ).json<Page<JobRunSummary>>();
    expect(children.total).toBe(3);
    expect(children.items.every((j) => j.name === 'image.scan')).toBe(true);
    expect(children.items.map((j) => j.id).sort()).toEqual([...out.jobs].sort());

    const [parent] = (await request('GET', '/jobs?name=assets.bulk&limit=1')).json<
      Page<JobRunSummary>
    >().items;
    expect(parent).toMatchObject({
      id: out.operationId,
      children: { total: 3, running: 3, failed: 0 },
    });
    expect(parent!.message).toContain('Escanear · 3 assets · 1 omitido · 3 tareas');

    const [event] = await audit('asset.bulk_scan');
    expect(event).toMatchObject({
      targetId: out.operationId,
      details: { count: 3, jobs: 3, skipped: 1 },
    });

    // Repetirlo mientras siguen en cola: los mismos jobs (deduplicados), no otros.
    const again = (
      await request('POST', '/assets/bulk/scan', { assetIds: [inv.web, inv.cache, inv.db] })
    ).json<BulkOperationResult>();
    expect([...again.jobs].sort()).toEqual([...out.jobs].sort());
    expect((await audit('asset.bulk_scan'))[0]!.details).toMatchObject({ alreadyRunning: 3 });
    const [latest] = (await request('GET', '/jobs?name=assets.bulk&limit=1')).json<
      Page<JobRunSummary>
    >().items;
    expect(latest!.message).toContain('3 tareas · 3 ya en curso');
    // Las ya en curso siguen colgando de la operación que las lanzó.
    expect(latest!.children).toBeUndefined();
  });

  it('por CVE: los afectados (imágenes y CT), filtrables por proyecto', async () => {
    const res = await request('POST', '/assets/bulk/preview', {
      vulnerabilityIds: ['cve-2026-0001'],
    });
    expect(res.statusCode).toBe(200);
    expect(res.json<BulkPreviewResponse>().assets.map((a) => a.name).sort()).toEqual([
      'ct-docker',
      'nginx:latest',
    ]);
    expect(
      (await request('POST', '/assets/bulk/preview', { vulnerabilityIds: ['CVE-1999-0000'] }))
        .statusCode,
    ).toBe(404);
    expect(
      (
        await request('POST', '/assets/bulk/preview', {
          assetIds: [inv.web],
          vulnerabilityIds: ['CVE-2026-0001'],
        })
      ).statusCode,
    ).toBe(400);
  });

  it('mueve a un proyecto (include, exclude, inherit) con una sola auditoría', async () => {
    const project = (await request('POST', '/projects', { name: 'Lote' })).json<{ id: string }>();
    const move = (mode: string, assetIds: string[]) =>
      request('POST', '/assets/bulk/project', { assetIds, project: project.id, mode });
    const res = await move('include', [inv.web, inv.cache]);
    expect(res.statusCode).toBe(200);
    expect(res.json<BulkOperationResult>().applied).toHaveLength(2);
    const projectsOf = async (id: string) =>
      ((await db.query('SELECT effective_projects FROM assets WHERE id = $1', [id])) as {
        effective_projects: string[];
      }[])[0]!.effective_projects;
    expect(await projectsOf(inv.web)).toContain(project.id);
    // La imagen entra en los proyectos de quien la usa (recalculado una vez).
    expect(await projectsOf(inv.images.nginx)).toContain(project.id);
    await move('inherit', [inv.web]);
    expect(await projectsOf(inv.web)).not.toContain(project.id);
    expect(
      (await audit('asset.bulk_project')).map((e) => e.details['mode']),
    ).toEqual(['inherit', 'include']);
    expect(await audit('project.member_set')).toHaveLength(0);
    expect((await move('include', [inv.web])).statusCode).toBe(200);
    expect(
      (await request('POST', '/assets/bulk/project', {
        assetIds: [inv.web],
        project: '00000000-0000-4000-8000-000000000000',
        mode: 'include',
      })).statusCode,
    ).toBe(404);
  });

  it('aplica una política: con el escaneo desactivado, escanear los omite con el motivo', async () => {
    const res = await request('POST', '/assets/bulk/policy', {
      assetIds: [inv.web, inv.cache],
      fields: { scanEnabled: false },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json<BulkOperationResult>().applied).toHaveLength(2);
    const scan = (
      await request('POST', '/assets/bulk/scan', { assetIds: [inv.web, inv.cache] })
    ).json<BulkOperationResult>();
    expect(scan.applied).toEqual([]);
    expect(scan.skipped.map((s) => s.reason)).toEqual([
      SCAN_DISABLED_REASON,
      SCAN_DISABLED_REASON,
    ]);
    const [event] = await audit('asset.bulk_policy');
    expect(event!.details).toMatchObject({ count: 2, scanEnabled: false });
    // Quitar la regla.
    const clear = await request('POST', '/assets/bulk/policy', {
      assetIds: [inv.web, inv.cache, inv.db],
      clear: true,
    });
    const out = clear.json<BulkOperationResult>();
    expect(out.applied).toHaveLength(2);
    expect(out.skipped).toEqual([expect.objectContaining({ name: 'db', reason: 'Ya estaba así' })]);
    expect((await request('POST', '/assets/bulk/policy', { assetIds: [inv.web] })).statusCode).toBe(
      400,
    );
  });

  it('permisos por acción: el lector nada, el operador recolecta y escanea pero no etiqueta', async () => {
    const target = { assetIds: [inv.web] };
    for (const path of ['tags', 'project', 'policy', 'collect', 'scan', 'retire'])
      expect(
        (await request('POST', `/assets/bulk/${path}`, target, viewer)).statusCode,
      ).toBe(403);
    expect(
      (await request('POST', '/assets/bulk/tags', { ...target, add: ['x'], remove: [] }, operator))
        .statusCode,
    ).toBe(403);
    expect((await request('POST', '/assets/bulk/retire', target, operator)).statusCode).toBe(403);
    expect((await request('POST', '/assets/bulk/scan', target, operator)).statusCode).toBe(202);
    const collect = await request('POST', '/assets/bulk/collect', { assetIds: [inv.ct, inv.pending] }, operator);
    expect(collect.statusCode).toBe(202);
    const out = collect.json<BulkOperationResult>();
    // El CT se recoge por su nodo, que no tiene host key: omitido con el motivo de la ficha.
    expect(out.skipped.map((s) => s.name).sort()).toEqual(['ct-docker', 'pendiente']);
    expect(out.skipped.every((s) => s.reason.length > 0)).toBe(true);
  });

  it('valida el tamaño y los ids: más de 500 o inexistentes', async () => {
    const many = Array.from({ length: 501 }, () => crypto.randomUUID());
    expect((await request('POST', '/assets/bulk/scan', { assetIds: many })).statusCode).toBe(400);
    expect((await request('POST', '/assets/bulk/scan', {})).statusCode).toBe(400);
    const ghost = '00000000-0000-4000-8000-000000000001';
    const out = (
      await request('POST', '/assets/bulk/tags', { assetIds: [ghost, inv.db], add: ['z'], remove: [] })
    ).json<BulkOperationResult>();
    expect(out.applied.map((a) => a.name)).toEqual(['db']);
    expect(out.skipped).toEqual([expect.objectContaining({ id: ghost, reason: 'No existe' })]);
  });

  it('dar de baja: la confirmación enseña el subárbol; una auditoría con todos', async () => {
    const preview = (
      await request('POST', '/assets/bulk/preview', { assetIds: [inv.ct, inv.pending] })
    ).json<BulkPreviewResponse>();
    expect(preview.assets.map((a) => a.name)).toEqual(['ct-docker', 'pendiente']);
    // El CT arrastra sus 3 contenedores (las imágenes no cuelgan por `contains`).
    expect(preview.retire.descendants.map((a) => a.name).sort()).toEqual(['cache', 'db', 'web']);
    expect(preview.retire.total).toBe(5);

    const res = await request('POST', '/assets/bulk/retire', {
      assetIds: [inv.ct, inv.pending],
    });
    expect(res.statusCode).toBe(200);
    const out = res.json<BulkOperationResult>();
    expect(out.applied).toHaveLength(2);
    expect(out.revocations).toEqual([]);
    const statuses: { status: string }[] = await db.query(
      `SELECT status FROM assets WHERE id = ANY($1)`,
      [[inv.ct, inv.pending, inv.web, inv.cache, inv.db]],
    );
    expect(statuses.every((s) => s.status === 'retired')).toBe(true);
    const [event] = await audit('asset.bulk_retire');
    expect(event!.details).toMatchObject({ count: 2, affected: 5 });
    expect(await audit('asset.retired')).toHaveLength(0);

    // Repetirlo: ya estaban dados de baja.
    const again = (
      await request('POST', '/assets/bulk/retire', { assetIds: [inv.ct] })
    ).json<BulkOperationResult>();
    expect(again.skipped).toEqual([
      expect.objectContaining({ reason: 'Ya estaba dado de baja' }),
    ]);
  });

  it('0 fugas: ninguna respuesta lleva referencias a secretos ni facts', () => {
    const all = responses.join('\n');
    for (const sentinel of SECRET_SENTINELS) expect(all).not.toContain(sentinel);
  });
});
