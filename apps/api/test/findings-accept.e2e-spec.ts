import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  AssetFindingsPage,
  AuditPage,
  FindingAcceptanceResult,
  VulnerabilitiesPage,
  VulnerabilityDetail,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { seedInventory, type SeededInventory } from './support/inventory-seed.js';

const EDITOR = { email: 'editor-riesgo@infraward.test', password: 'contraseña-del-editor' };
const OPERATOR = { email: 'operador-riesgo@infraward.test', password: 'contraseña-del-operador' };

/**
 * «Aceptar el riesgo» (DESIGN §9): por CVE y por finding, con motivo y caducidad, permisos, el
 * evento de auditoría, que sale de los abiertos pero sigue como afectado en el buscador, y reabrir.
 */
describe('Aceptar el riesgo (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let editor: string;
  let operator: string;
  let inv: SeededInventory;

  beforeAll(async () => {
    await prepareEnv('e2e_accept');
    app = await createTestApp();
    db = app.get(DataSource);
    const users = app.get(UsersService);
    await users.create(EDITOR.email, EDITOR.password, 'editor');
    await users.create(OPERATOR.email, OPERATOR.password, 'operator');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    editor = await loginToken(app, EDITOR.email, EDITOR.password);
    operator = await loginToken(app, OPERATOR.email, OPERATOR.password);
    inv = await seedInventory(db);
  });

  afterAll(async () => {
    await app?.close();
  });

  const post = (url: string, payload: object, token = admin) =>
    app.inject({ method: 'POST', url, payload, headers: authHeaders(token) });
  const get = <T>(url: string, token = admin) =>
    app
      .inject({ method: 'GET', url, headers: authHeaders(token) })
      .then((r) => r.json<T>());
  const openCves = async () =>
    (await get<VulnerabilitiesPage>('/vulnerabilities?status=open&limit=50')).items
      .map((v) => v.vulnerabilityId)
      .sort();

  it('valida el motivo, la caducidad y el destino', async () => {
    const short = await post('/findings/accept', {
      vulnerabilityIds: ['CVE-2026-0002'],
      reason: 'corto',
    });
    expect(short.statusCode).toBe(400);
    const past = await post('/findings/accept', {
      vulnerabilityIds: ['CVE-2026-0002'],
      reason: 'no se usa la función afectada',
      expiresAt: '2020-01-01T00:00:00Z',
    });
    expect(past.statusCode).toBe(400);
    const both = await post('/findings/accept', {
      vulnerabilityIds: ['CVE-2026-0002'],
      findingIds: ['00000000-0000-4000-8000-000000000000'],
      reason: 'no se usa la función afectada',
    });
    expect(both.statusCode).toBe(400);
    const missing = await post('/findings/accept', {
      findingIds: ['00000000-0000-4000-8000-000000000000'],
      reason: 'no se usa la función afectada',
    });
    expect(missing.statusCode).toBe(404);
  });

  it('un operador no puede aceptar el riesgo', async () => {
    const res = await post(
      '/findings/accept',
      { vulnerabilityIds: ['CVE-2026-0002'], reason: 'no se usa la función afectada' },
      operator,
    );
    expect(res.statusCode).toBe(403);
  });

  it('acepta por CVE: sale de los abiertos, sigue afectando y queda auditado', async () => {
    expect(await openCves()).toContain('CVE-2026-0002');
    const expiresAt = new Date(Date.now() + 30 * 86_400_000).toISOString();
    const res = await post(
      '/findings/accept',
      { vulnerabilityIds: ['cve-2026-0002'], reason: 'sin parche de la distro', expiresAt },
      editor,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json<FindingAcceptanceResult>()).toEqual({ updated: 2, vulnerabilities: 1 });
    expect(await openCves()).not.toContain('CVE-2026-0002');

    // El buscador lo sigue enseñando como afectado, con la aceptación.
    const detail = await get<VulnerabilityDetail>('/vulnerabilities/CVE-2026-0002');
    const packages = detail.tree.flatMap(function walk(n): typeof n.packages {
      return [...n.packages, ...n.children.flatMap(walk)];
    });
    expect(packages.length).toBe(2);
    for (const p of packages) {
      expect(p.status).toBe('accepted');
      expect(p.acceptance).toMatchObject({
        by: EDITOR.email,
        reason: 'sin parche de la distro',
      });
      expect(new Date(p.acceptance!.expiresAt!).toISOString()).toBe(expiresAt);
    }

    // Repetirlo: ya no hay abiertos.
    const again = await post(
      '/findings/accept',
      { vulnerabilityIds: ['CVE-2026-0002'], reason: 'sin parche de la distro' },
      editor,
    );
    expect(again.statusCode).toBe(409);

    const audit = (await get<AuditPage>('/audit?action=finding.accepted')).items;
    expect(audit[0]).toMatchObject({
      actorEmail: EDITOR.email,
      targetLabel: 'CVE-2026-0002',
      details: {
        count: 2,
        vulnerabilities: ['CVE-2026-0002'],
        reason: 'sin parche de la distro',
        expiresAt,
      },
    });
  });

  it('acepta un finding suelto y lo reabre', async () => {
    const page = await get<AssetFindingsPage>(`/assets/${inv.ct}/findings`);
    const finding = page.items.find((f) => f.vulnerabilityId === 'CVE-2026-0001')!;
    expect(finding.acceptance).toBeNull();
    const res = await post('/findings/accept', {
      findingIds: [finding.id],
      reason: 'el servicio no escucha fuera',
    });
    expect(res.json<FindingAcceptanceResult>()).toEqual({ updated: 1, vulnerabilities: 1 });
    // El de la imagen nginx con el mismo CVE sigue abierto.
    expect(await openCves()).toContain('CVE-2026-0001');
    const after = await get<AssetFindingsPage>(`/assets/${inv.ct}/findings?status=accepted`);
    expect(after.items.map((f) => f.id)).toEqual([finding.id]);
    expect(after.items[0]!.acceptance).toMatchObject({
      by: ADMIN.email,
      expiresAt: null,
    });

    const reopened = await post('/findings/reopen', { findingIds: [finding.id] });
    expect(reopened.json<FindingAcceptanceResult>()).toEqual({ updated: 1, vulnerabilities: 1 });
    const open = await get<AssetFindingsPage>(`/assets/${inv.ct}/findings?status=open`);
    const back = open.items.find((f) => f.id === finding.id)!;
    // La aceptación queda como historial.
    expect(back.acceptance?.reason).toBe('el servicio no escucha fuera');
    expect((await get<AuditPage>('/audit?action=finding.reopened')).items[0]).toMatchObject({
      actorEmail: ADMIN.email,
      details: { count: 1, vulnerabilities: ['CVE-2026-0001'] },
    });

    const twice = await post('/findings/reopen', { findingIds: [finding.id] });
    expect(twice.statusCode).toBe(409);
  });

  it('reabre por CVE', async () => {
    const res = await post('/findings/reopen', { vulnerabilityIds: ['CVE-2026-0002'] }, editor);
    expect(res.json<FindingAcceptanceResult>()).toEqual({ updated: 2, vulnerabilities: 1 });
    expect(await openCves()).toContain('CVE-2026-0002');
  });
});
