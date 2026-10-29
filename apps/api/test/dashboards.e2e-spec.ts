import { randomUUID } from 'node:crypto';
import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  DEFAULT_DASHBOARD,
  JOB_NAMES,
  QUEUE_NAMES,
  type AssetCountsData,
  type AttentionData,
  type DashboardDocument,
  type DashboardLayout,
  type ExpirationsData,
  type FixableVulnerabilitiesData,
  type NewVulnerabilitiesData,
  type PendingEnrollmentData,
  type Project,
  type ProjectStats,
  type TopVulnerabilitiesData,
  type TrendData,
  type VulnerabilityCountsData,
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
  seedInventory,
  type SeededInventory,
} from './support/inventory-seed.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
} from './support/worker.js';

const PASSWORD = 'otra-contraseña-larga';
const DAY = 86_400_000;

/**
 * Paneles personalizables (QoL-8, DESIGN §15): el panel de cada usuario y el de cada proyecto
 * (versión, permisos, auditoría, cascada), los datos de cada widget con sus filtros, la caché
 * corta y la muestra diaria de los gráficos con el worker real.
 */
describe('Paneles (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let admin: string;
  let editor: string;
  let viewer: string;
  let inv: SeededInventory;
  let homelab: Project;
  let domain: string;

  beforeAll(async () => {
    await prepareEnv('e2e_dashboards');
    app = await createTestApp();
    db = app.get(DataSource);
    const users = app.get(UsersService);
    await users.create('editor-dash@infraward.test', PASSWORD, 'editor');
    await users.create('viewer-dash@infraward.test', PASSWORD, 'viewer');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    editor = await loginToken(app, 'editor-dash@infraward.test', PASSWORD);
    viewer = await loginToken(app, 'viewer-dash@infraward.test', PASSWORD);

    inv = await seedInventory(db);
    // Prioridades fijas (sin worker): CVE-0001 urgente, CVE-0002 alta, CVE-0003 media.
    await db.query(`UPDATE findings SET priority = CASE vulnerability_id
        WHEN 'CVE-2026-0001' THEN 85 WHEN 'CVE-2026-0002' THEN 60 ELSE 35 END`);
    await db.query(`UPDATE assets SET tags = ARRAY['prod'] WHERE id = $1`, [
      inv.web,
    ]);
    // Un dominio que caduca en 10 días y un certificado caducado, dentro del nodo.
    const [d]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, discovered_name, status, facts) VALUES
         ('domain', 'homelab.dev', 'active', $1) RETURNING id`,
      [
        {
          registration: {
            expiresAt: new Date(Date.now() + 10 * DAY).toISOString(),
          },
        },
      ],
    );
    domain = d!.id;
    const [c]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, discovered_name, status, facts) VALUES
         ('certificate', 'homelab.dev (cert)', 'active', $1) RETURNING id`,
      [
        {
          certificate: {
            notAfter: new Date(Date.now() - 2 * DAY).toISOString(),
          },
        },
      ],
    );
    // Un dominio fuera de todo proyecto que caduca en 3 días.
    await db.query(
      `INSERT INTO assets (type, discovered_name, status, facts) VALUES
         ('domain', 'fuera.dev', 'active', $1)`,
      [
        {
          registration: {
            expiresAt: new Date(Date.now() + 3 * DAY).toISOString(),
          },
        },
      ],
    );

    const res = await request('POST', '/projects', { name: 'Homelab' });
    expect(res.statusCode).toBe(201);
    homelab = res.json<Project>();
    for (const id of [inv.node, domain, c!.id])
      expect(
        (
          await request('PUT', `/projects/${homelab.id}/members/${id}`, {
            mode: 'include',
          })
        ).statusCode,
      ).toBe(200);
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    payload?: object,
    token: string = admin,
  ) {
    return app.inject({ method, url, payload, headers: authHeaders(token) });
  }

  const widget = async <T>(
    type: string,
    query = '',
    token = admin,
  ): Promise<T> => {
    const res = await request(
      'GET',
      `/dashboard/widgets/${type}${query ? `?${query}` : ''}`,
      undefined,
      token,
    );
    expect(res.statusCode, res.body).toBe(200);
    return res.json<T>();
  };

  /** Un diseño pequeño válido. */
  const layout = (projectId?: string): DashboardLayout => ({
    schema: 1,
    widgets: [
      {
        id: 'top',
        type: 'top-vulnerabilities',
        x: 0,
        y: 0,
        w: 6,
        h: 5,
        filters: projectId ? { projectId } : { tags: ['prod'] },
        options: { limit: '10' },
      },
      {
        id: 'exp',
        type: 'expirations',
        x: 6,
        y: 0,
        w: 6,
        h: 5,
        filters: {},
        options: {},
      },
    ],
  });

  describe('panel personal', () => {
    it('sin guardar, el por defecto; al guardar se conserva; otro usuario no lo ve', async () => {
      const first = (
        await request('GET', '/dashboards/me')
      ).json<DashboardDocument>();
      expect(first).toMatchObject({
        isDefault: true,
        version: 0,
        layout: DEFAULT_DASHBOARD,
      });

      const saved = await request('PUT', '/dashboards/me', {
        layout: layout(),
        version: 0,
      });
      expect(saved.statusCode, saved.body).toBe(200);
      expect(saved.json<DashboardDocument>()).toMatchObject({
        isDefault: false,
        version: 1,
      });
      const again = (
        await request('GET', '/dashboards/me')
      ).json<DashboardDocument>();
      expect(again.layout.widgets.map((w) => w.id)).toEqual(['top', 'exp']);
      // Normalizado: las opciones que faltaban, con su valor por defecto.
      expect(again.layout.widgets[1]!.options).toEqual({
        kinds: ['domain', 'certificate'],
        horizonDays: null,
        limit: '10',
      });

      const other = (
        await request('GET', '/dashboards/me', undefined, viewer)
      ).json<DashboardDocument>();
      expect(other.isDefault).toBe(true);
    });

    it('409 con una versión vieja; 400 con un diseño no válido, con el motivo', async () => {
      const stale = await request('PUT', '/dashboards/me', {
        layout: layout(),
        version: 0,
      });
      expect(stale.statusCode).toBe(409);
      const overlap = layout();
      overlap.widgets[1]!.x = 3;
      const bad = await request('PUT', '/dashboards/me', {
        layout: overlap,
        version: 1,
      });
      expect(bad.statusCode).toBe(400);
      expect(bad.json<{ message: string }>().message).toContain('se solapan');
      const unknown = await request('PUT', '/dashboards/me', {
        layout: {
          schema: 1,
          widgets: [{ ...layout().widgets[0], type: 'nope' }],
        },
        version: 1,
      });
      expect(unknown.statusCode).toBe(400);
      const ok = await request('PUT', '/dashboards/me', {
        layout: layout(),
        version: 1,
      });
      expect(ok.json<DashboardDocument>().version).toBe(2);
    });

    it('restablecer vuelve al por defecto', async () => {
      const reset = await request('DELETE', '/dashboards/me');
      expect(reset.json<DashboardDocument>()).toMatchObject({
        isDefault: true,
        version: 0,
      });
    });
  });

  describe('panel de un proyecto', () => {
    it('sin guardar, la plantilla fijada al proyecto; un lector no lo cambia, un editor sí (auditado)', async () => {
      const tpl = (
        await request(
          'GET',
          `/projects/${homelab.id}/dashboard`,
          undefined,
          viewer,
        )
      ).json<DashboardDocument>();
      expect(tpl.isDefault).toBe(true);
      expect(tpl.layout.widgets.map((w) => w.type)).toEqual(
        expect.arrayContaining(['top-vulnerabilities', 'expirations']),
      );
      for (const w of tpl.layout.widgets)
        expect(w.filters.projectId).toBe(homelab.id);

      const denied = await request(
        'PUT',
        `/projects/${homelab.id}/dashboard`,
        { layout: layout(), version: 0 },
        viewer,
      );
      expect(denied.statusCode).toBe(403);

      // Un widget que apunta a otro proyecto (o a ninguno) queda fijado a este.
      const saved = await request(
        'PUT',
        `/projects/${homelab.id}/dashboard`,
        { layout: layout(randomUUID()), version: 0 },
        editor,
      );
      expect(saved.statusCode, saved.body).toBe(200);
      const doc = saved.json<DashboardDocument>();
      expect(doc).toMatchObject({
        isDefault: false,
        version: 1,
        updatedBy: expect.any(String),
      });
      for (const w of doc.layout.widgets)
        expect(w.filters.projectId).toBe(homelab.id);

      const [event]: {
        action: string;
        target_id: string;
        details: { widgets: string[] };
      }[] = await db.query(
        `SELECT action, target_id, details FROM audit_events
          WHERE action = 'project.dashboard_updated' ORDER BY occurred_at DESC LIMIT 1`,
      );
      expect(event).toMatchObject({
        target_id: homelab.id,
        details: { widgets: ['top-vulnerabilities', 'expirations'] },
      });

      const missing = await request(
        'GET',
        `/projects/${randomUUID()}/dashboard`,
      );
      expect(missing.statusCode).toBe(404);
    });

    it('se borra con el proyecto', async () => {
      const tmp = (
        await request('POST', '/projects', { name: 'Temporal' })
      ).json<Project>();
      await request('PUT', `/projects/${tmp.id}/dashboard`, {
        layout: layout(),
        version: 0,
      });
      const before: unknown[] = await db.query(
        `SELECT 1 FROM dashboards WHERE project_id = $1`,
        [tmp.id],
      );
      expect(before).toHaveLength(1);
      expect((await request('DELETE', `/projects/${tmp.id}`)).statusCode).toBe(
        204,
      );
      const after: unknown[] = await db.query(
        `SELECT 1 FROM dashboards WHERE project_id = $1`,
        [tmp.id],
      );
      expect(after).toHaveLength(0);
    });
  });

  describe('datos de cada widget', () => {
    it('vulnerabilidades prioritarias: todo, por proyecto y por tag (en el asset afectado)', async () => {
      const all = await widget<VulnerabilityCountsData>('vulnerability-counts');
      expect(all).toEqual({ urgent: 1, high: 1, medium: 1, kev: 0, cves: 3 });
      const project = await widget<VulnerabilityCountsData>(
        'vulnerability-counts',
        `projectId=${homelab.id}`,
      );
      expect(project.cves).toBe(3);
      // `prod` solo lo lleva el contenedor web (nginx: CVE-0001 y CVE-0002).
      const prod = await widget<VulnerabilityCountsData>(
        'vulnerability-counts',
        'tag=prod',
      );
      expect(prod).toMatchObject({ urgent: 1, high: 1, medium: 0, cves: 2 });
      const top = await widget<TopVulnerabilitiesData>(
        'top-vulnerabilities',
        'limit=5&minPriority=high',
      );
      expect(top.total).toBe(2);
      expect(
        top.items.map((v) => [v.vulnerabilityId, v.priority.band]),
      ).toEqual([
        ['CVE-2026-0001', 'urgent'],
        ['CVE-2026-0002', 'high'],
      ]);
    });

    it('tags con tildes: el widget y el filtro de Vulnerabilidades encuentran lo del servidor con ese tag', async () => {
      // El CT tiene sus propios hallazgos (CVE-0001); el tag lleva tilde y mayúscula.
      await db.query(
        `UPDATE assets SET tags = ARRAY['Producción'] WHERE id = $1`,
        [inv.ct],
      );
      const counts = await widget<VulnerabilityCountsData>(
        'vulnerability-counts',
        `tag=${encodeURIComponent('Producción')}`,
      );
      expect(counts.cves).toBe(1);
      for (const q of ['tag:Producción', 'tag:produccion', 'tag:PRODUCCIÓN']) {
        const res = await request(
          'GET',
          `/vulnerabilities?q=${encodeURIComponent(q)}&includeNoise=true`,
        );
        const ids = res
          .json<{ items: { vulnerabilityId: string }[] }>()
          .items.map((v) => v.vulnerabilityId);
        expect(ids, q).toEqual(['CVE-2026-0001']);
      }
      await db.query(`UPDATE assets SET tags = '{}' WHERE id = $1`, [inv.ct]);
    });

    it('assets por tipo o estado, con tipos y proyecto; pendientes de alta', async () => {
      const byType = await widget<AssetCountsData>(
        'asset-counts',
        `projectId=${homelab.id}&type=container&type=lxc`,
      );
      expect(byType.counts).toEqual({ container: 3, lxc: 1 });
      const byStatus = await widget<AssetCountsData>(
        'asset-counts',
        'groupBy=status',
      );
      expect(byStatus.counts).toMatchObject({ pending_enrollment: 1 });
      const pending = await widget<PendingEnrollmentData>(
        'pending-enrollment',
        'limit=5',
      );
      expect(pending.count).toBe(1);
      expect(pending.assets.map((a) => a.name)).toEqual(['pendiente']);
      const none = await widget<PendingEnrollmentData>(
        'pending-enrollment',
        `projectId=${homelab.id}`,
      );
      expect(none).toEqual({ count: 0, assets: [] });
    });

    it('resumen de assets y con parche: las mismas cifras que la tarjeta del proyecto', async () => {
      const project = (await request('GET', `/projects/${homelab.id}`)).json<{
        stats: ProjectStats;
      }>().stats;
      const assets = await widget<AssetCountsData>(
        'asset-summary',
        `projectId=${homelab.id}`,
      );
      expect(assets.total).toBe(project.assets);
      expect(assets.counts).toEqual(project.assetsByType);
      const fixable = await widget<FixableVulnerabilitiesData>(
        'fixable-vulnerabilities',
        `projectId=${homelab.id}`,
      );
      expect(fixable).toEqual({
        openFindings: project.openFindings,
        fixableFindings: project.fixableFindings,
        openVulnerabilities: project.openVulnerabilities,
      });
      expect(fixable.fixableFindings).toEqual({ CRITICAL: 2, HIGH: 2 });
      // Tags en el dueño: `prod` es el contenedor web, que no tiene hallazgos propios (son de su imagen).
      const prod = await widget<FixableVulnerabilitiesData>(
        'fixable-vulnerabilities',
        'tag=prod',
      );
      expect(prod.openVulnerabilities).toBe(0);
      const images = await widget<FixableVulnerabilitiesData>(
        'fixable-vulnerabilities',
        'type=image',
      );
      expect(images.openVulnerabilities).toBe(3);
    });

    it('caducidades del proyecto, la más próxima primero (y no las de fuera)', async () => {
      const exp = await widget<ExpirationsData>(
        'expirations',
        `projectId=${homelab.id}`,
      );
      expect(exp.horizonDays).toBeGreaterThan(10);
      expect(exp.items.map((e) => [e.asset.name, e.kind])).toEqual([
        ['homelab.dev (cert)', 'certificate'],
        ['homelab.dev', 'domain'],
      ]);
      expect(exp.items[0]!.daysLeft).toBeLessThan(0);
      const all = await widget<ExpirationsData>(
        'expirations',
        'kinds=domain&horizonDays=5',
      );
      expect(all.items.map((e) => e.asset.name)).toEqual(['fuera.dev']);
      const attention = await widget<AttentionData>(
        'attention',
        `projectId=${homelab.id}&kinds=domainsExpiring&kinds=certificatesExpiring`,
      );
      expect(attention.items.map((i) => [i.kind, i.count])).toEqual([
        ['certificatesExpiring', 1],
        ['domainsExpiring', 1],
      ]);
    });

    it('CVE nuevos de los últimos 7 días y evolución reconstruida con «desde»', async () => {
      const fresh = await widget<NewVulnerabilitiesData>(
        'new-vulnerabilities',
        'since=7d',
      );
      expect(fresh.total).toBe(3);
      await db.query(
        `UPDATE findings SET opened_at = now() - interval '20 days', fixed_at = NULL`,
      );
      await db.query(
        `UPDATE findings SET status = 'fixed', fixed_at = now() - interval '5 days'
          WHERE vulnerability_id = 'CVE-2026-0003'`,
      );
      const trend = await widget<TrendData>(
        'trend',
        'metric=open-findings&range=30d&tag=prod&type=container',
      );
      expect(trend).toMatchObject({
        approximate: true,
        bucket: 'day',
        ignoredFilters: false,
      });
      expect(trend.since!.slice(0, 10)).toBe(
        new Date(Date.now() - 20 * DAY).toISOString().slice(0, 10),
      );
      // Desde el primer hallazgo, nunca antes (sin ceros inventados).
      expect(trend.points).toHaveLength(21);
      expect(trend.points.at(-1)!.values).toMatchObject({
        CRITICAL: 1,
        HIGH: 1,
      });
      const flow = await widget<TrendData>(
        'trend',
        'metric=new-vs-fixed&range=30d',
      );
      const total = (k: string) =>
        flow.points.reduce((s, p) => s + (p.values[k] ?? 0), 0);
      expect(total('opened')).toBe(5);
      expect(total('fixed')).toBe(1);
    });

    it('caché corta: la segunda petición igual no vuelve a la BD y lo dice en Cache-Control', async () => {
      const q = `projectId=${homelab.id}&groupBy=type&tag=prod`;
      const first = await request(
        'GET',
        `/dashboard/widgets/asset-counts?${q}`,
      );
      expect(first.headers['cache-control']).toBe('private, max-age=30');
      await db.query(`UPDATE assets SET tags = ARRAY['prod'] WHERE id = $1`, [
        inv.cache,
      ]);
      const second = await request(
        'GET',
        `/dashboard/widgets/asset-counts?${q}`,
      );
      expect(second.json<AssetCountsData>()).toEqual(
        first.json<AssetCountsData>(),
      );
      const running = await request('GET', '/dashboard/widgets/running-jobs');
      expect(running.headers['cache-control']).toBe('private, max-age=5');
    });

    it('400 con filtros no válidos; un token de API de lectura puede leer los widgets', async () => {
      expect(
        (await request('GET', '/dashboard/widgets/asset-counts?type=ufo'))
          .statusCode,
      ).toBe(400);
      expect(
        (await request('GET', '/dashboard/widgets/top-vulnerabilities?limit=7'))
          .statusCode,
      ).toBe(400);
      expect(
        (await request('GET', '/dashboard/widgets/trend?metric=nope'))
          .statusCode,
      ).toBe(400);
      const created = await request('POST', '/auth/tokens', {
        name: 'panel',
        scope: 'read',
        expiresAt: new Date(Date.now() + 7 * DAY).toISOString(),
      });
      expect(created.statusCode).toBe(201);
      const secret = created.json<{ secret: string }>().secret;
      const res = await app.inject({
        method: 'GET',
        url: '/dashboard/widgets/vulnerability-counts',
        headers: { authorization: `Bearer ${secret}` },
      });
      expect(res.statusCode).toBe(200);
    });
  });

  describe('muestras diarias (worker real)', () => {
    it('al arrancar muestrea hoy (global y por proyecto); repetir el mismo día no duplica', async () => {
      worker = await startWorker({ METRICS_SAMPLE_INTERVAL: '24' });
      const count = async () =>
        (await db.query(
          `SELECT count(*)::int AS n FROM metric_samples WHERE day = (now() AT TIME ZONE 'UTC')::date`,
        )) as { n: number }[];
      // Global + Homelab, dos métricas cada uno.
      await waitFor(
        async () => (await count())[0]!.n === 4,
        30_000,
        () => worker!.output.join(''),
      );
      const queue = app.get<Queue>(getQueueToken(QUEUE_NAMES.system));
      const job = await queue.add(
        JOB_NAMES.metricsSample,
        { reason: 'e2e' },
        { jobId: randomUUID() },
      );
      await waitFor(
        async () => (await job.getState()) === 'completed',
        30_000,
        () => worker!.output.join(''),
      );
      expect((await count())[0]!.n).toBe(4);
      const [assets]: { values: Record<string, number> }[] = await db.query(
        `SELECT "values" FROM metric_samples WHERE metric = 'assets_by_status' AND project_id = $1`,
        [homelab.id],
      );
      expect(assets!.values['active']).toBeGreaterThan(0);
      const trend = await widget<TrendData>(
        'trend',
        `metric=assets-by-status&range=30d&projectId=${homelab.id}&tag=prod`,
      );
      expect(trend).toMatchObject({ approximate: false, ignoredFilters: true });
      expect(trend.points).toHaveLength(1);
      expect(trend.since).toBe(trend.points[0]!.day);
    });
  });
});
