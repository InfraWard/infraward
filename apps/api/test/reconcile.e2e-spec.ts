import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type { Queue } from 'bullmq';
import type {
  Asset,
  AssetPolicy,
  AssetTreeSummaryNode,
  EnqueueJobResponse,
  EnrollServerResponse,
  InventoryPolicyList,
  InventoryPolicyRule,
  InventoryReconcileJobResult,
  JobStatus,
  NotificationPage,
  Page,
  Snapshot,
  SnapshotSummary,
  VulnerabilitySummary,
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
import {
  createFakePve,
  type FakeGuest,
  type FakePve,
  type FakePveState,
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker, WORK_QUEUES } from './support/worker.js';

const VIEWER = {
  email: 'viewer-reconcile@infraward.test',
  password: 'otra-contraseña-larga',
};
const NGINX = `sha256:${'1'.repeat(64)}`;
const REDIS = `sha256:${'2'.repeat(64)}`;

const GUESTS: FakeGuest[] = [
  { type: 'lxc', vmid: 100, node: 'pve', name: 'debian', status: 'running' },
  {
    type: 'lxc',
    vmid: 101,
    node: 'pve',
    name: 'docker',
    status: 'running',
    docker: true,
    containers: [
      {
        name: 'web1',
        image: 'nginx:1.25',
        imageId: NGINX,
        state: 'running',
        published: { '80/tcp': 8080 },
      },
      {
        name: 'cache',
        image: 'redis:7.0',
        imageId: REDIS,
        state: 'running',
      },
    ],
  },
];

/**
 * Reconciliación (DESIGN §10) de punta a punta con el worker real y el nodo Proxmox simulado:
 * altas, snapshots solo con cambios (con su diff), missing → retired tras
 * RECONCILE_RETIRE_AFTER ejecuciones sin borrar nada, reaparición, notificaciones y la política
 * de inventario heredada (intervalo, escaneo, escaneo periódico).
 */
describe('Reconciliación (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let adminToken: string;
  let viewerToken: string;
  const responses: string[] = [];
  let node: Asset;
  let plain: Asset;
  let state: FakePveState;

  beforeAll(async () => {
    await prepareEnv('e2e_reconcile');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);

    pve = createFakePve();
    state = {
      node: 'pve',
      cluster: null,
      machineId: 'a'.repeat(32),
      ctMachineId: 'c'.repeat(32),
      guests: structuredClone(GUESTS),
      vulns: {
        [NGINX]: [
          {
            id: 'CVE-2024-6387',
            pkg: 'openssh-client',
            version: '1:9.2p1-2',
            fixed: '1:9.2p1-2+deb12u3',
            severity: 'HIGH',
          },
        ],
      },
    };
    pve.setState(state);

    const enroll = async (name: string) => {
      const res = await request('POST', '/assets/enroll', {
        host: '127.0.0.1',
        port: 22,
        name,
      });
      expect(res.statusCode).toBe(201);
      return res.json<EnrollServerResponse>().asset;
    };
    node = await enroll('pve');
    plain = await enroll('sin-proxmox');
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = ANY($1)`,
      [[node.id, plain.id], pve.fingerprint],
    );
    worker = await startWorker({
      ...pve.workerEnv(),
      RECONCILE_RETIRE_AFTER: '3',
    });
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    url: string,
    payload?: object,
    token: string | null = adminToken,
  ) {
    const res = await app.inject({
      method,
      url,
      payload,
      headers: token ? authHeaders(token) : {},
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  async function finished<T = unknown>(
    id: string,
  ): Promise<JobStatus & { result?: T }> {
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = (await request('GET', `/jobs/${id}`)).json<JobStatus>();
        return last.state === 'completed' || last.state === 'failed';
      },
      30_000,
      () =>
        `job sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    return last as JobStatus & { result?: T };
  }

  /** Espera a que las colas discovery y scan no tengan nada pendiente ni en curso. */
  async function settle(): Promise<void> {
    const queues = WORK_QUEUES.map((q) =>
      app.get<Queue>(getQueueToken(q)),
    );
    await waitFor(
      async () => {
        for (const queue of queues) {
          const counts = await queue.getJobCounts(
            'waiting',
            'active',
            'delayed',
            'prioritized',
          );
          if (Object.values(counts).some((n) => n > 0)) return false;
        }
        return true;
      },
      60_000,
      () => `colas sin vaciar\n${worker?.output.join('')}`,
    );
  }

  /** Reconciliación manual de una raíz (o de las vencidas) y espera a toda la cadena. */
  async function reconcile(
    assetId?: string,
  ): Promise<InventoryReconcileJobResult> {
    const res = await request(
      'POST',
      '/inventory/reconcile',
      assetId ? { assetId } : {},
    );
    expect(res.statusCode).toBe(202);
    const done = await finished<InventoryReconcileJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.state).toBe('completed');
    await settle();
    return done.result!;
  }

  async function assetByName(name: string): Promise<Asset> {
    const [row]: { id: string }[] = await db.query(
      `SELECT id FROM assets WHERE name = $1 ORDER BY created_at LIMIT 1`,
      [name],
    );
    expect(row).toBeDefined();
    return (await request('GET', `/assets/${row.id}`)).json<Asset>();
  }

  async function snapshots(assetId: string): Promise<SnapshotSummary[]> {
    return (
      await request('GET', `/assets/${assetId}/snapshots?limit=100`)
    ).json<Page<SnapshotSummary>>().items;
  }

  async function notifications(): Promise<NotificationPage> {
    return (await request('GET', '/notifications?limit=100')).json();
  }

  it('permisos: el viewer lee la política y las notificaciones, pero no cambia nada', async () => {
    expect(
      (await request('GET', '/inventory-policies', undefined, null)).statusCode,
    ).toBe(401);
    const list = await request(
      'GET',
      '/inventory-policies',
      undefined,
      viewerToken,
    );
    expect(list.statusCode).toBe(200);
    expect(list.json<InventoryPolicyList>().global).toMatchObject({
      scope: 'global',
      reconcileIntervalMinutes: 360,
      scanEnabled: true,
      scanPeriodic: true,
    });
    for (const [method, url, body] of [
      ['PUT', '/inventory-policies/global', { scanEnabled: false }],
      [
        'POST',
        '/inventory-policies',
        { scope: 'tag', tag: 'lab', scanEnabled: false },
      ],
      ['PUT', `/assets/${node.id}/policy`, { scanEnabled: false }],
      ['DELETE', `/assets/${node.id}/policy`, undefined],
      ['POST', '/inventory/reconcile', {}],
    ] as const)
      expect((await request(method, url, body, viewerToken)).statusCode).toBe(
        403,
      );
    expect(
      (await request('GET', '/notifications', undefined, viewerToken))
        .statusCode,
    ).toBe(200);
    expect(
      (
        await request(
          'GET',
          `/assets/${node.id}/policy`,
          undefined,
          viewerToken,
        )
      ).statusCode,
    ).toBe(200);
  });

  it('validación: reglas sin ningún campo, intervalos fuera de rango, duplicadas y raíces', async () => {
    expect(
      (await request('POST', '/inventory-policies', { scope: 'tag', tag: 'x' }))
        .statusCode,
    ).toBe(400);
    expect(
      (
        await request('PUT', '/inventory-policies/global', {
          reconcileIntervalMinutes: 2,
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (
        await request('POST', '/inventory-policies', {
          scope: 'tag',
          tag: 'con espacios',
          scanEnabled: false,
        })
      ).statusCode,
    ).toBe(400);
    const created = await request('POST', '/inventory-policies', {
      scope: 'tag',
      tag: 'dup',
      scanPeriodic: false,
    });
    expect(created.statusCode).toBe(201);
    expect(
      (
        await request('POST', '/inventory-policies', {
          scope: 'tag',
          tag: 'dup',
          scanEnabled: true,
        })
      ).statusCode,
    ).toBe(409);
    const id = created.json<InventoryPolicyRule>().id;
    expect(
      (await request('DELETE', `/inventory-policies/${id}`)).statusCode,
    ).toBe(204);
    const global = (
      await request('GET', '/inventory-policies')
    ).json<InventoryPolicyList>().global;
    expect(
      (await request('DELETE', `/inventory-policies/${global.id}`)).statusCode,
    ).toBe(409);
  });

  it('primera reconciliación: altas con snapshot y notificación, escaneos automáticos', async () => {
    const result = await reconcile(node.id);
    expect(result.assetIds).toEqual([node.id]);

    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    expect(tree.children.map((c) => c.name).sort()).toEqual([
      'debian',
      'docker',
    ]);
    const docker = tree.children.find((c) => c.name === 'docker')!;
    expect(docker.children.map((c) => c.name).sort()).toEqual([
      'cache',
      'web1',
    ]);

    // CT recogido: el snapshot del descubrimiento y el de la recolección, con su diff.
    const debian = await assetByName('debian');
    const snaps = await snapshots(debian.id);
    expect(snaps.map((s) => s.source)).toEqual(['collect', 'discover']);
    expect(snaps[0].previousId).toBe(snaps[1].id);
    // Contenedor (solo descubierto): un snapshot.
    const web1 = await assetByName('web1');
    expect((await snapshots(web1.id)).map((s) => s.source)).toEqual([
      'discover',
    ]);

    const page = await notifications();
    const created = page.items.filter((n) => n.kind === 'asset_created');
    expect(created.map((n) => n.assetName).sort()).toEqual(['docker', 'pve']);
    const fromPve = created.find((n) => n.assetName === 'pve')!;
    expect(fromPve.message).toBe('pve: 2 nuevos — debian (lxc), docker (lxc)');
    expect(fromPve.items.map((i) => [i.name, i.type])).toEqual([
      ['debian', 'lxc'],
      ['docker', 'lxc'],
    ]);
    expect(
      created
        .find((n) => n.assetName === 'docker')!
        .items.map((i) => i.name)
        .sort(),
    ).toEqual(['cache', 'web1']);
    expect(page.unread).toBe(page.total);

    // Escaneo automático (activado y periódico por defecto): nginx tiene su finding.
    const vulns = (
      await request('GET', '/vulnerabilities?status=open&minSeverity=LOW')
    ).json<Page<VulnerabilitySummary>>();
    expect(vulns.items.map((v) => v.vulnerabilityId)).toEqual([
      'CVE-2024-6387',
    ]);
  });

  it('sin cambios: recolección sin snapshot nuevo; el uptime y las fechas no cuentan', async () => {
    const debian = await assetByName('debian');
    const before = await snapshots(debian.id);
    const nodeBefore = await snapshots(node.id);
    await reconcile(node.id);
    expect(await snapshots(debian.id)).toEqual(before);
    expect(await snapshots(node.id)).toEqual(nodeBefore);
    const [run]: unknown[] = await db.query(
      `SELECT 1 FROM job_runs WHERE asset_id = $1 AND name = 'asset.collect'
        AND message LIKE '%(sin cambios)' LIMIT 1`,
      [debian.id],
    );
    expect(run).toBeDefined();
  });

  it('CT modificado: snapshot del descubrimiento con el diff de su configuración', async () => {
    state.guests.find((g) => g.vmid === 100)!.memory = 1024;
    state.guests.find((g) => g.vmid === 100)!.cores = 2;
    pve.setState(state);
    await reconcile(node.id);
    const debian = await assetByName('debian');
    const [latest] = await snapshots(debian.id);
    expect(latest.source).toBe('discover');
    expect(latest.changeSummary).toEqual([
      { section: 'proxmox', added: 0, removed: 0, changed: 4 },
    ]);
    const detail = (
      await request('GET', `/snapshots/${latest.id}`)
    ).json<Snapshot>();
    expect(detail.diff!.changes).toEqual([
      { path: 'proxmox.config.cores', kind: 'changed', before: 1, after: 2 },
      {
        path: 'proxmox.config.memory',
        kind: 'changed',
        before: 512,
        after: 1024,
      },
      { path: 'proxmox.cpus', kind: 'changed', before: 1, after: 2 },
      {
        path: 'proxmox.maxMemBytes',
        kind: 'changed',
        before: 512 * 1024 ** 2,
        after: 1024 * 1024 ** 2,
      },
    ]);
  });

  it('CT destruido: missing (con sus contenedores), retired a la 3.ª ejecución, nunca borrado', async () => {
    const saved = state.guests.find((g) => g.vmid === 101)!;
    state.guests = state.guests.filter((g) => g.vmid !== 101);
    pve.setState(state);

    await reconcile(node.id);
    let docker = await assetByName('docker');
    expect([docker.status, docker.missingRuns]).toEqual(['missing', 1]);
    expect(docker.missingSince).not.toBeNull();
    expect((await assetByName('web1')).status).toBe('missing');
    expect((await notifications()).items[0]).toMatchObject({
      kind: 'asset_missing',
      assetName: 'pve',
      message: 'pve: 1 desaparecido — docker (lxc)',
    });

    await reconcile(node.id);
    docker = await assetByName('docker');
    expect([docker.status, docker.missingRuns]).toEqual(['missing', 2]);

    await reconcile(node.id);
    docker = await assetByName('docker');
    expect([docker.status, docker.retiredAuto]).toEqual(['retired', true]);
    for (const name of ['web1', 'cache', 'nginx:1.25', 'redis:7.0'])
      expect((await assetByName(name)).status).toBe('retired');
    expect((await notifications()).items[0]).toMatchObject({
      kind: 'asset_retired',
      message: 'pve: 1 retirado tras no verse — docker (lxc)',
    });
    // Nada borrado: assets, snapshots y findings siguen.
    const [{ assets, snaps, findings }]: {
      assets: number;
      snaps: number;
      findings: number;
    }[] = await db.query(
      `SELECT (SELECT count(*)::int FROM assets) AS assets,
                (SELECT count(*)::int FROM snapshots s JOIN assets a ON a.id = s.asset_id
                  WHERE a.name = 'docker') AS snaps,
                (SELECT count(*)::int FROM findings) AS findings`,
    );
    expect(assets).toBeGreaterThanOrEqual(8);
    expect(snaps).toBeGreaterThan(0);
    expect(findings).toBeGreaterThan(0);
    // Retirados: fuera del árbol y de las vulnerabilidades.
    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    expect(tree.children.map((c) => c.name)).toEqual(['debian']);

    // Reaparece (mismo vmid): retirado automáticamente ⇒ vuelve con sus contenedores e imágenes.
    state.guests.push(saved);
    pve.setState(state);
    await reconcile(node.id);
    docker = await assetByName('docker');
    expect([docker.status, docker.retiredAuto, docker.missingRuns]).toEqual([
      'active',
      false,
      0,
    ]);
    for (const name of ['web1', 'cache', 'nginx:1.25'])
      expect((await assetByName(name)).status).toBe('active');
    expect((await notifications()).items.map((n) => n.kind)).toContain(
      'asset_reactivated',
    );
  });

  it('dado de baja a mano: no vuelve aunque siga existiendo', async () => {
    const debian = await assetByName('debian');
    expect((await request('DELETE', `/assets/${debian.id}`)).statusCode).toBe(
      200,
    );
    await reconcile(node.id);
    const after = await assetByName('debian');
    expect([after.status, after.retiredAuto]).toEqual(['retired', false]);
  });

  it('tick: solo encola las raíces con el intervalo vencido', async () => {
    expect(
      (
        await request('PUT', `/assets/${node.id}/policy`, {
          reconcileIntervalMinutes: 5,
        })
      ).statusCode,
    ).toBe(200);
    await db.query(
      `UPDATE assets SET reconciled_at = now() - interval '10 minutes' WHERE id = $1`,
      [node.id],
    );
    await db.query(`UPDATE assets SET reconciled_at = now() WHERE id = $1`, [
      plain.id,
    ]);
    const result = await reconcile();
    expect(result.assetIds).toEqual([node.id]);
    expect(result.notDue).toBe(1);
    const policy = (
      await request('GET', `/assets/${node.id}/policy`)
    ).json<AssetPolicy>();
    expect(policy.reconcileRoot).toEqual({ id: node.id, name: 'pve' });
    expect(policy.nextReconcileAt).not.toBeNull();
    // Solo raíces.
    const web1 = await assetByName('web1');
    expect(
      (await request('POST', '/inventory/reconcile', { assetId: web1.id }))
        .statusCode,
    ).toBe(409);
    const webPolicy = (
      await request('GET', `/assets/${web1.id}/policy`)
    ).json<AssetPolicy>();
    expect(webPolicy.reconcileRoot).toEqual({ id: node.id, name: 'pve' });
    expect(webPolicy.nextReconcileAt).toBeNull();
  });

  it('política heredada: el nodo sin escaneo lo pasa a CT, contenedores e imágenes', async () => {
    const res = await request('PUT', `/assets/${node.id}/policy`, {
      scanEnabled: false,
    });
    expect(res.statusCode).toBe(200);
    const web1 = await assetByName('web1');
    const p = (
      await request('GET', `/assets/${web1.id}/policy`)
    ).json<AssetPolicy>();
    expect(p.effective.values.scanEnabled).toBe(false);
    expect(p.effective.sources.scanEnabled).toEqual({
      kind: 'inherited',
      assetId: node.id,
      assetName: 'pve',
    });
    const nginx = await assetByName('nginx:1.25');
    const ip = (
      await request('GET', `/assets/${nginx.id}/policy`)
    ).json<AssetPolicy>();
    expect(ip.effective.values.scanEnabled).toBe(false);
    expect(ip.effective.sources.scanEnabled).toEqual({ kind: 'holders' });

    // Sin escaneo: 409 bajo demanda, fuera de la lista por defecto y del árbol; con «Ver todas», sí.
    const scan = await request('POST', `/assets/${web1.id}/scan`);
    expect(scan.statusCode).toBe(409);
    expect(scan.json<{ message: string }>().message).toMatch(/desactivado/);
    const list = (
      await request('GET', '/vulnerabilities?status=open&minSeverity=LOW')
    ).json<Page<VulnerabilitySummary>>();
    expect(list.total).toBe(0);
    const all = (
      await request(
        'GET',
        '/vulnerabilities?status=open&minSeverity=LOW&includeScanDisabled=true',
      )
    ).json<Page<VulnerabilitySummary>>();
    expect(all.total).toBe(1);
    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    const node1 = tree.children[0].children.find((c) => c.name === 'web1')!;
    expect(node1.scanDisabled).toBe(true);
    expect(node1.openFindings.HIGH).toBe(0);
    // La pestaña del asset los sigue enseñando.
    const own = (
      await request('GET', `/assets/${web1.id}/findings?status=open`)
    ).json<{
      total: number;
    }>();
    expect(own.total).toBe(1);

    // Y la reconciliación no encola escaneos.
    const runs = async () =>
      (
        await db.query(
          `SELECT count(*)::int AS n FROM job_runs WHERE name IN ('host.scan', 'image.scan')`,
        )
      )[0].n as number;
    const before = await runs();
    await reconcile(node.id);
    expect(await runs()).toBe(before);
  });

  it('escaneo solo bajo demanda (por etiqueta): nada automático, el manual sí', async () => {
    await request('DELETE', `/assets/${node.id}/policy`);
    const rule = await request('POST', '/inventory-policies', {
      scope: 'tag',
      tag: 'manual-scan',
      scanPeriodic: false,
    });
    expect(rule.statusCode).toBe(201);
    expect(
      (await request('PATCH', `/assets/${node.id}`, { tags: ['manual-scan'] }))
        .statusCode,
    ).toBe(200);
    const p = (
      await request('GET', `/assets/${node.id}/policy`)
    ).json<AssetPolicy>();
    expect(p.effective.values).toMatchObject({
      scanEnabled: true,
      scanPeriodic: false,
    });
    expect(p.effective.sources.scanPeriodic).toEqual({
      kind: 'tag',
      tag: 'manual-scan',
    });

    const hostScans = async () =>
      (
        await db.query(
          `SELECT count(*)::int AS n FROM job_runs WHERE name = 'host.scan' AND asset_id = $1`,
          [node.id],
        )
      )[0].n as number;
    const before = await hostScans();
    await reconcile(node.id);
    expect(await hostScans()).toBe(before);
    const manual = await request('POST', `/assets/${node.id}/scan`);
    expect(manual.statusCode).toBe(202);
    await settle();
    expect(await hostScans()).toBe(before + 1);
  });

  it('fallo en la reconciliación: aviso sin cambiar estados, y no se repite el mismo', async () => {
    const failures = async () =>
      (await notifications()).items.filter((n) => n.kind === 'reconcile_failed');
    const before = (await failures()).length;
    state.failResources = true;
    pve.setState(state);
    await reconcile(node.id);
    await reconcile(node.id);
    state.failResources = false;
    pve.setState(state);
    const after = await failures();
    expect(after.length).toBe(before + 1);
    expect(after[0]).toMatchObject({ assetName: 'pve' });
    expect(after[0].message).toMatch(/^Descubrimiento de pve en la reconciliación: /);
    // Nada pasa a missing por un fallo.
    expect((await assetByName('docker')).status).toBe('active');
  });

  it('notificaciones: marcar como leídas; sin fugas en respuestas ni BD', async () => {
    expect(
      (await request('GET', '/notifications/unread-count')).json(),
    ).toMatchObject({
      unread: expect.any(Number),
    });
    expect((await request('POST', '/notifications/seen')).statusCode).toBe(200);
    expect(
      (await request('GET', '/notifications/unread-count')).json(),
    ).toEqual({ unread: 0 });
    // El viewer tiene su propio «leído».
    expect(
      (
        await request(
          'GET',
          '/notifications/unread-count',
          undefined,
          viewerToken,
        )
      ).json<{
        unread: number;
      }>().unread,
    ).toBeGreaterThan(0);

    const [{ dump }]: { dump: string }[] = await db.query(
      `SELECT coalesce(string_agg(n::text, ''), '') ||
              coalesce((SELECT string_agg(s.diff::text, '') FROM snapshots s), '') AS dump
         FROM notifications n`,
    );
    for (const banned of ['PRIVATE KEY', 'hunter2', 'secreto', 'cipassword'])
      expect(
        [...responses, dump, worker!.output.join('')].join('\n'),
      ).not.toContain(banned);
  });
});
