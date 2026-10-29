import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  INVENTORY_POLICY_PRESETS,
  QUEUE_NAMES,
  type AssetPolicy,
  type EnrollServerResponse,
  type IssuedEnrollment,
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
import { createFakePve, type FakePve } from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
} from './support/worker.js';

const NGINX = `sha256:${'1'.repeat(64)}`;
const REDIS = `sha256:${'2'.repeat(64)}`;

/**
 * QoL-6b, criterio de «hecho»: un servidor dado de alta con una política que excluye las imágenes
 * no lanza ningún escaneo de imágenes en su primera recolección (worker real, servidor simulado
 * con Docker en el propio nodo y en un CT). Tags y proyecto ya están antes de recolectar.
 */
describe('Alta con organización y política (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker;
  let pve: FakePve;
  let admin: string;

  beforeAll(async () => {
    await prepareEnv('e2e_enrollment_policy', { ENROLL_THROTTLE_LIMIT: '1000' });
    app = await createTestApp();
    db = app.get(DataSource);
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    pve = createFakePve();
    pve.setState({
      node: 'pve',
      cluster: null,
      machineId: 'a'.repeat(32),
      ctMachineId: 'c'.repeat(32),
      nodeRoles: ['proxmox', 'docker'],
      hostDocker: {
        containers: [{ name: 'cache', image: 'redis:7', imageId: REDIS, state: 'running' }],
      },
      guests: [
        {
          type: 'lxc',
          vmid: 100,
          node: 'pve',
          name: 'docker',
          status: 'running',
          docker: true,
          containers: [{ name: 'web1', image: 'nginx:1.25', imageId: NGINX, state: 'running' }],
        },
      ],
      vulns: {
        [NGINX]: [{ id: 'CVE-2024-6387', pkg: 'openssh-client', version: '1', severity: 'HIGH' }],
        [REDIS]: [{ id: 'CVE-2024-0001', pkg: 'zlib1g', version: '1', severity: 'LOW' }],
      },
    });
    worker = await startWorker(pve.workerEnv());
  });

  afterAll(async () => {
    await stopWorker(worker);
    for (const name of Object.values(QUEUE_NAMES))
      await app?.get<Queue>(getQueueToken(name)).obliterate({ force: true });
    await app?.close();
  });

  function request(method: 'GET' | 'POST', url: string, payload?: object, token: string | null = admin) {
    return app.inject({ method, url, payload, headers: token ? authHeaders(token) : {} });
  }

  function tokenOf(enrollment: IssuedEnrollment): string {
    const match = /\/enroll\/([A-Za-z0-9_-]{43}) \|/.exec(enrollment.command);
    if (!match) throw new Error(`Comando inesperado: ${enrollment.command}`);
    return match[1]!;
  }

  /** Hasta que no quede nada en ninguna cola y la cadena haya llegado a los contenedores. */
  async function settle(): Promise<void> {
    const queues = Object.values(QUEUE_NAMES).map((q) => app.get<Queue>(getQueueToken(q)));
    await waitFor(
      async () => {
        const [{ n }] = await db.query(
          `SELECT count(*)::int AS n FROM assets WHERE type = 'image'`,
        );
        if (n < 2) return false;
        for (const queue of queues) {
          const counts = await queue.getJobCounts('waiting', 'active', 'delayed', 'prioritized');
          if (Object.values(counts).some((c) => c > 0)) return false;
        }
        return true;
      },
      90_000,
      () => `colas sin vaciar\n${worker?.output.join('')}`,
    );
  }

  it('la plantilla «Sin imágenes» con tag y proyecto: inventario completo, ningún image.scan', async () => {
    const project = (await request('POST', '/projects', { name: 'Clientes' })).json<{ id: string }>();
    const preset = INVENTORY_POLICY_PRESETS.find((p) => p.id === 'no-images')!;
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name: 'pve',
      authMode: 'static_key',
      tags: ['prueba'],
      projectIds: [project.id],
      policy: preset.fields,
    });
    expect(res.statusCode).toBe(201);
    const { asset, enrollment } = res.json<EnrollServerResponse>();

    // Antes de la primera recolección: tags, proyecto y regla propia, con la política calculada.
    const [row] = await db.query(
      `SELECT tags, effective_projects, effective_policy FROM assets WHERE id = $1`,
      [asset.id],
    );
    expect(row.tags).toEqual(['prueba']);
    expect(row.effective_projects).toEqual([project.id]);
    expect(row.effective_policy.values).toMatchObject({ scanEnabled: true, scanPeriodic: true });
    const policy = (await request('GET', `/assets/${asset.id}/policy`)).json<AssetPolicy>();
    expect(policy.rule?.scanExclusions).toEqual({ types: ['image'] });
    const [audit] = await db.query(
      `SELECT details FROM audit_events WHERE action = 'asset.created' AND target_id = $1`,
      [asset.id],
    );
    expect(audit.details).toMatchObject({ tags: ['prueba'], projects: ['Clientes'] });

    const done = await request(
      'POST',
      `/enroll/${tokenOf(enrollment)}/done`,
      { hostKeys: [{ type: 'ED25519', fingerprint: pve.fingerprint }] },
      null,
    );
    expect(done.statusCode).toBe(204);
    await settle();

    const runs: { name: string; n: number }[] = await db.query(
      `SELECT name, count(*)::int AS n FROM job_runs GROUP BY name ORDER BY name`,
    );
    const count = (name: string) => runs.find((r) => r.name === name)?.n ?? 0;
    expect(count('asset.collect')).toBeGreaterThanOrEqual(2);
    expect(count('asset.discover')).toBeGreaterThanOrEqual(2);
    // Ni las del nodo (stores) ni las del CT (heredan la regla del nodo).
    expect(count('image.scan')).toBe(0);

    const images: { name: string; policy: AssetPolicy['effective']; scan_status: string }[] =
      await db.query(
        `SELECT a.name, a.effective_policy AS policy, ci.scan_status
           FROM assets a JOIN container_images ci ON ci.asset_id = a.id
          WHERE a.type = 'image' ORDER BY a.name`,
      );
    expect(images.map((i) => i.name)).toEqual(['nginx:1.25', 'redis:7']);
    for (const image of images) {
      expect(image.policy.values.scanEnabled).toBe(false);
      expect(image.policy.sources.scanEnabled).toMatchObject({
        kind: 'excluded',
        match: { kind: 'type', type: 'image' },
      });
      expect(image.scan_status).not.toBe('scanned');
    }
    const [{ n: findings }] = await db.query(`SELECT count(*)::int AS n FROM findings`);
    expect(findings).toBe(0);
    // Lo descubierto hereda el proyecto (y la regla) del servidor.
    const [ct] = await db.query(
      `SELECT effective_projects FROM assets WHERE type = 'lxc'`,
    );
    expect(ct.effective_projects).toEqual([project.id]);
  }, 120_000);
});
