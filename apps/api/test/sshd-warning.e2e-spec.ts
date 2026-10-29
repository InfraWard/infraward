import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  Asset,
  AssetTreeSummaryNode,
  CollectedFacts,
  DashboardSummary,
  EnqueueJobResponse,
  EnrollServerResponse,
  JobStatus,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { createFakePve, type FakePve, type FakePveState } from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
} from './support/worker.js';

/** `sshd -T` de un nodo Proxmox recién instalado (root por contraseña), con más opciones. */
const SSHD_ROOT_PASSWORD = `port 22
permitrootlogin yes
passwordauthentication yes
kbdinteractiveauthentication no
hostkey /etc/ssh/ssh_host_ed25519_key
banner /etc/issue.centinela-sshd`;

const BASE: FakePveState = {
  node: 'pve-sshd',
  cluster: null,
  machineId: 'd'.repeat(32),
  ctMachineId: 'e'.repeat(32),
  guests: [],
  sshdConfig: SSHD_ROOT_PASSWORD,
};

/**
 * Aviso en solo lectura de sshd (QoL-7, sudoers v7): la recolección pasa `sshd -T` por el filtro
 * que corre en el servidor y solo guarda las tres opciones de autenticación; con root por
 * contraseña el servidor sale en el árbol, la ficha y el panel. Con la v6, solo la nota.
 */
describe('Aviso de login de root o por contraseña en sshd (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let token: string;
  let pve: FakePve;
  let worker: TestWorker;
  let node: Asset;

  beforeAll(async () => {
    await prepareEnv('e2e_sshd');
    app = await createTestApp();
    db = app.get(DataSource);
    token = await loginToken(app, ADMIN.email, ADMIN.password);
    pve = createFakePve();
    pve.setState({ ...BASE, collectSudoersVersion: 7 });
    const res = await request('POST', '/assets/enroll', { host: '127.0.0.1', port: 22, name: 'pve-sshd' });
    expect(res.statusCode).toBe(201);
    node = res.json<EnrollServerResponse>().asset;
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [node.id, pve.fingerprint],
    );
    worker = await startWorker(pve.workerEnv());
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
  });

  function request(method: 'GET' | 'POST', url: string, payload?: object) {
    return app.inject({ method, url, payload, headers: authHeaders(token) });
  }

  async function collect(): Promise<void> {
    const job = (await request('POST', `/assets/${node.id}/collect`)).json<EnqueueJobResponse>();
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = (await request('GET', `/jobs/${job.id}`)).json<JobStatus>();
        return last.state === 'completed' || last.state === 'failed';
      },
      30_000,
      () => `job sin terminar: ${JSON.stringify(last)}\n${worker.output.join('')}`,
    );
    expect(last?.state, worker.output.join('')).toBe('completed');
  }

  const facts = async () =>
    (await request('GET', `/assets/${node.id}`)).json<Asset>().facts as unknown as CollectedFacts;

  async function treeNode(): Promise<AssetTreeSummaryNode> {
    const tree = (await request('GET', '/assets/tree')).json<AssetTreeSummaryNode[]>();
    const found = tree.find((n) => n.id === node.id);
    expect(found).toBeDefined();
    return found!;
  }

  it('con la v7: solo las tres opciones, el aviso en el árbol, la ficha y el panel', async () => {
    await collect();
    const f = await facts();
    expect(f.sshd).toEqual({
      permitRootLogin: 'yes',
      passwordAuthentication: true,
      kbdInteractiveAuthentication: false,
    });
    expect(JSON.stringify(f)).not.toMatch(/centinela-sshd|ssh_host_ed25519_key/);
    expect(f.infraward.sudoersNotes ?? []).toEqual([]);
    expect((await treeNode()).sshdRisk).toBe('root-password');
    const dash = (await request('GET', '/dashboard')).json<DashboardSummary>();
    expect(dash.attention.sshdPasswordLogin.count).toBe(1);
    expect(dash.attention.sshdPasswordLogin.assets.map((a) => a.id)).toEqual([node.id]);
    expect(dash.vaultRotationOverdue).toBe(0);
  });

  it('con la configuración recomendada no hay aviso', async () => {
    pve.setState({
      ...BASE,
      collectSudoersVersion: 7,
      sshdConfig: 'permitrootlogin prohibit-password\npasswordauthentication no\nkbdinteractiveauthentication no',
    });
    await collect();
    expect((await facts()).sshd?.permitRootLogin).toBe('prohibit-password');
    expect((await treeNode()).sshdRisk).toBeNull();
    const dash = (await request('GET', '/dashboard')).json<DashboardSummary>();
    expect(dash.attention.sshdPasswordLogin.count).toBe(0);
  });

  it('con la v6: sin datos de sshd, sin aviso y con la nota de la v7', async () => {
    pve.setState({ ...BASE, collectSudoersVersion: 6 });
    await collect();
    const f = await facts();
    expect(f.sshd).toBeNull();
    expect(f.infraward.warnings).toEqual([]);
    expect(f.infraward.sudoersNotes).toEqual([expect.stringContaining('requiere sudoers v7')]);
    expect((await treeNode()).sshdRisk).toBeNull();
  });
});
