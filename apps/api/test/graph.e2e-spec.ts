import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type { Queue } from 'bullmq';
import type {
  Asset,
  AssetGraph,
  EnqueueJobResponse,
  EnrollServerResponse,
  GraphNode,
  JobStatus,
  Project,
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
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker, WORK_QUEUES } from './support/worker.js';

const NGINX = `sha256:${'1'.repeat(64)}`;
const REDIS = `sha256:${'2'.repeat(64)}`;

const GUESTS: FakeGuest[] = [
  { type: 'lxc', vmid: 100, node: 'pve', name: 'debian', status: 'running' },
  {
    type: 'lxc',
    vmid: 101,
    node: 'pve',
    name: 'pruebas',
    status: 'running',
    docker: true,
    volumes: ['webdata'],
    networks: ['app'],
    containers: [
      {
        name: 'web1',
        image: 'nginx:1.25',
        imageId: NGINX,
        state: 'running',
        published: { '80/tcp': 8080 },
        mounts: ['webdata'],
        networks: ['app'],
      },
      {
        name: 'web2',
        image: 'nginx:1.25',
        imageId: NGINX,
        state: 'running',
        networks: ['app'],
      },
      {
        name: 'cache',
        image: 'redis:7',
        imageId: REDIS,
        state: 'running',
        networks: ['app'],
      },
    ],
  },
];

const PASSWORD = 'otra-contraseña-larga';

/**
 * Grafos de relaciones (QoL-4, DESIGN §5): el mapa de un asset por saltos y la topología por
 * niveles, con el worker real y el nodo Proxmox simulado (CT «pruebas» con web1, web2 y cache,
 * un volumen y una red compartida).
 */
describe('Grafos de relaciones (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let adminToken: string;
  let viewerToken: string;
  /** Cuerpos de las respuestas de grafo y topología. */
  const responses: string[] = [];
  let node: Asset;
  const ids: Record<string, string> = {};

  beforeAll(async () => {
    await prepareEnv('e2e_graph');
    app = await createTestApp();
    db = app.get(DataSource);
    await app
      .get(UsersService)
      .create('viewer-graph@infraward.test', PASSWORD, 'viewer');
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(
      app,
      'viewer-graph@infraward.test',
      PASSWORD,
    );

    pve = createFakePve();
    pve.setState({
      node: 'pve',
      cluster: null,
      machineId: 'a'.repeat(32),
      ctMachineId: 'c'.repeat(32),
      guests: structuredClone(GUESTS),
      vulns: {
        [REDIS]: [
          {
            id: 'CVE-2025-49844',
            pkg: 'redis',
            version: '7.2.0',
            fixed: '7.2.11',
            severity: 'CRITICAL',
          },
        ],
      },
    });
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name: 'pve',
    });
    expect(res.statusCode).toBe(201);
    node = res.json<EnrollServerResponse>().asset;
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [node.id, pve.fingerprint],
    );
    worker = await startWorker({ ...pve.workerEnv() });
    await reconcile();
    const rows: { id: string; name: string }[] = await db.query(
      `SELECT id, name FROM assets`,
    );
    for (const r of rows) ids[r.name] = r.id;
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'PUT',
    url: string,
    payload?: object,
    token: string = adminToken,
  ) {
    const res = await app.inject({
      method,
      url,
      payload,
      headers: authHeaders(token),
    });
    if (/\/graph|\/topology/.test(url)) responses.push(res.body);
    return res;
  }

  async function reconcile(): Promise<void> {
    const res = await request('POST', '/inventory/reconcile', {
      assetId: node.id,
    });
    expect(res.statusCode).toBe(202);
    const id = res.json<EnqueueJobResponse>().id;
    await waitFor(
      async () =>
        (await request('GET', `/jobs/${id}`)).json<JobStatus>().state ===
        'completed',
      30_000,
      () => `reconciliación sin terminar\n${worker?.output.join('')}`,
    );
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

  const names = (g: AssetGraph) => g.nodes.map((n) => n.name).sort();
  const byName = (g: AssetGraph, name: string): GraphNode | undefined =>
    g.nodes.find((n) => n.name === name);
  const nameOf = (g: AssetGraph, id: string) =>
    g.nodes.find((n) => n.id === id)?.name;
  const edgesOf = (g: AssetGraph) =>
    g.edges
      .map((e) => `${nameOf(g, e.source)} ${e.type} ${nameOf(g, e.target)}`)
      .sort();

  it('el mapa de web1 a un salto: su CT, su imagen, su red y su volumen', async () => {
    const res = await request('GET', `/assets/${ids.web1}/graph`);
    expect(res.statusCode).toBe(200);
    const g = res.json<AssetGraph>();
    expect(g.centerId).toBe(ids.web1);
    expect(g.truncated).toBe(false);
    expect(names(g)).toEqual([
      'app',
      'nginx:1.25',
      'pruebas',
      'web1',
      'webdata',
    ]);
    expect(edgesOf(g)).toEqual([
      'pruebas contains app',
      'pruebas contains web1',
      'pruebas contains webdata',
      'pruebas stores nginx:1.25',
      'web1 attached_to app',
      'web1 instance_of nginx:1.25',
      'web1 mounts webdata',
    ]);
    expect(byName(g, 'web1')).toMatchObject({
      depth: 0,
      type: 'container',
      parentId: ids.pruebas,
      address: '8080→80/tcp',
      runtimeState: 'running',
    });
    expect(byName(g, 'pruebas')).toMatchObject({
      depth: 1,
      type: 'lxc',
      // Lo que queda a un salto más: el nodo, web2, cache y la imagen de redis.
      hidden: { server: 1, container: 2, image: 1 },
    });
    // La red compartida deja ver que tiene dos contenedores más.
    expect(byName(g, 'app')?.hidden).toEqual({ container: 2 });
  });

  it('a dos y tres saltos llega por la red y la imagen compartidas; cache con su CVE crítico', async () => {
    const g2 = (
      await request('GET', `/assets/${ids.web1}/graph?depth=2`)
    ).json<AssetGraph>();
    for (const name of ['web2', 'cache', 'pve', 'redis:7'])
      expect(byName(g2, name)?.depth, name).toBe(2);
    expect(byName(g2, 'cache')).toMatchObject({
      critical: 1,
      maxSeverity: 'CRITICAL',
    });
    expect(byName(g2, 'web2')?.maxSeverity).toBeNull();
    const g3 = (
      await request('GET', `/assets/${ids.web1}/graph?depth=3`)
    ).json<AssetGraph>();
    expect(byName(g3, 'debian')?.depth).toBe(3);
  });

  it('valida la profundidad y el asset', async () => {
    for (const depth of ['0', '4', 'x'])
      expect(
        (await request('GET', `/assets/${ids.web1}/graph?depth=${depth}`))
          .statusCode,
      ).toBe(400);
    expect(
      (
        await request(
          'GET',
          '/assets/00000000-0000-4000-8000-000000000000/graph',
        )
      ).statusCode,
    ).toBe(404);
  });

  it('topología del nodo: el nivel host resume el contenido de cada CT', async () => {
    const res = await request('GET', `/assets/topology?rootId=${node.id}`);
    expect(res.statusCode).toBe(200);
    const t = res.json<AssetGraph>();
    expect(names(t)).toEqual(['debian', 'pruebas', 'pve']);
    expect(byName(t, 'pruebas')).toMatchObject({
      parentId: node.id,
      hidden: { container: 3, volume: 1, network: 1, image: 2 },
      hiddenCritical: 1,
    });
    expect(t.edges).toEqual([]);
  });

  it('topología: al expandir el CT aparece su contenido agrupado en él', async () => {
    const t = (
      await request(
        'GET',
        `/assets/topology?rootId=${node.id}&expand=${ids.pruebas}`,
      )
    ).json<AssetGraph>();
    for (const name of [
      'web1',
      'web2',
      'cache',
      'webdata',
      'app',
      'nginx:1.25',
      'redis:7',
    ])
      expect(byName(t, name)?.parentId, name).toBe(ids.pruebas);
    expect(byName(t, 'pruebas')?.hidden).toEqual({});
    expect(edgesOf(t)).toEqual([
      'cache attached_to app',
      'cache instance_of redis:7',
      'web1 attached_to app',
      'web1 instance_of nginx:1.25',
      'web1 mounts webdata',
      'web2 attached_to app',
      'web2 instance_of nginx:1.25',
    ]);
    expect(
      (await request('GET', '/assets/topology?expand=no-es-un-uuid'))
        .statusCode,
    ).toBe(400);
  });

  it('topología de todo el inventario y de un proyecto', async () => {
    const all = (await request('GET', '/assets/topology')).json<AssetGraph>();
    expect(names(all)).toEqual(['debian', 'pruebas', 'pve']);

    const project = (
      await request('POST', '/projects', { name: 'Pruebas' })
    ).json<Project>();
    await request('PUT', `/projects/${project.id}/members/${ids.pruebas}`, {
      mode: 'include',
    });
    const t = (
      await request('GET', `/assets/topology?projectId=${project.id}`)
    ).json<AssetGraph>();
    // El nodo no está en el proyecto: el CT queda como raíz y su contenido, resumido.
    expect(names(t)).toEqual(['pruebas']);
    expect(byName(t, 'pruebas')).toMatchObject({
      parentId: null,
      hidden: { container: 3, volume: 1, network: 1, image: 2 },
    });
  });

  it('un lector puede verlos y las respuestas no llevan facts, conexión ni credenciales', async () => {
    for (const url of [
      `/assets/${ids.web1}/graph?depth=3`,
      `/assets/topology?expand=${ids.pruebas}`,
    ]) {
      const res = await request('GET', url, undefined, viewerToken);
      expect(res.statusCode).toBe(200);
      for (const node of res.json<AssetGraph>().nodes)
        expect(Object.keys(node).sort()).toEqual(
          [
            'address',
            'critical',
            'depth',
            'hidden',
            'hiddenCritical',
            'id',
            'maxSeverity',
            'name',
            'parentId',
            'runtimeState',
            'status',
            'type',
          ].sort(),
        );
    }
    expect(responses.length).toBeGreaterThan(8);
    for (const body of responses)
      expect(body).not.toMatch(/PRIVATE KEY|secret:\/\/|"facts"|"connection"/);
  });
});
