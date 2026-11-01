import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  Asset,
  AssetCollectJobResult,
  AssetRelations,
  AssetTreeSummaryNode,
  CollectedFacts,
  DockerContainerFacts,
  DockerHostResources,
  EnqueueJobResponse,
  EnrollServerResponse,
  JobStatus,
  Page,
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
import {
  createFakePve,
  podmanImageId,
  type FakePve,
  type FakePveState,
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
  WORK_QUEUES,
} from './support/worker.js';

/** Imágenes de las salidas reales de Podman 5.4.2 (fixtures del descubridor). */
const PAUSE = 'sha256:2d0a24883d63ae0d812c4bca762edaa522979dec299264d469bcbc155fea9b0d';
const NGINX = 'sha256:3d6cab9c2941df2441024a2f02a65ebe1b8916c3cbe7b9527f62627accea8004';
// La de alice: en los fixtures simulados, con el image ID de un docker-archive válido (fake-pve).
const ALPINE = podmanImageId(
  'sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731',
);
const HELPER = 'sudo -n /usr/local/libexec/infraward/infraward-query ';

const STATE: FakePveState = {
  node: 'podman01',
  cluster: null,
  machineId: 'd'.repeat(32),
  ctMachineId: 'f'.repeat(32),
  guests: [],
  nodeRoles: ['podman'],
  sudoersVersion: 8,
  collectSudoersVersion: 8,
  hostPodman: {
    // alice (1000) habilitada con socket y un contenedor; bob en la lista sin socket; carol
    // detectada (2 contenedores) fuera de la lista. `P uid lista socket storage linger ctrs nombre`.
    users: 'P 1000 1 1 1 1 1 alice\nP 1001 1 0 1 0 0 bob\nP 1002 0 0 1 0 2 carol\n',
    // root ya no tiene alpine: se saca del almacén de alice.
    rootMissing: [ALPINE],
  },
};

/**
 * Podman (#10) de punta a punta con el worker real y las salidas reales de Podman 5.4.2 (`ssh`,
 * `ansible-playbook` y `trivy` falsos): detección, contenedores de root (con pod) y rootless (con
 * unidad de quadlet), volúmenes, redes, avisos de lo que no se ve y escaneo con `podman save`.
 */
describe('Podman (e2e)', { timeout: 120_000 }, () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let token: string;
  let server: Asset;
  const responses: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_podman');
    app = await createTestApp();
    db = app.get(DataSource);
    token = await loginToken(app, ADMIN.email, ADMIN.password);
    pve = createFakePve();
    pve.setState(STATE);
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name: 'podman01',
    });
    expect(res.statusCode).toBe(201);
    server = res.json<EnrollServerResponse>().asset;
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [server.id, pve.fingerprint],
    );
    worker = await startWorker(pve.workerEnv());
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
  });

  async function request(method: 'GET' | 'POST', url: string, payload?: object) {
    const res = await app.inject({ method, url, payload, headers: authHeaders(token) });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  const get = async <T>(url: string): Promise<T> => {
    const res = await request('GET', url);
    expect(res.statusCode).toBe(200);
    return res.json<T>();
  };

  async function finished<T>(id: string): Promise<JobStatus & { result?: T }> {
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = await get<JobStatus>(`/jobs/${id}`);
        return last.state === 'completed' || last.state === 'failed';
      },
      60_000,
      () => `job sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    return last as JobStatus & { result?: T };
  }

  async function settle(): Promise<void> {
    for (const name of WORK_QUEUES) {
      const queue = app.get<Queue>(getQueueToken(name));
      await waitFor(
        async () => {
          const counts = await queue.getJobCounts('waiting', 'active', 'delayed', 'prioritized');
          return Object.values(counts).every((n) => n === 0);
        },
        60_000,
        () => `cola ${name} sin vaciar\n${worker?.output.join('')}`,
      );
    }
  }

  const byName = <T extends { name: string }>(list: T[], name: string) =>
    list.find((x) => x.name === name)!;

  it('recoger detecta podman-host (sin Docker) y avisa de lo rootless que no se ve', async () => {
    const res = await request('POST', `/assets/${server.id}/collect`);
    expect(res.statusCode).toBe(202);
    const job = await finished<AssetCollectJobResult>(res.json<EnqueueJobResponse>().id);
    await settle();
    expect(job.state, `${JSON.stringify(job)}\n${pve.sshCommands().join('\n')}`).toBe('completed');
    expect(job.result?.roles).toEqual(['podman-host']);
    const asset = await get<Asset>(`/assets/${server.id}`);
    const facts = asset.facts as unknown as CollectedFacts;
    expect(facts.detected).toMatchObject({ docker: null, podman: '5.4.2' });
    expect(facts.infraward.sudoersOutdated).toBe(false);
    const warnings = facts.infraward.warnings.join('\n');
    expect(warnings).toMatch(/2 contenedores de Podman rootless de carol sin inventariar/);
    expect(warnings).toMatch(/Podman rootless de bob: sin socket activo/);
    expect(warnings).not.toMatch(/alice/);
    // Detección automática: la ficha los lista para «Habilitar» (bob y carol).
    expect(
      facts.detected.podmanUsers,
    ).toEqual([
      { uid: 1000, name: 'alice', enabled: true, socket: true, storage: true, linger: true, containers: 1 },
      { uid: 1001, name: 'bob', enabled: true, socket: false, storage: true, linger: false, containers: 0 },
      { uid: 1002, name: 'carol', enabled: false, socket: false, storage: true, linger: false, containers: 2 },
    ]);
    const discovery = (
      await get<Page<{ state: string }>>(`/jobs?assetId=${server.id}&name=asset.discover`)
    ).items;
    expect(discovery.map((j) => j.state)).toEqual(['completed']);
  });

  it('contenedores de root y de alice (rootless); el infra del pod, no', async () => {
    const tree = await get<AssetTreeSummaryNode>(`/assets/${server.id}/tree`);
    expect(
      tree.children.filter((c) => c.type === 'container').map((c) => c.name).sort(),
    ).toEqual(['alice/uweb', 'enpod', 'parado', 'plain', 'web']);
    const facts = async (name: string) =>
      (await get<Asset>(`/assets/${byName(tree.children, name).id}`)).facts
        .docker as DockerContainerFacts;
    expect(await facts('web')).toMatchObject({ engine: 'podman', imageId: NGINX, state: 'running' });
    expect(await facts('enpod')).toMatchObject({ engine: 'podman', pod: 'mipod' });
    const uweb = await facts('alice/uweb');
    expect(uweb).toMatchObject({
      engine: 'podman',
      rootlessUser: 'alice',
      rootlessUid: 1000,
      systemdUnit: 'uweb.service',
      imageId: ALPINE,
    });
    // Claves naturales con el propietario.
    const keys: { natural_key: string }[] = await db.query(
      `SELECT a.natural_key FROM assets a JOIN asset_relations r ON r.child_id = a.id
        WHERE r.parent_id = $1 AND r.type = 'contains' AND a.type = 'container' ORDER BY 1`,
      [server.id],
    );
    expect(keys.map((k) => k.natural_key)).toEqual(
      ['alice:uweb', 'root:enpod', 'root:parado', 'root:plain', 'root:web'].map(
        (k) => `podman:${server.id}:${k}`,
      ),
    );
  });

  it('volúmenes, redes (la por defecto se llama podman y se enlaza) e imágenes', async () => {
    const d = await get<DockerHostResources>(`/assets/${server.id}/docker`);
    const usage = (list: DockerHostResources['volumes']) =>
      list.map((r) => [r.name, r.containers]);
    expect(usage(d.volumes)).toEqual([
      ['alice/udatos', 1],
      ['datos', 1],
    ]);
    expect(usage(d.networks)).toEqual([
      ['alice/podman', 0],
      ['podman', 3],
      ['red-app', 1],
      ['red6', 0],
    ]);
    expect(d.images.map((i) => i.name).sort()).toEqual([
      'docker.io/library/alpine:3.20',
      'docker.io/library/nginx:alpine',
      'localhost/podman-pause:5.4.2-1766335321',
    ]);
    const net = await get<AssetRelations>(`/assets/${byName(d.networks, 'podman').id}/relations`);
    expect(
      net.incoming.filter((r) => r.type === 'attached_to').map((r) => r.peer.name).sort(),
    ).toEqual(['enpod', 'parado', 'plain']);
  });

  it('las imágenes se sacan con podman save; la que root no tiene, del almacén de alice', async () => {
    const saves = pve
      .sshCommands()
      .filter((c) => c.startsWith(`${HELPER}podman-save `))
      .map((c) => c.slice(HELPER.length));
    expect(saves.sort()).toEqual(
      [
        `podman-save 1000 ${ALPINE}`,
        `podman-save root ${ALPINE}`,
        `podman-save root ${NGINX}`,
        `podman-save root ${PAUSE}`,
      ].sort(),
    );
    expect(pve.sshCommands().some((c) => c.includes('docker-save'))).toBe(false);
    expect(pve.trivyScans()).toHaveLength(3);
    const images: { image_id: string; scan_status: string }[] = await db.query(
      `SELECT image_id, scan_status FROM container_images ORDER BY image_id`,
    );
    expect(images).toEqual(
      [PAUSE, NGINX, ALPINE].sort().map((id) => ({ image_id: id, scan_status: 'scanned' })),
    );
  });

  it('el entorno y las etiquetas fuera de la lista no salen del servidor', async () => {
    const dump = JSON.stringify(
      await db.query(
        `SELECT (SELECT json_agg(facts) FROM assets) AS facts,
                (SELECT json_agg(facts) FROM snapshots) AS snapshots`,
      ),
    );
    const everything = [dump, ...responses, worker?.output.join('') ?? ''].join('\n');
    for (const secret of ['hunter2', 'secret.label'])
      expect(everything).not.toContain(secret);
  });
});
