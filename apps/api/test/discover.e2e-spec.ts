import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type { Queue } from 'bullmq';
import type {
  Asset,
  AssetCollectJobResult,
  AssetDiscoverJobResult,
  AssetTreeSummaryNode,
  CollectedFacts,
  DashboardSummary,
  DockerContainerFacts,
  EnqueueJobResponse,
  EnrollServerResponse,
  JobStatus,
  Page,
  ProxmoxGuestFacts,
  SnapshotSummary,
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
  email: 'viewer-discover@infraward.test',
  password: 'otra-contraseña-larga',
};
const NODE_MACHINE_ID = 'a'.repeat(32);
const CT_MACHINE_ID = 'c'.repeat(32);
const key = (vmid: number) => `proxmox:node:${NODE_MACHINE_ID}:${vmid}`;

const GUESTS: FakeGuest[] = [
  { type: 'lxc', vmid: 100, node: 'pve', name: 'debian', status: 'running' },
  {
    type: 'lxc',
    vmid: 101,
    node: 'pve',
    name: 'docker',
    status: 'stopped',
    docker: true,
    containers: [
      {
        name: 'web1',
        image: 'nginx:1.25',
        imageId: `sha256:${'1'.repeat(64)}`,
        state: 'running',
        published: { '80/tcp': 8080 },
        env: 'POSTGRES_PASSWORD=env-centinela',
      },
      {
        name: 'web2',
        image: 'nginx:1.25',
        imageId: `sha256:${'1'.repeat(64)}`,
        state: 'running',
      },
      {
        name: 'cache',
        image: 'redis:7.0',
        imageId: `sha256:${'2'.repeat(64)}`,
        state: 'exited',
        published: { '6379/tcp': 6379 },
      },
    ],
  },
  { type: 'qemu', vmid: 200, node: 'pve', name: 'win', status: 'running' },
];

/**
 * Descubrimiento de Proxmox de punta a punta con el worker real, PostgreSQL y Redis, y un nodo
 * simulado (`ssh`, `ssh-keyscan` y `ansible-playbook` falsos en el PATH del worker).
 */
describe('Descubrimiento de Proxmox (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let adminToken: string;
  let viewerToken: string;
  const responses: string[] = [];
  let privateKey: string;
  let node: Asset;
  let plain: Asset;
  let state: FakePveState;

  beforeAll(async () => {
    await prepareEnv('e2e_discover');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);

    pve = createFakePve();
    state = {
      node: 'pve',
      cluster: null,
      machineId: NODE_MACHINE_ID,
      ctMachineId: CT_MACHINE_ID,
      guests: structuredClone(GUESTS),
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
    privateKey = await app
      .get(SecretsService)
      .resolve(node.credentials.sshPrivateKey!);
    // Alta verificada sin servidor real: activo y con la huella del ssh-keyscan falso.
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = ANY($1)`,
      [[node.id, plain.id], pve.fingerprint],
    );
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'DELETE',
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

  /** Hijos `contains` (incluidos los retirados), cargados completos: el árbol es un resumen. */
  async function childrenOf(id: string): Promise<Asset[]> {
    const res = await request('GET', `/assets/${id}/tree?includeRetired=true`);
    expect(res.statusCode).toBe(200);
    const full = await Promise.all(
      res.json<AssetTreeSummaryNode>().children.map(async (c) => {
        const one = await request('GET', `/assets/${c.id}`);
        expect(one.statusCode).toBe(200);
        return one.json<Asset>();
      }),
    );
    return full.sort((a, b) => a.name.localeCompare(b.name));
  }

  const children = () => childrenOf(node.id);
  const containersOf = (ctId: string) => childrenOf(ctId);

  const byName = (list: Asset[], name: string) =>
    list.find((c) => c.name === name)!;

  /**
   * Espera a que no quede ningún job pendiente ni en curso en las colas de trabajo (recolección,
   * descubrimiento y los escaneos que encadenan, que esperan turno por host).
   */
  async function settle(): Promise<void> {
    const queues = WORK_QUEUES.map((q) => app.get<Queue>(getQueueToken(q)));
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

  it('discover: exige token, admin, UUID, asset existente y un nodo con descubridor', async () => {
    const url = `/assets/${node.id}/discover`;
    expect((await request('POST', url, undefined, null)).statusCode).toBe(401);
    expect(
      (await request('POST', url, undefined, viewerToken)).statusCode,
    ).toBe(403);
    expect((await request('POST', '/assets/x/discover')).statusCode).toBe(400);
    expect(
      (
        await request(
          'POST',
          '/assets/00000000-0000-4000-8000-000000000000/discover',
        )
      ).statusCode,
    ).toBe(404);
    // Aún no se ha recogido: no tiene el rol proxmox-node.
    const res = await request('POST', url);
    expect(res.statusCode).toBe(409);
    expect(res.json<{ message: string }>().message).toMatch(/proxmox-node/);
  });

  it('recoger el nodo detecta proxmox-node, encadena el descubrimiento y la recolección de los CT', async () => {
    worker = await startWorker(pve.workerEnv());
    const collect = await request('POST', `/assets/${node.id}/collect`);
    expect(collect.statusCode).toBe(202);
    const done = await finished<AssetCollectJobResult>(
      collect.json<EnqueueJobResponse>().id,
    );
    expect(done.state).toBe('completed');
    expect(done.result).toMatchObject({
      roles: ['proxmox-node'],
      via: 'ssh',
    });
    const discoveryId = done.result!.discoveryJobId!;
    expect(discoveryId).toBeTruthy();

    const discovered = await finished<AssetDiscoverJobResult>(discoveryId);
    expect(discovered.state).toBe('completed');
    expect(discovered.result).toMatchObject({
      discoverers: ['proxmox-node'],
      created: 3,
      updated: 0,
      missing: 0,
      collectQueued: 1,
      complete: true,
      warnings: [],
    });
    await settle();

    const list = await children();
    expect(list.map((c) => [c.name, c.type, c.naturalKey, c.status])).toEqual([
      ['debian', 'lxc', key(100), 'active'],
      ['docker', 'lxc', key(101), 'active'],
      ['win', 'vm', key(200), 'active'],
    ]);
    const debian = byName(list, 'debian');
    const facts = debian.facts as unknown as CollectedFacts & {
      proxmox: ProxmoxGuestFacts;
    };
    // Datos de Proxmox (sin contraseñas ni notas) + facts recogidos por dentro.
    expect(facts.proxmox).toMatchObject({
      vmid: 100,
      kind: 'lxc',
      node: 'pve',
      status: 'running',
      cluster: null,
    });
    expect(facts.proxmox.interfaces?.[0].ipv4).toEqual(['10.0.0.100/24']);
    expect(facts.proxmox.config).not.toHaveProperty('cipassword');
    expect(facts.proxmox.config).not.toHaveProperty('description');
    expect(facts.infraward).toMatchObject({ via: 'pct', warnings: [] });
    expect(facts.machineId).toBe(CT_MACHINE_ID);
    // La clave natural sigue siendo la de Proxmox, no el machine-id.
    expect(debian.naturalKey).toBe(key(100));
    expect(debian.hostKeyFingerprint).toBeNull();
    // El CT parado y la VM solo tienen lo de Proxmox.
    expect(Object.keys(byName(list, 'docker').facts)).toEqual(['proxmox']);
    expect(Object.keys(byName(list, 'win').facts)).toEqual(['proxmox']);
    const snapshots = await request('GET', `/assets/${debian.id}/snapshots`);
    // El del descubrimiento (facts de Proxmox) y el de la recolección, con su diff (§10).
    const page = snapshots.json<{
      total: number;
      items: { source: string; changeSummary: { section: string }[] | null }[];
    }>();
    expect(page.total).toBe(2);
    expect(page.items.map((i) => i.source)).toEqual(['collect', 'discover']);
    expect(page.items[1].changeSummary).toBeNull();
    expect(page.items[0].changeSummary?.map((c) => c.section)).toContain(
      'packages',
    );
  });

  it('al nodo solo se le piden consultas `pve-*` al ayudante y el CT se recoge con pct-exec desde el nodo', () => {
    expect(pve.sshCommands().length).toBeGreaterThanOrEqual(5);
    for (const command of pve.sshCommands()) {
      // Lo único que va sin sudo (o por pct-exec en un CT): leer las BDs de paquetes del SBOM.
      if (
        /^(ls|cat) /.test(command) ||
        /infraward-query pct-exec \d+ (ls|cat) /.test(command)
      ) {
        expect(command).toMatch(
          /^(sudo -n \/usr\/local\/libexec\/infraward\/infraward-query pct-exec \d+ )?(ls -1d -- (\/[a-z0-9_./-]+ ?)+|cat -- \/[a-z0-9_./-]+)$/i,
        );
        continue;
      }
      expect(command).toMatch(
        /^sudo -n \/usr\/local\/libexec\/infraward\/infraward-query (pve-cluster-status|pve-cluster-resources|pve-guest-config (lxc|qemu) [a-z0-9-]+ \d+|pve-lxc-interfaces [a-z0-9-]+ \d+|pct-exec \d+ docker (ps -a -q --no-trunc|inspect --format '[^']+'( [0-9a-f]{64})+|image inspect --format '[^']+'( sha256:[0-9a-f]{64})+))$/,
      );
    }
    const runs = pve.ansibleRuns();
    const ct = runs.find((r) => r.host.infraward_pct_vmid === 100)!;
    expect(ct.host).toMatchObject({
      ansible_host: '127.0.0.1',
      ansible_connection: 'infraward_pct',
    });
    expect(ct.vars).toMatchObject({
      infraward_via: 'pct',
      infraward_query_prefix: [],
    });
    const direct = runs.find((r) => r.host.infraward_pct_vmid === undefined)!;
    expect(direct.vars).toMatchObject({
      infraward_via: 'ssh',
      infraward_query_prefix: [
        'sudo',
        '-n',
        '/usr/local/libexec/infraward/infraward-query',
      ],
    });
  });

  it('volver a descubrir no duplica; un CT arrancado con Docker se recoge y es docker-host', async () => {
    state.guests[1].status = 'running';
    pve.setState(state);
    const res = await request('POST', `/assets/${node.id}/discover`);
    expect(res.statusCode).toBe(202);
    const done = await finished<AssetDiscoverJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.result).toMatchObject({
      created: 0,
      updated: 3,
      missing: 0,
      collectQueued: 2,
    });
    await settle();
    const list = await children();
    expect(list).toHaveLength(3);
    const docker = byName(list, 'docker');
    expect(docker.roles).toEqual(['docker-host']);
    expect((docker.facts as unknown as CollectedFacts).detected.docker).toBe(
      '28.3.1',
    );
    const count: { n: number }[] = await db.query(
      `SELECT count(*)::int AS n FROM assets WHERE natural_key LIKE 'proxmox:%'`,
    );
    expect(count[0].n).toBe(3);
    // docker-host ⇒ descubrimiento de sus contenedores desde el nodo (pct exec).
    const containers = await containersOf(docker.id);
    expect(
      containers.map((c) => [c.name, c.type, c.naturalKey, c.status]),
    ).toEqual([
      ['cache', 'container', `docker:${docker.id}:cache`, 'active'],
      ['web1', 'container', `docker:${docker.id}:web1`, 'active'],
      ['web2', 'container', `docker:${docker.id}:web2`, 'active'],
    ]);
    const web1 = byName(containers, 'web1').facts
      .docker as DockerContainerFacts;
    expect(web1).toMatchObject({
      image: 'nginx:1.25',
      imageId: `sha256:${'1'.repeat(64)}`,
      repoTags: ['nginx:1.25'],
      state: 'running',
      ports: [
        { containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 },
      ],
    });
    // Parado: los puertos configurados.
    expect(
      (byName(containers, 'cache').facts.docker as DockerContainerFacts).ports,
    ).toEqual([
      { containerPort: 6379, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 6379 },
    ]);
    // Segunda recolección del CT 100: segundo snapshot.
    const debian = byName(list, 'debian');
    const snapshots = await request('GET', `/assets/${debian.id}/snapshots`);
    expect(snapshots.json<{ total: number }>().total).toBe(2);
  });

  it('contenedores: los que desaparecen pasan a missing; si docker falla no cambia nada', async () => {
    const ct = byName(await children(), 'docker');
    const discoverCt = async () => {
      const res = await request('POST', `/assets/${ct.id}/discover`);
      expect(res.statusCode).toBe(202);
      return finished<AssetDiscoverJobResult>(
        res.json<EnqueueJobResponse>().id,
      );
    };
    const saved = structuredClone(state.guests[1].containers!);
    state.guests[1].containers = saved.filter((c) => c.name !== 'web2');
    pve.setState(state);
    let done = await discoverCt();
    expect(done.result).toMatchObject({
      discoverers: ['docker-host'],
      created: 0,
      updated: 2,
      missing: 1,
      complete: true,
    });
    expect(byName(await containersOf(ct.id), 'web2').status).toBe('missing');

    pve.setState({ ...state, failDocker: true });
    done = await discoverCt();
    expect(done.state).toBe('failed');
    expect(done.failedReason).toMatch(
      /^No se pudo listar Docker: docker ps falló \(código 1\): Cannot connect/,
    );
    expect((await containersOf(ct.id)).map((c) => c.status)).toEqual([
      'active',
      'active',
      'missing',
    ]);

    state.guests[1].containers = saved;
    pve.setState(state);
    done = await discoverCt();
    expect(done.result).toMatchObject({ reactivated: 1, missing: 0 });
    await settle();
  });

  it('collect de hijos: CT en marcha 202, VM 409, CT huérfano 409', async () => {
    const list = await children();
    const ct = await request(
      'POST',
      `/assets/${byName(list, 'debian').id}/collect`,
    );
    expect(ct.statusCode).toBe(202);
    await finished(ct.json<EnqueueJobResponse>().id);

    const vm = await request(
      'POST',
      `/assets/${byName(list, 'win').id}/collect`,
    );
    expect(vm.statusCode).toBe(409);
    expect(vm.json<{ message: string }>().message).toMatch(/VMs/);

    const orphan = await request('POST', '/assets', {
      type: 'lxc',
      name: 'huérfano',
      status: 'active',
    });
    expect(orphan.statusCode).toBe(201);
    const res = await request(
      'POST',
      `/assets/${orphan.json<Asset>().id}/collect`,
    );
    expect(res.statusCode).toBe(409);
    expect(res.json<{ message: string }>().message).toMatch(/padre/);
  });

  it('si el listado de pvesh falla, el job falla y no cambia ningún estado', async () => {
    const before = await children();
    pve.setState({ ...state, failResources: true });
    const res = await request('POST', `/assets/${node.id}/discover`);
    const done = await finished(res.json<EnqueueJobResponse>().id);
    expect(done.state).toBe('failed');
    expect(done.failedReason).toMatch(
      /^No se pudo listar Proxmox: pvesh get \/cluster\/resources falló \(código 1\): ipcc_send_rec/,
    );
    const after = await children();
    expect(after.map((c) => c.status)).toEqual(before.map((c) => c.status));
  });

  it('lo que desaparece pasa a missing y vuelve a active al reaparecer', async () => {
    pve.setState({
      ...state,
      guests: state.guests.filter((g) => g.vmid !== 200),
    });
    let res = await request('POST', `/assets/${node.id}/discover`);
    let done = await finished<AssetDiscoverJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.result).toMatchObject({ missing: 1, updated: 2 });
    expect(byName(await children(), 'win').status).toBe('missing');

    pve.setState(state);
    res = await request('POST', `/assets/${node.id}/discover`);
    done = await finished<AssetDiscoverJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.result).toMatchObject({ missing: 0, reactivated: 1 });
    expect(byName(await children(), 'win').status).toBe('active');
    await settle();
  });

  it('un CT migrado a otro nodo del clúster no desaparece', async () => {
    // El nodo se une al clúster «lab»: claves renombradas, mismos assets.
    const before = await children();
    state = { ...state, cluster: 'lab' };
    pve.setState(state);
    let res = await request('POST', `/assets/${node.id}/discover`);
    let done = await finished<AssetDiscoverJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.result).toMatchObject({ created: 0, renamed: 3, missing: 0 });
    await settle();
    const renamed = await children();
    expect(renamed.map((c) => c.id)).toEqual(before.map((c) => c.id));
    expect(renamed.map((c) => c.naturalKey)).toEqual([
      'proxmox:cluster:lab:100',
      'proxmox:cluster:lab:101',
      'proxmox:cluster:lab:200',
    ]);

    // La VM 200 se va a otro nodo del clúster (no inventariado): sigue activa aquí.
    state.guests[2].node = 'pve2';
    pve.setState(state);
    res = await request('POST', `/assets/${node.id}/discover`);
    done = await finished<AssetDiscoverJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.result).toMatchObject({ missing: 0, updated: 2 });
    expect(byName(await children(), 'win').status).toBe('active');
    await settle();
  });

  it('409 al descubrir desde un servidor sin rol con descubridor', async () => {
    const res = await request('POST', `/assets/${plain.id}/discover`);
    expect(res.statusCode).toBe(409);
  });

  it('el mismo servidor dado de alta dos veces: duplicado, sin guardar nada, y al purgar el otro se recoge', async () => {
    // `sin-proxmox` llega al mismo nodo simulado: mismo machine-id que `pve`, que ya lo tiene.
    const collect = async () => {
      const res = await request('POST', `/assets/${plain.id}/collect`);
      expect(res.statusCode).toBe(202);
      return finished<AssetCollectJobResult>(res.json<EnqueueJobResponse>().id);
    };
    const snapshots = async () =>
      (await request('GET', `/assets/${plain.id}/snapshots`)).json<
        Page<SnapshotSummary>
      >().total;
    const before = await snapshots();

    const dup = await collect();
    expect(dup.state).toBe('completed');
    expect(dup.result?.duplicateOf).toEqual({ id: node.id, name: 'pve' });
    expect(dup.result?.snapshotId).toBeNull();
    expect(await snapshots()).toBe(before);

    const one = (await request('GET', `/assets/${plain.id}`)).json<Asset>();
    expect(one.duplicateOfId).toBe(node.id);
    expect(one.duplicateOf).toMatchObject({ id: node.id, name: 'pve' });
    expect(one.naturalKey).toBeNull();
    expect(one.roles).toEqual([]);
    const original = (await request('GET', `/assets/${node.id}`)).json<Asset>();
    expect(original.duplicates?.map((d) => d.id)).toEqual([plain.id]);

    const tree = (await request('GET', '/assets/tree')).json<
      AssetTreeSummaryNode[]
    >();
    expect(tree.find((n) => n.id === plain.id)?.duplicateOf).toBe(node.id);
    expect(tree.find((n) => n.id === node.id)?.duplicateOf).toBeNull();
    const dashboard = (
      await request('GET', '/dashboard')
    ).json<DashboardSummary>();
    expect(dashboard.attention.duplicates.count).toBe(1);
    expect(dashboard.attention.duplicates.assets[0].id).toBe(plain.id);

    // Purgar el original quita la marca (FK) y la siguiente recolección guarda.
    await settle();
    const purge = await request('DELETE', `/assets/${node.id}?purge=true`);
    expect(purge.statusCode).toBe(200);
    expect(
      (await request('GET', `/assets/${plain.id}`)).json<Asset>().duplicateOfId,
    ).toBeNull();
    const saved = await collect();
    expect(saved.state).toBe('completed');
    expect(saved.result?.duplicateOf).toBeNull();
    expect(saved.result?.snapshotId).toEqual(expect.any(String));
    expect(await snapshots()).toBe(before + 1);
    expect(
      (await request('GET', `/assets/${plain.id}`)).json<Asset>().naturalKey,
    ).toBe(NODE_MACHINE_ID);
    await settle();
  });

  it('un clon (mismo machine-id, host keys distintas) se recoge con clave compuesta y aviso; al regenerarlo, clave normal', async () => {
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name: 'clon',
    });
    expect(res.statusCode).toBe(201);
    const clone = res.json<EnrollServerResponse>().asset;
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [clone.id, pve.fingerprint],
    );
    // `sin-proxmox` es el original (clave = machine-id) y su host key no es ninguna de las que
    // presenta el clon: otra máquina con el machine-id copiado.
    const otherKey = `SHA256:${'o'.repeat(43)}`;
    await db.query(
      `UPDATE assets SET host_key_fingerprint = $2 WHERE id = $1`,
      [plain.id, otherKey],
    );
    const collect = async () => {
      const r = await request('POST', `/assets/${clone.id}/collect`);
      expect(r.statusCode).toBe(202);
      return finished<AssetCollectJobResult>(r.json<EnqueueJobResponse>().id);
    };

    const first = await collect();
    expect(first.state).toBe('completed');
    expect(first.result?.duplicateOf).toBeNull();
    expect(first.result?.snapshotId).toEqual(expect.any(String));
    // No cuenta como recolección parcial.
    expect(first.result?.warnings).toEqual([]);
    const saved = (await request('GET', `/assets/${clone.id}`)).json<Asset>();
    expect(saved.naturalKey).toBe(`${NODE_MACHINE_ID}+${pve.fingerprint}`);
    expect(saved.duplicateOfId).toBeNull();
    expect(
      (saved.facts as unknown as CollectedFacts).infraward.machineIdClone,
    ).toEqual({
      machineId: NODE_MACHINE_ID,
      sharedWith: [{ id: plain.id, name: 'sin-proxmox' }],
    });
    const tree = (await request('GET', '/assets/tree')).json<
      AssetTreeSummaryNode[]
    >();
    expect(tree.find((n) => n.id === clone.id)?.machineIdClone).toBe(true);
    expect(tree.find((n) => n.id === plain.id)?.machineIdClone).toBe(false);
    const dashboard = (
      await request('GET', '/dashboard')
    ).json<DashboardSummary>();
    expect(dashboard.attention.clones.assets.map((a) => a.id)).toEqual([
      clone.id,
    ]);
    await settle();

    // Regenerado en el servidor: la clave pasa a ser el machine-id nuevo, en el mismo asset.
    const regenerated = 'd'.repeat(32);
    pve.setState({ ...state, machineId: regenerated });
    try {
      const second = await collect();
      expect(second.state).toBe('completed');
      const after = (await request('GET', `/assets/${clone.id}`)).json<Asset>();
      expect(after.naturalKey).toBe(regenerated);
      expect(
        (after.facts as unknown as CollectedFacts).infraward.machineIdClone,
      ).toBeNull();
      const dash = (
        await request('GET', '/dashboard')
      ).json<DashboardSummary>();
      expect(dash.attention.clones.count).toBe(0);
      await settle();
    } finally {
      pve.setState(state);
      await db.query(
        `UPDATE assets SET host_key_fingerprint = $2 WHERE id = $1`,
        [plain.id, pve.fingerprint],
      );
    }
  });

  it('aparece en OpenAPI', async () => {
    const spec = (await app.inject({ url: '/openapi.json' })).json<{
      paths: Record<string, unknown>;
    }>();
    expect(spec.paths['/assets/{id}/discover']).toBeDefined();
  });

  it('ni la clave privada ni secretos de la config de Proxmox salen en respuestas, logs ni BD', async () => {
    const body = privateKey.split('\n')[1];
    const dump: { facts: string }[] = await db.query(
      `SELECT facts::text AS facts FROM assets UNION ALL SELECT facts::text FROM snapshots`,
    );
    for (const text of [
      responses.join('\n'),
      worker?.output.join('') ?? '',
      dump.map((d) => d.facts).join('\n'),
    ]) {
      expect(text).not.toContain(body);
      expect(text).not.toContain('hunter2');
      expect(text).not.toContain('$5$secreto');
      expect(text).not.toContain('env-centinela');
    }
  });
});
