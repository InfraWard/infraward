import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type { Queue } from 'bullmq';
import type {
  Asset,
  AssetPolicy,
  AssetProjects,
  AssetTreeSummaryNode,
  DashboardSummary,
  EnqueueJobResponse,
  EnrollServerResponse,
  InventoryPolicyRule,
  JobStatus,
  Page,
  Project,
  ProjectDetail,
  ProjectWithStats,
  TagInfo,
  UserRole,
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
  waitPrioritized,
  type TestWorker, WORK_QUEUES } from './support/worker.js';

const NGINX = `sha256:${'1'.repeat(64)}`;

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
    ],
  },
];

const PASSWORD = 'otra-contraseña-larga';
const ROLES: UserRole[] = ['editor', 'operator', 'auditor', 'viewer'];

/**
 * Organización del inventario (QoL-3, DESIGN §5 y §10) con el worker real y el nodo Proxmox
 * simulado: nombre visible que sobrevive a la reconciliación, tags y sus colores, notas,
 * proyectos con pertenencia heredada (excepciones e imágenes), filtros y política por proyecto.
 */
describe('Organización del inventario (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let state: FakePveState;
  let adminToken: string;
  const tokens = {} as Record<UserRole, string>;
  const responses: string[] = [];
  let node: Asset;
  let other: Asset;
  let homelab: Project;

  beforeAll(async () => {
    await prepareEnv('e2e_organization');
    app = await createTestApp();
    db = app.get(DataSource);
    for (const role of ROLES)
      await app
        .get(UsersService)
        .create(`${role}-org@infraward.test`, PASSWORD, role);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    for (const role of ROLES)
      tokens[role] = await loginToken(app, `${role}-org@infraward.test`, PASSWORD);

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
    other = await enroll('fuera');
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [node.id, pve.fingerprint],
    );
    worker = await startWorker({ ...pve.workerEnv() });
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
    responses.push(res.body);
    return res;
  }

  async function reconcile(): Promise<void> {
    const res = await request('POST', '/inventory/reconcile', {
      assetId: node.id,
    });
    expect(res.statusCode).toBe(202);
    const id = res.json<EnqueueJobResponse>().id;
    await waitFor(
      async () => {
        const job = (await request('GET', `/jobs/${id}`)).json<JobStatus>();
        return job.state === 'completed';
      },
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

  async function byDiscoveredName(name: string): Promise<Asset> {
    const [row]: { id: string }[] = await db.query(
      `SELECT id FROM assets WHERE discovered_name = $1 ORDER BY created_at LIMIT 1`,
      [name],
    );
    expect(row, name).toBeDefined();
    return (await request('GET', `/assets/${row.id}`)).json<Asset>();
  }

  async function auditActions(): Promise<string[]> {
    const rows: { action: string }[] = await db.query(
      `SELECT action FROM audit_events ORDER BY occurred_at, id`,
    );
    return rows.map((r) => r.action);
  }

  function flatten(nodes: AssetTreeSummaryNode[]): AssetTreeSummaryNode[] {
    return nodes.flatMap((n) => [n, ...flatten(n.children)]);
  }

  it('primera reconciliación: el árbol del nodo', async () => {
    await reconcile();
    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    expect(flatten([tree]).map((n) => n.name).sort()).toEqual([
      'debian',
      'docker',
      'pve',
      'web1',
    ]);
  });

  it('nombre visible: renombrar un CT descubierto sobrevive a la reconciliación', async () => {
    const debian = await byDiscoveredName('debian');
    expect(debian).toMatchObject({
      name: 'debian',
      discoveredName: 'debian',
      displayName: null,
    });
    const renamed = await request('PATCH', `/assets/${debian.id}`, {
      displayName: '  Base de datos  ',
    });
    expect(renamed.statusCode).toBe(200);
    expect(renamed.json<Asset>()).toMatchObject({
      name: 'Base de datos',
      discoveredName: 'debian',
      displayName: 'Base de datos',
    });

    // Proxmox lo renombra: se actualiza el descubierto, el visible se queda.
    state.guests.find((g) => g.vmid === 100)!.name = 'debian-13';
    pve.setState(state);
    await reconcile();
    const after = (await request('GET', `/assets/${debian.id}`)).json<Asset>();
    expect(after).toMatchObject({
      name: 'Base de datos',
      discoveredName: 'debian-13',
      displayName: 'Base de datos',
    });
    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    expect(tree.children.find((c) => c.id === debian.id)).toMatchObject({
      name: 'Base de datos',
      discoveredName: 'debian-13',
    });
    // Se busca por los dos nombres.
    for (const q of ['base de', 'debian-1'])
      expect(
        (await request('GET', `/assets?q=${encodeURIComponent(q)}`))
          .json<Page<Asset>>()
          .items.map((a) => a.id),
        q,
      ).toEqual([debian.id]);

    // Volver al descubierto.
    const restored = await request('PATCH', `/assets/${debian.id}`, {
      displayName: null,
    });
    expect(restored.json<Asset>()).toMatchObject({
      name: 'debian-13',
      displayName: null,
    });
    // El nombre descubierto no se edita y el visible no puede quedar vacío.
    for (const body of [{ name: 'x' }, { displayName: '   ' }])
      expect(
        (await request('PATCH', `/assets/${debian.id}`, body)).statusCode,
        JSON.stringify(body),
      ).toBe(400);
    await request('PATCH', `/assets/${debian.id}`, { displayName: 'Base de datos' });
  });

  it('tags: la reconciliación no los toca; colores y autocompletado', async () => {
    const docker = await byDiscoveredName('docker');
    const res = await request('PATCH', `/assets/${docker.id}`, {
      tags: ['lab', 'web', 'lab'],
    });
    expect(res.json<Asset>().tags).toEqual(['lab', 'web']);
    await reconcile();
    expect(
      (await request('GET', `/assets/${docker.id}`)).json<Asset>().tags,
    ).toEqual(['lab', 'web']);

    expect(
      (await request('PUT', '/tags/lab/style', { color: '#2563EB' })).json<TagInfo>(),
    ).toEqual({ tag: 'lab', assets: 1, color: '#2563eb' });
    await request('PUT', '/tags/sin-uso/style', { color: '#dc2626' });
    const tags = (await request('GET', '/tags')).json<TagInfo[]>();
    expect(tags).toEqual([
      { tag: 'lab', assets: 1, color: '#2563eb' },
      { tag: 'sin-uso', assets: 0, color: '#dc2626' },
      { tag: 'web', assets: 1, color: null },
    ]);
    await request('PUT', '/tags/sin-uso/style', { color: null });
    expect(
      (await request('GET', '/tags')).json<TagInfo[]>().map((t) => t.tag),
    ).toEqual(['lab', 'web']);
    for (const [url, body] of [
      ['/tags/lab/style', { color: 'azul' }],
      ['/tags/con%20espacio/style', { color: '#000000' }],
    ] as const)
      expect((await request('PUT', url, body)).statusCode, url).toBe(400);
  });

  it('borrar un tag: se quita de todos los assets, se olvida su color y se audita', async () => {
    const docker = await byDiscoveredName('docker');
    const before = (await request('GET', `/assets/${docker.id}`)).json<Asset>().tags;
    await request('PATCH', `/assets/${docker.id}`, { tags: [...before, 'borrame'] });
    await request('PUT', '/tags/borrame/style', { color: '#dc2626' });
    const res = await request('DELETE', '/tags/borrame');
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ assets: 1 });
    expect((await request('GET', `/assets/${docker.id}`)).json<Asset>().tags).toEqual(before);
    expect(
      (await request('GET', '/tags')).json<TagInfo[]>().map((t) => t.tag),
    ).not.toContain('borrame');
    expect((await request('DELETE', '/tags/borrame')).statusCode).toBe(404);
    expect((await request('DELETE', '/tags/con%20espacio')).statusCode).toBe(400);
  });

  it('notas: Markdown en la ficha (no en el árbol); vacías = sin notas', async () => {
    const docker = await byDiscoveredName('docker');
    const notes = '# Docker\n\n- Reinicia los **lunes**\n<script>alert(1)</script>';
    const res = await request('PATCH', `/assets/${docker.id}`, { notes });
    expect(res.json<Asset>().notes).toBe(notes);
    expect(
      (await request('GET', `/assets/${docker.id}`)).json<Asset>().notes,
    ).toBe(notes);
    expect(
      (await request('GET', '/assets?q=docker')).json<Page<Asset>>().items[0],
    ).not.toHaveProperty('notes');
    expect(
      (await request('PATCH', `/assets/${docker.id}`, { notes: 'x'.repeat(20_001) }))
        .statusCode,
    ).toBe(400);
    expect(
      (await request('PATCH', `/assets/${docker.id}`, { notes: '  ' })).json<Asset>()
        .notes,
    ).toBeNull();
    await request('PATCH', `/assets/${docker.id}`, { notes });
  });

  it('proyectos: el nodo entra con sus CT, contenedores e imágenes; excepciones y re-inclusión', async () => {
    const created = await request('POST', '/projects', {
      name: 'Homelab',
      description: 'Lo de casa',
      color: '#0D9488',
    });
    expect(created.statusCode).toBe(201);
    homelab = created.json<Project>();
    expect(homelab).toMatchObject({ name: 'Homelab', color: '#0d9488' });
    expect(
      (await request('POST', '/projects', { name: 'homelab' })).statusCode,
    ).toBe(409);

    const set = await request(
      'PUT',
      `/projects/${homelab.id}/members/${node.id}`,
      { mode: 'include' },
    );
    expect(set.statusCode).toBe(200);
    expect(set.json<ProjectDetail>().members).toEqual([
      expect.objectContaining({
        mode: 'include',
        asset: expect.objectContaining({ id: node.id }),
      }),
    ]);

    const members = async () =>
      (await request('GET', `/assets?projectId=${homelab.id}&limit=200`))
        .json<Page<Asset>>()
        .items.map((a) => a.discoveredName)
        .sort();
    expect(await members()).toEqual([
      'debian-13',
      'docker',
      'nginx:1.25',
      'pve',
      'web1',
    ]);
    // El árbol lleva los proyectos de cada nodo.
    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    expect(flatten([tree]).every((n) => n.projects.includes(homelab.id))).toBe(
      true,
    );

    // Origen: directo, heredado del nodo y, en la imagen, por quienes la usan.
    const web1 = await byDiscoveredName('web1');
    const image = await byDiscoveredName('nginx:1.25');
    expect(
      (await request('GET', `/assets/${node.id}/projects`)).json<AssetProjects>()
        .projects[0].source,
    ).toEqual({ kind: 'direct' });
    expect(
      (await request('GET', `/assets/${web1.id}/projects`)).json<AssetProjects>()
        .projects[0].source,
    ).toMatchObject({ kind: 'inherited', from: { id: node.id } });
    expect(
      (await request('GET', `/assets/${image.id}/projects`)).json<AssetProjects>()
        .projects[0].source,
    ).toEqual({ kind: 'holders' });

    // Excepción en el CT docker: sale con su contenedor y la imagen.
    const docker = await byDiscoveredName('docker');
    await request('PUT', `/projects/${homelab.id}/members/${docker.id}`, {
      mode: 'exclude',
    });
    expect(await members()).toEqual(['debian-13', 'pve']);
    expect(
      (await request('GET', `/assets/${docker.id}/projects`)).json<AssetProjects>(),
    ).toMatchObject({ projects: [], excluded: [{ id: homelab.id }] });
    // Un include más abajo vuelve a meter el contenedor (y su imagen).
    await request('PUT', `/projects/${homelab.id}/members/${web1.id}`, {
      mode: 'include',
    });
    expect(await members()).toEqual(['debian-13', 'nginx:1.25', 'pve', 'web1']);
    await request('DELETE', `/projects/${homelab.id}/members/${web1.id}`);
    await request('DELETE', `/projects/${homelab.id}/members/${docker.id}`);
    expect(await members()).toHaveLength(5);

    // Un asset puede estar en varios proyectos.
    const extra = (
      await request('POST', '/projects', { name: 'Web' })
    ).json<Project>();
    await request('PUT', `/projects/${extra.id}/members/${docker.id}`, {
      mode: 'include',
    });
    expect(
      (await request('GET', `/assets/${web1.id}`)).json<Asset>().projects.sort(),
    ).toEqual([homelab.id, extra.id].sort());
    // Borrar el proyecto quita su pertenencia.
    expect(
      (await request('DELETE', `/projects/${extra.id}`)).statusCode,
    ).toBe(204);
    expect(
      (await request('GET', `/assets/${web1.id}`)).json<Asset>().projects,
    ).toEqual([homelab.id]);
  });

  it('filtros por proyecto: vulnerabilidades, panel y resumen del proyecto', async () => {
    const vulns = (
      await request(
        'GET',
        `/vulnerabilities?status=open&minSeverity=LOW&projectId=${homelab.id}`,
      )
    ).json<Page<VulnerabilitySummary>>();
    expect(vulns.items).toEqual([
      expect.objectContaining({
        vulnerabilityId: 'CVE-2024-6387',
        images: 1,
        containers: 1,
      }),
    ]);
    const empty = (
      await request('POST', '/projects', { name: 'Vacío' })
    ).json<Project>();
    expect(
      (
        await request(
          'GET',
          `/vulnerabilities?status=open&minSeverity=LOW&projectId=${empty.id}`,
        )
      ).json<Page<VulnerabilitySummary>>().total,
    ).toBe(0);

    await waitPrioritized(db);
    const dash = (
      await request('GET', `/dashboard?projectId=${homelab.id}`)
    ).json<DashboardSummary>();
    expect(dash.assetsByType).toMatchObject({
      server: 1,
      lxc: 2,
      container: 1,
      image: 1,
    });
    // Lo prioritario del proyecto: el CVE de su contenedor (HIGH, con parche y en marcha).
    expect(dash.vulnerabilities.cves).toBe(1);
    expect(dash.vulnerabilities.top.map((v) => v.vulnerabilityId)).toEqual(['CVE-2024-6387']);
    expect(
      (await request('GET', `/dashboard?projectId=${empty.id}`)).json<DashboardSummary>()
        .vulnerabilities.cves,
    ).toBe(0);
    const all = (await request('GET', '/dashboard')).json<DashboardSummary>();
    // «fuera» (pendiente de alta) no es del proyecto.
    expect(all.assetsByType.server).toBe(2);
    expect(
      (await request('GET', `/dashboard?projectId=${empty.id}`)).json<DashboardSummary>()
        .assetsByType.server,
    ).toBe(0);
    expect(
      (await request('GET', '/dashboard?projectId=no-uuid')).statusCode,
    ).toBe(400);

    const list = (await request('GET', '/projects')).json<ProjectWithStats[]>();
    expect(list.map((p) => p.name)).toEqual(['Homelab', 'Vacío']);
    expect(list[0].stats).toMatchObject({
      assets: 5,
      assetsByType: { server: 1, lxc: 2, container: 1, image: 1 },
      openVulnerabilities: 1,
      fixableFindings: { HIGH: 1, CRITICAL: 0 },
    });
    expect(list[1].stats.assets).toBe(0);
    await request('DELETE', `/projects/${empty.id}`);
    expect(other.id).toBeDefined();
  });

  it('política por proyecto: se aplica a sus assets; la etiqueta gana al proyecto', async () => {
    const rule = await request('POST', '/inventory-policies', {
      scope: 'project',
      projectId: homelab.id,
      scanEnabled: false,
    });
    expect(rule.statusCode).toBe(201);
    expect(rule.json<InventoryPolicyRule>()).toMatchObject({
      scope: 'project',
      projectId: homelab.id,
      projectName: 'Homelab',
    });
    expect(
      (
        await request('POST', '/inventory-policies', {
          scope: 'project',
          projectId: homelab.id,
          scanPeriodic: false,
        })
      ).statusCode,
    ).toBe(409);

    const debian = await byDiscoveredName('debian-13');
    const policy = (
      await request('GET', `/assets/${debian.id}/policy`)
    ).json<AssetPolicy>();
    expect(policy.effective.values.scanEnabled).toBe(false);
    expect(policy.effective.sources.scanEnabled).toEqual({
      kind: 'project',
      projectId: homelab.id,
      projectName: 'Homelab',
    });
    // Sin escaneo, sus vulnerabilidades salen de la lista.
    expect(
      (
        await request(
          'GET',
          `/vulnerabilities?status=open&minSeverity=LOW&projectId=${homelab.id}`,
        )
      ).json<Page<VulnerabilitySummary>>().total,
    ).toBe(0);

    // docker tiene el tag lab: una regla por etiqueta gana a la del proyecto.
    await request('POST', '/inventory-policies', {
      scope: 'tag',
      tag: 'lab',
      scanEnabled: true,
    });
    const docker = await byDiscoveredName('docker');
    const dockerPolicy = (
      await request('GET', `/assets/${docker.id}/policy`)
    ).json<AssetPolicy>();
    expect(dockerPolicy.effective.sources.scanEnabled).toEqual({
      kind: 'tag',
      tag: 'lab',
    });
    expect(dockerPolicy.effective.values.scanEnabled).toBe(true);

    // Al borrar el proyecto, su regla se va con él.
    const projectRule = rule.json<InventoryPolicyRule>();
    expect(
      (await request('GET', '/inventory-policies')).json<{
        rules: InventoryPolicyRule[];
      }>().rules.map((r) => r.id),
    ).toContain(projectRule.id);
  });

  it('permisos: solo admin y editor organizan; leer no exige permiso', async () => {
    const debian = await byDiscoveredName('debian-13');
    const writes: [string, string, object | undefined][] = [
      ['PATCH', `/assets/${debian.id}`, { displayName: 'x' }],
      ['PATCH', `/assets/${debian.id}`, { tags: ['x'] }],
      ['PATCH', `/assets/${debian.id}`, { notes: 'x' }],
      ['PUT', '/tags/lab/style', { color: '#000000' }],
      ['DELETE', '/tags/lab', undefined],
      ['POST', '/projects', { name: 'Intruso' }],
      ['PATCH', `/projects/${homelab.id}`, { name: 'x' }],
      ['PUT', `/projects/${homelab.id}/members/${debian.id}`, { mode: 'exclude' }],
      ['DELETE', `/projects/${homelab.id}/members/${node.id}`, undefined],
      ['DELETE', `/projects/${homelab.id}`, undefined],
      [
        'POST',
        '/inventory-policies',
        { scope: 'project', projectId: homelab.id, scanPeriodic: false },
      ],
    ];
    for (const role of ['operator', 'auditor', 'viewer'] as const) {
      for (const [method, url, body] of writes)
        expect(
          (await request(method as 'POST', url, body, tokens[role])).statusCode,
          `${role} ${method} ${url}`,
        ).toBe(403);
      for (const url of [
        '/projects',
        `/projects/${homelab.id}`,
        `/assets/${debian.id}/projects`,
        '/tags',
      ])
        expect(
          (await request('GET', url, undefined, tokens[role])).statusCode,
          `${role} ${url}`,
        ).toBe(200);
    }
    const edited = await request(
      'PATCH',
      `/projects/${homelab.id}`,
      { description: 'Editado por el editor' },
      tokens.editor,
    );
    expect(edited.statusCode).toBe(200);
    expect(
      (
        await request(
          'PATCH',
          `/assets/${debian.id}`,
          { tags: ['bd'] },
          tokens.editor,
        )
      ).statusCode,
    ).toBe(200);
  });

  it('auditoría: cada cambio, sin el texto de las notas', async () => {
    const actions = await auditActions();
    for (const action of [
      'asset.renamed',
      'asset.tags_changed',
      'asset.notes_changed',
      'tag.style_changed',
      'project.created',
      'project.updated',
      'project.deleted',
      'project.member_set',
      'project.member_removed',
      'policy.rule_created',
    ])
      expect(actions, action).toContain(action);
    const [renamed]: { details: Record<string, unknown> }[] = await db.query(
      `SELECT details FROM audit_events WHERE action = 'asset.renamed'
        ORDER BY occurred_at LIMIT 1`,
    );
    expect(renamed.details).toMatchObject({
      nameFrom: 'debian',
      nameTo: 'Base de datos',
      discoveredName: 'debian',
    });
    const [{ dump }]: { dump: string }[] = await db.query(
      `SELECT string_agg(details::text, '') AS dump FROM audit_events
        WHERE action = 'asset.notes_changed'`,
    );
    expect(dump).not.toContain('lunes');
    expect(dump).toContain('lengthTo');
    const [policy]: { target_type: string; target_label: string }[] =
      await db.query(
        `SELECT target_type, target_label FROM audit_events
          WHERE action = 'policy.rule_created' AND details->>'scope' = 'project'`,
      );
    expect(policy).toEqual({
      target_type: 'project',
      target_label: 'Proyecto «Homelab»',
    });
    for (const banned of ['PRIVATE KEY'])
      expect(
        [...responses, worker!.output.join('')].join('\n'),
      ).not.toContain(banned);
  });
});
