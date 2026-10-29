import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  Asset,
  AssetCollectJobResult,
  AssetDiscoverJobResult,
  AssetFindingsPage,
  AssetVulnerabilitiesPage,
  AssetRelations,
  AssetTreeSummaryNode,
  EnqueueJobResponse,
  EnrollServerResponse,
  FindingSearchResult,
  ImageScanJobResult,
  JobStatus,
  Page,
  ScanAssetResponse,
  DashboardSummary,
  JobRunSummary,
  UserSummary,
  VulnerabilitySummary,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { readdirSync } from 'node:fs';
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
  type FakeContainer,
  type FakePve,
  type FakePveState,
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
  waitPrioritized, WORK_QUEUES } from './support/worker.js';

const VIEWER = {
  email: 'viewer-scan@infraward.test',
  password: 'otra-contraseña-larga',
};
const NGINX = `sha256:${'1'.repeat(64)}`;
const REDIS = `sha256:${'2'.repeat(64)}`;
const HUGE = `sha256:${'3'.repeat(64)}`;

const CONTAINERS: FakeContainer[] = [
  {
    name: 'web1',
    image: 'nginx:1.25',
    imageId: NGINX,
    state: 'running',
    published: { '80/tcp': 8080 },
    env: 'DB_PASSWORD=env-centinela',
  },
  { name: 'web2', image: 'nginx:1.25', imageId: NGINX, state: 'running' },
  { name: 'cache', image: 'redis:7.0', imageId: REDIS, state: 'exited' },
  {
    name: 'ml',
    image: 'pytorch:latest',
    imageId: HUGE,
    state: 'running',
    imageSize: 50_000_000,
  },
];

/**
 * Escaneo con Trivy de punta a punta (DESIGN §9) con el worker real, PostgreSQL y Redis, y un
 * nodo Proxmox simulado con un CT con Docker (`ssh`, `ansible-playbook` y `trivy` falsos).
 */
describe('Escaneo de imágenes y findings (e2e)', () => {
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
  let ct: AssetTreeSummaryNode;
  let state: FakePveState;

  beforeAll(async () => {
    await prepareEnv('e2e_scan');
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
      guests: [
        {
          type: 'lxc',
          vmid: 100,
          node: 'pve',
          name: 'docker',
          status: 'running',
          docker: true,
          containers: structuredClone(CONTAINERS),
        },
      ],
      vulns: {
        [NGINX]: [
          {
            id: 'CVE-2024-6387',
            pkg: 'openssh-client',
            version: '1:9.2p1-2',
            fixed: '1:9.2p1-2+deb12u3',
            severity: 'HIGH',
          },
          {
            id: 'CVE-2025-0838',
            pkg: 'libabsl20220623',
            version: '20220623.1-1',
            severity: 'CRITICAL',
          },
        ],
        [REDIS]: [
          {
            id: 'CVE-2024-6387',
            pkg: 'openssh-client',
            version: '1:9.2p1-2',
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
    plain = await enroll('sin-docker');
    privateKey = await app
      .get(SecretsService)
      .resolve(node.credentials.sshPrivateKey!);
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
    method: 'GET' | 'POST',
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

  /**
   * Espera a que las colas de descubrimiento y escaneo estén vacías y a que el historial lo
   * refleje: el líder del worker (`JobEventsListener`) pasa las filas de `job_runs` a terminadas al recibir
   * los eventos de BullMQ, un poco después (en un runner lento, el panel aún las contaría).
   */
  async function settle(): Promise<void> {
    const queues = WORK_QUEUES.map((name) =>
      app.get<Queue>(getQueueToken(name)),
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
      30_000,
      () => `colas sin vaciar\n${worker?.output.join('')}`,
    );
    let pending: unknown[] = [];
    await waitFor(
      async () => {
        pending = await db.query(
          `SELECT name, state FROM job_runs WHERE state IN ('queued', 'active')`,
        );
        return pending.length === 0;
      },
      30_000,
      () => `job_runs sin terminar: ${JSON.stringify(pending)}\n${worker?.output.join('')}`,
    );
  }

  async function containers(): Promise<AssetTreeSummaryNode[]> {
    const res = await request('GET', `/assets/${ct.id}/tree`);
    expect(res.statusCode).toBe(200);
    return res
      .json<AssetTreeSummaryNode>()
      .children.sort((a, b) => a.name.localeCompare(b.name));
  }

  const byName = (list: AssetTreeSummaryNode[], name: string) =>
    list.find((c) => c.name === name)!;

  async function findingsOf(name: string, query = '') {
    const res = await request(
      'GET',
      `/assets/${byName(await containers(), name).id}/findings${query}`,
    );
    expect(res.statusCode).toBe(200);
    return res.json<AssetFindingsPage>();
  }

  const findingCount = async () =>
    (
      (await db.query(`SELECT count(*)::int AS n FROM findings`)) as {
        n: number;
      }[]
    )[0].n;

  const dockerSaves = () =>
    pve.sshCommands().filter((c) => / docker save | docker-save /.test(c));

  async function discoverCt(): Promise<AssetDiscoverJobResult> {
    const res = await request('POST', `/assets/${ct.id}/discover`);
    expect(res.statusCode).toBe(202);
    const done = await finished<AssetDiscoverJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.state).toBe('completed');
    await settle();
    return done.result!;
  }

  it('recoger el nodo encadena: CT ⇒ docker-host ⇒ contenedores ⇒ un escaneo por imagen', async () => {
    worker = await startWorker({
      ...pve.workerEnv(),
      TRIVY_MAX_IMAGE_SIZE: String(10 * 1024 * 1024),
    });
    const res = await request('POST', `/assets/${node.id}/collect`);
    const done = await finished<AssetCollectJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.state).toBe('completed');
    await settle();

    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    ct = tree.children[0];
    expect(ct.roles).toEqual(['docker-host']);
    const list = await containers();
    expect(list.map((c) => [c.name, c.type, c.status])).toEqual([
      ['cache', 'container', 'active'],
      ['ml', 'container', 'active'],
      ['web1', 'container', 'active'],
      ['web2', 'container', 'active'],
    ]);

    // nginx en dos contenedores: una sola descarga y un solo análisis. La imagen grande no se
    // descarga.
    expect(pve.trivyScans()).toHaveLength(2);
    expect(dockerSaves().sort()).toEqual([
      `sudo -n /usr/local/libexec/infraward/infraward-query pct-exec 100 docker save ${NGINX}`,
      `sudo -n /usr/local/libexec/infraward/infraward-query pct-exec 100 docker save ${REDIS}`,
    ]);
    // La base de datos de Trivy se descargó una vez (vulnerabilidades y Java).
    expect(pve.trivyDownloads().map((a) => a[1])).toEqual([
      '--download-db-only',
      '--download-java-db-only',
    ]);
  });

  /** Ejecuciones registradas, cuando ninguna sigue en cola o en curso. */
  async function jobRuns(query = ''): Promise<JobRunSummary[]> {
    let running = -1;
    await waitFor(
      async () => {
        running = (await request('GET', '/jobs?state=running')).json<
          Page<JobRunSummary>
        >().total;
        return running === 0;
      },
      10_000,
      () => `${running} ejecuciones sin terminar`,
    );
    const res = await request('GET', `/jobs?limit=200${query}`);
    expect(res.statusCode).toBe(200);
    return res.json<Page<JobRunSummary>>().items;
  }

  it('job_runs registra la cadena con su asset, su origen y su duración', async () => {
    const runs = await jobRuns();
    const one = (name: string, assetId: string) =>
      runs.find((r) => r.name === name && r.assetId === assetId)!;
    const collectNode = one('asset.collect', node.id);
    const discoverNode = one('asset.discover', node.id);
    const collectCt = one('asset.collect', ct.id);
    const discoverCt = one('asset.discover', ct.id);
    expect(collectNode).toMatchObject({
      assetName: 'pve',
      assetType: 'server',
      state: 'completed',
      progress: 100,
      parentJobId: null,
      error: null,
    });
    expect(collectNode.startedAt).not.toBeNull();
    expect(collectNode.durationMs).toBeGreaterThanOrEqual(0);
    expect(collectNode.message).toBeTruthy();
    expect(discoverNode.parentJobId).toBe(collectNode.id);
    expect(collectCt.parentJobId).toBe(discoverNode.id);
    expect(discoverCt.parentJobId).toBe(collectCt.id);
    const scans = runs.filter((r) => r.name === 'image.scan');
    expect(scans.length).toBeGreaterThanOrEqual(2);
    for (const scan of scans)
      expect(scan).toMatchObject({
        assetType: 'image',
        state: 'completed',
        parentJobId: discoverCt.id,
      });
    // De la más reciente a la más antigua.
    const created = runs.map((r) => Date.parse(r.createdAt));
    expect(created).toEqual([...created].sort((a, b) => b - a));

    // Las de un contenedor incluyen los escaneos de su imagen.
    const web1 = byName(await containers(), 'web1');
    const forWeb1 = await jobRuns(`&assetId=${web1.id}`);
    expect(forWeb1.map((r) => [r.name, r.assetName])).toContainEqual([
      'image.scan',
      'nginx:1.25',
    ]);
    expect(forWeb1.every((r) => r.name === 'image.scan')).toBe(true);
    expect((await request('GET', '/jobs?state=nope')).statusCode).toBe(400);
    expect((await request('GET', '/jobs?assetId=x')).statusCode).toBe(400);
  });

  it('cada contenedor ve los findings de su imagen, guardados una sola vez en el asset image', async () => {
    const web1 = await findingsOf('web1');
    expect(web1.total).toBe(2);
    expect(
      web1.items.map((f) => [f.vulnerabilityId, f.severity, f.status]),
    ).toEqual([
      ['CVE-2025-0838', 'CRITICAL', 'open'],
      ['CVE-2024-6387', 'HIGH', 'open'],
    ]);
    expect(web1.items[1]).toMatchObject({
      packageName: 'openssh-client',
      installedVersion: '1:9.2p1-2',
      fixedVersion: '1:9.2p1-2+deb12u3',
      fixStatus: 'fixed',
    });
    expect(web1.image).toMatchObject({
      assetId: web1.items[0].assetId,
      imageId: NGINX,
      repoTags: ['nginx:1.25'],
      scanStatus: 'scanned',
      scanReason: null,
      scanSource: 'docker_save',
      trivyVersion: '0.75.0',
      vulnerabilityCount: 2,
    });
    const web2 = await findingsOf('web2');
    expect(web2.items.map((f) => f.id)).toEqual(web1.items.map((f) => f.id));
    expect((await findingsOf('cache')).total).toBe(1);
    // nginx (2) + redis (1): ninguna fila por contenedor.
    expect(await findingCount()).toBe(3);

    // La imagen es un asset (clave natural = image ID) enlazado con instance_of.
    const image = (
      await request('GET', `/assets/${web1.image!.assetId}`)
    ).json<Asset>();
    expect(image).toMatchObject({
      type: 'image',
      name: 'nginx:1.25',
      naturalKey: NGINX,
      status: 'active',
    });
    const relations = (
      await request(
        'GET',
        `/assets/${byName(await containers(), 'web1').id}/relations`,
      )
    ).json<AssetRelations>();
    expect(relations.outgoing).toContainEqual(
      expect.objectContaining({ childId: image.id, type: 'instance_of' }),
    );
    const own = await request('GET', `/assets/${image.id}/findings`);
    expect(own.json<AssetFindingsPage>()).toMatchObject({
      total: 2,
      image: { imageId: NGINX },
    });
    // Las imágenes no son raíces del árbol.
    const forest = (await request('GET', '/assets/tree')).json<
      AssetTreeSummaryNode[]
    >();
    expect(forest.some((n) => n.type === 'image')).toBe(false);
    // El árbol cuenta los findings abiertos de la imagen en cada contenedor.
    const counts = Object.fromEntries(
      (await containers()).map((c) => [c.name, c.openFindings]),
    );
    const sev = (critical: number, high: number) => ({
      UNKNOWN: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: high,
      CRITICAL: critical,
    });
    expect(counts).toMatchObject({
      web1: sev(1, 1),
      web2: sev(1, 1),
      cache: sev(0, 1),
    });
    expect(ct.openFindings).toEqual(sev(0, 0));
  });

  it('GET /assets/:id/vulnerabilities agrupa por CVE con sus paquetes y pagina por CVE', async () => {
    const web1 = byName(await containers(), 'web1');
    const imageId = (await findingsOf('web1')).image!.assetId;
    // El mismo CVE en otros dos paquetes (uno sin parche): se copian filas en la BD.
    const copy = (pkg: string, fixed: string | null) =>
      db.query(
        `INSERT INTO findings
         SELECT (jsonb_populate_record(NULL::findings, to_jsonb(f) || jsonb_build_object(
                  'id', gen_random_uuid(), 'package_name', $2::text, 'fixed_version', $3::text,
                  'fingerprint', md5($2::text)))).*
           FROM findings f WHERE f.asset_id = $1 AND f.vulnerability_id = 'CVE-2024-6387'
            AND f.package_name = 'openssh-client'`,
        [imageId, pkg, fixed],
      );
    await copy('openssh-server', '1:9.2p1-2+deb12u3');
    await copy('openssh-sftp-server', null);
    try {
      const get = async (query = '') => {
        const res = await request(
          'GET',
          `/assets/${web1.id}/vulnerabilities${query}`,
        );
        expect(res.statusCode).toBe(200);
        return res.json<AssetVulnerabilitiesPage>();
      };
      // Por severidad: el orden por defecto (prioridad) depende de si el worker ya la calculó.
      const all = await get('?sort=severity');
      expect(all.total).toBe(2);
      expect(all.image).toMatchObject({ imageId: NGINX });
      expect(
        all.items.map((g) => [g.vulnerabilityId, g.severity, g.fixable]),
      ).toEqual([
        ['CVE-2025-0838', 'CRITICAL', expect.any(Boolean)],
        ['CVE-2024-6387', 'HIGH', true],
      ]);
      const ssh = all.items[1];
      expect(ssh.title).toBe('CVE-2024-6387 en openssh-client');
      // Dentro del CVE el orden va por prioridad, que el worker puede recalcular en cualquier
      // momento: se comprueba el contenido, no el orden.
      expect(
        ssh.packages
          .map((p) => [p.packageName, p.fixedVersion])
          .sort(([a], [b]) => String(a).localeCompare(String(b))),
      ).toEqual([
        ['openssh-client', '1:9.2p1-2+deb12u3'],
        ['openssh-server', '1:9.2p1-2+deb12u3'],
        ['openssh-sftp-server', null],
      ]);
      // Los filtros van por finding: con parche, el paquete sin parche no sale.
      const fixable = await get('?fixable=true&minSeverity=HIGH');
      expect(
        fixable.items.find((g) => g.vulnerabilityId === 'CVE-2024-6387')!
          .packages,
      ).toHaveLength(2);
      // Paginación por CVE, con el total aunque la página quede vacía.
      const page = await get('?sort=severity&limit=1&offset=1');
      expect([page.total, page.items.map((g) => g.vulnerabilityId)]).toEqual([
        2,
        ['CVE-2024-6387'],
      ]);
      expect((await get('?offset=10')).total).toBe(2);
      expect((await get('?vulnerabilityId=cve-2024-6387')).total).toBe(1);
      expect(
        (
          await request(
            'GET',
            `/assets/${web1.id}/vulnerabilities?minSeverity=GRAVE`,
          )
        ).statusCode,
      ).toBe(400);
    } finally {
      await db.query(
        `DELETE FROM findings WHERE asset_id = $1 AND package_name IN ('openssh-server', 'openssh-sftp-server')`,
        [imageId],
      );
    }
  });

  it('una imagen que supera TRIVY_MAX_IMAGE_SIZE queda no escaneada con su motivo', async () => {
    const ml = await findingsOf('ml');
    expect(ml.total).toBe(0);
    expect(ml.image).toMatchObject({
      imageId: HUGE,
      scanStatus: 'skipped',
      scanReason: 'Supera TRIVY_MAX_IMAGE_SIZE (48 MiB > 10 MiB)',
    });
  });

  it('volver a descubrir y escanear no duplica findings ni vuelve a analizar las imágenes', async () => {
    const before = await findingCount();
    const discovered = await discoverCt();
    // La imagen saltada se reintenta (y se vuelve a saltar sin descargar nada).
    expect(discovered).toMatchObject({ created: 0, updated: 4, scanQueued: 1 });

    const res = await request('POST', `/assets/${ct.id}/scan`);
    expect(res.statusCode).toBe(202);
    const all = res.json<ScanAssetResponse>().jobs;
    // El CT: su SBOM y una por imagen.
    expect(all.map((j) => j.name).sort()).toEqual([
      'host.scan',
      'image.scan',
      'image.scan',
      'image.scan',
    ]);
    const jobs = all.filter((j) => j.name === 'image.scan');
    const results = await Promise.all(
      jobs.map((j) => finished<ImageScanJobResult>(j.id)),
    );
    await settle();
    const byImage = Object.fromEntries(
      results.map((r) => [r.result!.imageId, r.result!]),
    );
    expect(byImage[NGINX]).toMatchObject({
      cached: true,
      containers: 2,
      findingsCreated: 0,
    });
    expect(byImage[REDIS]).toMatchObject({ cached: true, findingsCreated: 0 });
    expect(byImage[HUGE]).toMatchObject({ scanStatus: 'skipped' });

    expect(await findingCount()).toBe(before);
    expect(pve.trivyScans()).toHaveLength(2);
    expect(dockerSaves()).toHaveLength(2);
    const duplicates: unknown[] = await db.query(
      `SELECT asset_id, fingerprint FROM findings GROUP BY 1, 2 HAVING count(*) > 1`,
    );
    expect(duplicates).toEqual([]);
  });

  it('un re-escaneo forzado tras parchear la imagen marca como fixed lo que ya no está', async () => {
    state.vulns![NGINX] = state.vulns![NGINX].filter(
      (v) => v.id !== 'CVE-2025-0838',
    );
    pve.setState(state);
    const web1 = byName(await containers(), 'web1');
    const res = await request('POST', `/assets/${web1.id}/scan?force=true`);
    expect(res.statusCode).toBe(202);
    const done = await finished<ImageScanJobResult>(
      res.json<ScanAssetResponse>().jobs[0].id,
    );
    expect(done.result).toMatchObject({
      cached: false,
      containers: 2,
      findingsCreated: 0,
      findingsFixed: 1,
    });
    expect(pve.trivyScans()).toHaveLength(3);
    for (const name of ['web1', 'web2']) {
      const page = await findingsOf(name);
      expect(page.total).toBe(2);
      expect(
        Object.fromEntries(
          page.items.map((f) => [f.vulnerabilityId, f.status]),
        ),
      ).toEqual({ 'CVE-2025-0838': 'fixed', 'CVE-2024-6387': 'open' });
      expect(
        page.items.find((f) => f.status === 'fixed')!.fixedAt,
      ).toBeTruthy();
    }
    expect((await findingsOf('web1', '?status=open')).total).toBe(1);
    // Los `fixed` ya no cuentan en el árbol.
    expect(byName(await containers(), 'web2').openFindings).toMatchObject({
      CRITICAL: 0,
      HIGH: 1,
    });
  });

  it('un contenedor recreado con otra imagen ya escaneada: pasa a la nueva sin analizar nada', async () => {
    const web2 = state.guests[0].containers!.find((c) => c.name === 'web2')!;
    web2.image = 'redis:7.0';
    web2.imageId = REDIS;
    pve.setState(state);
    const discovered = await discoverCt();
    expect(discovered.scanQueued).toBe(1); // solo la imagen saltada
    const page = await findingsOf('web2');
    expect(page.image).toMatchObject({ imageId: REDIS });
    expect(page.items.map((f) => [f.vulnerabilityId, f.status])).toEqual([
      ['CVE-2024-6387', 'open'],
    ]);
    const links: { n: number }[] = await db.query(
      `SELECT count(*)::int AS n FROM asset_relations r JOIN assets c ON c.id = r.parent_id
        WHERE r.type = 'instance_of' AND c.name = 'web2'`,
    );
    expect(links[0].n).toBe(1);
    expect(pve.trivyScans()).toHaveLength(3);
  });

  it('búsqueda por CVE: un finding por imagen con los contenedores afectados', async () => {
    const res = await request(
      'GET',
      '/findings?vulnerabilityId=cve-2024-6387&status=open',
    );
    expect(res.statusCode).toBe(200);
    const page = res.json<Page<FindingSearchResult>>();
    expect(page.total).toBe(2);
    const images = new Map(
      (
        (await db.query(
          `SELECT id, name FROM assets WHERE type = 'image'`,
        )) as { id: string; name: string }[]
      ).map((r) => [r.id, r.name] as const),
    );
    expect(
      Object.fromEntries(
        page.items.map((f) => [
          images.get(f.assetId),
          f.affected.map((a) => [a.name, a.type, a.parentId]),
        ]),
      ),
    ).toEqual({
      'nginx:1.25': [['web1', 'container', ct.id]],
      'redis:7.0': [
        ['cache', 'container', ct.id],
        ['web2', 'container', ct.id],
      ],
    });
    // Cada finding dice en qué imagen se detectó.
    expect(
      page.items.map((f) => [f.owner.id, f.owner.name, f.owner.type]).sort(),
    ).toEqual(
      [...images.entries()]
        .map(([id, name]) => [id, name, 'image'])
        .filter(([, name]) => name === 'nginx:1.25' || name === 'redis:7.0')
        .sort(),
    );
    const critical = await request('GET', '/findings?severity=critical');
    expect(critical.json<Page<FindingSearchResult>>().total).toBe(1);
    expect(
      (await request('GET', '/findings?severity=EXTREME')).statusCode,
    ).toBe(400);
    expect(
      (await request('GET', '/findings?vulnerabilityId=a%20b')).statusCode,
    ).toBe(400);
  });

  it('GET /vulnerabilities: una fila por CVE con sus imágenes y contenedores', async () => {
    // CVE-2025-0838 ya está `fixed` (re-escaneo tras parchear nginx): sin filtro de estado, sale.
    // Por severidad: el orden por defecto (prioridad) depende de si el worker ya la calculó.
    const res = await request('GET', '/vulnerabilities?sort=severity');
    expect(res.statusCode).toBe(200);
    const page = res.json<Page<VulnerabilitySummary>>();
    expect(page.total).toBe(2);
    expect(page.items).toMatchObject([
      {
        vulnerabilityId: 'CVE-2025-0838',
        severity: 'CRITICAL',
        fixable: false,
        packageNames: ['libabsl20220623'],
        images: 1,
        containers: 1,
        otherAssets: 0,
      },
      {
        vulnerabilityId: 'CVE-2024-6387',
        severity: 'HIGH',
        // Con parche en nginx, sin él en redis.
        fixable: true,
        packageNames: ['openssh-client'],
        images: 2,
        containers: 3,
        otherAssets: 0,
      },
    ]);
    const open = (await request('GET', '/vulnerabilities?status=open')).json<
      Page<VulnerabilitySummary>
    >();
    expect(open.items.map((v) => v.vulnerabilityId)).toEqual(['CVE-2024-6387']);
    // Mismo criterio que la ficha: con parche y ≥ HIGH.
    const fixable = (
      await request(
        'GET',
        '/vulnerabilities?status=open&fixable=true&minSeverity=HIGH',
      )
    ).json<Page<VulnerabilitySummary>>();
    expect(
      fixable.items.map((v) => [v.vulnerabilityId, v.images, v.containers]),
    ).toEqual([['CVE-2024-6387', 1, 1]]);
    // q: CVE por prefijo o paquete por subcadena, también en /findings y en la ficha.
    const ids = async (url: string) =>
      (await request('GET', url))
        .json<Page<VulnerabilitySummary>>()
        .items.map((v) => v.vulnerabilityId);
    expect(await ids('/vulnerabilities?q=cve-2025')).toEqual(['CVE-2025-0838']);
    expect(await ids('/vulnerabilities?q=SSH')).toEqual(['CVE-2024-6387']);
    expect(await ids('/vulnerabilities?q=%25')).toEqual([]);
    expect(
      (await request('GET', '/findings?q=absl')).json<
        Page<FindingSearchResult>
      >().total,
    ).toBe(1);
    const web1 = byName(await containers(), 'web1');
    expect(
      (await request('GET', `/assets/${web1.id}/vulnerabilities?q=openssh`))
        .json<AssetVulnerabilitiesPage>()
        .items.map((v) => v.vulnerabilityId),
    ).toEqual(['CVE-2024-6387']);
    // Paginación por CVE.
    const second = (
      await request('GET', '/vulnerabilities?limit=1&offset=1')
    ).json<Page<VulnerabilitySummary>>();
    expect([second.total, second.items.length]).toEqual([2, 1]);
    const beyond = (await request('GET', '/vulnerabilities?offset=10')).json<
      Page<VulnerabilitySummary>
    >();
    expect([beyond.total, beyond.items]).toEqual([2, []]);
    expect(
      (await request('GET', '/vulnerabilities?minSeverity=EXTREME')).statusCode,
    ).toBe(400);
    expect(
      // La búsqueda admite hasta 2000 (el parser corta a 500 con aviso).
      (await request('GET', `/vulnerabilities?q=${'x'.repeat(2001)}`))
        .statusCode,
    ).toBe(400);
    expect(
      (await request('GET', '/vulnerabilities', undefined, viewerToken))
        .statusCode,
    ).toBe(200);
  });

  it('GET /dashboard: assets por tipo, lo accionable y la actividad reciente', async () => {
    // Lo que encolaron los tests anteriores, terminado también en el historial.
    await settle();
    await waitPrioritized(db);
    const res = await request('GET', '/dashboard', undefined, viewerToken);
    expect(res.statusCode).toBe(200);
    const summary = res.json<DashboardSummary>();
    const [types]: {
      servers: number;
      cts: number;
      containers: number;
      images: number;
    }[] = await db.query(
      `SELECT count(*) FILTER (WHERE type = 'server')::int AS servers,
                count(*) FILTER (WHERE type = 'lxc')::int AS cts,
                count(*) FILTER (WHERE type = 'container')::int AS containers,
                count(*) FILTER (WHERE type = 'image')::int AS images
           FROM assets WHERE status <> 'retired'`,
    );
    expect(summary.assetsByType).toMatchObject({
      server: types.servers,
      lxc: types.cts,
      container: types.containers,
      image: types.images,
    });
    expect(summary.pendingEnrollment).toBe(0);
    // Lo mismo que la vista principal de Vulnerabilidades (prioridad ≥ media, sin ruido ni
    // imágenes sin uso).
    const main = (
      await request(
        'GET',
        '/vulnerabilities?status=open&inUse=true&minPriority=medium&limit=100',
        undefined,
        viewerToken,
      )
    ).json<Page<VulnerabilitySummary>>();
    expect(summary.vulnerabilities.cves).toBe(main.total);
    expect(summary.vulnerabilities.top.map((v) => v.vulnerabilityId)).toEqual(
      main.items.slice(0, 5).map((v) => v.vulnerabilityId),
    );
    expect(summary.attention.failedJobs.count).toBe(0);
    expect(summary.runningJobs).toBe(0);
    expect(summary.recentActivity.length).toBeGreaterThan(0);
    expect(summary.recentActivity.length).toBeLessThanOrEqual(8);
    expect(
      (await request('GET', '/dashboard', undefined, null)).statusCode,
    ).toBe(401);
  });

  it('GET /users: solo admin y sin el hash de la contraseña', async () => {
    expect(
      (await request('GET', '/users', undefined, viewerToken)).statusCode,
    ).toBe(403);
    const res = await request('GET', '/users');
    expect(res.statusCode).toBe(200);
    const users = res.json<UserSummary[]>();
    expect(users.map((u) => [u.email, u.role])).toEqual(
      expect.arrayContaining([
        [ADMIN.email, 'admin'],
        [VIEWER.email, 'viewer'],
      ]),
    );
    for (const user of users)
      expect(Object.keys(user).sort()).toEqual([
        'active',
        'createdAt',
        'email',
        'emergency',
        'id',
        'lastLoginAt',
        'mfaEnabled',
        'mustChangePassword',
        'name',
        'oidcLinked',
        'origin',
        'role',
      ]);
    expect(res.body).not.toMatch(/argon2|password_?hash/i);
  });

  it('scan de un asset image: un job para esa imagen', async () => {
    const [image]: { id: string }[] = await db.query(
      `SELECT id FROM assets WHERE type = 'image' AND natural_key = $1`,
      [NGINX],
    );
    const res = await request('POST', `/assets/${image.id}/scan`);
    expect(res.statusCode).toBe(202);
    const done = await finished<ImageScanJobResult>(
      res.json<ScanAssetResponse>().jobs[0].id,
    );
    expect(done.result).toMatchObject({ imageId: NGINX, cached: true });
  });

  it('scan: exige token, admin, UUID, asset existente y un contenedor o host Docker', async () => {
    const url = `/assets/${ct.id}/scan`;
    expect((await request('POST', url, undefined, null)).statusCode).toBe(401);
    expect(
      (await request('POST', url, undefined, viewerToken)).statusCode,
    ).toBe(403);
    expect((await request('POST', '/assets/x/scan')).statusCode).toBe(400);
    expect(
      (
        await request(
          'POST',
          '/assets/00000000-0000-4000-8000-000000000000/scan',
        )
      ).statusCode,
    ).toBe(404);
    // Un servidor sin Docker: solo su SBOM.
    const res = await request('POST', `/assets/${plain.id}/scan`);
    expect(res.statusCode).toBe(202);
    const [host] = res.json<ScanAssetResponse>().jobs;
    expect(host.name).toBe('host.scan');
    expect((await finished(host.id)).state).toBe('completed');
    // Lo que no es un servidor con conexión, un CT, Docker ni una imagen: 409.
    const domain = await request('POST', '/assets', {
      type: 'domain',
      name: 'ejemplo.test',
    });
    expect(domain.statusCode).toBe(201);
    const conflict = await request(
      'POST',
      `/assets/${domain.json<Asset>().id}/scan`,
    );
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json<{ message: string }>().message).toMatch(
      /servidores con conexión, CT, contenedores, imágenes y hosts Docker/,
    );
    // Un viewer sí lee findings.
    expect(
      (
        await request(
          'GET',
          `/assets/${ct.id}/findings`,
          undefined,
          viewerToken,
        )
      ).statusCode,
    ).toBe(200);
    expect(
      (await request('GET', '/findings', undefined, null)).statusCode,
    ).toBe(401);
  });

  it('aparece en OpenAPI', async () => {
    const spec = (await app.inject({ url: '/openapi.json' })).json<{
      paths: Record<string, unknown>;
    }>();
    expect(spec.paths['/assets/{id}/scan']).toBeDefined();
    expect(spec.paths['/assets/{id}/findings']).toBeDefined();
    expect(spec.paths['/findings']).toBeDefined();
    expect(spec.paths['/assets/{id}/vulnerabilities']).toBeDefined();
    for (const path of ['/vulnerabilities', '/jobs', '/dashboard', '/users'])
      expect(spec.paths[path], path).toBeDefined();
  });

  it('no quedan ficheros en el directorio de escaneo del worker', () => {
    // Cada réplica trabaja en su subdirectorio (DESIGN §20): solo puede quedar el suyo, vacío.
    expect(
      readdirSync(pve.scanDir, { recursive: true }).filter(
        (entry) => !/^worker-\d+$/.test(String(entry)),
      ),
    ).toEqual([]);
  });

  it('ni la clave privada ni el entorno de los contenedores salen en respuestas, logs ni BD', async () => {
    const body = privateKey.split('\n')[1];
    const dump: { text: string }[] = await db.query(
      `SELECT facts::text AS text FROM assets
       UNION ALL SELECT facts::text FROM snapshots
       UNION ALL SELECT row_to_json(f)::text FROM findings f
       UNION ALL SELECT row_to_json(i)::text FROM container_images i
       UNION ALL SELECT row_to_json(r)::text FROM job_runs r`,
    );
    for (const text of [
      responses.join('\n'),
      worker?.output.join('') ?? '',
      dump.map((d) => d.text).join('\n'),
    ]) {
      expect(text).not.toContain(body);
      expect(text).not.toContain('env-centinela');
    }
  });
});
