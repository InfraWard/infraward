import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  Asset,
  AssetCollectJobResult,
  AssetDiscoverJobResult,
  AssetRelations,
  AssetTreeSummaryNode,
  CertificateFacts,
  CollectedFacts,
  DashboardSummary,
  DockerContainerFacts,
  DockerHostResources,
  EnqueueJobResponse,
  EnrollServerResponse,
  JobStatus,
  Page,
  VulnerabilitySummary,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { readFileSync } from 'node:fs';
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
  type FakePlesk,
  type FakePve,
  type FakePveState,
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
  waitPrioritized, WORK_QUEUES } from './support/worker.js';

const WP = `sha256:${'a'.repeat(64)}`;
const MARIADB = `sha256:${'b'.repeat(64)}`;
const ALPINE = `sha256:${'c'.repeat(64)}`;

/** Filas de `plesk db` (las mismas que los tests del descubridor, con certificados reales). */
const pleskRows = (name: string): object[] =>
  readFileSync(
    new URL(
      `../../../packages/connectors/src/plesk/fixtures/${name}.jsonl`,
      import.meta.url,
    ),
    'utf8',
  )
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as object);
const PLESK: FakePlesk = {
  domains: pleskRows('domains'),
  aliases: pleskRows('aliases'),
  databases: pleskRows('databases'),
  certificates: pleskRows('certificates'),
};

const STATE: FakePveState = {
  node: 'plesk01',
  cluster: null,
  machineId: 'e'.repeat(32),
  ctMachineId: 'f'.repeat(32),
  guests: [],
  nodeRoles: ['plesk', 'docker'],
  collectSudoersVersion: 4,
  plesk: PLESK,
  hostDocker: {
    containers: [
      {
        name: 'wordpress',
        image: 'wordpress:6',
        imageId: WP,
        state: 'running',
        published: { '80/tcp': 8080 },
        mounts: ['wp-data'],
        networks: ['plesk-net'],
      },
      {
        name: 'mariadb',
        image: 'mariadb:11',
        imageId: MARIADB,
        state: 'running',
        mounts: ['db-data'],
        networks: ['plesk-net'],
      },
    ],
    volumes: ['db-data', 'huerfano', 'wp-data'],
    networks: ['bridge', 'plesk-net', 'sin-uso'],
    extraImages: [{ image: 'alpine:3.20', imageId: ALPINE }],
  },
  vulns: {
    [WP]: [
      { id: 'CVE-2026-1001', pkg: 'openssl', version: '3.0.1', fixed: '3.0.2', severity: 'CRITICAL' },
    ],
    [MARIADB]: [
      { id: 'CVE-2026-1002', pkg: 'zlib', version: '1.2', fixed: '1.3', severity: 'HIGH' },
    ],
    // Solo en la imagen sin uso.
    [ALPINE]: [
      { id: 'CVE-2026-1003', pkg: 'busybox', version: '1.36', fixed: '1.37', severity: 'CRITICAL' },
    ],
  },
};

/**
 * Sesión 14 de punta a punta con el worker real: un servidor Plesk con Docker (simulado: `ssh`,
 * `ansible-playbook` y `trivy` falsos). Volúmenes, redes e imágenes sin uso; dominios,
 * suscripciones, bases de datos y certificados de Plesk; escaneo de sus imágenes.
 */
// Un escaneo con el host ocupado se aplaza 20-40 s (HostBusy): esperas de 60 s y tests de 120 s.
describe('Docker completo y Plesk (e2e)', { timeout: 120_000 }, () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let token: string;
  let server: Asset;
  const responses: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_docker_plesk');
    app = await createTestApp();
    db = app.get(DataSource);
    token = await loginToken(app, ADMIN.email, ADMIN.password);
    pve = createFakePve();
    pve.setState(STATE);
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name: 'plesk01',
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

  async function request(
    method: 'GET' | 'POST' | 'DELETE',
    url: string,
    payload?: object,
  ) {
    const res = await app.inject({
      method,
      url,
      payload,
      headers: authHeaders(token),
    });
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

  /** Espera a que no quede nada pendiente en las colas de descubrimiento y escaneo. */
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

  async function collect(): Promise<JobStatus & { result?: AssetCollectJobResult }> {
    const res = await request('POST', `/assets/${server.id}/collect`);
    expect(res.statusCode).toBe(202);
    const job = await finished<AssetCollectJobResult>(res.json<EnqueueJobResponse>().id);
    await settle();
    return job;
  }

  async function discover(): Promise<JobStatus & { result?: AssetDiscoverJobResult }> {
    const res = await request('POST', `/assets/${server.id}/discover`);
    expect(res.statusCode).toBe(202);
    const job = await finished<AssetDiscoverJobResult>(res.json<EnqueueJobResponse>().id);
    await settle();
    return job;
  }

  const byName = <T extends { name: string }>(list: T[], name: string) =>
    list.find((x) => x.name === name)!;

  it('recoger el servidor detecta plesk y docker-host y descubre los dos', async () => {
    const job = await collect();
    expect(job.state, `${JSON.stringify(job)}\n${pve.sshCommands().join("\n")}`).toBe('completed');
    expect(job.result?.roles).toEqual(['docker-host', 'plesk']);
    const discovery = (
      await get<Page<{ name: string; state: string; assetId: string | null }>>(
        `/jobs?assetId=${server.id}&name=asset.discover`,
      )
    ).items;
    expect(discovery.map((j) => j.state)).toEqual(['completed']);
  });

  it('árbol: suscripción → dominio → (base de datos, certificado) y contenedores; sin volúmenes ni redes', async () => {
    const tree = await get<AssetTreeSummaryNode>(`/assets/${server.id}/tree`);
    const kids = (n: AssetTreeSummaryNode) =>
      n.children.map((c) => `${c.type}:${c.name}`).sort();
    expect(kids(tree)).toEqual([
      'certificate:default certificate',
      'container:mariadb',
      'container:wordpress',
      'subscription:ejemplo.com',
      'subscription:tienda.example.org',
    ]);
    const sub = byName(tree.children, 'ejemplo.com');
    expect(kids(sub)).toEqual([
      'domain:blog.ejemplo.com',
      'domain:ejemplo.com',
      'domain:ejemplo.es',
      'domain:otro-ejemplo.net',
    ]);
    const main = byName(sub.children, 'ejemplo.com');
    expect(kids(main)).toEqual([
      'certificate:Lets Encrypt ejemplo.com',
      'database:wp_ejemplo',
    ]);
    // Caducidad del certificado en el árbol (de la parte pública).
    const le = byName(main.children, 'Lets Encrypt ejemplo.com');
    expect(le.expiresAt).toBe('2027-01-09T00:36:49.000Z');
    expect(JSON.stringify(tree)).not.toMatch(/"type":"(volume|network)"/);
  });

  it('volúmenes, redes e imágenes del host con su uso', async () => {
    const d = await get<DockerHostResources>(`/assets/${server.id}/docker`);
    const usage = (list: DockerHostResources['volumes']) =>
      list.map((r) => [r.name, r.containers, r.inUse]);
    expect(usage(d.volumes)).toEqual([
      ['db-data', 1, true],
      ['huerfano', 0, false],
      ['wp-data', 1, true],
    ]);
    expect(usage(d.networks)).toEqual([
      ['bridge', 0, false],
      ['plesk-net', 2, true],
      ['sin-uso', 0, false],
    ]);
    expect(usage(d.images)).toEqual([
      ['alpine:3.20', 0, false],
      ['mariadb:11', 1, true],
      ['wordpress:6', 1, true],
    ]);
    // «qué contenedores comparten esta red»: las relaciones entrantes de la red.
    const net = byName(d.networks, 'plesk-net');
    const rel = await get<AssetRelations>(`/assets/${net.id}/relations`);
    expect(
      rel.incoming.filter((r) => r.type === 'attached_to').map((r) => r.peer.name).sort(),
    ).toEqual(['mariadb', 'wordpress']);
    // «qué contenedor usa este volumen».
    const vol = byName(d.volumes, 'wp-data');
    const vrel = await get<AssetRelations>(`/assets/${vol.id}/relations`);
    expect(vrel.incoming.map((r) => [r.type, r.peer.name])).toEqual([
      ['contains', 'plesk01'],
      ['mounts', 'wordpress'],
    ]);
    const wp = (await get<Asset>(`/assets/${byName(d.images, 'wordpress:6').id}`));
    expect(wp.status).toBe('active');
    // Facts del contenedor con montajes y redes.
    const containers = (await get<AssetTreeSummaryNode>(`/assets/${server.id}/tree`)).children;
    const wordpress = await get<Asset>(`/assets/${byName(containers, 'wordpress').id}`);
    const facts = wordpress.facts.docker as DockerContainerFacts;
    expect(facts.mounts).toEqual([
      { type: 'volume', name: 'wp-data', source: null, destination: '/data/wp-data', readOnly: false },
    ]);
    expect(facts.networks).toEqual([{ name: 'plesk-net', ipv4: '172.18.0.2', ipv6: null }]);
  });

  it('las imágenes del servidor Plesk se escanean, también la sin uso; lo accionable la deja fuera', async () => {
    // Una descarga y un análisis por imagen, desde el propio servidor (sudoers v4).
    const scanned = pve.trivyScans().length;
    expect(scanned).toBe(3);
    expect(
      pve.sshCommands().filter((c) => c.startsWith('sudo -n /usr/local/libexec/infraward/infraward-query docker-save ')),
    ).toHaveLength(3);
    const all = await get<Page<VulnerabilitySummary>>('/vulnerabilities?status=open');
    expect(all.items.map((v) => [v.vulnerabilityId, v.unusedImages]).sort()).toEqual([
      ['CVE-2026-1001', 0],
      ['CVE-2026-1002', 0],
      ['CVE-2026-1003', 1],
    ]);
    const actionable = await get<Page<VulnerabilitySummary>>(
      '/vulnerabilities?status=open&minSeverity=HIGH&fixable=true&inUse=true',
    );
    expect(actionable.items.map((v) => v.vulnerabilityId).sort()).toEqual([
      'CVE-2026-1001',
      'CVE-2026-1002',
    ]);
    await waitPrioritized(db);
    const dashboard = await get<DashboardSummary>('/dashboard');
    // CRITICAL de wordpress y HIGH de mariadb; el CRITICAL de alpine (sin uso) no cuenta.
    expect(dashboard.vulnerabilities.cves).toBe(2);
    expect(dashboard.vulnerabilities.top.map((v) => v.vulnerabilityId).sort()).toEqual([
      'CVE-2026-1001',
      'CVE-2026-1002',
    ]);
  });

  it('certificados que caducan, en el panel', async () => {
    const dashboard = await get<DashboardSummary>('/dashboard');
    const certs = await db.query<{ name: string; not_after: string }[]>(
      `SELECT name, facts->'certificate'->>'notAfter' AS not_after FROM assets WHERE type = 'certificate'`,
    );
    const soon = Date.now() + 30 * 86_400_000;
    expect(dashboard.attention.certificatesExpiring.assets.map((a) => a.name).sort()).toEqual(
      certs.filter((c) => Date.parse(c.not_after) < soon).map((c) => c.name).sort(),
    );
    const le = await db.query<{ facts: { certificate: CertificateFacts } }[]>(
      `SELECT facts FROM assets WHERE type = 'certificate' AND name = 'Lets Encrypt ejemplo.com'`,
    );
    expect(le[0]!.facts.certificate).toMatchObject({
      letsEncrypt: true,
      usedBy: ['ejemplo.com', 'otro-ejemplo.net'],
    });
    const domain = await db.query<{ id: string }[]>(
      `SELECT id FROM assets WHERE type = 'domain' AND name = 'otro-ejemplo.net'`,
    );
    const rel = await get<AssetRelations>(`/assets/${domain[0]!.id}/relations`);
    expect(rel.outgoing.map((r) => [r.type, r.peer.name])).toEqual([
      ['secured_by', 'Lets Encrypt ejemplo.com'],
    ]);
  });

  it('repetir no duplica nada', async () => {
    const count = async () =>
      (await db.query<{ n: number }[]>(`SELECT count(*)::int AS n FROM assets`))[0]!.n;
    const relations = async () =>
      (await db.query<{ n: number }[]>(`SELECT count(*)::int AS n FROM asset_relations`))[0]!.n;
    const before = [await count(), await relations()];
    const job = await discover();
    expect(job.result).toMatchObject({ created: 0, missing: 0, complete: true });
    expect([await count(), await relations()]).toEqual(before);
  });

  it('lo que desaparece del host pasa a missing: imagen sin host, volumen y dominio', async () => {
    pve.setState({
      ...STATE,
      hostDocker: { ...STATE.hostDocker, volumes: ['db-data', 'wp-data'], extraImages: [] },
      plesk: { ...PLESK, aliases: [] },
    });
    try {
      const job = await discover();
      expect(job.result?.missing).toBe(2);
      const status = async (type: string, name: string) =>
        (await db.query<{ status: string }[]>(
          `SELECT status FROM assets WHERE type = $1 AND name = $2`,
          [type, name],
        ))[0]!.status;
      expect(await status('volume', 'huerfano')).toBe('missing');
      expect(await status('domain', 'ejemplo.es')).toBe('missing');
      expect(await status('image', 'alpine:3.20')).toBe('missing');
      const d = await get<DockerHostResources>(`/assets/${server.id}/docker`);
      expect(d.images.map((i) => i.name)).toEqual(['mariadb:11', 'wordpress:6']);
    } finally {
      pve.setState(STATE);
    }
    // Vuelven a estar: active otra vez.
    await discover();
    const back = await db.query<{ status: string }[]>(
      `SELECT status FROM assets WHERE name IN ('huerfano', 'ejemplo.es', 'alpine:3.20')`,
    );
    expect(back.map((r) => r.status)).toEqual(['active', 'active', 'active']);
  });

  it('si plesk db falla, Docker sigue y nada de Plesk cambia de estado', async () => {
    pve.setState({ ...STATE, plesk: { ...PLESK, fail: 'databases' } });
    try {
      const job = await discover();
      expect(job.state).toBe('completed');
      expect(job.result?.discoverers).toEqual(['docker-host']);
      expect(job.result?.warnings).toEqual([
        "plesk: No se pudo leer Plesk: plesk db (databases) falló (código 1): ERROR 1054 (42S22) at line 1: Unknown column 'x'",
      ]);
      const missing = await db.query<{ n: number }[]>(
        `SELECT count(*)::int AS n FROM assets WHERE status = 'missing'`,
      );
      expect(missing[0]!.n).toBe(0);
    } finally {
      pve.setState(STATE);
    }
  });

  it('sudoers v3 (sin el ayudante de root): desactualizado; lo que sudo no deja listar no se marca como missing', async () => {
    pve.setState({
      ...STATE,
      collectSudoersVersion: 3,
      hostDocker: { ...STATE.hostDocker, denyUnusedListing: true },
    });
    try {
      await collect();
      const asset = await get<Asset>(`/assets/${server.id}`);
      const meta = (asset.facts as unknown as CollectedFacts).infraward;
      expect(meta.sudoersOutdated).toBe(true);
      expect(meta.warnings).toEqual([
        'sudoers desactualizado (v3, hace falta v4): genera un comando de actualización',
      ]);
      // Solo las notas de la v5 (rutas de los proxies), la v6 (procesos) y la v7 (sshd): no
      // desactualizan.
      expect(meta.sudoersNotes).toEqual([
        expect.stringContaining('requiere sudoers v5'),
        expect.stringContaining('requiere sudoers v6'),
        expect.stringContaining('requiere sudoers v7'),
      ]);
      // El descubrimiento que encadena la recolección no ve `huerfano` ni `sin-uso`: no son missing.
      const left = await db.query<{ name: string; status: string }[]>(
        `SELECT name, status FROM assets WHERE name IN ('huerfano', 'sin-uso') ORDER BY name`,
      );
      expect(left).toEqual([
        { name: 'huerfano', status: 'active' },
        { name: 'sin-uso', status: 'active' },
      ]);
    } finally {
      pve.setState(STATE);
      await collect();
    }
  });

  it('nunca se guardan contraseñas de Plesk ni opciones de volúmenes (facts, snapshots, respuestas, logs)', async () => {
    const dump = JSON.stringify(
      await db.query(
        `SELECT (SELECT json_agg(facts) FROM assets) AS facts,
                (SELECT json_agg(facts) FROM snapshots) AS snapshots,
                (SELECT json_agg(r) FROM job_runs r) AS runs`,
      ),
    );
    const everything = [dump, ...responses, worker?.output.join('') ?? ''].join('\n');
    for (const secret of ['centinela-plesk', 'centinela-volumen', 'PRIVATE KEY', 'BEGIN CERTIFICATE', 'passwd'])
      expect(everything).not.toContain(secret);
  });
});
