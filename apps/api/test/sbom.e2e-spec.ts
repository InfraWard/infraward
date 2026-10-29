import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  Asset,
  AssetCollectJobResult,
  AssetFindingsPage,
  AssetPackagesPage,
  AssetTreeSummaryNode,
  EnqueueJobResponse,
  EnrollServerResponse,
  HostScanJobResult,
  JobRunSummary,
  JobStatus,
  Page,
  IntelStatus,
  SbomReevaluateJobResult,
  ScanAssetResponse,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { readdirSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
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
  type FakePve,
  type FakePveState,
  type FakeVuln,
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker, WORK_QUEUES } from './support/worker.js';

const VIEWER = {
  email: 'viewer-sbom@infraward.test',
  password: 'otra-contraseña-larga',
};
const NGINX = `sha256:${'1'.repeat(64)}`;

const OPENSSL: FakeVuln = {
  id: 'CVE-2026-0001',
  pkg: 'openssl',
  version: '3.5.1-1',
  fixed: '3.5.1-2',
  severity: 'HIGH',
};
const SSH_CVE: FakeVuln = {
  id: 'CVE-2024-6387',
  pkg: 'openssh-client',
  version: '1:9.2p1-2',
  fixed: '1:9.2p1-2+deb12u3',
  severity: 'HIGH',
};
const ABSL_CVE: FakeVuln = {
  id: 'CVE-2025-0838',
  pkg: 'libabsl20220623',
  version: '20220623.1-1',
  severity: 'CRITICAL',
};

/**
 * SBOMs de punta a punta (DESIGN §5, §9) con el worker real, PostgreSQL y Redis, y un nodo Proxmox
 * simulado: SBOM del nodo y de sus CT (copia de dpkg con `cat`, `trivy rootfs`), SBOM de una
 * imagen (`docker save`, `trivy image`), paquetes, re-evaluación sin conectarse a ninguna
 * máquina con la transición open → fixed → open, y relleno de imágenes escaneadas sin SBOM.
 */
// Un escaneo con el host ocupado se aplaza 20-40 s (HostBusy): esperas de 60 s y tests de 120 s.
describe('SBOMs y re-evaluación (e2e)', { timeout: 120_000 }, () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let adminToken: string;
  let viewerToken: string;
  const responses: string[] = [];
  let privateKey: string;
  let node: Asset;
  let state: FakePveState;
  let ctDocker: AssetTreeSummaryNode;
  let ctPlain: AssetTreeSummaryNode;
  let imageId: string;

  beforeAll(async () => {
    await prepareEnv('e2e_sbom');
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
          containers: [
            {
              name: 'web1',
              image: 'nginx:1.25',
              imageId: NGINX,
              state: 'running',
            },
          ],
        },
        {
          type: 'lxc',
          vmid: 101,
          node: 'pve',
          name: 'sin-dpkg',
          status: 'running',
        },
      ],
      packages: {
        node: [
          { name: 'bash', version: '5.2.37-2' },
          { name: 'openssl', version: '3.5.1-1' },
        ],
        '101': null,
      },
      hostVulns: [OPENSSL],
      vulns: { [NGINX]: [SSH_CVE] },
    };
    pve.setState(state);

    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name: 'pve',
    });
    expect(res.statusCode).toBe(201);
    node = res.json<EnrollServerResponse>().asset;
    privateKey = await app
      .get(SecretsService)
      .resolve(node.credentials.sshPrivateKey!);
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [node.id, pve.fingerprint],
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
      60_000,
      () =>
        `job sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    return last as JobStatus & { result?: T };
  }

  /** Espera a que las colas de descubrimiento y escaneo estén vacías. */
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
      // Un escaneo que encuentra ocupado el hueco del host se aplaza 20-40 s (HostBusy).
      60_000,
      () => `colas sin vaciar\n${worker?.output.join('')}`,
    );
    // BullMQ da el job por terminado antes de que el JobRunTracker pase su fila de job_runs a
    // completed: la Actividad y el estado de la re-evaluación (lastRun) se leen de ahí.
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

  async function reevaluate(): Promise<SbomReevaluateJobResult> {
    const res = await request('POST', '/sboms/reevaluate');
    expect(res.statusCode).toBe(202);
    const done = await finished<SbomReevaluateJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.state, JSON.stringify(done)).toBe('completed');
    await settle();
    return done.result!;
  }

  const findings = async (assetId: string) =>
    (
      await request('GET', `/assets/${assetId}/findings?limit=200`)
    ).json<AssetFindingsPage>();

  const statusOf = async (assetId: string, vulnerabilityId: string) =>
    (await findings(assetId)).items.find(
      (f) => f.vulnerabilityId === vulnerabilityId,
    );

  const storedSbom = async (assetId: string): Promise<string> => {
    const [row]: { content: Buffer }[] = await db.query(
      'SELECT content FROM sboms WHERE asset_id = $1',
      [assetId],
    );
    return gunzipSync(row.content).toString('utf8');
  };

  it('recoger el nodo encadena el SBOM del nodo, de sus CT y de la imagen de sus contenedores', async () => {
    worker = await startWorker(pve.workerEnv());
    const res = await request('POST', `/assets/${node.id}/collect`);
    const done = await finished<AssetCollectJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.state).toBe('completed');
    expect(done.result!.hostScanJobId).toEqual(expect.any(String));
    await settle();

    const nodeScan = await finished<HostScanJobResult>(
      done.result!.hostScanJobId!,
    );
    expect(nodeScan.result).toMatchObject({
      status: 'scanned',
      unchanged: false,
      packageCount: 2,
      vulnerabilityCount: 1,
      findingsCreated: 1,
    });

    const tree = (
      await request('GET', `/assets/${node.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    ctDocker = tree.children.find((c) => c.name === 'docker')!;
    ctPlain = tree.children.find((c) => c.name === 'sin-dpkg')!;

    // Paquetes y resumen del SBOM del nodo.
    const packages = (
      await request('GET', `/assets/${node.id}/packages`)
    ).json<AssetPackagesPage>();
    expect(packages.items.map((p) => [p.name, p.version, p.ecosystem])).toEqual(
      [
        ['bash', '5.2.37-2', 'deb'],
        ['openssl', '3.5.1-1', 'deb'],
      ],
    );
    expect(packages.sbom).toMatchObject({
      assetId: node.id,
      source: 'rootfs',
      format: 'cyclonedx',
      os: { family: 'debian', name: '13' },
      packageCount: 2,
      vulnerabilityCount: 1,
      evaluationError: null,
    });
    expect(
      (
        await request('GET', `/assets/${node.id}/packages?q=SSL`)
      ).json<AssetPackagesPage>().items,
    ).toHaveLength(1);
    // Los findings del servidor, en el propio servidor, con el resumen de su SBOM.
    const page = await findings(node.id);
    expect(page.items.map((f) => [f.vulnerabilityId, f.status])).toEqual([
      ['CVE-2026-0001', 'open'],
    ]);
    expect(page.sbom?.packageCount).toBe(2);

    // CT 100 (dpkg por defecto) con SBOM; CT 101 sin BD de paquetes: no escaneado, sin fallo.
    expect(
      (
        await request('GET', `/assets/${ctDocker.id}/packages`)
      ).json<AssetPackagesPage>().sbom?.packageCount,
    ).toBe(2);
    const plainRuns = (
      await request('GET', `/jobs?assetId=${ctPlain.id}&name=host.scan`)
    ).json<Page<JobRunSummary>>().items;
    expect(plainRuns.map((r) => [r.state, r.message])).toEqual([
      [
        'completed',
        'No escaneado: Ninguna BD de paquetes reconocida (dpkg, apk o rpm)',
      ],
    ]);
    expect(
      (await request('GET', `/assets/${ctPlain.id}/sbom`)).statusCode,
    ).toBe(404);

    // La imagen: SBOM y paquetes en el asset `image`; el contenedor llega a ellos.
    const web1 = (
      await request('GET', `/assets/${ctDocker.id}/tree`)
    ).json<AssetTreeSummaryNode>().children[0];
    const viaContainer = (
      await request('GET', `/assets/${web1.id}/packages`)
    ).json<AssetPackagesPage>();
    expect(viaContainer.sbom).toMatchObject({ source: 'docker_save' });
    expect(viaContainer.items.map((p) => p.name)).toEqual(['openssh-client']);
    imageId = viaContainer.sbom!.assetId;
    expect(imageId).not.toBe(web1.id);
  });

  it('solo se lee sin sudo (o por pct-exec en un CT) y solo los ficheros de la lista', () => {
    const reads = pve
      .sshCommands()
      .filter((c) => /^(sudo -n \S+ pct-exec \d+ )?(ls|cat) /.test(c));
    expect(reads).toContain('cat -- /var/lib/dpkg/status');
    expect(reads).toContain(
      'sudo -n /usr/local/libexec/infraward/infraward-query pct-exec 100 cat -- /var/lib/dpkg/status',
    );
    for (const c of reads)
      expect(c).toMatch(
        /^(sudo -n \/usr\/local\/libexec\/infraward\/infraward-query pct-exec \d+ )?(ls -1d -- |cat -- \/(etc\/os-release|var\/lib\/dpkg\/status)$)/,
      );
    expect(
      pve.sshCommands().some((c) => c.startsWith('cat -- /etc/shadow')),
    ).toBe(false);
  });

  it('el SBOM guardado no lleva las etiquetas de la imagen y se descarga tal cual', async () => {
    const stored = await storedSbom(imageId);
    expect(stored).toContain('pkg:deb/debian/openssh-client@1:9.2p1-2');
    expect(stored).not.toContain('centinela-etiqueta');
    expect(stored).not.toContain('Labels');
    const res = await request('GET', `/assets/${imageId}/sbom`);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain(
      'application/vnd.cyclonedx+json',
    );
    expect(res.body).toBe(stored);
  });

  it('re-evaluación sin conectarse: lo que la BD de Trivy deja de ver pasa a fixed, lo nuevo se abre y lo que vuelve se reabre', async () => {
    const ssh = pve.sshCommands().length;
    const ansible = pve.ansibleRuns().length;
    const analyses = pve.trivyScans().length + pve.trivyRootfs().length;

    // La BD de Trivy «cambia»: openssl ya no es vulnerable y en la imagen aparece otro CVE (los
    // paquetes no cambian: el SBOM guardado es el mismo).
    pve.setState({
      ...state,
      hostVulns: [],
      vulns: {
        [NGINX]: [
          SSH_CVE,
          { ...ABSL_CVE, pkg: 'openssh-client', version: '1:9.2p1-2' },
        ],
      },
    });
    const first = await reevaluate();
    expect(first).toMatchObject({
      sboms: 3, // nodo, CT 100 e imagen (el CT 101 no tiene)
      evaluated: 3,
      failed: 0,
      findingsCreated: 1,
      findingsFixed: 2, // openssl en el nodo y en el CT 100
      dbUpdateError: null,
      backfillQueued: 0,
    });
    const fixed = await statusOf(node.id, 'CVE-2026-0001');
    expect(fixed).toMatchObject({ status: 'fixed' });
    expect(fixed!.fixedAt).not.toBeNull();
    expect((await statusOf(imageId, 'CVE-2025-0838'))?.status).toBe('open');
    expect((await statusOf(imageId, 'CVE-2024-6387'))?.status).toBe('open');

    // Vuelve a aparecer: se reabre el mismo finding (sin duplicar).
    pve.setState(state);
    const second = await reevaluate();
    expect(second).toMatchObject({ evaluated: 3, findingsCreated: 0 });
    const reopened = await statusOf(node.id, 'CVE-2026-0001');
    expect(reopened).toMatchObject({
      id: fixed!.id,
      status: 'open',
      fixedAt: null,
    });
    expect((await statusOf(imageId, 'CVE-2025-0838'))?.status).toBe('fixed');

    // Ni SSH, ni Ansible, ni análisis nuevos: solo `trivy sbom` sobre lo guardado.
    expect(pve.sshCommands()).toHaveLength(ssh);
    expect(pve.ansibleRuns()).toHaveLength(ansible);
    expect(pve.trivyScans().length + pve.trivyRootfs().length).toBe(analyses);
    expect(pve.trivyEvaluations().length).toBeGreaterThanOrEqual(6);
    const sbom = (
      await request('GET', `/assets/${node.id}/packages`)
    ).json<AssetPackagesPage>().sbom!;
    expect(sbom.evaluatedAt).not.toBeNull();
    expect(sbom.dbUpdatedAt).toBe('2026-10-09T19:06:47.000Z');
  });

  it('volver a escanear un servidor sin cambios no lo re-evalúa; con otro paquete, reemplaza el SBOM', async () => {
    const res = await request('POST', `/assets/${node.id}/scan`);
    expect(res.statusCode).toBe(202);
    const { jobs } = res.json<ScanAssetResponse>();
    expect(jobs.map((j) => j.name)).toEqual(['host.scan']);
    const same = await finished<HostScanJobResult>(jobs[0].id);
    expect(same.result).toMatchObject({ unchanged: true, cached: true });

    pve.setState({
      ...state,
      packages: {
        ...state.packages,
        node: [
          { name: 'bash', version: '5.2.37-2' },
          { name: 'openssl', version: '3.5.1-2' },
        ],
      },
    });
    const again = await request('POST', `/assets/${node.id}/scan`);
    const patched = await finished<HostScanJobResult>(
      again.json<ScanAssetResponse>().jobs[0].id,
    );
    expect(patched.result).toMatchObject({
      unchanged: false,
      cached: false,
      findingsFixed: 1,
    });
    expect((await statusOf(node.id, 'CVE-2026-0001'))?.status).toBe('fixed');
    const packages = (
      await request('GET', `/assets/${node.id}/packages`)
    ).json<AssetPackagesPage>();
    expect(packages.items.map((p) => p.version)).toEqual([
      '5.2.37-2',
      '3.5.1-2',
    ]);
    pve.setState(state);
  });

  it('relleno: una imagen escaneada sin SBOM se vuelve a escanear una vez; si falla, no se reintenta sola', async () => {
    await db.query('DELETE FROM sboms WHERE asset_id = $1', [imageId]);
    const saves = () =>
      pve.sshCommands().filter((c) => c.includes(`docker save ${NGINX}`))
        .length;
    const before = saves();
    const ok = await reevaluate();
    expect(ok).toMatchObject({ sboms: 2, backfillQueued: 1 });
    expect(saves()).toBe(before + 1);
    expect(
      (
        await request('GET', `/assets/${imageId}/packages`)
      ).json<AssetPackagesPage>().sbom,
    ).not.toBeNull();
    // El registro de job_runs lo actualiza el worker después de que BullMQ dé el job por
    // terminado: con las colas ya vacías puede seguir en `active` un instante. Se espera al
    // estado final en lugar de leer el intermedio.
    let backfill: JobRunSummary | undefined;
    await waitFor(
      async () => {
        backfill = (
          await request('GET', `/jobs?assetId=${imageId}&name=image.scan`)
        ).json<Page<JobRunSummary>>().items[0];
        return backfill?.state === 'completed' || backfill?.state === 'failed';
      },
      60_000,
      () => `relleno sin terminar: ${JSON.stringify(backfill)}`,
    );
    expect(backfill!.state).toBe('completed');

    // El host ya no tiene la imagen: el relleno falla, se anota y la siguiente re-evaluación no
    // lo vuelve a intentar.
    await db.query('DELETE FROM sboms WHERE asset_id = $1', [imageId]);
    pve.setState({
      ...state,
      guests: state.guests.map((g) =>
        g.vmid === 100 ? { ...g, containers: [] } : g,
      ),
    });
    expect(await reevaluate()).toMatchObject({ backfillQueued: 1 });
    expect(saves()).toBe(before + 2);
    const [image]: { scan_status: string; failed: Date | null }[] =
      await db.query(
        `SELECT scan_status, sbom_backfill_failed_at AS failed FROM container_images WHERE asset_id = $1`,
        [imageId],
      );
    expect(image.scan_status).toBe('scanned');
    expect(image.failed).not.toBeNull();
    expect(await reevaluate()).toMatchObject({ backfillQueued: 0 });
    expect(saves()).toBe(before + 2);
    pve.setState(state);
  });

  it('Vulnerabilidades: fecha de la BD de Trivy y re-evaluación con descarga forzada de la BD', async () => {
    const status = async () =>
      (await request('GET', '/vulnerabilities/intel')).json<IntelStatus>().trivy;
    expect(await status()).toMatchObject({
      // UpdatedAt del metadata.json que deja el Trivy falso.
      dbUpdatedAt: '2026-10-09T19:06:47.000Z',
      sboms: expect.any(Number),
      lastRun: { state: 'completed', error: null },
    });
    // Sin downloadDb, la BD aún fresca no se vuelve a descargar.
    const before = pve.trivyDownloads().length;
    await reevaluate();
    expect(pve.trivyDownloads()).toHaveLength(before);
    // Con downloadDb, se descarga aunque no haya caducado.
    const res = await request('POST', '/sboms/reevaluate', { downloadDb: true });
    expect(res.statusCode).toBe(202);
    const done = await finished<SbomReevaluateJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.state).toBe('completed');
    // Las dos BDs: la de vulnerabilidades y la de Java.
    expect(pve.trivyDownloads()).toHaveLength(before + 2);
    await settle();
    const after = await status();
    expect(after.lastRun).toMatchObject({
      jobId: done.id,
      state: 'completed',
      message: expect.stringContaining('SBOMs evaluados'),
    });
    const [audit]: { details: Record<string, unknown> }[] = await db.query(
      `SELECT details FROM audit_events WHERE action = 'vulnerabilities.reevaluate_requested'
        ORDER BY occurred_at DESC LIMIT 1`,
    );
    expect(audit!.details).toMatchObject({ jobId: done.id, downloadDb: true });
    expect(
      (await request('POST', '/sboms/reevaluate', { downloadDb: 'sí' })).statusCode,
    ).toBe(400);
  });

  it('permisos: re-evaluar y escanear solo admin; leer, cualquiera autenticado', async () => {
    expect(
      (await request('POST', '/sboms/reevaluate', undefined, viewerToken))
        .statusCode,
    ).toBe(403);
    expect(
      (await request('POST', `/assets/${node.id}/scan`, undefined, viewerToken))
        .statusCode,
    ).toBe(403);
    expect(
      (await request('GET', `/assets/${node.id}/packages`, undefined, null))
        .statusCode,
    ).toBe(401);
    expect(
      (
        await request(
          'GET',
          `/assets/${node.id}/packages`,
          undefined,
          viewerToken,
        )
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await request(
          'GET',
          '/assets/00000000-0000-4000-8000-000000000000/packages',
        )
      ).statusCode,
    ).toBe(404);
    expect(
      (await request('GET', `/assets/${node.id}/packages?ecosystem=$(id)`))
        .statusCode,
    ).toBe(400);
  });

  it('OpenAPI documenta los endpoints de SBOM', async () => {
    const spec = (await request('GET', '/openapi.json', undefined, null)).json<{
      paths: Record<string, unknown>;
    }>();
    expect(Object.keys(spec.paths)).toEqual(
      expect.arrayContaining([
        '/assets/{id}/packages',
        '/assets/{id}/sbom',
        '/sboms/reevaluate',
      ]),
    );
  });

  it('sin fugas: ni la clave, ni ficheros ajenos, ni etiquetas en respuestas, logs, BD o disco', async () => {
    await settle();
    const keyLine = privateKey.split('\n')[1];
    const haystacks = [
      responses.join('\n'),
      worker?.output.join('') ?? '',
      ...(
        (await db.query(`SELECT content FROM sboms`)) as { content: Buffer }[]
      ).map((r) => gunzipSync(r.content).toString('utf8')),
      JSON.stringify(await db.query('SELECT * FROM packages')),
      JSON.stringify(await db.query('SELECT * FROM job_runs')),
    ];
    for (const text of haystacks) {
      expect(text).not.toContain(keyLine);
      expect(text).not.toContain('centinela-shadow');
      expect(text).not.toContain('centinela-etiqueta');
    }
    // Cada réplica trabaja en su subdirectorio (DESIGN §20): solo puede quedar el suyo, vacío.
    expect(
      readdirSync(pve.scanDir, { recursive: true }).filter(
        (entry) => !/^worker-\d+$/.test(String(entry)),
      ),
    ).toEqual([]);
  });
});
