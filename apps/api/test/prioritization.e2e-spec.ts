import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  JOB_NAMES,
  QUEUE_NAMES,
  type Asset,
  type AssetTreeSummaryNode,
  type AssetVulnerabilitiesPage,
  type EnqueueJobResponse,
  type EnrollServerResponse,
  type IntelStatus,
  type JobStatus,
  type Notification,
  type Page,
  type VulnerabilitiesPage,
  type VulnerabilityDetail,
  type VulnerabilityIntelJobResult,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
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
  type FakeVuln,
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  waitPrioritized,
  type TestWorker, WORK_QUEUES } from './support/worker.js';

const VIEWER = {
  email: 'viewer-prio@infraward.test',
  password: 'otra-contraseña-larga',
};

const KERNEL_RUNNING = 'proxmox-kernel-7.0.2-6-pve-signed';
const KERNEL_OLD = 'proxmox-kernel-6.14.8-2-pve-signed';

/** El servidor: kernel 7.0.2-6-pve (el de los facts), sshd en el 22 con openssl cargado. */
const VULNS: FakeVuln[] = [
  // Crítico, en KEV, de una librería que carga sshd (expuesto en 0.0.0.0:22): urgente y aviso.
  {
    id: 'CVE-2026-7001',
    pkg: 'openssl',
    version: '3.5.1-1',
    fixed: '3.5.1-2',
    severity: 'CRITICAL',
    cvss: 9.8,
  },
  // Otro kernel instalado: ruido.
  {
    id: 'CVE-2026-7002',
    pkg: KERNEL_OLD,
    version: '6.14.8-2',
    severity: 'HIGH',
    cvss: 7.8,
  },
  // Cabeceras de la fuente del kernel: ruido.
  {
    id: 'CVE-2026-7003',
    pkg: 'linux-libc-dev',
    version: '6.12.38-1',
    severity: 'HIGH',
    cvss: 7.8,
  },
  // La distribución no lo corregirá: ruido.
  {
    id: 'CVE-2026-7004',
    pkg: 'bash',
    version: '5.2.37-2',
    severity: 'HIGH',
    cvss: 7.5,
    status: 'will_not_fix',
  },
  // El kernel en ejecución: se queda (sin parche, prioridad media).
  {
    id: 'CVE-2026-7005',
    pkg: KERNEL_RUNNING,
    version: '7.0.2-6',
    severity: 'HIGH',
    cvss: 7.8,
  },
  // MEDIUM sin contexto: prioridad baja.
  {
    id: 'CVE-2026-7006',
    pkg: 'bash',
    version: '5.2.37-2',
    severity: 'MEDIUM',
    cvss: 5.5,
  },
];

const KEV = JSON.stringify({
  catalogVersion: '2026.10.18',
  dateReleased: '2026-10-18T14:00:00.000Z',
  vulnerabilities: [
    {
      cveID: 'CVE-2026-7001',
      vulnerabilityName: 'OpenSSL de prueba',
      dateAdded: '2026-10-18',
      dueDate: '2026-11-08',
      knownRansomwareCampaignUse: 'Known',
    },
    {
      cveID: 'CVE-2026-9999',
      vulnerabilityName: 'Fuera del inventario',
      dateAdded: '2026-10-01',
    },
  ],
});
const EPSS = gzipSync(
  '#model_version:v2025.03.14,score_date:2026-10-18T00:00:00+0000\ncve,epss,percentile\nCVE-2026-7001,0.92,0.999\nCVE-2026-7005,0.02,0.6\n',
);

/** KEV y EPSS falsos, con ETag (304) y modos de fallo. */
function intelServer() {
  const hits: {
    path: string;
    ifNoneMatch: string | undefined;
    status: number;
  }[] = [];
  let mode: 'ok' | 'fail' | 'broken' = 'ok';
  const server: Server = createServer((req, res) => {
    const kev = req.url === '/kev.json';
    const etag = kev ? '"kev-1"' : '"epss-1"';
    const ifNoneMatch = req.headers['if-none-match'];
    let status = 200;
    if (mode === 'fail') status = 503;
    else if (ifNoneMatch === etag) status = 304;
    hits.push({ path: req.url ?? '', ifNoneMatch, status });
    if (status !== 200) {
      res
        .writeHead(status)
        .end(status === 503 ? 'centinela-cuerpo' : undefined);
      return;
    }
    res.writeHead(200, { etag, 'content-type': 'application/octet-stream' });
    res.end(kev ? KEV : mode === 'broken' ? EPSS.subarray(0, 20) : EPSS);
  });
  return {
    server,
    hits,
    setMode: (m: typeof mode) => (mode = m),
    url: (path: string) =>
      `http://127.0.0.1:${(server.address() as AddressInfo).port}${path}`,
  };
}

/**
 * Priorización (DESIGN §9, sesión 19) con el worker real, PostgreSQL, Redis, un servidor
 * simulado y KEV/EPSS falsos: descarga con caché y fallos que conservan los datos, ruido (kernel
 * no en uso, sin corrección prevista), prioridad explicable con contexto de procesos (sudoers v6),
 * filtros y el aviso inmediato de un crítico en KEV y expuesto, una sola vez.
 */
describe('Priorización de vulnerabilidades (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  let intel: ReturnType<typeof intelServer>;
  let adminToken: string;
  let viewerToken: string;
  let node: Asset;

  beforeAll(async () => {
    await prepareEnv('e2e_prio');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);

    intel = intelServer();
    await new Promise<void>((resolve) =>
      intel.server.listen(0, '127.0.0.1', resolve),
    );

    pve = createFakePve();
    pve.setState({
      node: 'pve',
      cluster: null,
      machineId: 'a'.repeat(32),
      ctMachineId: 'c'.repeat(32),
      guests: [],
      collectSudoersVersion: 6,
      processes: 'P\t1\tsshd\tssh.service\topenssh-server\topenssl,libc6\n',
      packages: {
        node: [
          { name: 'openssl', version: '3.5.1-1' },
          { name: 'bash', version: '5.2.37-2' },
          { name: KERNEL_RUNNING, version: '7.0.2-6' },
          { name: KERNEL_OLD, version: '6.14.8-2' },
          { name: 'linux-libc-dev', version: '6.12.38-1' },
        ],
      },
      hostVulns: VULNS,
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
    worker = await startWorker({
      ...pve.workerEnv(),
      KEV_URL: intel.url('/kev.json'),
      EPSS_URL: intel.url('/epss.csv.gz'),
    });
    // Recolección (facts con los procesos) y, encadenado, el SBOM del servidor con sus findings.
    const collect = await request('POST', `/assets/${node.id}/collect`);
    expect((await finished(collect.json<EnqueueJobResponse>().id)).state).toBe(
      'completed',
    );
    await settle();
    await waitPrioritized(db);
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
    await new Promise((resolve) => intel?.server.close(resolve));
  });

  async function request(
    method: 'GET' | 'POST',
    url: string,
    payload?: object,
    token = adminToken,
  ) {
    return app.inject({ method, url, payload, headers: authHeaders(token) });
  }
  const get = async <T>(url: string, token = adminToken) => {
    const res = await request('GET', url, undefined, token);
    expect(res.statusCode, res.body).toBe(200);
    return res.json<T>();
  };

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

  async function settle(): Promise<void> {
    const queues = [...WORK_QUEUES, QUEUE_NAMES.system].map((name) => app.get<Queue>(getQueueToken(name)));
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
  }

  /** Descarga sin forzar (como la periódica): usa la caché HTTP. */
  async function intelRun(): Promise<VulnerabilityIntelJobResult> {
    const id = randomUUID();
    await app
      .get<Queue>(getQueueToken(QUEUE_NAMES.system))
      .add(JOB_NAMES.vulnerabilityIntel, {}, { jobId: id });
    const done = await finished<VulnerabilityIntelJobResult>(id);
    expect(done.state, JSON.stringify(done)).toBe('completed');
    return done.result!;
  }

  const kevAlerts = async () =>
    (await get<Page<Notification>>('/notifications?limit=50')).items.filter(
      (n) => n.kind === 'vulnerability_kev',
    );

  it('antes de KEV: ningún aviso; CVSS de Trivy en los findings', async () => {
    expect(await kevAlerts()).toEqual([]);
    const [row] = await db.query<{ cvss: number }[]>(
      `SELECT cvss_score AS cvss FROM findings WHERE vulnerability_id = 'CVE-2026-7001'`,
    );
    expect(row!.cvss).toBeCloseTo(9.8);
  });

  it('KEV y EPSS: descarga a mano (viewer no puede), estado y caché HTTP', async () => {
    expect(
      (await request('POST', '/vulnerabilities/intel/refresh', {}, viewerToken))
        .statusCode,
    ).toBe(403);
    const res = await request('POST', '/vulnerabilities/intel/refresh');
    expect(res.statusCode).toBe(202);
    const done = await finished<VulnerabilityIntelJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(done.result?.feeds).toEqual([
      { source: 'kev', outcome: 'updated', records: 2 },
      { source: 'epss', outcome: 'updated', records: 2 },
    ]);
    const status = await get<IntelStatus>(
      '/vulnerabilities/intel',
      viewerToken,
    );
    expect(status.feeds).toEqual([
      expect.objectContaining({
        source: 'kev',
        enabled: true,
        version: '2026.10.18',
        recordCount: 2,
        lastError: null,
        stale: false,
      }),
      expect.objectContaining({
        source: 'epss',
        enabled: true,
        version: '2026-10-18',
        recordCount: 2,
        lastError: null,
        stale: false,
      }),
    ]);
    // Sin forzar: If-None-Match con el ETag guardado y un 304 que no descarga nada.
    const again = await intelRun();
    expect(again.feeds.map((f) => f.outcome)).toEqual([
      'not_modified',
      'not_modified',
    ]);
    expect(intel.hits.slice(-2)).toEqual([
      { path: '/kev.json', ifNoneMatch: '"kev-1"', status: 304 },
      { path: '/epss.csv.gz', ifNoneMatch: '"epss-1"', status: 304 },
    ]);
    await settle();
    await waitPrioritized(db);
  });

  it('aviso inmediato: crítico, en KEV y expuesto; una sola vez', async () => {
    let alerts: Notification[] = [];
    await waitFor(
      async () => (alerts = await kevAlerts()).length > 0,
      20_000,
      () => `sin aviso de KEV\n${worker?.output.join('')}`,
    );
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      assetId: node.id,
      total: 1,
      items: [
        {
          id: 'CVE-2026-7001',
          type: 'vulnerability',
          name: 'CVE-2026-7001 (openssl)',
        },
      ],
    });
    expect(alerts[0]!.message).toContain('KEV');
    // Otra descarga forzada (datos iguales) y otra pasada de prioridad: no se repite.
    await finished(
      (
        await request('POST', '/vulnerabilities/intel/refresh')
      ).json<EnqueueJobResponse>().id,
    );
    await settle();
    await waitPrioritized(db);
    expect(await kevAlerts()).toHaveLength(1);
  });

  it('vista principal: por prioridad, sin ruido, con el porqué y lo oculto con su motivo', async () => {
    const page = await get<VulnerabilitiesPage>(
      '/vulnerabilities?status=open&inUse=true&minPriority=medium',
      viewerToken,
    );
    expect(page.items.map((v) => v.vulnerabilityId)).toEqual([
      'CVE-2026-7001',
      'CVE-2026-7005',
    ]);
    const top = page.items[0]!;
    expect(top).toMatchObject({
      kev: true,
      epss: expect.closeTo(0.92, 3),
      cvss: expect.closeTo(9.8, 3),
    });
    expect(top.priority).toMatchObject({ score: 100, band: 'urgent' });
    expect(top.priority!.reasons.map((r) => r.code)).toEqual([
      'kev',
      'epss',
      'port',
      'service',
      'fix',
      'cvss',
    ]);
    expect(top.priority!.reasons[2]).toEqual({
      code: 'port',
      ports: [22],
      process: 'sshd',
    });
    expect(top.priority!.reasons[3]).toEqual({
      code: 'service',
      process: 'sshd',
      unit: 'ssh.service',
      via: 'lib',
    });
    expect(page.items[1]!.priority?.band).toBe('medium');
    expect(page.hidden).toEqual({
      kernel_not_running: 2,
      no_fix_planned: 1,
      low_priority: 1,
    });

    // Cada motivo abre lo suyo.
    const kernel = await get<VulnerabilitiesPage>(
      '/vulnerabilities?status=open&hidden=kernel_not_running',
    );
    expect(kernel.items.map((v) => v.vulnerabilityId).sort()).toEqual([
      'CVE-2026-7002',
      'CVE-2026-7003',
    ]);
    expect(kernel.hidden).toBeNull();
    const reasons = (
      await get<AssetVulnerabilitiesPage>(
        `/assets/${node.id}/vulnerabilities?limit=50`,
      )
    ).items;
    const old = reasons.find((g) => g.vulnerabilityId === 'CVE-2026-7002');
    expect(old?.noiseReason).toBe('kernel_not_running');
    expect(old?.priority?.reasons[0]).toEqual({
      code: 'kernel_other',
      running: '7.0.2-6-pve',
    });
    expect(
      reasons.find((g) => g.vulnerabilityId === 'CVE-2026-7003')?.priority
        ?.reasons[0],
    ).toEqual({
      code: 'kernel_aux',
    });
    const wontFix = reasons.find((g) => g.vulnerabilityId === 'CVE-2026-7004');
    expect(wontFix?.noiseReason).toBe('no_fix_planned');
    expect(wontFix?.priority?.reasons[0]).toEqual({
      code: 'no_fix_planned',
      fixStatus: 'will_not_fix',
    });
    const nofix = await get<VulnerabilitiesPage>(
      '/vulnerabilities?status=open&hidden=no_fix_planned',
    );
    expect(nofix.items.map((v) => v.vulnerabilityId)).toEqual([
      'CVE-2026-7004',
    ]);
    const low = await get<VulnerabilitiesPage>(
      '/vulnerabilities?status=open&hidden=low_priority&minPriority=medium',
    );
    expect(low.items.map((v) => v.vulnerabilityId)).toEqual(['CVE-2026-7006']);
  });

  it('kernels que no corren: fuera de los recuentos del resumen y, con includeNoise=false, de la ficha', async () => {
    const tree = await get<AssetTreeSummaryNode[]>('/assets/tree', viewerToken);
    const find = (nodes: AssetTreeSummaryNode[]): AssetTreeSummaryNode | undefined =>
      nodes.map((n) => (n.id === node.id ? n : find(n.children))).find(Boolean);
    // 7002 (otro kernel) y 7003 (linux-libc-dev) no cuentan: van aparte.
    expect(find(tree)).toMatchObject({
      openFindings: { CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 0 },
      fixableFindings: { CRITICAL: 1, HIGH: 0 },
      kernelNotRunningFindings: 2,
    });

    // La ficha, por defecto (sin el parámetro), como antes: con el ruido marcado.
    const all = await get<AssetVulnerabilitiesPage>(
      `/assets/${node.id}/vulnerabilities?status=open&limit=50`,
    );
    expect(all.total).toBe(6);
    expect(all.hidden ?? null).toBeNull();
    // La web pide sin el ruido y enseña lo que queda fuera.
    const clean = await get<AssetVulnerabilitiesPage>(
      `/assets/${node.id}/vulnerabilities?status=open&includeNoise=false&minPriority=medium&limit=50`,
      viewerToken,
    );
    expect(clean.items.map((g) => g.vulnerabilityId)).toEqual([
      'CVE-2026-7001',
      'CVE-2026-7005',
    ]);
    expect(clean.hidden).toEqual({ kernel_not_running: 2, no_fix_planned: 1 });
  });

  it('filtros: KEV, EPSS, expuestas, prioridad en la búsqueda y orden por severidad', async () => {
    const ids = async (query: string) =>
      (
        await get<VulnerabilitiesPage>(`/vulnerabilities?status=open&${query}`)
      ).items.map((v) => v.vulnerabilityId);
    expect(await ids('kev=true')).toEqual(['CVE-2026-7001']);
    expect(await ids('minEpss=0.5')).toEqual(['CVE-2026-7001']);
    expect(await ids('minEpss=0.01')).toEqual([
      'CVE-2026-7001',
      'CVE-2026-7005',
    ]);
    expect(await ids('exposure=any')).toEqual(['CVE-2026-7001']);
    expect(await ids(`q=${encodeURIComponent('prioridad:urgente')}`)).toEqual([
      'CVE-2026-7001',
    ]);
    expect(
      await ids(`q=${encodeURIComponent('-prioridad:urgente prioridad:baja')}`),
    ).toEqual(['CVE-2026-7006']);
    expect(await ids('includeNoise=true&sort=severity')).toEqual([
      'CVE-2026-7001',
      'CVE-2026-7005',
      'CVE-2026-7002',
      'CVE-2026-7003',
      'CVE-2026-7004',
      'CVE-2026-7006',
    ]);
    expect(
      (await request('GET', '/vulnerabilities?minEpss=2')).statusCode,
    ).toBe(400);
    expect(
      (await request('GET', '/vulnerabilities?hidden=otra')).statusCode,
    ).toBe(400);
  });

  it('ficha del CVE: KEV, EPSS y la prioridad con su porqué', async () => {
    const d = await get<VulnerabilityDetail>(
      '/vulnerabilities/CVE-2026-7001',
      viewerToken,
    );
    expect(d.enrichment).toEqual({
      kev: {
        added: '2026-10-18',
        due: '2026-11-08',
        ransomware: true,
        name: 'OpenSSL de prueba',
      },
      epss: {
        score: expect.closeTo(0.92, 3),
        percentile: expect.closeTo(0.999, 3),
      },
    });
    expect(d.priority?.score).toBe(100);
    expect(d.tree[0]).toMatchObject({
      name: 'pve',
      priority: { score: 100, band: 'urgent' },
    });
    const none = await get<VulnerabilityDetail>(
      '/vulnerabilities/CVE-2026-7006',
    );
    expect(none.enrichment).toEqual({ kev: null, epss: null });
  });

  it('un fallo de red o un fichero roto conserva los datos y lo dice', async () => {
    intel.setMode('fail');
    const failed = await intelRun();
    expect(failed.feeds).toEqual([
      { source: 'kev', outcome: 'failed', error: 'HTTP 503' },
      { source: 'epss', outcome: 'failed', error: 'HTTP 503' },
    ]);
    let status = await get<IntelStatus>('/vulnerabilities/intel');
    expect(status.feeds[0]).toMatchObject({
      version: '2026.10.18',
      recordCount: 2,
      lastError: 'HTTP 503',
    });
    expect(status.feeds[0]!.lastErrorAt).not.toBeNull();
    expect(JSON.stringify(status)).not.toContain('centinela');
    // Siguen en KEV.
    expect(
      (await get<VulnerabilitiesPage>('/vulnerabilities?kev=true')).total,
    ).toBe(1);

    intel.setMode('broken');
    // Forzado: sin caché HTTP (el KEV se vuelve a leer igual; el EPSS llega roto).
    const res = await request('POST', '/vulnerabilities/intel/refresh');
    const broken = await finished<VulnerabilityIntelJobResult>(
      res.json<EnqueueJobResponse>().id,
    );
    expect(broken.result?.feeds[1]).toEqual({
      source: 'epss',
      outcome: 'failed',
      error: 'el fichero de EPSS no se pudo descomprimir',
    });
    status = await get<IntelStatus>('/vulnerabilities/intel');
    expect(status.feeds[0]!.lastError).toBeNull();
    expect(status.feeds[1]).toMatchObject({
      version: '2026-10-18',
      recordCount: 2,
    });
    expect(
      (await get<VulnerabilitiesPage>('/vulnerabilities?minEpss=0.5')).total,
    ).toBe(1);
    intel.setMode('ok');
  });

  it('panel: lo prioritario con su porqué', async () => {
    const dash = await get<{
      vulnerabilities: {
        urgent: number;
        kev: number;
        cves: number;
        top: { vulnerabilityId: string }[];
      };
    }>('/dashboard', viewerToken);
    expect(dash.vulnerabilities).toMatchObject({ urgent: 1, kev: 1, cves: 2 });
    expect(dash.vulnerabilities.top.map((v) => v.vulnerabilityId)).toEqual([
      'CVE-2026-7001',
      'CVE-2026-7005',
    ]);
  });
});
