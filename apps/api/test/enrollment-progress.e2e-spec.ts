import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  AssetFindingsPage,
  AssetTreeSummaryNode,
  EnrollServerResponse,
  EnrollmentProgress,
  IssuedEnrollment,
} from '@infraward/shared-types';
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
} from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
} from './support/worker.js';

const VIEWER = {
  email: 'viewer-progress@infraward.test',
  password: 'otra-contraseña-larga',
};

const NGINX = `sha256:${'1'.repeat(64)}`;
const OTHER_FP = `SHA256:${'Z'.repeat(43)}`;

/** Lector de un flujo SSE real (la API escuchando en un puerto) con fetch. */
class SseReader {
  readonly events: { type: string; data: string }[] = [];
  readonly raw: string[] = [];
  private readonly controller = new AbortController();
  private done: Promise<void> = Promise.resolve();
  status = 0;
  contentType = '';

  async open(url: string, token: string | null): Promise<void> {
    const res = await fetch(url, {
      headers: token ? authHeaders(token) : {},
      signal: this.controller.signal,
    });
    this.status = res.status;
    this.contentType = res.headers.get('content-type') ?? '';
    if (!res.ok || !res.body) {
      this.raw.push(await res.text());
      return;
    }
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    this.done = (async () => {
      let buffer = '';
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) return;
          this.raw.push(value);
          buffer += value;
          let end: number;
          while ((end = buffer.indexOf('\n\n')) >= 0) {
            const block = buffer.slice(0, end);
            buffer = buffer.slice(end + 2);
            let type = 'message';
            const data: string[] = [];
            for (const line of block.split('\n')) {
              if (line.startsWith('event: ')) type = line.slice(7);
              else if (line.startsWith('data: ')) data.push(line.slice(6));
            }
            this.events.push({ type, data: data.join('\n') });
          }
        }
      } catch {
        // cerrado por el test
      }
    })();
  }

  progress(): EnrollmentProgress[] {
    return this.events
      .filter((e) => e.type === 'progress')
      .map((e) => JSON.parse(e.data) as EnrollmentProgress);
  }

  last(): EnrollmentProgress | undefined {
    return this.progress().at(-1);
  }

  async close(): Promise<void> {
    this.controller.abort();
    await this.done;
  }
}

describe('Progreso del alta por SSE (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker;
  let pve: FakePve;
  let state: FakePveState;
  let baseUrl: string;
  let adminToken: string;
  let viewerToken: string;
  const output: string[] = [];
  const responses: string[] = [];
  const readers: SseReader[] = [];
  const privateKeys: string[] = [];
  const tokens: string[] = [];
  let node: EnrollServerResponse;

  beforeAll(async () => {
    await prepareEnv('e2e_enrollment_progress', {
      ENROLL_THROTTLE_LIMIT: '1000',
    });
    for (const stream of [process.stdout, process.stderr]) {
      const write = stream.write.bind(stream) as (
        ...args: unknown[]
      ) => boolean;
      vi.spyOn(stream, 'write').mockImplementation((...args: unknown[]) => {
        output.push(String(args[0]));
        return write(...args);
      });
    }
    app = await createTestApp();
    await app.listen(0, '127.0.0.1');
    baseUrl = (await app.getUrl()).replace('[::1]', '127.0.0.1');
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
          {
            id: 'CVE-2024-0001',
            pkg: 'zlib1g',
            version: '1:1.2.13',
            fixed: '1:1.2.13.1',
            severity: 'LOW',
          },
        ],
      },
    };
    pve.setState(state);
    worker = await startWorker(pve.workerEnv());
  });

  afterAll(async () => {
    for (const r of readers) await r.close();
    vi.restoreAllMocks();
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

  async function enroll(
    name: string,
    installSudo?: boolean,
  ): Promise<EnrollServerResponse> {
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 22,
      name,
      ...(installSudo === undefined ? {} : { installSudo }),
    });
    expect(res.statusCode).toBe(201);
    const body = res.json<EnrollServerResponse>();
    privateKeys.push(
      await app
        .get(SecretsService)
        .resolve(body.asset.credentials.sshPrivateKey!),
    );
    tokens.push(tokenOf(body.enrollment));
    return body;
  }

  function tokenOf(enrollment: IssuedEnrollment): string {
    const match = /\/enroll\/([A-Za-z0-9_-]{43}) \|/.exec(enrollment.command);
    if (!match) throw new Error(`Comando inesperado: ${enrollment.command}`);
    return match[1];
  }

  async function watch(
    assetId: string,
    token: string | null = adminToken,
  ): Promise<SseReader> {
    const reader = new SseReader();
    readers.push(reader);
    await reader.open(`${baseUrl}/assets/${assetId}/enrollment/events`, token);
    return reader;
  }

  async function until(
    reader: SseReader,
    phase: EnrollmentProgress['phase'],
    timeoutMs = 45_000,
  ): Promise<EnrollmentProgress> {
    await waitFor(
      () => reader.last()?.phase === phase,
      timeoutMs,
      () =>
        `fase ${phase} no alcanzada: ${JSON.stringify(reader.last(), null, 1)}\n${worker.output.join('')}`,
    );
    return reader.last()!;
  }

  it('los comandos llevan --install-sudo solo si se pide, y el embebido no lleva token', async () => {
    node = await enroll('pve', true);
    const token = tokenOf(node.enrollment);
    expect(node.enrollment.command).toBe(
      `curl -fsSL http://infraward.test/enroll/${token} | bash -s -- --install-sudo`,
    );
    const embedded =
      /^echo '([A-Za-z0-9+/=]+)' \| base64 -d \| gunzip \| bash -s -- --install-sudo$/.exec(
        node.enrollment.embeddedCommand,
      );
    expect(embedded).not.toBeNull();
    const script = gunzipSync(Buffer.from(embedded![1], 'base64')).toString();
    expect(script).toContain(`local mode='embedded'`);
    expect(script).toContain(`local token=''`);
    expect(script).toContain(node.enrollment.publicKey);
    expect(script).not.toContain(token);
    expect(script).not.toContain('infraward.test');

    // El script servido por URL es el online, sin cambios.
    const served = await request('GET', `/enroll/${token}`, undefined, null);
    expect(served.body).toContain(`local mode='online'`);

    // Sin pedirlo: sudo bash, como siempre.
    const plain = await enroll('sin-opcion');
    expect(plain.enrollment.command).toMatch(/\| sudo bash$/);
    expect(plain.enrollment.embeddedCommand).toMatch(/\| gunzip \| sudo bash$/);

    // Un comando nuevo puede cambiar la opción.
    const reissued = await request(
      'POST',
      `/assets/${plain.asset.id}/enrollment/token`,
      { installSudo: true },
    );
    expect(reissued.statusCode).toBe(201);
    const issued = reissued.json<IssuedEnrollment>();
    tokens.push(tokenOf(issued));
    expect(issued.command).toMatch(/\| bash -s -- --install-sudo$/);
    // Y sin cuerpo, sin la opción.
    const again = await request(
      'POST',
      `/assets/${plain.asset.id}/enrollment/token`,
    );
    expect(again.statusCode).toBe(201);
    tokens.push(tokenOf(again.json<IssuedEnrollment>()));
    expect(again.json<IssuedEnrollment>().command).toMatch(/\| sudo bash$/);
  });

  it('SSE: 401 sin token, 404 si el asset no existe, y cualquier rol puede seguirlo', async () => {
    const anon = await watch(node.asset.id, null);
    expect(anon.status).toBe(401);
    const missing = await watch('00000000-0000-4000-8000-000000000000');
    expect(missing.status).toBe(404);
    const badId = await watch('no-es-uuid');
    expect(badId.status).toBe(400);
    const viewer = await watch(node.asset.id, viewerToken);
    expect(viewer.status).toBe(200);
    expect(viewer.contentType).toContain('text/event-stream');
    await until(viewer, 'waiting');
    await viewer.close();
  });

  it('alta por URL de principio a fin: esperando → conectando → escaneando → listo', async () => {
    const reader = await watch(node.asset.id);
    const first = await until(reader, 'waiting');
    expect(first).toMatchObject({
      assetId: node.asset.id,
      assetName: 'pve',
      assetStatus: 'pending_enrollment',
      jobs: [],
      truncated: false,
    });

    const done = await request(
      'POST',
      `/enroll/${tokenOf(node.enrollment)}/done`,
      { hostKeys: [{ type: 'ED25519', fingerprint: pve.fingerprint }] },
      null,
    );
    expect(done.statusCode).toBe(204);

    const ready = await until(reader, 'ready');
    const phases = reader
      .progress()
      .map((p) => p.phase)
      .filter((p, i, all) => p !== all[i - 1]);
    expect(phases[0]).toBe('waiting');
    expect(phases).toContain('connecting');
    expect(phases).toContain('scanning');
    expect(phases.at(-1)).toBe('ready');
    // Nunca hacia atrás ni «listo» antes de tiempo.
    const order = ['waiting', 'connecting', 'scanning', 'ready'];
    expect(phases.map((p) => order.indexOf(p))).toEqual(
      [...phases.map((p) => order.indexOf(p))].sort((a, b) => a - b),
    );

    expect(ready.assetStatus).toBe('active');
    expect(ready.enrollment.status).toBe('verified');
    // Verificación → recolección del nodo → descubrimiento → recolección del CT →
    // descubrimiento del CT → escaneo de la imagen.
    expect(ready.jobs.map((j) => j.name)).toEqual([
      'enrollment.verify',
      'asset.collect',
      'asset.discover',
      'asset.collect',
      'asset.discover',
      'image.scan',
    ]);
    expect(ready.jobs.every((j) => j.state === 'completed')).toBe(true);
    expect(ready.jobs[0].assetId).toBe(node.asset.id);
    expect(ready.jobs[1].assetId).toBe(node.asset.id);
    expect(ready.jobs[3].assetId).not.toBe(node.asset.id);
    expect(ready.jobs[5].assetId).toBeNull();
    expect(ready.jobs[0].message).toBe('Conexión verificada');
    // Durante el escaneo se vio el progreso de algún job.
    expect(
      reader
        .progress()
        .some((p) => p.jobs.some((j) => j.state === 'active' && j.message)),
    ).toBe(true);
    // Solo lo necesario: sin datos ni resultados de los jobs.
    expect(Object.keys(ready.jobs[0]).sort()).toEqual([
      'assetId',
      'failedReason',
      'id',
      'message',
      'name',
      'progress',
      'state',
    ]);
    await reader.close();

    // Al reconectar, el estado completo llega en el primer evento.
    const again = await watch(node.asset.id);
    const snapshot = await until(again, 'ready');
    expect(snapshot.jobs).toHaveLength(6);
    await again.close();
  });

  it('findings: con parche y severidad mínima, o todos', async () => {
    const tree = (
      await request('GET', `/assets/${node.asset.id}/tree`)
    ).json<AssetTreeSummaryNode>();
    const web1 = tree.children[0].children.find((c) => c.name === 'web1')!;
    const list = async (query: string) => {
      const res = await request('GET', `/assets/${web1.id}/findings${query}`);
      expect(res.statusCode).toBe(200);
      return res
        .json<AssetFindingsPage>()
        .items.map((f) => `${f.vulnerabilityId}:${f.severity}`);
    };
    expect(await list('')).toEqual([
      'CVE-2025-0838:CRITICAL',
      'CVE-2024-6387:HIGH',
      'CVE-2024-0001:LOW',
    ]);
    // Filtro por defecto de la web: abiertos, con parche y MEDIUM o más.
    expect(await list('?status=open&fixable=true&minSeverity=MEDIUM')).toEqual([
      'CVE-2024-6387:HIGH',
    ]);
    expect(await list('?fixable=true')).toEqual([
      'CVE-2024-6387:HIGH',
      'CVE-2024-0001:LOW',
    ]);
    expect(await list('?fixable=false')).toEqual(['CVE-2025-0838:CRITICAL']);
    expect(await list('?minSeverity=high')).toEqual([
      'CVE-2025-0838:CRITICAL',
      'CVE-2024-6387:HIGH',
    ]);
    const search = await request(
      'GET',
      '/findings?minSeverity=CRITICAL&fixable=false',
    );
    expect(search.json<{ total: number }>().total).toBe(1);
    for (const bad of ['?minSeverity=GRAVE', '?fixable=quizas']) {
      expect(
        (await request('GET', `/assets/${web1.id}/findings${bad}`)).statusCode,
      ).toBe(400);
    }
  });

  it('script embebido: las huellas pegadas que no coinciden hacen fallar la verificación', async () => {
    // Sin CT: el resto de altas no deben tocar el árbol del nodo.
    pve.setState({ ...state, guests: [] });
    const server = await enroll('embebido-mal');
    const reader = await watch(server.asset.id);
    await until(reader, 'waiting');

    expect(
      (
        await request('POST', `/assets/${server.asset.id}/enrollment/confirm`, {
          sshUser: 'inventory',
          hostKeys: [{ type: 'ED25519', fingerprint: 'SHA256:corta' }],
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (
        await request('POST', `/assets/${server.asset.id}/enrollment/confirm`, {
          sshUser: 'inventory',
          hostKeys: [],
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (
        await request(
          'POST',
          `/assets/${server.asset.id}/enrollment/confirm`,
          {
            sshUser: 'inventory',
            hostKeys: [{ type: 'ED25519', fingerprint: OTHER_FP }],
          },
          viewerToken,
        )
      ).statusCode,
    ).toBe(403);

    const res = await request(
      'POST',
      `/assets/${server.asset.id}/enrollment/confirm`,
      {
        sshUser: 'inventory',
        hostKeys: [
          { type: 'ED25519', fingerprint: OTHER_FP },
          { type: 'ED25519', fingerprint: OTHER_FP },
        ],
      },
    );
    expect(res.statusCode).toBe(202);
    expect(
      res.json<{ reportedHostKeys: unknown[] }>().reportedHostKeys,
    ).toEqual([{ type: 'ED25519', fingerprint: OTHER_FP }]);
    await until(reader, 'failed');
    // La fase la marca el worker al fallar; el estado de la ejecución lo escribe después el líder
    // con los eventos de la cola (llega en otro `progress`).
    await waitFor(
      () => !!reader.last()?.jobs.length && reader.last()!.jobs.every((j) => j.state === 'failed'),
      30_000,
      () => `ejecuciones: ${JSON.stringify(reader.last()?.jobs)}`,
    );
    const failed = reader.last()!;
    expect(failed.phase).toBe('failed');
    expect(failed.enrollment.error).toMatch(/posible suplantación/);
    expect(failed.assetStatus).toBe('pending_enrollment');
    expect(failed.jobs.map((j) => [j.name, j.state])).toEqual([
      ['enrollment.verify', 'failed'],
    ]);
    // La huella no se fija con un fallo.
    const [row] = (await db.query(
      `SELECT host_key_fingerprint FROM assets WHERE id = $1`,
      [server.asset.id],
    )) as { host_key_fingerprint: string | null }[];
    expect(row.host_key_fingerprint).toBeNull();

    // Comando nuevo: vuelve a «esperando» en el mismo flujo, y con las huellas buenas, listo.
    const reissued = await request(
      'POST',
      `/assets/${server.asset.id}/enrollment/token`,
    );
    expect(reissued.statusCode).toBe(201);
    tokens.push(tokenOf(reissued.json<IssuedEnrollment>()));
    await until(reader, 'waiting');
    const ok = await request(
      'POST',
      `/assets/${server.asset.id}/enrollment/confirm`,
      {
        sshUser: 'inventory',
        hostKeys: [
          { type: 'RSA', fingerprint: OTHER_FP },
          { type: 'ED25519', fingerprint: pve.fingerprint },
        ],
      },
    );
    expect(ok.statusCode).toBe(202);
    const ready = await until(reader, 'ready');
    expect(ready.enrollment).toMatchObject({
      method: 'manual',
      status: 'verified',
      sshUser: 'inventory',
    });
    expect(ready.assetStatus).toBe('active');
    const [pinned] = (await db.query(
      `SELECT host_key_fingerprint FROM assets WHERE id = $1`,
      [server.asset.id],
    )) as { host_key_fingerprint: string | null }[];
    expect(pinned.host_key_fingerprint).toBe(pve.fingerprint);
    await reader.close();
  });

  it('el flujo se cierra al desconectar el cliente', async () => {
    const reader = await watch(node.asset.id);
    await until(reader, 'ready');
    await reader.close();
    expect(reader.events.length).toBeGreaterThan(0);
  });

  it('ni claves privadas ni tokens en eventos, respuestas o logs', () => {
    const sse = readers.flatMap((r) => r.raw).join('\n');
    const logs = [...output, ...worker.output].join('\n');
    const everything = [sse, logs, ...responses].join('\n');
    expect(everything).not.toContain('PRIVATE KEY');
    for (const key of privateKeys) {
      for (const line of key.split('\n').filter((l) => l.length > 20)) {
        expect(everything).not.toContain(line);
      }
    }
    // Los tokens solo aparecen en las respuestas que emiten el comando.
    for (const token of tokens) {
      expect(sse).not.toContain(token);
      expect(logs).not.toContain(token);
    }
  });
});
