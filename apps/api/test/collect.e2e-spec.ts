import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  Asset,
  EnqueueJobResponse,
  EnrollServerResponse,
  JobRunLog,
  JobRunSummary,
  JobStatus,
  Page,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
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
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
} from './support/worker.js';

const VIEWER = {
  email: 'viewer-collect@infraward.test',
  password: 'otra-contraseña-larga',
};

/** Puerto sin nada escuchando: la recolección falla al leer la host key. */
const CLOSED_PORT = 1;
const FP = `SHA256:${'c'.repeat(43)}`;

describe('Recolección (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let adminToken: string;
  let viewerToken: string;
  const output: string[] = [];
  const responses: string[] = [];
  let privateKey: string;
  /** Asset dado de alta (verificación simulada en la BD) en un puerto cerrado. */
  let asset: Asset;
  let pending: Asset;
  /** Ejecución fallida de la primera recolección (con su log). */
  let failedRunId: string;
  /** Ejecución con un log caducado. */
  let oldRunId: string;

  beforeAll(async () => {
    await prepareEnv('e2e_collect');
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
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);

    const enroll = async (name: string) => {
      const res = await request('POST', '/assets/enroll', {
        host: '127.0.0.1',
        port: CLOSED_PORT,
        name,
      });
      expect(res.statusCode).toBe(201);
      return res.json<EnrollServerResponse>().asset;
    };
    asset = await enroll('e2e-collect');
    pending = await enroll('e2e-collect-pending');
    privateKey = await app
      .get(SecretsService)
      .resolve(asset.credentials.sshPrivateKey!);
    // Alta verificada sin servidor real: activo y con huella fijada.
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [asset.id, FP],
    );
  });

  afterAll(async () => {
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

  async function finished(id: string): Promise<JobStatus> {
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = (await request('GET', `/jobs/${id}`)).json<JobStatus>();
        return last.state === 'completed' || last.state === 'failed';
      },
      30_000,
      () =>
        `recolección sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    return last!;
  }

  it('exige token, rol admin, UUID y asset existente', async () => {
    const url = `/assets/${asset.id}/collect`;
    expect((await request('POST', url, undefined, null)).statusCode).toBe(401);
    expect(
      (await request('POST', url, undefined, viewerToken)).statusCode,
    ).toBe(403);
    expect((await request('POST', '/assets/no-uuid/collect')).statusCode).toBe(
      400,
    );
    expect(
      (
        await request(
          'POST',
          '/assets/00000000-0000-4000-8000-000000000000/collect',
        )
      ).statusCode,
    ).toBe(404);
  });

  it('409 si el asset no está dado de alta', async () => {
    const res = await request('POST', `/assets/${pending.id}/collect`);
    expect(res.statusCode).toBe(409);
    expect(res.json<{ message: string }>().message).toMatch(
      /pending_enrollment/,
    );
  });

  it('encola en la cola discovery y deduplica por asset', async () => {
    // Sin worker todavía: el job se queda esperando.
    const first = await request('POST', `/assets/${asset.id}/collect`);
    expect(first.statusCode).toBe(202);
    const job = first.json<EnqueueJobResponse>();
    expect(job).toMatchObject({ name: 'asset.collect', queue: 'collect' });
    const second = await request('POST', `/assets/${asset.id}/collect`);
    expect(second.json<EnqueueJobResponse>().id).toBe(job.id);
    const status = (await request('GET', `/jobs/${job.id}`)).json<JobStatus>();
    expect(status).toMatchObject({ queue: 'collect', state: 'waiting' });

    // Un log caducado (de hace 40 días) de una ejecución que sigue en el historial: el líder lo
    // poda al arrancar (COLLECTION_LOG_RETENTION_DAYS, 30 por defecto) y deja la ejecución.
    oldRunId = randomUUID();
    await db.query(
      `INSERT INTO job_runs (id, name, queue, asset_id, asset_name, state, created_at, started_at, finished_at)
       VALUES ($1, 'asset.collect', 'collect', $2, 'e2e-collect', 'completed', now(), now(), now())`,
      [oldRunId, asset.id],
    );
    await db.query(
      `INSERT INTO job_run_logs (job_run_id, attempt, asset_id, entries, started_at, updated_at)
       VALUES ($1, 1, $2, '[]', now() - interval '40 days', now() - interval '40 days')`,
      [oldRunId, asset.id],
    );

    // El worker la procesa: sin servidor, falla al leer la host key y el asset no cambia.
    worker = await startWorker({ SSH_CONNECT_TIMEOUT: '3' });
    const done = await finished(job.id);
    expect(done.state).toBe('failed');
    expect(done.failedReason).toMatch(
      /^No se pudo leer la host key de 127\.0\.0\.1:1/,
    );
    expect(done.events.at(-1)?.message).toMatch(/^Fallo: /);
    failedRunId = job.id;
    const after = (await request('GET', `/assets/${asset.id}`)).json<Asset>();
    expect(after).toMatchObject({
      status: 'active',
      hostKeyFingerprint: FP,
      facts: {},
      roles: [],
    });
    const snapshots = await request('GET', `/assets/${asset.id}/snapshots`);
    expect(snapshots.json<{ total: number }>().total).toBe(0);

    // Terminado el job, se puede volver a lanzar.
    const again = await request('POST', `/assets/${asset.id}/collect`);
    expect(again.json<EnqueueJobResponse>().id).not.toBe(job.id);
    await finished(again.json<EnqueueJobResponse>().id);
  });

  it('historial de recolecciones del asset (como la ficha) y su log (con assets.operate)', async () => {
    const url = `/assets/${asset.id}/runs`;
    expect((await request('GET', url, undefined, null)).statusCode).toBe(401);
    expect(
      (await request('GET', '/assets/00000000-0000-4000-8000-000000000000/runs'))
        .statusCode,
    ).toBe(404);
    // Un lector (sin permisos de escritura) ve lo mismo que en la ficha.
    const list = await request('GET', url, undefined, viewerToken);
    expect(list.statusCode).toBe(200);
    const page = list.json<Page<JobRunSummary>>();
    const failed = page.items.find((r) => r.id === failedRunId);
    expect(failed).toMatchObject({
      name: 'asset.collect',
      state: 'failed',
      hasLog: true,
    });
    expect(failed!.durationMs).toBeGreaterThanOrEqual(0);

    // El log lleva el stderr de los servidores: un lector no lo ve.
    expect(
      (await request('GET', `${url}/${failedRunId}/log`, undefined, viewerToken)).statusCode,
    ).toBe(403);

    let log: JobRunLog | undefined;
    // El último guardado del log llega al terminar el job (justo después del evento de fallo).
    await waitFor(async () => {
      const res = await request('GET', `${url}/${failedRunId}/log`);
      expect(res.statusCode).toBe(200);
      log = res.json<JobRunLog>();
      return !!log.attempts[0]?.entries.some((e) => e.kind === 'result');
    }, 10_000, () => `log sin resultado: ${JSON.stringify(log)}`);
    expect(log!.run).toMatchObject({ id: failedRunId, state: 'failed' });
    const [attempt] = log!.attempts;
    expect(attempt).toMatchObject({ attempt: 1, truncated: false });
    const messages = attempt!.entries.map((e) => `${e.level} ${e.kind} ${e.message}`);
    expect(messages[0]).toMatch(/^info step asset\.collect en .+ \(intento 1\)$/);
    expect(messages).toContainEqual(
      expect.stringMatching(/^(info|warn) command ssh-keyscan 127\.0\.0\.1:1$/),
    );
    expect(messages.at(-1)).toMatch(/^error result Fallido: No se pudo leer la host key/);
    const keyscan = attempt!.entries.find((e) => e.kind === 'command');
    expect(keyscan!.durationMs).toBeGreaterThanOrEqual(0);

    // La ejecución debe ser de ese asset; si no, 404 (aunque exista).
    expect(
      (await request('GET', `/assets/${pending.id}/runs/${failedRunId}/log`)).statusCode,
    ).toBe(404);
    expect((await request('GET', `${url}/no-uuid/log`)).statusCode).toBe(400);
  });

  it('el líder poda los logs caducados y deja la ejecución', async () => {
    await waitFor(async () => {
      const rows: unknown[] = await db.query(
        'SELECT 1 FROM job_run_logs WHERE job_run_id = $1',
        [oldRunId],
      );
      return rows.length === 0;
    }, 15_000, () => `log caducado sin podar\n${worker?.output.join('')}`);
    const res = await request('GET', `/assets/${asset.id}/runs/${oldRunId}/log`);
    expect(res.statusCode).toBe(200);
    expect(res.json<JobRunLog>()).toMatchObject({
      run: { id: oldRunId, hasLog: false },
      attempts: [],
    });
  });

  it('aparece en OpenAPI', async () => {
    const spec = (await app.inject({ url: '/openapi.json' })).json<{
      paths: Record<string, unknown>;
    }>();
    expect(spec.paths['/assets/{id}/collect']).toBeDefined();
    expect(spec.paths['/assets/{id}/runs']).toBeDefined();
    expect(spec.paths['/assets/{id}/runs/{runId}/log']).toBeDefined();
  });

  it('la clave privada no aparece en respuestas ni logs (API y worker)', () => {
    expect(privateKey).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
    const body = privateKey.split('\n')[1];
    for (const text of [
      responses.join('\n'),
      output.join(''),
      worker?.output.join('') ?? '',
    ]) {
      expect(text).not.toContain(body);
    }
  });
});
