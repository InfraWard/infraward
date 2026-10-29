import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  EnqueueJobResponse,
  JobRunSummary,
  JobStatus,
  Page,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { ORPHAN_ERROR } from '../src/jobs/job-runs.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { startWorker, waitFor, type TestWorker } from './support/worker.js';

describe('Jobs: API → cola → worker (e2e)', () => {
  let app: NestFastifyApplication;
  let worker: TestWorker;
  let auth: Record<string, string>;

  beforeAll(async () => {
    await prepareEnv('e2e_jobs');
    app = await createTestApp();
    worker = await startWorker();
    auth = authHeaders(await loginToken(app, ADMIN.email, ADMIN.password));
  });

  afterAll(async () => {
    if (worker?.child.exitCode === null) worker.child.kill('SIGKILL');
    await app?.close();
  });

  it('POST /jobs/ping exige token y valida el cuerpo', async () => {
    const anonymous = await app.inject({
      method: 'POST',
      url: '/jobs/ping',
      payload: {},
    });
    expect(anonymous.statusCode).toBe(401);

    const invalid = await app.inject({
      method: 'POST',
      url: '/jobs/ping',
      headers: auth,
      payload: { steps: 0, stepDelayMs: -1, extra: true },
    });
    expect(invalid.statusCode).toBe(400);
  });

  it('encola un ping que el worker procesa con progreso consultable', async () => {
    const enqueued = await app.inject({
      method: 'POST',
      url: '/jobs/ping',
      headers: auth,
      payload: { steps: 4, stepDelayMs: 100, message: 'hola' },
    });
    expect(enqueued.statusCode).toBe(202);
    const { id, name, queue } = enqueued.json<EnqueueJobResponse>();
    expect({ name, queue }).toEqual({ name: 'ping', queue: 'system' });

    const getStatus = async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/jobs/${id}`,
        headers: auth,
      });
      expect(res.statusCode).toBe(200);
      return res.json<JobStatus<'ping'>>();
    };

    const seenStates = new Set<string>();
    let status = await getStatus();
    await waitFor(
      async () => {
        status = await getStatus();
        seenStates.add(status.state);
        return status.state === 'completed' || status.state === 'failed';
      },
      15_000,
      () => `el job sigue en ${status.state}`,
    );

    expect(status.state).toBe('completed');
    expect(status.progress).toBe(100);
    expect(status.result).toMatchObject({
      pong: true,
      message: 'hola',
      steps: 4,
    });
    expect(status.finishedAt).toBeDefined();
    expect(status.events.map((e) => e.progress)).toEqual([0, 25, 50, 75, 100]);
    expect(status.events.at(-1)?.message).toBe('Paso 4/4');
    const times = status.events.map((e) => Date.parse(e.at));
    expect(times).toEqual([...times].sort((a, b) => a - b));
    // Con 4 pasos de 100 ms el sondeo ve el job en curso antes de terminar.
    expect(seenStates.has('active')).toBe(true);
  });

  it('GET /jobs: el ping queda en el historial, terminado y con su duración', async () => {
    let run: JobRunSummary | undefined;
    await waitFor(
      async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/jobs?name=ping',
          headers: auth,
        });
        expect(res.statusCode).toBe(200);
        run = res.json<Page<JobRunSummary>>().items[0];
        return run?.state === 'completed';
      },
      10_000,
      () => `ejecución: ${JSON.stringify(run)}`,
    );
    expect(run).toMatchObject({
      name: 'ping',
      queue: 'system',
      assetId: null,
      progress: 100,
      message: 'Paso 4/4',
      error: null,
      parentJobId: null,
    });
    // 4 pasos de 100 ms.
    expect(run!.durationMs).toBeGreaterThanOrEqual(300);
    expect((await app.inject({ method: 'GET', url: '/jobs' })).statusCode).toBe(
      401,
    );
  });

  it('GET /jobs: una ejecución sin terminar cuyo job ya no está en la cola pasa a fallida', async () => {
    const id = randomUUID();
    await app.get(DataSource).query(
      `INSERT INTO job_runs (id, name, queue, state, started_at, created_at)
       VALUES ($1, 'asset.collect', 'discovery', 'active', now() - interval '5 minutes',
               now() - interval '5 minutes')`,
      [id],
    );
    const res = await app.inject({
      method: 'GET',
      url: '/jobs?state=failed',
      headers: auth,
    });
    const run = res.json<Page<JobRunSummary>>().items.find((r) => r.id === id);
    expect(run).toMatchObject({ state: 'failed', error: ORPHAN_ERROR });
    expect(run!.finishedAt).not.toBeNull();
  });

  it('GET /jobs/:id devuelve 404 si el job no existe y 400 si el id no es un UUID', async () => {
    const missing = await app.inject({
      method: 'GET',
      url: '/jobs/00000000-0000-4000-8000-000000000000',
      headers: auth,
    });
    expect(missing.statusCode).toBe(404);
    const invalid = await app.inject({
      method: 'GET',
      url: '/jobs/no-es-un-uuid',
      headers: auth,
    });
    expect(invalid.statusCode).toBe(400);
  });

  it('el worker se detiene limpiamente con SIGTERM', async () => {
    const exited = new Promise<void>((done) =>
      worker.child.once('exit', () => done()),
    );
    worker.child.kill('SIGTERM');
    await exited;
    expect(worker.output.join('')).toContain('Worker detenido (SIGTERM)');
  });

  it('publica los endpoints de jobs en OpenAPI', async () => {
    const spec = await app.inject({ method: 'GET', url: '/openapi.json' });
    expect(Object.keys(spec.json().paths)).toEqual(
      expect.arrayContaining(['/jobs', '/jobs/ping', '/jobs/{id}']),
    );
  });
});
