import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  EnqueueJobResponse,
  JobRunLog,
  JobRunSummary,
  JobStatus,
  Page,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { ORPHAN_ERROR } from '../src/jobs/job-runs.service.js';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { startWorker, waitFor, type TestWorker } from './support/worker.js';

const VIEWER = {
  email: 'viewer-jobs@infraward.test',
  password: 'otra-contraseña-larga',
};

describe('Jobs: API → cola → worker (e2e)', () => {
  let app: NestFastifyApplication;
  let worker: TestWorker;
  let auth: Record<string, string>;
  let viewer: Record<string, string>;

  beforeAll(async () => {
    await prepareEnv('e2e_jobs');
    app = await createTestApp();
    worker = await startWorker();
    auth = authHeaders(await loginToken(app, ADMIN.email, ADMIN.password));
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    viewer = authHeaders(await loginToken(app, VIEWER.email, VIEWER.password));
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
      parent: null,
      // Lo encoló la API a petición de alguien.
      origin: 'manual',
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

  describe('origen, detalle y log de una ejecución', () => {
    const bulk = randomUUID();
    const collect = randomUUID();
    const discover = randomUUID();
    const scheduled = randomUUID();
    const orphan = randomUUID();
    const get = (url: string, headers = auth) =>
      app.inject({ method: 'GET', url, headers });

    beforeAll(async () => {
      const db = app.get(DataSource);
      await db.query(
        `INSERT INTO job_runs (id, name, queue, asset_name, state, progress, message, parent_job_id,
                               trigger, created_at, started_at, finished_at)
         VALUES ($1, 'assets.bulk', 'system', 'pve, web', 'completed', 100,
                 'Recolectar · 2 assets · 1 tarea · por admin@infraward.test', NULL, NULL,
                 now() - interval '4 minutes', now() - interval '4 minutes', now() - interval '4 minutes'),
                ($2, 'asset.collect', 'collect', 'pve', 'failed', 100, NULL, $1, NULL,
                 now() - interval '3 minutes', now() - interval '3 minutes', now() - interval '2 minutes'),
                ($3, 'asset.discover', 'discovery', 'pve', 'completed', 100, NULL, $2, NULL,
                 now() - interval '2 minutes', now() - interval '2 minutes', now() - interval '1 minute'),
                ($4, 'asset.collect', 'collect', 'web', 'completed', 100, NULL, NULL, 'schedule',
                 now() - interval '1 minute', now() - interval '1 minute', now()),
                ($5, 'asset.discover', 'discovery', 'web', 'completed', 100, NULL, $6, NULL,
                 now(), now(), now())`,
        [bulk, collect, discover, scheduled, orphan, randomUUID()],
      );
      await db.query(
        `INSERT INTO job_run_logs (job_run_id, attempt, worker, entries, started_at, updated_at)
         VALUES ($1, 1, 'worker-1', $2::jsonb, now(), now())`,
        [
          collect,
          JSON.stringify([
            { at: new Date().toISOString(), level: 'error', kind: 'result', message: 'Fallido: sin SSH' },
          ]),
        ],
      );
    });

    it('GET /jobs: cada ejecución trae de dónde viene y la tarea o el lote que la lanzó', async () => {
      const items = (await get('/jobs?limit=100')).json<Page<JobRunSummary>>().items;
      const byId = new Map(items.map((r) => [r.id, r]));
      expect(byId.get(collect)).toMatchObject({
        origin: 'bulk',
        parent: {
          id: bulk,
          name: 'assets.bulk',
          state: 'completed',
          message: 'Recolectar · 2 assets · 1 tarea · por admin@infraward.test',
        },
        hasLog: true,
      });
      expect(byId.get(discover)).toMatchObject({
        origin: 'chain',
        parent: { id: collect, name: 'asset.collect', state: 'failed' },
      });
      expect(byId.get(scheduled)).toMatchObject({ origin: 'schedule', parent: null });
      // El padre ya no está en el historial: encadenada, sin datos del padre.
      expect(byId.get(orphan)).toMatchObject({ origin: 'chain', parent: null });
      expect(byId.get(bulk)).toMatchObject({
        origin: null,
        children: { total: 1, running: 0, failed: 1 },
      });
    });

    it('GET /jobs?origin= filtra por origen (y valida el valor)', async () => {
      const ids = async (origin: string) =>
        (await get(`/jobs?origin=${origin}&limit=100`))
          .json<Page<JobRunSummary>>()
          .items.map((r) => r.id);
      expect(await ids('bulk')).toEqual([collect]);
      expect(await ids('chain')).toEqual(expect.arrayContaining([discover, orphan]));
      expect(await ids('chain')).not.toContain(collect);
      expect(await ids('schedule')).toEqual([scheduled]);
      expect(await ids('manual')).not.toContain(scheduled);
      expect((await get('/jobs?origin=otro')).statusCode).toBe(400);
    });

    it('GET /jobs/runs/:id: el detalle, con sus tareas; 404 si no existe', async () => {
      const res = await get(`/jobs/runs/${bulk}`, viewer);
      expect(res.statusCode).toBe(200);
      expect(res.json<JobRunSummary>()).toMatchObject({
        id: bulk,
        name: 'assets.bulk',
        children: { total: 1, failed: 1 },
      });
      expect((await get(`/jobs/runs/${randomUUID()}`)).statusCode).toBe(404);
      expect((await get('/jobs/runs/no-uuid')).statusCode).toBe(400);
      expect((await app.inject({ method: 'GET', url: `/jobs/runs/${bulk}` })).statusCode).toBe(401);
    });

    it('GET /jobs/runs/:id/log: con assets.operate; un lector, 403', async () => {
      expect((await get(`/jobs/runs/${collect}/log`, viewer)).statusCode).toBe(403);
      const res = await get(`/jobs/runs/${collect}/log`);
      expect(res.statusCode).toBe(200);
      const log = res.json<JobRunLog>();
      expect(log.run).toMatchObject({ id: collect, origin: 'bulk', hasLog: true });
      expect(log.attempts[0]!.entries[0]!.message).toBe('Fallido: sin SSH');
      // Sin asset ni log: vacío, no 404.
      const empty = await get(`/jobs/runs/${bulk}/log`);
      expect(empty.json<JobRunLog>().attempts).toEqual([]);
      expect((await get(`/jobs/runs/${randomUUID()}/log`)).statusCode).toBe(404);
    });
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
      expect.arrayContaining([
        '/jobs',
        '/jobs/ping',
        '/jobs/{id}',
        '/jobs/runs/{id}',
        '/jobs/runs/{id}/log',
      ]),
    );
  });
});
