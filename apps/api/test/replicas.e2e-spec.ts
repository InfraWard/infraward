import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type { EnqueueJobResponse, WorkerReplica } from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { startWorker, stopWorker, waitFor, type TestWorker } from './support/worker.js';

interface RunRow {
  state: string;
  worker: string | null;
  attempt: number;
  message: string | null;
  error: string | null;
}

/**
 * Varias réplicas del worker (sesión W-0, DESIGN §20): procesos worker reales con el mismo Redis y
 * la misma BD. Una réplica que muere (`kill -9`) no deja su job colgado: otra lo retoma; una que
 * para (SIGTERM) devuelve el suyo a la cola; un job que se perdió de la cola pasa a fallido.
 */
describe('Réplicas del worker (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let auth: Record<string, string>;
  const workers = new Map<string, TestWorker>();

  const start = async (name: string) => {
    workers.set(name, await startWorker({ WORKER_NAME: name, WORKER_SHUTDOWN_GRACE: '2' }));
  };

  beforeAll(async () => {
    await prepareEnv('e2e_replicas');
    app = await createTestApp();
    db = app.get(DataSource);
    auth = authHeaders(await loginToken(app, ADMIN.email, ADMIN.password));
    await start('e2e-a');
    await start('e2e-b');
  });

  afterAll(async () => {
    for (const w of workers.values()) await stopWorker(w);
    await app?.close();
  });

  const ping = async (steps: number, stepDelayMs: number) => {
    const res = await app.inject({
      method: 'POST',
      url: '/jobs/ping',
      headers: auth,
      payload: { steps, stepDelayMs },
    });
    expect(res.statusCode).toBe(202);
    return res.json<EnqueueJobResponse>().id;
  };
  const row = async (id: string): Promise<RunRow | undefined> =>
    ((await db.query(
      `SELECT state, worker, attempt, message, error FROM job_runs WHERE id = $1`,
      [id],
    )) as RunRow[])[0];
  const output = () =>
    [...workers.entries()].map(([n, w]) => `--- ${n}\n${w.output.join('')}`).join('\n');

  it('GET /jobs/workers: las dos réplicas, sus colas y un solo líder', async () => {
    let replicas: WorkerReplica[] = [];
    await waitFor(
      async () => {
        replicas = (
          await app.inject({ method: 'GET', url: '/jobs/workers', headers: auth })
        ).json<WorkerReplica[]>();
        return replicas.length === 2 && replicas.some((r) => r.leader);
      },
      30_000,
      () => JSON.stringify(replicas),
    );
    expect(replicas.map((r) => r.name)).toEqual(['e2e-a', 'e2e-b']);
    expect(replicas.filter((r) => r.leader)).toHaveLength(1);
    expect(replicas[0]!.queues).toEqual(
      expect.arrayContaining(['system', 'collect', 'discovery', 'image-scan', 'host-scan']),
    );
  });

  it('kill -9 de la réplica que ejecuta un job: otra lo retoma y la Actividad lo cierra', async () => {
    const id = await ping(20, 500);
    let run: RunRow | undefined;
    await waitFor(
      async () => (run = await row(id))?.state === 'active' && !!run?.worker,
      20_000,
      () => `${JSON.stringify(run)}\n${output()}`,
    );
    const victim = run!.worker!;
    workers.get(victim)!.child.kill('SIGKILL');
    workers.delete(victim);
    // Lock de 60 s + comprobación de stalled cada 30 s: como mucho ~100 s, y 9 s del ping.
    await waitFor(
      async () => (run = await row(id))?.state === 'completed',
      150_000,
      () => `${JSON.stringify(run)}\n${output()}`,
    );
    expect(run!.worker).not.toBe(victim);
    expect(run!.attempt).toBe(2);
    // Vuelve a tener dos réplicas para el siguiente.
    await start(victim);
  }, 200_000);

  it('SIGTERM con un job en curso: termina o lo devuelve a la cola, y otra réplica lo acaba', async () => {
    const id = await ping(20, 500);
    let run: RunRow | undefined;
    await waitFor(
      async () => (run = await row(id))?.state === 'active' && !!run?.worker,
      20_000,
      () => `${JSON.stringify(run)}\n${output()}`,
    );
    const stopping = run!.worker!;
    const w = workers.get(stopping)!;
    await stopWorker(w);
    workers.delete(stopping);
    // Parada limpia (Nest termina con la misma señal tras sus hooks), sin llegar al SIGKILL.
    expect(w.child.signalCode).not.toBe('SIGKILL');
    expect(w.output.join('')).toContain(`Devuelto a la cola al parar ${stopping}`);
    await waitFor(
      async () => (run = await row(id))?.state === 'completed',
      60_000,
      () => `${JSON.stringify(run)}\n${output()}`,
    );
    expect(run!.worker).not.toBe(stopping);
    expect(run!.attempt).toBe(2);
    await start(stopping);
  }, 120_000);

  it('un job que ya no está en la cola no se queda «en curso»: el líder lo da por perdido', async () => {
    const id = randomUUID();
    await db.query(
      `INSERT INTO job_runs (id, name, queue, state, created_at, started_at, worker)
       VALUES ($1, 'asset.collect', 'collect', 'active', now() - interval '5 minutes',
               now() - interval '5 minutes', 'e2e-muerto')`,
      [id],
    );
    // El barrido va cada minuto (y al elegirse líder).
    let run: RunRow | undefined;
    await waitFor(
      async () => (run = await row(id))?.state === 'failed',
      90_000,
      () => `${JSON.stringify(run)}\n${output()}`,
    );
    expect(run!.error).toBe(
      'El job se perdió: e2e-muerto dejó de responder y ya no está en la cola',
    );
  }, 120_000);
});
