import { QUEUE_PREFIX } from '@infraward/shared-types';
import { Queue, Worker, type Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { DistributedLock } from '../redis/distributed-lock.js';
import type { WorkerRedis } from '../redis/redis.js';
import { execFileRunner } from '../ssh/ssh-client.js';
import { connect, startRedis, testConfig } from '../test/redis.js';
import { currentJob, HostBusy } from './job-context.js';
import { JobRunner } from './job-runner.js';
import type { JobRuns, JobRunUpdate } from './job-runs.js';

/** La envoltura de los jobs con BullMQ y Redis reales (DESIGN §20). */
describe('JobRunner (BullMQ real)', () => {
  let stop: () => Promise<void>;
  let url: URL;
  let redis: WorkerRedis;
  let queue: Queue;
  let worker: Worker | undefined;
  const tracked: [string, JobRunUpdate][] = [];
  const runs = {
    start: () => Promise.resolve(1),
    track: (job: Job, update: JobRunUpdate) =>
      {
        tracked.push([job.id!, update]);
        return Promise.resolve();
      },
  } as unknown as JobRuns;

  beforeAll(async () => {
    ({ url, stop } = await startRedis());
    redis = await connect(testConfig(url));
  });
  beforeEach(async () => {
    await redis.client.flushdb();
    tracked.length = 0;
    queue = new Queue(`runner-${randomUUID()}`, {
      connection: { host: url.hostname, port: Number(url.port), db: 13 },
      prefix: QUEUE_PREFIX,
    });
  });
  afterEach(async () => {
    await worker?.close(true);
    await queue.obliterate({ force: true });
    await queue.close();
  });
  afterAll(async () => {
    await redis.client.quit();
    await stop();
  });

  function consume(
    runner: JobRunner,
    fn: (job: Job) => Promise<unknown>,
    concurrency = 2,
  ) {
    worker = new Worker(
      queue.name,
      (job: Job, token?: string) => runner.run(job, token, fn),
      {
        connection: { host: url.hostname, port: Number(url.port), db: 13 },
        prefix: QUEUE_PREFIX,
        concurrency,
        name: 'worker-1',
      },
    );
    return worker;
  }

  const until = async (check: () => boolean | Promise<boolean>, ms = 15_000) => {
    const deadline = Date.now() + ms;
    while (!(await check())) {
      if (Date.now() > deadline) throw new Error('tiempo agotado');
      await sleep(50);
    }
  };

  it('host ocupado: vuelve a la cola retrasado, sin gastar intento, y luego termina', async () => {
    const runner = new JobRunner(runs, new DistributedLock(redis));
    let calls = 0;
    consume(runner, () => {
      calls++;
      if (calls === 1) throw new HostBusy('Esperando turno en pve', 200);
      return Promise.resolve('hecho');
    });
    const job = await queue.add('ping', {}, { jobId: randomUUID(), attempts: 1 });
    await until(async () => (await queue.getJobState(job.id!)) === 'completed');
    const done = (await queue.getJob(job.id!))!;
    expect(done.returnvalue).toBe('hecho');
    expect(calls).toBe(2);
    expect(tracked).toContainEqual([
      job.id,
      { state: 'queued', message: 'Esperando turno en pve' },
    ]);
  });

  it('parada: aborta el job y sus procesos hijos, vuelve a la cola sin gastar intento', async () => {
    const runner = new JobRunner(runs, new DistributedLock(redis));
    runner.setWorkerName('worker-2');
    let started = 0;
    let child: { code: number | null } | undefined;
    consume(runner, async () => {
      started++;
      if (started > 1) return 'retomado';
      // Un proceso largo (como un docker save): el aborto lo mata.
      child = await execFileRunner('sleep', ['30'], 60_000);
      throw new Error('el proceso murió');
    });
    const job = await queue.add('ping', {}, { jobId: randomUUID(), attempts: 1 });
    await until(() => runner.active === 1);
    await sleep(200);
    const began = Date.now();
    runner.abort('shutdown');
    await until(async () => (await queue.getJobState(job.id!)) === 'completed');
    expect(Date.now() - began).toBeLessThan(10_000);
    expect(child).toEqual({ code: null, stdout: '', stderr: '' });
    // Con `attempts: 1`, si la parada contara como intento el job habría fallado: solo cuenta el
    // que terminó.
    expect((await queue.getJob(job.id!))!.attemptsMade).toBe(1);
    expect(tracked).toContainEqual([
      job.id,
      { state: 'queued', message: 'Devuelto a la cola al parar worker-2' },
    ]);
  });

  it('lock perdido: se aborta y no se toca el job (ya es de otra réplica)', async () => {
    const runner = new JobRunner(runs, new DistributedLock(redis));
    let aborted = false;
    consume(runner, async () => {
      await sleep(10_000, undefined, { signal: currentJob()!.signal }).catch(
        () => (aborted = true),
      );
      throw new Error('cortado');
    });
    const job = await queue.add('ping', {}, { jobId: randomUUID() });
    await until(() => runner.active === 1);
    runner.abort('lock-lost', [job.id!]);
    await until(() => aborted);
    expect(tracked.filter(([, u]) => u.state === 'queued')).toEqual([]);
  });

  it('un job a la vez por operación y asset entre réplicas (aunque BullMQ diera dos)', async () => {
    const [a, b] = [
      new JobRunner(runs, new DistributedLock(redis)),
      new JobRunner(runs, new DistributedLock(await connect(testConfig(url)))),
    ];
    let running = 0;
    let max = 0;
    const work = async () => {
      running++;
      max = Math.max(max, running);
      await sleep(300);
      running--;
      return 'ok';
    };
    consume(a, work, 1); // este worker lo cierra el afterEach
    const second = new Worker(
      queue.name,
      (job: Job, token?: string) => b.run(job, token, work),
      {
        connection: { host: url.hostname, port: Number(url.port), db: 13 },
        prefix: QUEUE_PREFIX,
        concurrency: 1,
      },
    );
    // Sin deduplicación: dos recolecciones del mismo asset en la cola.
    const jobs = await Promise.all(
      [1, 2].map(() =>
        queue.add('asset.collect', { assetId: 'a1' }, { jobId: randomUUID() }),
      ),
    );
    await until(
      async () =>
        (
          await Promise.all(jobs.map((j) => queue.getJobState(j.id!)))
        ).every((s) => s === 'completed'),
      40_000,
    );
    expect(max).toBe(1);
    expect(
      tracked.some(([, u]) => u.message?.startsWith('Otra ejecución de esta operación')),
    ).toBe(true);
    await second.close();
  });
});
