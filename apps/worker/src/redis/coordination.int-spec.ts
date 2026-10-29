import type { Job } from 'bullmq';
import { setTimeout as sleep } from 'node:timers/promises';
import { HostSlots, SLOT_TTL_MS } from '../jobs/host-slots.js';
import {
  currentJob,
  HostBusy,
  runInJobContext,
  type JobContext,
} from '../jobs/job-context.js';
import { connect, startRedis, testConfig } from '../test/redis.js';
import { DistributedLock } from './distributed-lock.js';
import { LeaderElection } from './leader.js';
import type { WorkerRedis } from './redis.js';
import { WorkerIdentity } from './worker-identity.js';
import { WORKER_LEADER_KEY } from '@infraward/shared-types';

describe('coordinación entre réplicas (Redis real)', () => {
  let stop: () => Promise<void>;
  let url: URL;
  const clients: WorkerRedis[] = [];
  const replica = async (values = {}) => {
    const redis = await connect(testConfig(url, values));
    clients.push(redis);
    return redis;
  };

  beforeAll(async () => {
    ({ url, stop } = await startRedis());
  });
  beforeEach(async () => {
    const redis = await replica();
    await redis.client.flushdb();
  });
  afterAll(async () => {
    await Promise.all(clients.map((c) => c.client.quit()));
    await stop();
  });

  const context = (id: string): JobContext => ({
    job: { id } as Job,
    token: 't',
    worker: 'w',
    signal: new AbortController().signal,
    attempt: null,
    leases: [],
  });

  describe('HostSlots', () => {
    it('como mucho HOST_MAX_JOBS por host entre réplicas, y HOST_MAX_SCAN_JOBS escaneos', async () => {
      const [a, b] = [
        new HostSlots(testConfig(url), await replica()),
        new HostSlots(testConfig(url), await replica()),
      ];
      const jobs = ['j1', 'j2', 'j3', 's1', 's2'].map(context);
      const take = (slots: HostSlots, c: JobContext, kind?: 'scan') =>
        runInJobContext(c, () => slots.acquire('node', 'pve', kind)).then(
          () => 'ok',
          (e: unknown) => (e instanceof HostBusy ? 'busy' : 'error'),
        );
      expect(await take(a, jobs[3]!, 'scan')).toBe('ok');
      // Un segundo escaneo, desde otra réplica: no (tope de escaneos).
      expect(await take(b, jobs[4]!, 'scan')).toBe('busy');
      expect(await take(b, jobs[0]!)).toBe('ok');
      // Total 2: ni un job normal más.
      expect(await take(a, jobs[1]!)).toBe('busy');
      // Otro host es otro semáforo.
      await expect(
        runInJobContext(jobs[2]!, () => a.acquire('other', 'otro')),
      ).resolves.toBeUndefined();
      // Al soltar, entra el siguiente.
      await Promise.all(jobs[3]!.leases.map((l) => l.release()));
      expect(await take(a, jobs[1]!)).toBe('ok');
    });

    it('el mensaje de espera dice el host y cuántos hay; con un retraso con jitter', async () => {
      const slots = new HostSlots(testConfig(url, { HOST_MAX_JOBS: 1 }), await replica());
      await runInJobContext(context('a'), () => slots.acquire('node', 'pve'));
      const error = await runInJobContext(context('b'), () =>
        slots.acquire('node', 'pve'),
      ).catch((e: unknown) => e as HostBusy);
      expect(error).toBeInstanceOf(HostBusy);
      expect(error!.message).toBe('Esperando turno en pve (1 jobs en curso, máximo 1)');
      expect(error!.delayMs).toBeGreaterThanOrEqual(5000);
    });

    it('la concesión de una réplica muerta caduca sola; la renovación la mantiene', async () => {
      const redis = await replica();
      const slots = new HostSlots(testConfig(url, { HOST_MAX_JOBS: 1 }), redis);
      const alive = context('alive');
      await runInJobContext(alive, () => slots.acquire('node', 'pve'));
      // Simula el paso del tiempo: la concesión vence.
      const [key] = slots.keys('node');
      await redis.client.zadd(key!, Date.now() - 1, 'alive');
      await expect(
        runInJobContext(context('next'), () => slots.acquire('node', 'pve')),
      ).resolves.toBeUndefined();
      // Renovar una concesión ya caducada no la recupera a escondidas.
      await alive.leases[0]!.renew();
      expect(await redis.client.zscore(key!, 'alive')).toBeNull();
      expect(SLOT_TTL_MS).toBe(60_000);
    });

    it('terminal: cupo propio por host y por persona entre réplicas, aparte del de los jobs', async () => {
      const [a, b] = [
        new HostSlots(testConfig(url, { HOST_MAX_JOBS: 1 }), await replica()),
        new HostSlots(testConfig(url, { HOST_MAX_JOBS: 1 }), await replica()),
      ];
      // Un job ocupa el único hueco de jobs del host: las terminales no lo cuentan.
      await runInJobContext(context('job-1'), () => a.acquire('nodo-t', 'pve'));
      const s1 = await a.acquireTerminal({ host: 'nodo-t' }, 'sesion-1', 2);
      const s2 = await b.acquireTerminal({ host: 'nodo-t' }, 'sesion-2', 2);
      const s3 = await b.acquireTerminal({ host: 'nodo-t' }, 'sesion-3', 2);
      expect([!!s1.lease, !!s2.lease, !!s3.lease]).toEqual([true, true, false]);
      expect(s3.running).toBe(2);
      // Y las terminales tampoco quitan hueco a los jobs de otro host.
      await expect(
        runInJobContext(context('job-2'), () => b.acquire('otro-nodo', 'pve2')),
      ).resolves.toBeUndefined();
      await s1.lease!.release();
      expect((await a.acquireTerminal({ host: 'nodo-t' }, 'sesion-3', 2)).lease).not.toBeNull();

      const u1 = await a.acquireTerminal({ user: 'ana' }, 'sesion-a', 1);
      const u2 = await b.acquireTerminal({ user: 'ana' }, 'sesion-b', 1);
      const other = await b.acquireTerminal({ user: 'luis' }, 'sesion-c', 1);
      expect([!!u1.lease, !!u2.lease, !!other.lease]).toEqual([true, false, true]);
      // La renovación mantiene la concesión; la caducada se libera sola.
      await u1.lease!.renew();
      expect((await b.acquireTerminal({ user: 'ana' }, 'sesion-b', 1)).lease).toBeNull();
    });

    it('fuera de un job no limita', async () => {
      const slots = new HostSlots(testConfig(url, { HOST_MAX_JOBS: 1 }), await replica());
      expect(currentJob()).toBeUndefined();
      await slots.acquire('node', 'pve');
      await slots.acquire('node', 'pve');
    });
  });

  describe('DistributedLock', () => {
    it('uno a la vez entre réplicas; el lock de otro no se suelta', async () => {
      const [a, b] = [
        new DistributedLock(await replica()),
        new DistributedLock(await replica()),
      ];
      const held = await a.tryAcquire('trivy-db');
      expect(held).not.toBeNull();
      expect(await b.tryAcquire('trivy-db')).toBeNull();
      // Un token ajeno no lo libera.
      const redis = await replica();
      await redis.client.eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0",
        1,
        redis.key('lock', 'trivy-db'),
        'otro-token',
      );
      expect(await b.tryAcquire('trivy-db')).toBeNull();
      await held!.release();
      const next = await b.tryAcquire('trivy-db');
      expect(next).not.toBeNull();
      await next!.release();
    });

    it('acquire espera a que se suelte; runExclusive se salta si está tomado', async () => {
      const a = new DistributedLock(await replica());
      const held = (await a.tryAcquire('x'))!;
      setTimeout(() => void held.release(), 300);
      const started = Date.now();
      const second = await a.acquire('x', { waitMs: 5000, pollMs: 50 });
      expect(second).not.toBeNull();
      expect(Date.now() - started).toBeGreaterThanOrEqual(250);
      expect(await a.runExclusive('x', () => Promise.resolve(1))).toEqual({
        skipped: true,
      });
      await second!.release();
      expect(await a.runExclusive('x', () => Promise.resolve(1))).toEqual({
        skipped: false,
        value: 1,
      });
    });

    it('se renueva mientras se tiene y avisa si lo pierde', async () => {
      const redis = await replica();
      const lock = (await new DistributedLock(redis).tryAcquire('y', 1500))!;
      await sleep(2000);
      expect(await redis.client.get(redis.key('lock', 'y'))).toBe(lock.token);
      await redis.client.set(redis.key('lock', 'y'), 'otro');
      // Se renueva cada max(1 s, ttl/3).
      await sleep(1300);
      expect(lock.lost.aborted).toBe(true);
      await lock.release();
      expect(await redis.client.get(redis.key('lock', 'y'))).toBe('otro');
    });
  });

  describe('WorkerIdentity', () => {
    it('worker-1, worker-2…: el menor libre; al soltarlo lo recupera la siguiente', async () => {
      const ids = await Promise.all(
        [0, 1, 2].map(async () => new WorkerIdentity(testConfig(url), await replica())),
      );
      const names = [];
      for (const id of ids) names.push(await id.claim());
      expect(names).toEqual(['worker-1', 'worker-2', 'worker-3']);
      expect(await ids[0]!.alive('worker-2')).toBe(true);
      await ids[1]!.release();
      expect(await ids[0]!.alive('worker-2')).toBe(false);
      const again = new WorkerIdentity(testConfig(url), await replica());
      expect(await again.claim()).toBe('worker-2');
      await Promise.all([...ids, again].map((i) => i.release()));
    });

    it('WORKER_NAME manda', async () => {
      const id = new WorkerIdentity(
        testConfig(url, { WORKER_NAME: 'remoto-madrid' }),
        await replica(),
      );
      expect(await id.claim()).toBe('remoto-madrid');
      await id.release();
    });
  });

  describe('LeaderElection', () => {
    it('un solo líder; al parar, otro toma el relevo', async () => {
      const events: string[] = [];
      const hooks = (name: string) => ({
        elected: () => Promise.resolve(void events.push(`${name}+`)),
        demoted: () => Promise.resolve(void events.push(`${name}-`)),
      });
      const [a, b] = [
        new LeaderElection(await replica()),
        new LeaderElection(await replica()),
      ];
      a.start('worker-1', hooks('worker-1'));
      await sleep(200);
      b.start('worker-2', hooks('worker-2'));
      await sleep(200);
      expect([a.isLeader, b.isLeader]).toEqual([true, false]);
      const redis = await replica();
      expect(await redis.client.get(WORKER_LEADER_KEY)).toBe('worker-1');
      await a.stop();
      // El siguiente tick de b (cada 10 s) lo toma; aquí, a mano.
      await (b as unknown as { tick(): Promise<void> }).tick();
      expect(b.isLeader).toBe(true);
      expect(events).toEqual(['worker-1+', 'worker-1-', 'worker-2+']);
      await b.stop();
      expect(await redis.client.get(WORKER_LEADER_KEY)).toBeNull();
    });
  });
});
