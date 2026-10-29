import type { DataSource } from 'typeorm';
import type { JobQueues } from './job-queues.js';
import type { JobRuns } from './job-runs.js';
import { OrphanSweeper } from './orphan-sweeper.js';

describe('OrphanSweeper', () => {
  it('concilia la Actividad con BullMQ: perdidos a fallidos, terminados y devueltos a la cola', async () => {
    const rows = [
      { id: 'lost', queue: 'collect', state: 'active', worker: 'worker-2' },
      { id: 'gone', queue: 'collect', state: 'queued', worker: null },
      { id: 'done', queue: 'collect', state: 'active', worker: 'worker-1' },
      { id: 'failed', queue: 'host-scan', state: 'active', worker: 'worker-1' },
      { id: 'back', queue: 'collect', state: 'active', worker: 'worker-3' },
      { id: 'running', queue: 'collect', state: 'active', worker: 'worker-1' },
      { id: 'old-queue', queue: 'nope', state: 'active', worker: null },
    ];
    const states: Record<string, string> = {
      lost: 'unknown',
      gone: 'unknown',
      done: 'completed',
      failed: 'failed',
      back: 'delayed',
      running: 'active',
    };
    const queue = {
      getJobState: (id: string) => Promise.resolve(states[id]),
      getJob: () => Promise.resolve({ failedReason: 'SSH caído' }),
    };
    const queues = {
      get: (name: string) => {
        if (name === 'nope') throw new Error('Cola desconocida');
        return queue;
      },
    } as unknown as JobQueues;
    const runs = {
      finishById: vi.fn(() => Promise.resolve()),
      requeuedById: vi.fn((_id: string, reason: (w: string) => string) =>
        Promise.resolve(void reason('worker-3')),
      ),
    };
    const sweeper = new OrphanSweeper(
      { query: () => Promise.resolve(rows) } as unknown as DataSource,
      queues,
      runs as unknown as JobRuns,
    );
    await expect(sweeper.sweep()).resolves.toBe(5);
    expect(runs.finishById.mock.calls).toEqual([
      [
        'lost',
        'failed',
        'El job se perdió: worker-2 dejó de responder y ya no está en la cola',
      ],
      ['gone', 'failed', 'El job ya no está en la cola (caducó o se borró)'],
      ['done', 'completed', null],
      ['failed', 'failed', 'SSH caído'],
    ]);
    expect(runs.requeuedById.mock.calls.map((c) => c[0])).toEqual(['back']);
  });
});
