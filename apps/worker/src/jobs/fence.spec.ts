import type { Job } from 'bullmq';
import type { EntityManager } from 'typeorm';
import { assertFence } from './fence.js';
import { runInJobContext, SupersededError } from './job-context.js';

const manager = (attempt: number | undefined) => {
  const query = vi.fn(() =>
    Promise.resolve(attempt === undefined ? [] : [{ attempt }]),
  );
  return { query } as unknown as EntityManager & { query: typeof query };
};
const inJob = (attempt: number | null, fn: () => Promise<void>) =>
  runInJobContext(
    {
      job: { id: 'j1' } as Job,
      token: 't',
      worker: 'worker-1',
      signal: new AbortController().signal,
      attempt,
      leases: [],
    },
    fn,
  );

describe('assertFence', () => {
  it('deja escribir si el intento sigue siendo el de esta ejecución (y bloquea su fila)', async () => {
    const m = manager(3);
    await inJob(3, () => assertFence(m));
    expect(m.query).toHaveBeenCalledWith(
      'SELECT attempt FROM job_runs WHERE id = $1 FOR UPDATE',
      ['j1'],
    );
  });

  it('otra réplica lo retomó (intento mayor): SupersededError y no se escribe', async () => {
    await expect(inJob(3, () => assertFence(manager(4)))).rejects.toBeInstanceOf(
      SupersededError,
    );
  });

  it('sin fila, sin fencing token o fuera de un job no comprueba nada', async () => {
    await inJob(3, () => assertFence(manager(undefined)));
    const m = manager(9);
    await inJob(null, () => assertFence(m));
    await assertFence(m);
    expect(m.query).not.toHaveBeenCalled();
  });
});
