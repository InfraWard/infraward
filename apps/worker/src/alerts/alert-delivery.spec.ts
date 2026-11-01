import type { ConfigService } from '@nestjs/config';
import type { SecretsService } from '@infraward/secrets';
import type { DataSource } from 'typeorm';
import { describe, expect, it, vi } from 'vitest';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { JobQueues } from '../jobs/job-queues.js';
import { AlertDelivery } from './alert-delivery.js';
import type { EmailSender } from './email-sender.js';

const N1 = '00000000-0000-4000-8000-000000000001';
const N2 = '00000000-0000-4000-8000-000000000002';
const CHANNEL = { id: 'c1', enabled: true, kinds: null, includeAdminOnly: false };

/** BD falsa: la tanda pendiente, las consultas que llegan y si la transacción se confirmó. */
function setup(add: () => Promise<unknown>) {
  const pending = [
    { id: N1, kind: 'asset_created', audience_roles: null },
    { id: N2, kind: 'asset_created', audience_roles: null },
  ];
  const committed: string[][] = [];
  const db = {
    getRepository: () => ({ find: () => Promise.resolve([CHANNEL]) }),
    transaction: async (fn: (m: unknown) => Promise<unknown>) => {
      const queries: string[] = [];
      const m = {
        query: (sql: string) => {
          queries.push(sql.trim().split(/\s+/)[0]!);
          return Promise.resolve(sql.trim().startsWith('SELECT') ? pending : []);
        },
      };
      // Como PostgreSQL: si la función lanza, nada de lo que hizo queda.
      const result = await fn(m);
      committed.push(queries);
      return result;
    },
  };
  const queues = { add: vi.fn(add) };
  const delivery = new AlertDelivery(
    { get: () => undefined } as unknown as ConfigService<EnvironmentVariables, true>,
    db as unknown as DataSource,
    queues as unknown as JobQueues,
    {} as SecretsService,
    {} as EmailSender,
  );
  return { delivery, queues, committed };
}

describe('AlertDelivery.dispatch', () => {
  it('encola un envío por notificación y canal y solo entonces las marca', async () => {
    const { delivery, queues, committed } = setup(() => Promise.resolve());
    await expect(delivery.dispatch()).resolves.toBe(2);
    expect(queues.add.mock.calls.map((c) => (c[2] as { jobId: string }).jobId)).toEqual([
      `alert-${N1}-c1`,
      `alert-${N2}-c1`,
    ]);
    // Leer (bloqueando), encolar y marcar en la misma transacción.
    expect(committed).toEqual([['SELECT', 'UPDATE']]);
  });

  it('si Redis falla a medias, no se marca ninguna: la siguiente pasada las reparte', async () => {
    let calls = 0;
    const { delivery, committed } = setup(() =>
      ++calls === 2 ? Promise.reject(new Error('Redis caído')) : Promise.resolve(),
    );
    await expect(delivery.dispatch()).rejects.toThrow('Redis caído');
    expect(committed).toEqual([]);
  });
});
