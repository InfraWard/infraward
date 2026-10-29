import type { JobQueues } from '../jobs/job-queues.js';
import type { Job } from 'bullmq';
import type { DataSource } from 'typeorm';
import { describe, expect, it, vi } from 'vitest';
import type { DomainLinker } from '../domains/domain-linker.js';
import type { ExpiryAlerts } from '../domains/expiry-alerts.js';
import { InventoryReconciler, isDue } from './reconciler.js';

const policy = (minutes: number) => ({
  values: {
    reconcileIntervalMinutes: minutes,
    scanEnabled: true,
    scanPeriodic: true,
  },
});
const NOW = new Date('2026-10-12T12:00:00Z');
const ago = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000);

describe('isDue', () => {
  it('nunca reconciliado ⇒ sí; dentro del intervalo ⇒ no; vencido ⇒ sí; 0 ⇒ nunca', () => {
    const c = (minutes: number, at: Date | null) => ({
      id: 'a',
      name: 'a',
      type: 'server' as const,
      effectivePolicy: policy(minutes),
      reconciledAt: at,
    });
    expect(isDue(c(60, null), NOW)).toBe(true);
    expect(isDue(c(60, ago(59)), NOW)).toBe(false);
    expect(isDue(c(60, ago(60)), NOW)).toBe(true);
    expect(isDue(c(0, null), NOW)).toBe(false);
    // Sin calcular: la de por defecto (6 h).
    expect(isDue({ ...c(0, ago(300)), effectivePolicy: {} }, NOW)).toBe(false);
    expect(isDue({ ...c(0, ago(360)), effectivePolicy: {} }, NOW)).toBe(true);
  });
});

describe('InventoryReconciler.run', () => {
  function setup(
    rows: {
      id: string;
      name: string;
      minutes: number;
      at: Date | null;
      type?: string;
    }[],
  ) {
    const queries: string[] = [];
    const db = {
      query: vi.fn((sql: string, params: unknown[]) => {
        queries.push(sql);
        if (sql.includes('SELECT a.id'))
          return Promise.resolve(
            rows
              .filter((r) => !params[0] || r.id === params[0])
              .map((r) => ({
                id: r.id,
                name: r.name,
                type: r.type ?? 'server',
                effective_policy: policy(r.minutes),
                reconciled_at: r.at,
              })),
          );
        return Promise.resolve([]);
      }),
      manager: { query: vi.fn(() => Promise.resolve([])) },
    } as unknown as DataSource;
    const queue = {
      add: vi.fn((name: string, data: unknown) =>
        Promise.resolve({
          id: `job-${(data as { assetId: string }).assetId}`,
          name,
          data,
          opts: {},
          queueName: 'discovery',
        }),
      ),
    };
    const linker = { link: vi.fn(() => Promise.resolve({ links: 0, dangling: 0, notified: 0 })) };
    const expiry = { run: vi.fn(() => Promise.resolve(0)) };
    return {
      reconciler: new InventoryReconciler(
        db,
        { ...queue, get: () => queue } as unknown as JobQueues,
        linker as unknown as DomainLinker,
        expiry as unknown as ExpiryAlerts,
      ),
      queue,
      db,
      linker,
      expiry,
    };
  }
  const job = (data: object, repeat = false) =>
    ({
      id: 'r1',
      data,
      repeatJobKey: repeat ? 'repeat:x' : undefined,
      log: () => Promise.resolve(),
      updateProgress: () => Promise.resolve(),
    }) as unknown as Job;

  it('encola solo las raíces vencidas, con trigger reconcile y deduplicadas por asset', async () => {
    vi.useFakeTimers({ now: NOW });
    const t = setup([
      { id: 'pve', name: 'pve', minutes: 5, at: ago(10) },
      { id: 'web', name: 'web', minutes: 60, at: ago(10) },
      { id: 'off', name: 'off', minutes: 0, at: null },
    ]);
    const result = await t.reconciler.run(job({}, true));
    vi.useRealTimers();
    expect(result).toEqual({ queued: 1, assetIds: ['pve'], notDue: 2 });
    expect(t.queue.add).toHaveBeenCalledWith(
      'asset.collect',
      { assetId: 'pve', trigger: 'reconcile' },
      expect.objectContaining({ deduplication: { id: 'pve' } }),
    );
  });

  it('a un conector de dominios le encola su sincronización; el tick enlaza y revisa caducidades', async () => {
    vi.useFakeTimers({ now: NOW });
    const t = setup([
      { id: 'cf', name: 'Cloudflare', minutes: 5, at: ago(10), type: 'dns_provider' },
    ]);
    const result = await t.reconciler.run(job({}, true));
    vi.useRealTimers();
    expect(result.assetIds).toEqual(['cf']);
    expect(t.queue.add).toHaveBeenCalledWith(
      'domains.sync',
      { assetId: 'cf', trigger: 'reconcile' },
      expect.objectContaining({ deduplication: { id: 'domains:cf' } }),
    );
    expect(t.linker.link).toHaveBeenCalledTimes(1);
    expect(t.expiry.run).toHaveBeenCalledTimes(1);
  });

  it('un fallo al enlazar no tumba la reconciliación', async () => {
    const t = setup([]);
    t.linker.link.mockRejectedValueOnce(new Error('x'));
    await expect(t.reconciler.run(job({}, true))).resolves.toMatchObject({ queued: 0 });
    expect(t.expiry.run).toHaveBeenCalled();
  });

  it('una concreta va aunque no le toque', async () => {
    const t = setup([{ id: 'web', name: 'web', minutes: 60, at: new Date() }]);
    const result = await t.reconciler.run(job({ assetId: 'web' }));
    expect(result.assetIds).toEqual(['web']);
  });
});
