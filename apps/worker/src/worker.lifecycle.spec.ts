import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from './config/env.validation.js';
import type { LeaderTasks } from './jobs/leader-tasks.js';
import type { WorkerPool } from './jobs/worker-pool.js';
import type { LeaderElection } from './redis/leader.js';
import type { WorkerRedis } from './redis/redis.js';
import type { WorkerIdentity } from './redis/worker-identity.js';
import type { WorkDirCleaner } from './scan/work-dirs.js';
import type { SchemaGate } from './schema-gate.js';
import { WorkerLifecycle } from './worker.lifecycle.js';

// El arranque real del módulo (con Redis y la cola) lo cubren los e2e de la API.
describe('WorkerLifecycle', () => {
  function setup(eligible = true) {
    const order: string[] = [];
    const step = (name: string, value?: unknown) =>
      vi.fn(() => {
        order.push(name);
        return Promise.resolve(value);
      });
    const values: Record<string, unknown> = {
      WORKER_LEADER_ELIGIBLE: eligible,
      WORKER_SHUTDOWN_GRACE: 90,
    };
    const lifecycle = new WorkerLifecycle(
      { get: (k: string) => values[k] } as unknown as ConfigService<
        EnvironmentVariables,
        true
      >,
      { client: { connect: step('redis') } } as unknown as WorkerRedis,
      {
        claim: step('identidad', 'worker-2'),
        publish: step('ficha'),
        release: step('soltar nombre'),
        host: 'h1',
      } as unknown as WorkerIdentity,
      { clean: step('limpieza') } as unknown as WorkDirCleaner,
      {
        start: vi.fn(() => {
          order.push('workers');
          return { collect: 4, scan: 1 };
        }),
        stop: step('parar workers'),
      } as unknown as WorkerPool,
      {
        start: vi.fn(() => order.push('líder')),
        stop: step('dejar el liderazgo'),
      } as unknown as LeaderElection,
      {} as LeaderTasks,
      { wait: step('esquema') } as unknown as SchemaGate,
    );
    return { lifecycle, order };
  }

  it('arranca en orden: esquema al día, nombre, limpieza, workers y después la candidatura a líder', async () => {
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    const { lifecycle, order } = setup();
    await lifecycle.onApplicationBootstrap();
    expect(order).toEqual(['redis', 'esquema', 'identidad', 'limpieza', 'workers', 'ficha', 'líder']);
    expect(log).toHaveBeenCalledWith('Worker listo: worker-2 (h1): collect×4, scan×1');
    log.mockRestore();
  });

  it('un worker que no puede ser líder no se presenta', async () => {
    const { lifecycle, order } = setup(false);
    await lifecycle.onApplicationBootstrap();
    expect(order).not.toContain('líder');
  });

  it('para en orden: suelta el liderazgo, espera a los jobs y suelta su nombre', async () => {
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    const { lifecycle, order } = setup();
    await lifecycle.beforeApplicationShutdown('SIGTERM');
    lifecycle.onApplicationShutdown('SIGTERM');
    expect(order).toEqual(['dejar el liderazgo', 'parar workers', 'soltar nombre']);
    expect(log).toHaveBeenCalledWith('Worker detenido (SIGTERM)');
    log.mockRestore();
  });
});
