import {
  Injectable,
  Logger,
  type BeforeApplicationShutdown,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SERVICE_NAMES, type QueueName } from '@infraward/shared-types';
import type { EnvironmentVariables } from './config/env.validation.js';
import { LeaderTasks } from './jobs/leader-tasks.js';
import { WorkerPool } from './jobs/worker-pool.js';
import { LeaderElection } from './redis/leader.js';
import { WorkerIdentity } from './redis/worker-identity.js';
import { WorkerRedis } from './redis/redis.js';
import { WorkDirCleaner } from './scan/work-dirs.js';
import { SchemaGate } from './schema-gate.js';

/**
 * Arranque y parada ordenados de la réplica (DESIGN §20).
 * Arranque: esquema de la BD al día (lo migra la API) → nombre estable → limpieza de lo que dejó a medias → workers de BullMQ (ya con su
 * nombre y concurrencia; hasta aquí no se toma ningún job) → candidatura a líder.
 * Parada (SIGTERM): deja de optar a líder, deja de pedir jobs y espera a los que están en curso
 * hasta `WORKER_SHUTDOWN_GRACE`; los que no terminen se abortan (con sus procesos hijos), vuelven
 * a la cola y sus directorios se borran. Al final suelta su nombre.
 */
@Injectable()
export class WorkerLifecycle
  implements OnApplicationBootstrap, BeforeApplicationShutdown, OnApplicationShutdown
{
  private readonly logger = new Logger(SERVICE_NAMES.worker);

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly redis: WorkerRedis,
    private readonly identity: WorkerIdentity,
    private readonly cleaner: WorkDirCleaner,
    private readonly pool: WorkerPool,
    private readonly leader: LeaderElection,
    private readonly leaderTasks: LeaderTasks,
    private readonly schema: SchemaGate,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.redis.client.connect();
    // Sin el esquema al día (la API migra al arrancar), los jobs fallarían: se espera.
    await this.schema.wait();
    const name = await this.identity.claim();
    await this.cleaner
      .clean()
      .catch((error: unknown) =>
        this.logger.warn(
          `No se pudieron limpiar los temporales: ${(error as Error).name}`,
        ),
      );
    const queues = this.pool.start(name);
    await this.identity.publish(Object.keys(queues) as QueueName[]);
    if (this.config.get('WORKER_LEADER_ELIGIBLE', { infer: true }))
      this.leader.start(name, this.leaderTasks);
    const summary = Object.entries(queues)
      .map(([queue, n]) => `${queue}×${n}`)
      .join(', ');
    this.logger.log(`Worker listo: ${name} (${this.identity.host}): ${summary}`);
  }

  async beforeApplicationShutdown(signal?: string): Promise<void> {
    this.logger.log(`Parando${signal ? ` (${signal})` : ''}`);
    await this.leader.stop();
    await this.pool.stop(
      this.config.get('WORKER_SHUTDOWN_GRACE', { infer: true }) * 1000,
    );
    await this.identity.release();
  }

  onApplicationShutdown(signal?: string): void {
    this.logger.log(`Worker detenido${signal ? ` (${signal})` : ''}`);
  }
}
