import { getQueueToken } from '@nestjs/bullmq';
import {
  Injectable,
  Logger,
  NotFoundException,
  type OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ModuleRef } from '@nestjs/core';
import { InjectDataSource } from '@nestjs/typeorm';
import { recordQueuedJob } from '@infraward/domain';
import {
  JOB_NAMES,
  JOB_QUEUES,
  QUEUE_NAMES,
  WORKER_LEADER_KEY,
  WORKER_REPLICA_KEY_PREFIX,
  type EnqueueJobResponse,
  type JobData,
  type JobName,
  type JobResult,
  type JobRunTrigger,
  type JobProgressEvent,
  type JobState,
  type JobStatus,
  type WorkerReplica,
  type WorkerReplicaInfo,
} from '@infraward/shared-types';
import type { Job, Queue } from 'bullmq';
import { Redis } from 'ioredis';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';

/** Encola jobs para el worker y consulta su estado. La API nunca los ejecuta. */
@Injectable()
export class JobsService implements OnModuleDestroy {
  private readonly logger = new Logger(JobsService.name);
  private readonly queueRefs = new Map<string, Queue>();
  private redis: Redis | null = null;

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly moduleRef: ModuleRef,
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  /**
   * Las colas, por nombre. Se resuelven al usarlas: Nest puede crear este servicio antes que los
   * proveedores de las colas.
   */
  private get queues(): Readonly<Record<string, Queue>> {
    if (!this.queueRefs.size)
      for (const name of Object.values(QUEUE_NAMES))
        this.queueRefs.set(
          name,
          this.moduleRef.get<Queue>(getQueueToken(name), { strict: false }),
        );
    return Object.fromEntries(this.queueRefs);
  }

  /**
   * Réplicas del worker vivas (DESIGN §20): la ficha que cada una publica en Redis y renueva
   * mientras corre (caduca si muere), y cuál es el líder.
   */
  async workers(): Promise<WorkerReplica[]> {
    // Conexión perezosa: solo la abre quien mira las réplicas.
    this.redis ??= new Redis({
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
      maxRetriesPerRequest: 2,
    });
    const keys: string[] = [];
    let cursor = '0';
    do {
      const [next, batch] = await this.redis.scan(
        cursor,
        'MATCH',
        `${WORKER_REPLICA_KEY_PREFIX}*`,
        'COUNT',
        200,
      );
      cursor = next;
      keys.push(...batch);
    } while (cursor !== '0');
    const [leader, ...values] = keys.length
      ? await this.redis.mget(WORKER_LEADER_KEY, ...keys)
      : [await this.redis.get(WORKER_LEADER_KEY)];
    const now = Date.now();
    return values
      .flatMap((raw): WorkerReplica[] => {
        try {
          const info = JSON.parse(raw ?? '') as WorkerReplicaInfo;
          return [
            {
              name: info.name,
              host: info.host,
              queues: info.queues,
              uptimeSeconds: Math.max(
                0,
                Math.round((now - Date.parse(info.startedAt)) / 1000),
              ),
              leader: info.name === leader,
            },
          ];
        } catch {
          return [];
        }
      })
      .sort((a, b) => a.name.localeCompare(b.name, 'es', { numeric: true }));
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis?.quit().catch(() => undefined);
  }

  /**
   * Encola un job. Con `deduplicationId`, si ya hay uno pendiente o en curso con ese id no se
   * crea otro: se devuelve el existente (`deduplicated`). `parentJobId`: la operación en lote que
   * lo lanza (QoL-6), para verlos juntos en la Actividad. `trigger`: qué lo lanzó si no cuelga de
   * nada (por omisión, una petición a la API).
   */
  async enqueue<N extends JobName>(
    name: N,
    data: JobData<N>,
    options: {
      deduplicationId?: string;
      parentJobId?: string;
      trigger?: JobRunTrigger;
    } = {},
  ): Promise<EnqueueJobResponse> {
    const queue = JOB_QUEUES[name];
    // UUID como jobId: único entre colas, así basta el id para consultar el estado.
    const jobId = randomUUID();
    const job = await this.queues[queue].add(name, data, {
      jobId,
      ...(options.deduplicationId
        ? { deduplication: { id: options.deduplicationId } }
        : {}),
    });
    // Historial (Actividad). Si falla, el job ya está encolado: el worker creará la fila al empezar.
    await recordQueuedJob(
      this.db.manager,
      job,
      options.parentJobId ?? null,
      options.trigger ?? 'manual',
    ).catch((error: unknown) =>
      this.logger.warn(
        `No se pudo registrar el job ${job.id}: ${(error as Error).message}`,
      ),
    );
    return {
      id: job.id!,
      name,
      queue,
      ...(job.id !== jobId ? { deduplicated: true } : {}),
    };
  }

  /**
   * Job corto cuyo resultado se espera en la propia petición (consultas al worker, como
   * `vulnerability.lookup`). Sin historial: su id no es un UUID (`<prefijo><uuid>`), así que ni
   * la API ni el worker lo registran en `job_runs`. null si no termina a tiempo o falla; uno que
   * no llegó a empezar se quita de la cola.
   */
  async runQuick<N extends JobName>(
    name: N,
    data: JobData<N>,
    options: { idPrefix: string; timeoutMs: number },
  ): Promise<JobResult<N> | null> {
    const queue = this.queues[JOB_QUEUES[name]];
    const job = await queue.add(name, data, {
      jobId: `${options.idPrefix}${randomUUID()}`,
      attempts: 1,
      removeOnComplete: { age: 60 },
      removeOnFail: { age: 60 },
    });
    const deadline = Date.now() + options.timeoutMs;
    for (let wait = 20; ; wait = Math.min(wait * 2, 200)) {
      const state = await queue.getJobState(job.id!);
      if (state === 'completed') {
        const done = (await queue.getJob(job.id!)) as Job | undefined;
        return (done?.returnvalue ?? null) as JobResult<N> | null;
      }
      if (state === 'failed' || state === 'unknown') return null;
      if (Date.now() >= deadline) {
        if (state !== 'active') await job.remove().catch(() => undefined);
        return null;
      }
      await sleep(wait);
    }
  }

  /** Estado de un job en BullMQ ('unknown' si ya no existe). */
  state(id: string, queueName: string): Promise<JobState> {
    const queue = this.queues[queueName];
    return queue ? queue.getJobState(id) : Promise.resolve('unknown');
  }

  async status(id: string): Promise<JobStatus> {
    for (const [queueName, queue] of Object.entries(this.queues)) {
      // Estado antes que los datos: si se leyera después, el job podría haber terminado entre
      // ambas lecturas y verse `completed` sin `returnvalue`.
      const state = await queue.getJobState(id);
      const job = (await queue.getJob(id)) as Job | undefined;
      if (job && isJobName(job.name)) {
        const { logs } = await queue.getJobLogs(id);
        return {
          id,
          name: job.name,
          queue: queueName as JobStatus['queue'],
          state,
          progress: typeof job.progress === 'number' ? job.progress : 0,
          events: logs.flatMap(parseProgressEvent),
          result: job.returnvalue ?? undefined,
          failedReason: job.failedReason || undefined,
          createdAt: new Date(job.timestamp).toISOString(),
          finishedAt: job.finishedOn
            ? new Date(job.finishedOn).toISOString()
            : undefined,
        };
      }
    }
    throw new NotFoundException('Job no encontrado');
  }

  /**
   * Vistazo a un job de nombre conocido (solo su cola, y solo el último evento de progreso), para
   * seguir cadenas de jobs. null si ya no existe (retención agotada).
   */
  async peek<N extends JobName>(
    name: N,
    id: string,
  ): Promise<JobPeek<N> | null> {
    const queue = this.queues[JOB_QUEUES[name]];
    const state = await queue.getJobState(id);
    const job = (await queue.getJob(id)) as Job | undefined;
    if (job?.name !== name) return null;
    const { logs } = await queue.getJobLogs(id, -1, -1);
    return {
      id,
      name,
      state,
      progress: typeof job.progress === 'number' ? job.progress : 0,
      message: logs.flatMap(parseProgressEvent).at(-1)?.message ?? null,
      failedReason: job.failedReason || null,
      data: job.data as JobData<N>,
      result: (job.returnvalue ?? null) as JobResult<N> | null,
    };
  }
}

export interface JobPeek<N extends JobName = JobName> {
  id: string;
  name: N;
  state: JobState;
  progress: number;
  message: string | null;
  failedReason: string | null;
  data: JobData<N>;
  result: JobResult<N> | null;
}

function isJobName(name: string): name is JobName {
  return Object.values<string>(JOB_NAMES).includes(name);
}

/** Cada línea del log del job es un JobProgressEvent en JSON; se ignora lo que no lo sea. */
function parseProgressEvent(line: string): JobProgressEvent[] {
  try {
    const event = JSON.parse(line) as Partial<JobProgressEvent>;
    if (
      typeof event.progress === 'number' &&
      typeof event.message === 'string' &&
      typeof event.at === 'string'
    ) {
      return [
        { progress: event.progress, message: event.message, at: event.at },
      ];
    }
  } catch {
    // línea no JSON
  }
  return [];
}
