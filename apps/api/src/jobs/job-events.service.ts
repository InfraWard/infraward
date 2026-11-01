import { Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  QUEUE_NAMES,
  QUEUE_PREFIX,
  type QueueName,
} from '@infraward/shared-types';
import { QueueEvents } from 'bullmq';
import { Observable, Subject } from 'rxjs';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Colas cuyos eventos interesan a la web (las del alta y lo que encadena): todas menos `system` y
 * `alerts` (sus jobs no salen en la Actividad).
 */
const WATCHED_QUEUES: readonly QueueName[] = Object.values(QUEUE_NAMES).filter(
  (q) => q !== QUEUE_NAMES.system && q !== QUEUE_NAMES.alerts,
);

const WATCHED_EVENTS = ['active', 'progress', 'completed', 'failed'] as const;

/** Algo le pasó a un job: solo el id y el tipo; el estado se lee después de la cola. */
export interface JobEvent {
  queue: QueueName;
  jobId: string;
  event: (typeof WATCHED_EVENTS)[number];
}

/**
 * Eventos de los jobs (BullMQ `QueueEvents`, un stream de Redis por cola) publicados como
 * Observable. Las conexiones se abren con la primera suscripción y se comparten.
 */
@Injectable()
export class JobEventsService implements OnModuleDestroy {
  private readonly logger = new Logger(JobEventsService.name);
  private readonly subject = new Subject<JobEvent>();
  private listeners: QueueEvents[] | null = null;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  get events$(): Observable<JobEvent> {
    this.start();
    return this.subject.asObservable();
  }

  private start(): void {
    if (this.listeners) return;
    const connection = {
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
    };
    this.listeners = WATCHED_QUEUES.map((queue) => {
      const events = new QueueEvents(queue, {
        connection,
        prefix: QUEUE_PREFIX,
      });
      for (const event of WATCHED_EVENTS) {
        events.on(event, ({ jobId }: { jobId: string }) =>
          this.subject.next({ queue, jobId, event }),
        );
      }
      // Sin conexión a Redis los clientes siguen con el sondeo de respaldo.
      events.on('error', (error: Error) =>
        this.logger.warn(`Eventos de la cola ${queue}: ${error.name}`),
      );
      return events;
    });
  }

  async onModuleDestroy(): Promise<void> {
    const listeners = this.listeners ?? [];
    this.listeners = null;
    this.subject.complete();
    await Promise.allSettled(listeners.map((l) => l.close()));
  }
}
