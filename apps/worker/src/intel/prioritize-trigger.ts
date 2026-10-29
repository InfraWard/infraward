import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import {
  FINDINGS_PRIORITIZE_ID,
  JOB_NAMES,
  QUEUE_NAMES,
  type FindingsPrioritizeJobData,
} from '@infraward/shared-types';
import { Queue } from 'bullmq';
import { randomUUID } from 'node:crypto';

/** Ventana en la que se juntan las peticiones (una ráfaga de escaneos = un solo recálculo). */
export const PRIORITIZE_DEBOUNCE_MS = 3000;

/**
 * Pide un `findings.prioritize` (DESIGN §9) tras lo que cambia la prioridad: findings nuevos,
 * facts, contenedores, caminos de dominios o KEV/EPSS. Las peticiones de unos segundos se juntan
 * en un job; su id no es un UUID, así que no llena la Actividad. Nunca lanza.
 */
@Injectable()
export class PrioritizeTrigger {
  private readonly logger = new Logger(PrioritizeTrigger.name);

  constructor(@InjectQueue(QUEUE_NAMES.system) private readonly queue: Queue) {}

  async request(reason: string): Promise<void> {
    try {
      await this.queue.add(
        JOB_NAMES.findingsPrioritize,
        {} satisfies FindingsPrioritizeJobData,
        {
          jobId: `prioritize-${randomUUID()}`,
          delay: PRIORITIZE_DEBOUNCE_MS,
          deduplication: {
            id: FINDINGS_PRIORITIZE_ID,
            ttl: PRIORITIZE_DEBOUNCE_MS,
          },
          removeOnComplete: { age: 3600, count: 100 },
          removeOnFail: { age: 86_400, count: 100 },
        },
      );
    } catch (error) {
      this.logger.warn(
        `No se pudo pedir el recálculo de prioridades (${reason}): ${(error as Error).name}`,
      );
    }
  }
}
