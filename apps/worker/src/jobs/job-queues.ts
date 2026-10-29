import { getQueueToken } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import {
  JOB_QUEUES,
  QUEUE_NAMES,
  type JobData,
  type JobName,
  type QueueName,
} from '@infraward/shared-types';
import type { Job, JobsOptions, Queue } from 'bullmq';

/** Todas las colas, y la de cada job: así el código que encola no tiene que saber en cuál va. */
@Injectable()
export class JobQueues {
  private readonly queues = new Map<QueueName, Queue>();

  constructor(private readonly moduleRef: ModuleRef) {}

  /**
   * Se resuelven al usarlas, no en el constructor: Nest puede crear este servicio antes que los
   * proveedores de las colas (no dependen unos de otros).
   */
  get(name: QueueName): Queue {
    let queue = this.queues.get(name);
    if (!queue) {
      if (!(Object.values(QUEUE_NAMES) as string[]).includes(name))
        throw new Error(`Cola desconocida: ${name}`);
      queue = this.moduleRef.get<Queue>(getQueueToken(name), { strict: false });
      this.queues.set(name, queue);
    }
    return queue;
  }

  entries(): [QueueName, Queue][] {
    return Object.values(QUEUE_NAMES).map((name) => [name, this.get(name)]);
  }

  /** Encola en la cola del job (`JOB_QUEUES`). */
  add<N extends JobName>(
    name: N,
    data: JobData<N>,
    opts?: JobsOptions,
  ): Promise<Job> {
    return this.get(JOB_QUEUES[name]).add(name, data, opts);
  }
}
