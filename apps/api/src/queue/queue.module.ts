import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { QUEUE_NAMES, QUEUE_PREFIX } from '@infraward/shared-types';
import type { EnvironmentVariables } from '../config/env.validation.js';

const queues = BullModule.registerQueue(
  ...Object.values(QUEUE_NAMES).map((name) => ({
    name,
    defaultJobOptions: {
      // Retención limitada: el estado de un job se puede consultar durante ese tiempo.
      removeOnComplete: { age: 3600, count: 1000 },
      removeOnFail: { age: 86400 },
    },
  })),
);

/** Conexión con Redis y colas de BullMQ en las que la API encola trabajo para el worker. */
@Module({
  imports: [
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables, true>) => ({
        prefix: QUEUE_PREFIX,
        connection: {
          host: config.get('REDIS_HOST', { infer: true }),
          port: config.get('REDIS_PORT', { infer: true }),
          password: config.get('REDIS_PASSWORD', { infer: true }),
          db: config.get('REDIS_DB', { infer: true }),
        },
      }),
    }),
    queues,
  ],
  exports: [queues],
})
export class QueueModule {}
