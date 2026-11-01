import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { createDiscoverers } from '@infraward/connectors';
import { openBaoSourceFromEnv, SecretsModule } from '@infraward/secrets';
import { QUEUE_NAMES, QUEUE_PREFIX } from '@infraward/shared-types';
import { ENV_FILES } from './config/env-files.js';
import {
  secretsProviders,
  validateEnv,
  type EnvironmentVariables,
} from './config/env.validation.js';
import { AnsibleRunner } from './collect/ansible-runner.js';
import { DatabaseModule } from './database.module.js';
import { AssetRoutes, DISCOVERERS } from './jobs/asset-routes.js';
import { DiscoveryProcessor } from './jobs/discovery.processor.js';
import { ScanProcessor } from './jobs/scan.processor.js';
import { EnrollmentProcessor } from './jobs/enrollment.processor.js';
import { HostSlots } from './jobs/host-slots.js';
import { JobEventsListener } from './jobs/job-events-listener.js';
import { JobQueues } from './jobs/job-queues.js';
import { JobRunner } from './jobs/job-runner.js';
import { JobRuns } from './jobs/job-runs.js';
import { LeaderTasks } from './jobs/leader-tasks.js';
import { OrphanSweeper } from './jobs/orphan-sweeper.js';
import { WorkerPool } from './jobs/worker-pool.js';
import { DistributedLock } from './redis/distributed-lock.js';
import { LeaderElection } from './redis/leader.js';
import { WorkerRedis } from './redis/redis.js';
import { WorkerIdentity } from './redis/worker-identity.js';
import { WorkDirCleaner } from './scan/work-dirs.js';
import { SchemaGate } from './schema-gate.js';
import { SystemProcessor } from './jobs/system.processor.js';
import {
  execFileRunner,
  PROCESS_RUNNER,
  PROCESS_STREAMER,
  spawnStreamer,
  SshClient,
} from './ssh/ssh-client.js';
import { loggedRunner, loggedStreamer } from './jobs/logged-process.js';
import { JobRunLogs } from './jobs/job-run-logs.js';
import { SshIdentities } from './ssh/ssh-identity.js';
import { HostScanner } from './scan/host-scanner.js';
import { SbomReevaluator } from './scan/sbom-reevaluator.js';
import { ScanScheduler } from './scan/scan-scheduler.js';
import { InventoryReconciler } from './inventory/reconciler.js';
import { ListingReconciler } from './inventory/listing-reconciler.js';
import { DomainLinker } from './domains/domain-linker.js';
import { ServiceLinker } from './domains/service-linker.js';
import { DomainSync } from './domains/domain-sync.js';
import { ExpiryAlerts } from './domains/expiry-alerts.js';
import { TrivyRunner } from './scan/trivy-runner.js';
import { IntelUpdater } from './intel/intel-updater.js';
import { FindingPrioritizer } from './intel/prioritizer.js';
import { MetricSampler } from './metrics/metric-sampler.js';
import { AlertDelivery } from './alerts/alert-delivery.js';
import { EmailSender } from './alerts/email-sender.js';
import { AcceptanceExpiry } from './scan/acceptance-expiry.js';
import { PrioritizeTrigger } from './intel/prioritize-trigger.js';
import { WorkerLifecycle } from './worker.lifecycle.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ENV_FILES,
      validate: validateEnv,
    }),
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
    BullModule.registerQueue(
      ...Object.values(QUEUE_NAMES).map((name) => ({ name })),
    ),
    DatabaseModule,
    // Mismos proveedores y clave maestra que la API.
    SecretsModule.forRoot({
      inject: [ConfigService],
      useFactory: (config: ConfigService<EnvironmentVariables, true>) => ({
        enabled: secretsProviders(
          config.get('SECRETS_PROVIDERS', { infer: true }),
        ),
        local: {
          key: config.get('SECRETS_LOCAL_MASTER_KEY', { infer: true }),
          file: config.get('SECRETS_LOCAL_MASTER_KEY_FILE', { infer: true }),
        },
        openbao: openBaoSourceFromEnv((name) =>
          config.get(name as keyof EnvironmentVariables, { infer: true }),
        ),
        cacheTtlSeconds: config.get('SECRETS_CACHE_TTL', { infer: true }),
      }),
    }),
  ],
  providers: [
    WorkerLifecycle,
    SystemProcessor,
    EnrollmentProcessor,
    DiscoveryProcessor,
    ScanProcessor,
    WorkerRedis,
    WorkerIdentity,
    DistributedLock,
    LeaderElection,
    JobQueues,
    JobRuns,
    JobRunLogs,
    JobRunner,
    WorkerPool,
    HostSlots,
    JobEventsListener,
    OrphanSweeper,
    LeaderTasks,
    WorkDirCleaner,
    SchemaGate,
    SshClient,
    SshIdentities,
    AnsibleRunner,
    AssetRoutes,
    ScanScheduler,
    TrivyRunner,
    HostScanner,
    SbomReevaluator,
    InventoryReconciler,
    ListingReconciler,
    DomainLinker,
    ServiceLinker,
    DomainSync,
    ExpiryAlerts,
    IntelUpdater,
    FindingPrioritizer,
    MetricSampler,
    PrioritizeTrigger,
    AcceptanceExpiry,
    AlertDelivery,
    EmailSender,
    // Cada proceso de un job deja su comando, duración y fallo en el log de la ejecución.
    { provide: PROCESS_RUNNER, useValue: loggedRunner(execFileRunner) },
    { provide: PROCESS_STREAMER, useValue: loggedStreamer(spawnStreamer) },
    { provide: DISCOVERERS, useFactory: createDiscoverers },
  ],
})
export class WorkerModule {}
