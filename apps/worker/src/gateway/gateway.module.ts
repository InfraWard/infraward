import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { createDiscoverers } from '@infraward/connectors';
import { DOMAIN_ENTITIES } from '@infraward/domain';
import { AssetRoutes, DISCOVERERS } from '../jobs/asset-routes.js';
import { HostSlots } from '../jobs/host-slots.js';
import { WorkerRedis } from '../redis/redis.js';
import { WorkerIdentity } from '../redis/worker-identity.js';
import { SchemaGate } from '../schema-gate.js';
import { execFileRunner, PROCESS_RUNNER, SshClient } from '../ssh/ssh-client.js';
import { GatewayApiClient } from './gateway-api.client.js';
import { GATEWAY_ENV_FILES, validateGatewayEnv, type GatewayEnvironment } from './gateway.env.js';
import { GatewayIdentity, GatewayLifecycle } from './gateway.lifecycle.js';
import { GatewayControl } from './gateway-control.js';
import { GatewayServer } from './gateway.server.js';
import { InteractiveRoutes } from './interactive-routes.js';
import { PinnedHostKeys } from './pinned-host-keys.js';

/**
 * Modo `gateway` del worker (sesión 21, DESIGN §3 y §11): mismo código e imagen, otro proceso.
 * Solo atiende sesiones interactivas: sin colas, sin líder y **sin `SecretsModule`** (los
 * certificados los firma la API). Lee la BD solo para resolver las rutas de los assets.
 */
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: GATEWAY_ENV_FILES,
      validate: validateGatewayEnv,
    }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<GatewayEnvironment, true>) => ({
        type: 'postgres',
        host: config.get('DATABASE_HOST', { infer: true }),
        port: config.get('DATABASE_PORT', { infer: true }),
        username: config.get('DATABASE_USER', { infer: true }),
        password: config.get('DATABASE_PASSWORD', { infer: true }),
        database: config.get('DATABASE_NAME', { infer: true }),
        // Solo el inventario: ni la tabla de secretos locales ni nada de la API.
        entities: DOMAIN_ENTITIES,
        synchronize: false,
        migrationsRun: false,
        logging: ['error', 'warn'],
      }),
    }),
  ],
  providers: [
    WorkerRedis,
    { provide: WorkerIdentity, useClass: GatewayIdentity },
    HostSlots,
    SchemaGate,
    { provide: PROCESS_RUNNER, useValue: execFileRunner },
    SshClient,
    { provide: DISCOVERERS, useFactory: createDiscoverers },
    AssetRoutes,
    InteractiveRoutes,
    PinnedHostKeys,
    GatewayApiClient,
    GatewayServer,
    GatewayControl,
    GatewayLifecycle,
  ],
})
export class GatewayModule {}
