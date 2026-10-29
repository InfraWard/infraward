import {
  Injectable,
  Logger,
  type BeforeApplicationShutdown,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { WorkerRedis } from '../redis/redis.js';
import { WorkerIdentity } from '../redis/worker-identity.js';
import { SchemaGate } from '../schema-gate.js';
import type { GatewayEnvironment } from './gateway.env.js';
import { GatewayControl } from './gateway-control.js';
import { GatewayServer } from './gateway.server.js';

/**
 * Identidad del gateway: `gateway-<n>` (o `GATEWAY_NAME`), con el mismo lease en Redis que las
 * réplicas del worker. No publica ficha de réplica: no consume colas.
 */
@Injectable()
export class GatewayIdentity extends WorkerIdentity {
  protected override get prefix(): string {
    return 'gateway';
  }

  protected override get nameVariable(): string {
    return 'GATEWAY_NAME';
  }
}

/**
 * Arranque y parada del modo `gateway` (sesión 21): esquema al día, nombre, y el servidor de la
 * terminal. Al parar, avisa a las sesiones abiertas y espera como mucho `GATEWAY_SHUTDOWN_GRACE`
 * antes de cerrarlas limpiamente (un reinicio del worker de jobs no las afecta: es otro proceso).
 */
@Injectable()
export class GatewayLifecycle implements OnApplicationBootstrap, BeforeApplicationShutdown {
  private readonly logger = new Logger(GatewayLifecycle.name);

  constructor(
    private readonly config: ConfigService<GatewayEnvironment, true>,
    private readonly redis: WorkerRedis,
    private readonly schema: SchemaGate,
    private readonly identity: WorkerIdentity,
    private readonly server: GatewayServer,
    private readonly control: GatewayControl,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.redis.client.connect();
    await this.schema.wait();
    const name = await this.identity.claim();
    const port = await this.server.listen(name);
    await this.control.start(name);
    this.logger.log(`Gateway listo (${name}) en el puerto ${port}`);
  }

  async beforeApplicationShutdown(signal?: string): Promise<void> {
    this.logger.log(`Parando el gateway${signal ? ` (${signal})` : ''}`);
    await this.server.drain(this.config.get('GATEWAY_SHUTDOWN_GRACE', { infer: true }) * 1000);
    await this.control.stop();
    await this.identity.release();
  }
}
