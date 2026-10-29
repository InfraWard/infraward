import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  TERMINAL_CONTROL_CHANNEL,
  type TerminalControlMessage,
} from '@infraward/shared-types';
import type { Redis } from 'ioredis';
import { WorkerRedis } from '../redis/redis.js';
import { GatewayApiClient } from './gateway-api.client.js';
import type { GatewayEnvironment } from './gateway.env.js';
import { GatewayServer } from './gateway.server.js';

/**
 * Lo que une el gateway con la API mientras hay sesiones (sesión 22, DESIGN §11):
 * - **cortes al momento**: suscrito al canal de Redis en el que la API pide cortar sesiones
 *   (sesión web cerrada, persona desactivada, permiso retirado); corta las suyas;
 * - **latido** cada `GATEWAY_HEARTBEAT_INTERVAL` con sus sesiones: la API las da por vivas (si
 *   el gateway muere, el barrido de la API las cierra) y devuelve las que hay que cortar (por si
 *   se perdió el aviso).
 */
@Injectable()
export class GatewayControl {
  private readonly logger = new Logger(GatewayControl.name);
  private subscriber?: Redis;
  private timer?: NodeJS.Timeout;
  private beating = false;

  constructor(
    private readonly config: ConfigService<GatewayEnvironment, true>,
    private readonly redis: WorkerRedis,
    private readonly api: GatewayApiClient,
    private readonly server: GatewayServer,
  ) {}

  async start(gatewayName: string): Promise<void> {
    this.subscriber = this.redis.client.duplicate();
    this.subscriber.on('error', (error: Error) =>
      this.logger.warn(`Canal de control: ${error.message}`),
    );
    this.subscriber.on('message', (_channel: string, raw: string) => this.onMessage(raw));
    await this.subscriber.subscribe(TERMINAL_CONTROL_CHANNEL);
    const every = this.config.get('GATEWAY_HEARTBEAT_INTERVAL', { infer: true }) * 1000;
    this.timer = setInterval(() => void this.beat(gatewayName), every);
    this.timer.unref();
  }

  /** Tras la parada ordenada (las sesiones laten mientras dura la gracia). */
  async stop(): Promise<void> {
    clearInterval(this.timer);
    await this.subscriber?.quit().catch(() => undefined);
  }

  /** Un latido; si la API no responde, se intenta en el siguiente (las sesiones siguen). */
  async beat(gatewayName: string): Promise<void> {
    if (this.beating) return;
    this.beating = true;
    try {
      const sessions = this.server
        .liveSessions()
        .map((s) => ({ id: s.id!, active: s.takeActivity() }));
      if (sessions.length === 0) return;
      const { revoke } = await this.api.heartbeat({ gateway: gatewayName, sessions });
      this.server.revoke(revoke);
    } catch (error) {
      this.logger.warn(`Latido sin respuesta de la API: ${(error as Error).message}`);
    } finally {
      this.beating = false;
    }
  }

  private onMessage(raw: string): void {
    let message: TerminalControlMessage;
    try {
      message = JSON.parse(raw) as TerminalControlMessage;
    } catch {
      return;
    }
    if (message?.type !== 'revoke' || !Array.isArray(message.sessions)) return;
    this.server.revoke(
      message.sessions.filter(
        (s): s is { id: string; message: string } =>
          typeof s?.id === 'string' && typeof s.message === 'string',
      ),
    );
  }
}
