import { Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  TERMINAL_CONTROL_CHANNEL,
  type TerminalControlMessage,
  type TerminalRevocation,
} from '@infraward/shared-types';
import { Redis } from 'ioredis';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Canal API → gateways (sesión 22): pide cortar sesiones al momento por pub/sub de Redis. Cada
 * gateway corta las suyas. Si el aviso se pierde (Redis caído, gateway reconectando), el
 * siguiente latido devuelve las mismas sesiones (`POST /internal/gateway/heartbeat`).
 */
@Injectable()
export class TerminalControl implements OnModuleDestroy {
  private readonly logger = new Logger(TerminalControl.name);
  private client?: Redis;

  constructor(private readonly config: ConfigService<EnvironmentVariables, true>) {}

  async revoke(sessions: TerminalRevocation[]): Promise<void> {
    if (sessions.length === 0) return;
    const message: TerminalControlMessage = { type: 'revoke', sessions };
    try {
      await this.redis().publish(TERMINAL_CONTROL_CHANNEL, JSON.stringify(message));
    } catch (error) {
      this.logger.warn(
        `No se pudo avisar al gateway (lo hará el siguiente latido): ${(error as Error).message}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.client?.quit().catch(() => undefined);
  }

  /** Conexión perezosa: sin terminales que cortar nunca se abre. */
  private redis(): Redis {
    this.client ??= new Redis({
      host: this.config.get('REDIS_HOST', { infer: true }),
      port: this.config.get('REDIS_PORT', { infer: true }),
      password: this.config.get('REDIS_PASSWORD', { infer: true }),
      db: this.config.get('REDIS_DB', { infer: true }),
      maxRetriesPerRequest: 2,
    });
    return this.client;
  }
}
