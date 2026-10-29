import { Injectable, type OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import { createHash } from 'node:crypto';
import type { EnvironmentVariables } from '../../config/env.validation.js';

/** Vida de un flujo de login OIDC sin completar (y de su cookie). */
export const OIDC_FLOW_TTL_SECONDS = 600;
const KEY_PREFIX = 'infraward:oidc:flow:';

/** Lo que se guarda al empezar el flujo y se consume (una vez) en el callback. */
export interface OidcFlowState {
  /** sha256 del token de la cookie del navegador que empezó el flujo. */
  bindingHash: string;
  codeVerifier: string;
  nonce: string;
  returnUrl: string;
  /**
   * Reautenticación (step-up) de una sesión ya abierta, no un login: a la vuelta se marca esa
   * sesión (la cookie Strict de la sesión no llega al callback, que viene de otro sitio).
   */
  reauth?: { sessionId: string; userId: string; startedAt: number };
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Estado de los flujos OIDC en curso, en Redis (compartido entre réplicas), con caducidad y de
 * un solo uso: `take` lo lee y lo borra a la vez (GETDEL), así que un `state` repetido falla.
 * La clave es el sha256 del `state`.
 */
@Injectable()
export class OidcStateStore implements OnModuleDestroy {
  private client: Redis | null = null;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  async save(state: string, flow: OidcFlowState): Promise<void> {
    await this.redis().set(
      KEY_PREFIX + sha256Hex(state),
      JSON.stringify(flow),
      'EX',
      OIDC_FLOW_TTL_SECONDS,
    );
  }

  async take(state: string): Promise<OidcFlowState | null> {
    const raw = await this.redis().getdel(KEY_PREFIX + sha256Hex(state));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as OidcFlowState;
    } catch {
      return null;
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.client?.quit().catch(() => undefined);
  }

  /** Conexión perezosa: sin OIDC configurado nunca se abre. */
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
