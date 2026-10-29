import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerGuard, type ThrottlerRequest } from '@nestjs/throttler';
import type { FastifyRequest } from 'fastify';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Límite de revelados por usuario (no por IP), además de la reautenticación: una sesión robada
 * y recién reautenticada no puede vaciar la caja fuerte de golpe. Va tras los guards globales.
 */
@Injectable()
export class VaultRevealThrottlerGuard extends ThrottlerGuard {
  @Inject(ConfigService)
  private readonly config: ConfigService<EnvironmentVariables, true>;

  protected override handleRequest(props: ThrottlerRequest): Promise<boolean> {
    const ttl = this.config.get('VAULT_REVEAL_THROTTLE_TTL', { infer: true }) * 1000;
    return super.handleRequest({
      ...props,
      limit: this.config.get('VAULT_REVEAL_THROTTLE_LIMIT', { infer: true }),
      ttl,
      blockDuration: ttl,
      getTracker: (req: Record<string, unknown>) => {
        const user = (req as unknown as FastifyRequest).user;
        return user ? `vault-reveal:${user.id}` : this.getTracker(req);
      },
    });
  }
}
