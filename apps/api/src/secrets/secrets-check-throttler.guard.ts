import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerGuard, type ThrottlerRequest } from '@nestjs/throttler';
import type { FastifyRequest } from 'fastify';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Límite de `POST /secrets/check` por usuario (no por IP: detrás de un proxy todos los admins
 * compartirían IP). Evita sondear en masa qué referencias existen. Va detrás de los guards
 * globales, así que solo cuenta peticiones de admins autenticados.
 */
@Injectable()
export class SecretsCheckThrottlerGuard extends ThrottlerGuard {
  @Inject(ConfigService)
  private readonly config: ConfigService<EnvironmentVariables, true>;

  protected override handleRequest(props: ThrottlerRequest): Promise<boolean> {
    const ttl =
      this.config.get('SECRETS_CHECK_THROTTLE_TTL', { infer: true }) * 1000;
    return super.handleRequest({
      ...props,
      limit: this.config.get('SECRETS_CHECK_THROTTLE_LIMIT', { infer: true }),
      ttl,
      blockDuration: ttl,
      getTracker: (req: Record<string, unknown>) => {
        const user = (req as unknown as FastifyRequest).user;
        return user ? `user:${user.id}` : this.getTracker(req);
      },
    });
  }
}
