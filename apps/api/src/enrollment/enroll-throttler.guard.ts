import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerGuard, type ThrottlerRequest } from '@nestjs/throttler';
import type { EnvironmentVariables } from '../config/env.validation.js';

/**
 * Límite por IP de `/enroll/*`, que son públicos (solo llevan el token). Los tokens tienen
 * 256 bits y no se pueden adivinar; el límite evita que se usen para machacar la API.
 */
@Injectable()
export class EnrollThrottlerGuard extends ThrottlerGuard {
  @Inject(ConfigService)
  private readonly config: ConfigService<EnvironmentVariables, true>;

  protected override handleRequest(props: ThrottlerRequest): Promise<boolean> {
    const ttl = this.config.get('ENROLL_THROTTLE_TTL', { infer: true }) * 1000;
    return super.handleRequest({
      ...props,
      limit: this.config.get('ENROLL_THROTTLE_LIMIT', { infer: true }),
      ttl,
      blockDuration: ttl,
    });
  }
}
