import { Injectable } from '@nestjs/common';
import { ThrottlerGuard, type ThrottlerRequest } from '@nestjs/throttler';
import { createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';

/**
 * Límite de los códigos TOTP y de recuperación (segundo paso del login, reautenticación y alta),
 * con LOGIN_THROTTLE_LIMIT/TTL como el login, pero **por usuario** y compartido entre esas
 * rutas: repartir los intentos entre IPs o endpoints no permite adivinar un código de 6 cifras.
 * Sin usuario (no debería pasar: son rutas con sesión), por IP.
 */
@Injectable()
export class MfaThrottlerGuard extends ThrottlerGuard {
  protected override handleRequest(props: ThrottlerRequest): Promise<boolean> {
    return super.handleRequest({
      ...props,
      getTracker: (req) => {
        const request = req as FastifyRequest;
        return Promise.resolve(
          request.user ? `user:${request.user.id}` : `ip:${request.ip}`,
        );
      },
      generateKey: (_context, tracker, name) =>
        createHash('sha256').update(`mfa-${name}-${tracker}`).digest('hex'),
    });
  }
}
