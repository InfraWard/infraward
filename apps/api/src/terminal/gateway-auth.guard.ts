import {
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { GATEWAY_AUTH_SCHEME } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { createHash, timingSafeEqual } from 'node:crypto';
import { GATEWAY_SECRET_HASH } from './terminal.tokens.js';

/**
 * Rutas internas del gateway (`/internal/gateway/*`): `Authorization: Gateway <secreto>`, con el
 * secreto de GATEWAY_API_SECRET_FILE (comparado por su sha256 en tiempo constante). Sin el
 * secreto configurado, las rutas no existen (404). Nunca se acepta una sesión ni un token de API.
 */
@Injectable()
export class GatewayAuthGuard implements CanActivate {
  constructor(@Inject(GATEWAY_SECRET_HASH) private readonly expected: Buffer | null) {}

  canActivate(context: ExecutionContext): boolean {
    if (!this.expected) throw new NotFoundException();
    const header = context.switchToHttp().getRequest<FastifyRequest>().headers.authorization;
    const prefix = `${GATEWAY_AUTH_SCHEME} `;
    if (typeof header !== 'string' || !header.startsWith(prefix) || header.length > 512)
      throw new UnauthorizedException();
    const given = createHash('sha256').update(header.slice(prefix.length), 'utf8').digest();
    if (!timingSafeEqual(given, this.expected)) throw new UnauthorizedException();
    return true;
  }
}

/** sha256 del secreto del gateway leído de su fichero (sin espacios ni saltos finales). */
export function gatewaySecretHash(secret: string): Buffer {
  const trimmed = secret.trim();
  if (trimmed.length < 32)
    throw new Error('GATEWAY_API_SECRET_FILE: el secreto debe tener al menos 32 caracteres');
  return createHash('sha256').update(trimmed, 'utf8').digest();
}
