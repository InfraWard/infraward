import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CSRF_HEADER } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import {
  webOrigins,
  type EnvironmentVariables,
} from '../config/env.validation.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Guard global (tras el de sesión): en POST/PUT/PATCH/DELETE,
 * - si el navegador dice de dónde viene (`Origin`, `Sec-Fetch-Site`), tiene que ser la web
 *   (también en los @Public(), p. ej. el login: evita el CSRF de login);
 * - con sesión, exige `X-CSRF-Token` igual al de la sesión. El token no está en ninguna cookie:
 *   la web lo recibe en el cuerpo de /auth/login y /auth/session y lo guarda en memoria.
 * Las llamadas sin navegador (el script de alta con curl) no mandan Origin ni cookie.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly origins: Set<string>;

  constructor(config: ConfigService<EnvironmentVariables, true>) {
    this.origins = new Set(
      webOrigins({
        WEB_ORIGIN: config.get('WEB_ORIGIN', { infer: true }),
        PUBLIC_URL: config.get('PUBLIC_URL', { infer: true }),
        NODE_ENV: config.get('NODE_ENV', { infer: true }),
      }),
    );
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    if (SAFE_METHODS.has(request.method)) return true;

    const origin = header(request, 'origin');
    if (origin !== undefined && !this.origins.has(origin))
      throw forbidden('Origen no permitido');
    if (header(request, 'sec-fetch-site') === 'cross-site')
      throw forbidden('Petición entre sitios');

    const session = request.authSession;
    if (!session) return true;
    const sent = header(request, CSRF_HEADER);
    if (!sent || !sameToken(sent, session.csrfToken))
      throw forbidden('Falta el token CSRF o no es válido');
    return true;
  }
}

function header(request: FastifyRequest, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function sameToken(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function forbidden(message: string): ForbiddenException {
  return new ForbiddenException({ statusCode: 403, code: 'csrf', message });
}
