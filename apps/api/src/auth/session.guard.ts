import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import {
  API_TOKEN_PREFIX,
  MFA_PENDING,
  MFA_SETUP_REQUIRED,
  PASSWORD_CHANGE_REQUIRED,
  SESSION_REQUIRED,
} from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { ApiTokensService } from './api-tokens.service.js';
import { mfaSetupRequired } from './mfa/mfa-policy.js';
import {
  ALLOW_MFA_PENDING,
  ALLOW_MFA_SETUP,
  ALLOW_PASSWORD_CHANGE,
  IS_PUBLIC,
  SESSION_ONLY,
} from './public.decorator.js';
import { readSessionCookie } from './session-cookie.js';
import { SessionService } from './session.service.js';

/**
 * Guard global: exige la cookie de una sesión vigente o un token de API (`Authorization: Bearer`,
 * QoL-6) salvo en endpoints @Public(). El usuario y su rol se leen de la BD en cada petición:
 * desactivar a alguien o cambiarle el rol surte efecto al momento. Con un `Bearer iwt_…` manda el
 * token (aunque venga una cookie): uno inválido es 401. Otras cabeceras Authorization se ignoran.
 * La sesión intermedia del login (`mfa`) solo vale en `@AllowMfaPending()`, y un admin local que
 * entró con contraseña sin TOTP solo en `@AllowMfaSetup()` (se comprueba en cada petición: cubre
 * también a quien asciendan a admin con la sesión abierta).
 */
@Injectable()
export class SessionGuard implements CanActivate {
  private readonly secure: boolean;

  constructor(
    private readonly sessions: SessionService,
    private readonly apiTokens: ApiTokensService,
    private readonly reflector: Reflector,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.secure = config.get('SESSION_COOKIE_SECURE', { infer: true });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC,
      targets,
    );
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const bearer = readBearer(request);
    if (bearer !== null) {
      const resolved = await this.apiTokens.resolve(bearer, request.ip || null);
      if (!resolved) throw new UnauthorizedException();
      if (this.reflector.getAllAndOverride<boolean>(SESSION_ONLY, targets))
        throw new ForbiddenException({
          statusCode: 403,
          code: SESSION_REQUIRED,
          message: 'Este endpoint exige la sesión web, no un token de API',
        });
      const { token, user } = resolved;
      request.user = {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        mfaEnabled: Boolean(user.totpSecretRef),
      };
      request.apiToken = {
        id: token.id,
        scope: token.scope,
        prefix: token.prefix,
      };
      return true;
    }

    const token = readSessionCookie(request, this.secure);
    const resolved = token ? await this.sessions.resolve(token) : null;
    if (!resolved) throw new UnauthorizedException();

    const { session, user } = resolved;
    request.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      mfaEnabled: Boolean(user.totpSecretRef),
    };
    request.authSession = {
      id: session.id,
      purpose: session.purpose,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      authMethod: session.authMethod,
      reauthenticatedAt: session.reauthenticatedAt,
    };
    const allows = (key: string) =>
      this.reflector.getAllAndOverride<boolean>(key, targets) === true;
    if (session.purpose === 'mfa') {
      if (allows(ALLOW_MFA_PENDING)) return true;
      throw new ForbiddenException({
        statusCode: 403,
        code: MFA_PENDING,
        message: 'Falta el código de verificación',
      });
    }
    if (
      session.purpose === 'password_change' &&
      !this.reflector.getAllAndOverride<boolean>(ALLOW_PASSWORD_CHANGE, targets)
    ) {
      throw new ForbiddenException({
        statusCode: 403,
        code: PASSWORD_CHANGE_REQUIRED,
        message: 'Debes cambiar la contraseña temporal',
      });
    }
    if (
      session.purpose === 'full' &&
      mfaSetupRequired(user, session.authMethod) &&
      !allows(ALLOW_MFA_SETUP)
    )
      throw new ForbiddenException({
        statusCode: 403,
        code: MFA_SETUP_REQUIRED,
        message:
          'Los administradores deben configurar la verificación en dos pasos antes de seguir',
      });
    return true;
  }
}

/**
 * Token de API de `Authorization: Bearer iwt_…`, o null si no hay. Solo un Bearer con nuestro
 * prefijo cuenta: otras credenciales que el navegador o un proxy añaden solos (Basic guardado para
 * el host, el Bearer de un oauth2-proxy…) se ignoran y vale la cookie, como antes de QoL-6.
 */
function readBearer(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match?.[1].startsWith(API_TOKEN_PREFIX) ? match[1] : null;
}
