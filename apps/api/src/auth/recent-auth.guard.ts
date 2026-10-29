import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import {
  MFA_REQUIRED_FOR_ACTION,
  RECENT_AUTH_REQUIRED,
  SENSITIVE_ACTIONS,
  type RecentAuthError,
} from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { auditActorOf } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { RequestSession } from './authenticated-user.js';
import { RECENT_AUTH, type RecentAuthRule } from './recent-auth.decorator.js';

/** ¿Se confirmó la identidad de esta sesión hace menos de `maxAgeMs`? */
export function isRecentlyAuthenticated(
  session: Pick<RequestSession, 'reauthenticatedAt'>,
  maxAgeMs: number,
  now = Date.now(),
): boolean {
  const at = session.reauthenticatedAt?.getTime();
  // Un `auth_time` del proveedor un poco adelantado sigue valiendo; uno del futuro lejano, no.
  return at !== undefined && now - at < maxAgeMs && at - now < 60_000;
}

/**
 * Guard global, el último (tras sesión, CSRF y permisos): aplica `@RecentAuth()` (DESIGN §14).
 * - Con un token de API: 403 `recent_auth_required` sin método (solo desde la web).
 * - Usuario que entró con contraseña y sin TOTP: 403 `mfa_required_for_action` (debe activarlo).
 * - Sin una reautenticación en los últimos REAUTH_MAX_AGE segundos: 403 `recent_auth_required`
 *   con el método (`totp` o `oidc`). La web lo pide y repite la petición.
 * Cada rechazo queda en la auditoría (`auth.reauth_required`).
 */
@Injectable()
export class RecentAuthGuard implements CanActivate {
  private readonly maxAgeMs: number;

  constructor(
    private readonly reflector: Reflector,
    private readonly audit: AuditService,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.maxAgeMs = config.get('REAUTH_MAX_AGE', { infer: true }) * 1000;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const rule = this.reflector.get<RecentAuthRule | undefined>(
      RECENT_AUTH,
      context.getHandler(),
    );
    if (!rule) return true;
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    if (rule.when && !rule.when(request)) return true;

    const session = request.authSession;
    let error: RecentAuthError;
    if (!session || request.apiToken) {
      error = this.error(
        RECENT_AUTH_REQUIRED,
        rule,
        null,
        'Esta acción solo se puede hacer desde la web, confirmando tu identidad',
      );
    } else if (session.authMethod === 'password' && !request.user?.mfaEnabled) {
      error = this.error(
        MFA_REQUIRED_FOR_ACTION,
        rule,
        'totp',
        'Activa la verificación en dos pasos en tu perfil para hacer esto',
      );
    } else if (isRecentlyAuthenticated(session, this.maxAgeMs)) {
      return true;
    } else {
      error = this.error(
        RECENT_AUTH_REQUIRED,
        rule,
        session.authMethod === 'oidc' ? 'oidc' : 'totp',
        'Confirma tu identidad para continuar',
      );
    }
    await this.audit.record(auditActorOf(request), 'auth.reauth_required', {
      outcome: 'failure',
      details: {
        action: rule.action,
        reason: error.code,
        method: error.method,
      },
    });
    throw new ForbiddenException(error);
  }

  private error(
    code: RecentAuthError['code'],
    rule: RecentAuthRule,
    method: RecentAuthError['method'],
    message: string,
  ): RecentAuthError {
    return {
      statusCode: 403,
      code,
      message: `${SENSITIVE_ACTIONS[rule.action]}: ${message.charAt(0).toLowerCase()}${message.slice(1)}`,
      action: rule.action,
      method,
    };
  }
}
