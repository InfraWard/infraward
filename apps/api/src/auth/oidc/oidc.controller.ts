import {
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiFoundResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiQuery,
  ApiTags,
  ApiTooManyRequestsResponse,
} from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { AuthProviders } from '@infraward/shared-types';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AuditService } from '../../audit/audit.service.js';
import type { EnvironmentVariables } from '../../config/env.validation.js';
import { AuthProvidersDto } from '../auth.dto.js';
import type {
  AuthenticatedUser,
  RequestSession,
} from '../authenticated-user.js';
import { CurrentSession, CurrentUser } from '../current-user.decorator.js';
import { Public, SessionOnly } from '../public.decorator.js';
import { setSessionCookie } from '../session-cookie.js';
import { clientOf } from '../client-context.js';
import { OidcService, withReauthResult } from './oidc.service.js';
import { safeReturnPath } from './oidc-settings.js';
import { OIDC_FLOW_TTL_SECONDS } from './oidc-state.store.js';

/**
 * Cookie que ata un flujo OIDC al navegador que lo empezó. SameSite=Lax (no Strict): el
 * callback llega como navegación desde el proveedor (otro sitio) y tiene que llevarla.
 */
export function oidcFlowCookieName(secure: boolean): string {
  return secure ? '__Host-iw_oidc' : 'iw_oidc';
}

@ApiTags('auth')
@Controller('auth')
export class OidcController {
  private readonly secure: boolean;
  private readonly localLogin: boolean;

  constructor(
    private readonly oidc: OidcService,
    private readonly audit: AuditService,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.secure = config.get('SESSION_COOKIE_SECURE', { infer: true });
    this.localLogin = config.get('LOCAL_LOGIN', { infer: true });
  }

  /** Cómo se puede entrar: la web enseña el formulario, el botón del proveedor o los dos. */
  @Public()
  @Get('providers')
  @ApiOkResponse({ type: AuthProvidersDto })
  providers(): AuthProviders {
    const settings = this.oidc.settings;
    return {
      local: this.localLogin,
      oidc: settings ? { name: settings.providerName } : null,
    };
  }

  /** Empieza el login con el proveedor: redirige a su página de autorización. */
  @Public()
  @Get('oidc/login')
  @UseGuards(ThrottlerGuard)
  @ApiQuery({ name: 'returnUrl', required: false })
  @ApiFoundResponse({
    description: 'Redirección al proveedor (o a /login si no responde)',
  })
  @ApiNotFoundResponse({ description: 'OIDC no está configurado' })
  @ApiTooManyRequestsResponse()
  async login(
    @Query('returnUrl') returnUrl: unknown,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const settings = this.oidc.settings;
    if (!settings) throw new NotFoundException();
    try {
      const { authorizationUrl, bindingToken } =
        await this.oidc.begin(returnUrl);
      this.setFlowCookie(reply, bindingToken);
      return reply.redirect(authorizationUrl, 302);
    } catch {
      await this.audit.record(
        { actorId: null, actorEmail: null, ip: clientOf(request).ip },
        'auth.login_failed',
        {
          outcome: 'failure',
          details: { method: 'oidc', reason: 'provider_unavailable' },
        },
      );
      return reply.redirect(
        `${settings.webOrigin}/login?oidcError=unavailable`,
        302,
      );
    }
  }

  /**
   * Reautenticación (step-up) de la sesión actual con el proveedor: navegación completa desde la
   * web (la cookie Strict de la sesión va con ella). El proveedor pide otra vez las credenciales
   * (`prompt=login`, `max_age=0`) y el callback marca la sesión y vuelve a `returnUrl?reauth=ok`.
   */
  @Get('oidc/reauth')
  @SessionOnly()
  @UseGuards(ThrottlerGuard)
  @ApiQuery({ name: 'returnUrl', required: false })
  @ApiFoundResponse({ description: 'Redirección al proveedor' })
  @ApiNotFoundResponse({ description: 'OIDC no está configurado' })
  @ApiTooManyRequestsResponse()
  async reauth(
    @Query('returnUrl') returnUrl: unknown,
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const settings = this.oidc.settings;
    if (!settings) throw new NotFoundException();
    if (session.authMethod !== 'oidc')
      throw new ConflictException(
        'Tu sesión no viene del proveedor OIDC: confirma tu identidad con tu código',
      );
    try {
      const { authorizationUrl, bindingToken } = await this.oidc.begin(
        returnUrl,
        { sessionId: session.id, userId: user.id },
      );
      this.setFlowCookie(reply, bindingToken);
      return reply.redirect(authorizationUrl, 302);
    } catch {
      return reply.redirect(
        settings.webOrigin + withReauthResult(safeReturnPath(returnUrl), 'failed'),
        302,
      );
    }
  }

  /**
   * Vuelta del proveedor: valida y abre la sesión de siempre (cookie httpOnly) o vuelve a /login
   * con un código de error genérico (el motivo concreto queda en la auditoría).
   */
  @Public()
  @Get('oidc/callback')
  @UseGuards(ThrottlerGuard)
  @ApiFoundResponse({
    description: 'A la web con la sesión abierta, o a /login?oidcError=…',
  })
  @ApiNotFoundResponse({ description: 'OIDC no está configurado' })
  @ApiTooManyRequestsResponse()
  async callback(
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    if (!this.oidc.settings) throw new NotFoundException();
    const cookieName = oidcFlowCookieName(this.secure);
    const query = Object.fromEntries(
      Object.entries((request.query ?? {}) as Record<string, unknown>).filter(
        (entry): entry is [string, string] => typeof entry[1] === 'string',
      ),
    );
    const result = await this.oidc.complete(
      query,
      request.cookies?.[cookieName],
      clientOf(request),
    );
    void reply.clearCookie(cookieName, {
      httpOnly: true,
      secure: this.secure,
      sameSite: 'lax',
      path: '/',
    });
    if (result.ok && result.sessionToken)
      setSessionCookie(reply, result.sessionToken, this.secure);
    return reply.redirect(result.redirectUrl, 302);
  }

  private setFlowCookie(reply: FastifyReply, bindingToken: string): void {
    void reply.setCookie(oidcFlowCookieName(this.secure), bindingToken, {
      httpOnly: true,
      secure: this.secure,
      sameSite: 'lax',
      path: '/',
      maxAge: OIDC_FLOW_TTL_SECONDS,
    });
  }
}
