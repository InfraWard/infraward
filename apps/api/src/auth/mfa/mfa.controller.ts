import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  MfaSetupResponse,
  MfaStatus,
  ReauthResponse,
  RecoveryCodesResponse,
  SessionInfo,
  UserSummary,
} from '@infraward/shared-types';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AuditCtx, type AuditActor } from '../../audit/audit-context.decorator.js';
import type { EnvironmentVariables } from '../../config/env.validation.js';
import { UserSummaryDto } from '../../users/users.dto.js';
import { UsersService } from '../../users/users.service.js';
import { SessionInfoDto } from '../auth.dto.js';
import { AuthService } from '../auth.service.js';
import type { AuthenticatedUser, RequestSession } from '../authenticated-user.js';
import { clientOf } from '../client-context.js';
import { CurrentSession, CurrentUser } from '../current-user.decorator.js';
import { Can } from '../permissions.decorator.js';
import {
  AllowMfaPending,
  AllowMfaSetup,
  SessionOnly,
} from '../public.decorator.js';
import { RecentAuth } from '../recent-auth.decorator.js';
import { setSessionCookie } from '../session-cookie.js';
import {
  MfaCodeDto,
  MfaSetupResponseDto,
  MfaStatusDto,
  ReauthDto,
  ReauthResponseDto,
  RecoveryCodesResponseDto,
} from './mfa.dto.js';
import { MfaThrottlerGuard } from './mfa-throttler.guard.js';
import { MfaService } from './mfa.service.js';

/**
 * Verificación en dos pasos (TOTP) y reautenticación reciente de los usuarios locales
 * (DESIGN §14). Todo con la sesión web; los códigos, con el límite de intentos por usuario.
 */
@ApiTags('auth')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@SessionOnly()
@Controller('auth')
export class MfaController {
  private readonly secure: boolean;

  constructor(
    private readonly mfa: MfaService,
    private readonly auth: AuthService,
    private readonly users: UsersService,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.secure = config.get('SESSION_COOKIE_SECURE', { infer: true });
  }

  @Get('mfa')
  @AllowMfaSetup()
  @ApiOkResponse({ type: MfaStatusDto })
  async status(@CurrentUser() user: AuthenticatedUser): Promise<MfaStatus> {
    return this.mfa.status(await this.requireUser(user.id));
  }

  /**
   * Segundo paso del login con la sesión intermedia: abre la sesión de verdad (cookie nueva).
   * 400 con un código incorrecto; al quinto, 401 y hay que volver a entrar.
   */
  @Post('mfa/verify')
  @AllowMfaPending()
  @UseGuards(MfaThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: SessionInfoDto })
  @ApiBadRequestResponse({ description: 'Código incorrecto' })
  @ApiTooManyRequestsResponse()
  async verify(
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession,
    @Body() body: MfaCodeDto,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<SessionInfo> {
    const { token, info } = await this.auth.verifyMfa(
      user.id,
      session,
      body.code,
      clientOf(request),
    );
    setSessionCookie(reply, token, this.secure);
    return info;
  }

  /**
   * Empieza el alta (o el cambio de dispositivo, que exige reautenticación): el secreto y el QR
   * se enseñan una vez; no vale hasta confirmarlo con `mfa/enable`.
   */
  @Post('mfa/setup')
  @AllowMfaSetup()
  @RecentAuth('mfa.replace', (request) => request.user?.mfaEnabled === true)
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: MfaSetupResponseDto })
  @ApiConflictResponse({ description: 'Cuenta OIDC (el MFA lo aplica el proveedor)' })
  @ApiForbiddenResponse({ description: 'Cambio de dispositivo sin reautenticación reciente' })
  setup(@CurrentUser() user: AuthenticatedUser): Promise<MfaSetupResponse> {
    return this.mfa.beginSetup(user.id);
  }

  /** Confirma el alta con un código de la app; devuelve los códigos de recuperación (una vez). */
  @Post('mfa/enable')
  @AllowMfaSetup()
  @UseGuards(MfaThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: RecoveryCodesResponseDto })
  @ApiBadRequestResponse({ description: 'Código incorrecto' })
  @ApiConflictResponse({ description: 'No hay un alta en curso' })
  @ApiTooManyRequestsResponse()
  enable(
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession,
    @Body() body: MfaCodeDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<RecoveryCodesResponse> {
    return this.mfa.enable(user.id, body.code, session.id, actor);
  }

  @Post('mfa/disable')
  @RecentAuth('mfa.disable')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  @ApiConflictResponse({ description: 'Admin local: le es obligatoria' })
  async disable(
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<void> {
    await this.mfa.disable(user.id, actor);
  }

  @Post('mfa/recovery-codes')
  @RecentAuth('mfa.recovery_regenerate')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: RecoveryCodesResponseDto })
  regenerate(
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<RecoveryCodesResponse> {
    return this.mfa.regenerateRecoveryCodes(user.id, actor);
  }

  /**
   * Reautenticación reciente (step-up) con un código TOTP o de recuperación: durante
   * REAUTH_MAX_AGE, las acciones sensibles no lo vuelven a pedir.
   */
  @Post('reauth')
  @UseGuards(MfaThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: ReauthResponseDto })
  @ApiBadRequestResponse({ description: 'Código incorrecto' })
  @ApiConflictResponse({
    description: 'Sesión OIDC (se reautentica en el proveedor) o usuario sin TOTP',
  })
  @ApiTooManyRequestsResponse()
  reauth(
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession,
    @Body() body: ReauthDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<ReauthResponse> {
    return this.auth.reauthenticate(user.id, session, body.code, body.action, actor);
  }

  private async requireUser(id: string) {
    const found = await this.users.findById(id);
    if (!found) throw new UnauthorizedException();
    return found;
  }
}

/** Un admin quita la verificación en dos pasos de otro usuario (perdió el dispositivo). */
@ApiTags('users')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Requiere users.manage y reautenticación reciente' })
@SessionOnly()
@Can('users.manage')
@Controller('users')
export class MfaAdminController {
  constructor(
    private readonly mfa: MfaService,
    private readonly users: UsersService,
  ) {}

  @Post(':id/mfa/reset')
  @RecentAuth('user.mfa_reset')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: UserSummaryDto })
  @ApiNotFoundResponse()
  @ApiBadRequestResponse({ description: 'Tu propia cuenta (usa tu perfil)' })
  @ApiConflictResponse({ description: 'No la tiene activada' })
  async reset(
    @Param('id', new ParseUUIDPipe()) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<UserSummary> {
    return this.users.summary(await this.mfa.adminReset(id, actor));
  }
}
