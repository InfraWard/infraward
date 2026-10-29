import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Patch,
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
  ApiOkResponse,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { ThrottlerException, ThrottlerGuard } from '@nestjs/throttler';
import type {
  LogoutResponse,
  SessionInfo,
  UserProfile,
} from '@infraward/shared-types';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import {
  ChangeEmailDto,
  ChangePasswordDto,
  LoginDto,
  LogoutResponseDto,
  SessionInfoDto,
  UpdateProfileDto,
  UserProfileDto,
} from './auth.dto.js';
import { AuthService } from './auth.service.js';
import { clientOf } from './client-context.js';
import { LoginAccountLimiter } from './login-account-limiter.js';
import type {
  AuthenticatedUser,
  RequestSession,
} from './authenticated-user.js';
import { CurrentSession, CurrentUser } from './current-user.decorator.js';
import {
  AllowMfaPending,
  AllowMfaSetup,
  AllowPasswordChange,
  Public,
  SessionOnly,
} from './public.decorator.js';
import { clearSessionCookie, setSessionCookie } from './session-cookie.js';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly secure: boolean;

  constructor(
    private readonly auth: AuthService,
    private readonly accountLimiter: LoginAccountLimiter,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.secure = config.get('SESSION_COOKIE_SECURE', { infer: true });
  }

  /**
   * Abre la sesión: la cookie httpOnly lleva el token; el cuerpo, el token CSRF y el perfil.
   * Límites: por IP (ThrottlerGuard) y por cuenta (LoginAccountLimiter, solo los fallos).
   */
  @Public()
  @Post('login')
  @UseGuards(ThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: SessionInfoDto })
  @ApiUnauthorizedResponse({ description: 'Credenciales inválidas' })
  @ApiTooManyRequestsResponse({
    description: 'Demasiados intentos; reintentar tras Retry-After',
  })
  async login(
    @Body() body: LoginDto,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<SessionInfo> {
    const client = clientOf(request);
    const retryAfter = await this.accountLimiter.retryAfter(body.email, client.ip);
    if (retryAfter !== null) {
      void reply.header('Retry-After', String(retryAfter));
      throw new ThrottlerException();
    }
    let result: Awaited<ReturnType<AuthService['login']>>;
    try {
      result = await this.auth.login(body.email, body.password, client);
    } catch (error) {
      if (error instanceof UnauthorizedException)
        await this.accountLimiter.failed(body.email);
      throw error;
    }
    await this.accountLimiter.succeeded(body.email, client.ip);
    const { token, info } = result;
    setSessionCookie(reply, token, this.secure);
    return info;
  }

  /** La sesión actual (la web la recupera al cargar). */
  @Get('session')
  @AllowPasswordChange()
  @AllowMfaPending()
  @AllowMfaSetup()
  @SessionOnly()
  @ApiCookieAuth()
  @ApiOkResponse({ type: SessionInfoDto })
  @ApiUnauthorizedResponse()
  session(
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession,
  ): Promise<SessionInfo> {
    return this.auth.session(user, session);
  }

  /** Cierra la sesión; si vino del proveedor OIDC, devuelve la URL para cerrar la suya. */
  @Post('logout')
  @AllowPasswordChange()
  @AllowMfaPending()
  @AllowMfaSetup()
  @SessionOnly()
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth()
  @ApiOkResponse({ type: LogoutResponseDto })
  @ApiUnauthorizedResponse()
  async logout(
    @CurrentSession() session: RequestSession,
    @AuditCtx() actor: AuditActor,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<LogoutResponse> {
    const result = await this.auth.logout(session, actor);
    clearSessionCookie(reply, this.secure);
    return result;
  }

  @Get('me')
  @AllowMfaSetup()
  @ApiCookieAuth()
  @ApiOkResponse({ type: UserProfileDto })
  @ApiUnauthorizedResponse()
  me(@CurrentUser() user: AuthenticatedUser): Promise<UserProfile> {
    return this.auth.profile(user.id);
  }

  @Patch('me')
  @ApiCookieAuth()
  @ApiOkResponse({ type: UserProfileDto })
  @ApiUnauthorizedResponse()
  updateMe(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: UpdateProfileDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<UserProfile> {
    return this.auth.updateProfile(user.id, body.name, actor);
  }

  /**
   * Cambia el email propio (pide la contraseña actual; con el límite de intentos del login).
   * Con OIDC configurado, 409: lo cambia un admin (ver AuthService.changeEmail).
   */
  @Post('email')
  @SessionOnly()
  @UseGuards(ThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth()
  @ApiOkResponse({ type: UserProfileDto })
  @ApiBadRequestResponse({
    description: 'Email no válido o contraseña actual incorrecta',
  })
  @ApiConflictResponse({
    description:
      'Ya existe un usuario con ese email, OIDC configurado, cuenta OIDC/enlazada o admin de emergencia',
  })
  @ApiTooManyRequestsResponse({
    description: 'Demasiados intentos; reintentar tras Retry-After',
  })
  @ApiUnauthorizedResponse()
  @ApiForbiddenResponse({ description: 'Falta el token CSRF' })
  changeEmail(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: ChangeEmailDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<UserProfile> {
    return this.auth.changeEmail(
      user.id,
      body.email,
      body.currentPassword,
      actor,
    );
  }

  /**
   * Cambia la contraseña propia (pide la actual salvo con una temporal). Cierra todas las
   * sesiones del usuario y abre una nueva (nueva cookie y nuevo token CSRF). Con el límite de
   * intentos del login (la contraseña actual se puede probar aquí).
   */
  @Post('password')
  @AllowPasswordChange()
  @AllowMfaSetup()
  @SessionOnly()
  @UseGuards(ThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth()
  @ApiOkResponse({ type: SessionInfoDto })
  @ApiBadRequestResponse({
    description:
      'Contraseña actual incorrecta o nueva que no cumple la política',
  })
  @ApiTooManyRequestsResponse({
    description: 'Demasiados intentos; reintentar tras Retry-After',
  })
  @ApiUnauthorizedResponse()
  @ApiForbiddenResponse({ description: 'Falta el token CSRF' })
  async changePassword(
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession,
    @Body() body: ChangePasswordDto,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<SessionInfo> {
    const { token, info } = await this.auth.changePassword(
      user.id,
      session,
      body.currentPassword,
      body.newPassword,
      clientOf(request),
    );
    setSessionCookie(reply, token, this.secure);
    return info;
  }
}
