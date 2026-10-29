import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  ApiTokenSummary,
  CreatedApiTokenResponse,
} from '@infraward/shared-types';
import { roleCanWrite } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import {
  ApiTokenListQueryDto,
  ApiTokenSummaryDto,
  CreateApiTokenDto,
  CreatedApiTokenResponseDto,
} from './api-tokens.dto.js';
import { ApiTokensService } from './api-tokens.service.js';
import type { AuthenticatedUser } from './authenticated-user.js';
import { CurrentUser } from './current-user.decorator.js';
import { Can } from './permissions.decorator.js';
import { SessionOnly } from './public.decorator.js';
import { RecentAuth } from './recent-auth.decorator.js';

const uuid = new ParseUUIDPipe();

/**
 * Tokens de API propios (QoL-6, DESIGN §14). Solo con la sesión web: un token no puede crear
 * otros ni revocarlos.
 */
@ApiTags('api-tokens')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Exige la sesión web (no un token)' })
@SessionOnly()
@Controller('auth/tokens')
export class OwnApiTokensController {
  constructor(private readonly tokens: ApiTokensService) {}

  @Get()
  @ApiOkResponse({ type: [ApiTokenSummaryDto] })
  list(@CurrentUser() user: AuthenticatedUser): Promise<ApiTokenSummary[]> {
    return this.tokens.listForUser(user.id);
  }

  /** El token en claro solo sale en esta respuesta. */
  /** Uno que puede escribir (alcance `role` de un rol que escribe) exige reautenticación. */
  @Post()
  @RecentAuth('api_token.create_write', (request) => isWriteToken(request))
  @ApiCreatedResponse({ type: CreatedApiTokenResponseDto })
  @ApiBadRequestResponse({ description: 'Caducidad pasada o a más de un año' })
  @ApiConflictResponse({
    description: 'Nombre repetido o demasiados tokens vigentes',
  })
  create(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateApiTokenDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<CreatedApiTokenResponse> {
    return this.tokens.create(user.id, body, actor);
  }

  @Delete(':id')
  @ApiOkResponse({ type: ApiTokenSummaryDto })
  @ApiNotFoundResponse()
  revoke(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<ApiTokenSummary> {
    return this.tokens.revoke(id, actor, { ownerId: user.id });
  }
}

/** Los tokens de todos los usuarios (admin): ver y revocar, nunca su valor. */
@ApiTags('api-tokens')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({
  description: 'Requiere users.manage y la sesión web',
})
@Can('users.manage')
@SessionOnly()
@Controller('api-tokens')
export class ApiTokensAdminController {
  constructor(private readonly tokens: ApiTokensService) {}

  @Get()
  @ApiOkResponse({ type: [ApiTokenSummaryDto] })
  list(@Query() query: ApiTokenListQueryDto): Promise<ApiTokenSummary[]> {
    return this.tokens.listAll({ userId: query.userId });
  }

  @Delete(':id')
  @ApiOkResponse({ type: ApiTokenSummaryDto })
  @ApiNotFoundResponse()
  revoke(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<ApiTokenSummary> {
    return this.tokens.revoke(id, actor);
  }
}

function isWriteToken(request: FastifyRequest): boolean {
  const body = request.body as { scope?: unknown } | undefined;
  return (
    body?.scope === 'role' && !!request.user && roleCanWrite(request.user.role)
  );
}
