import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiConflictResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiExcludeController,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import type {
  AssetTerminalStatus,
  CreateTerminalSessionResponse,
} from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import type { AuthenticatedUser, RequestSession } from '../auth/authenticated-user.js';
import { CurrentSession, CurrentUser } from '../auth/current-user.decorator.js';
import { CanOnAsset } from '../auth/permissions.decorator.js';
import { Public, SessionOnly } from '../auth/public.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import { GatewayAuthGuard } from './gateway-auth.guard.js';
import {
  AssetTerminalStatusDto,
  CreateTerminalSessionDto,
  GatewayHeartbeatDto,
  GatewayHeartbeatResponseDto,
  RedeemedTerminalSessionDto,
  RedeemTicketDto,
  TerminalCertificateDto,
  TerminalCertificateRequestDto,
  TerminalClosedDto,
  TerminalOpenedDto,
  TerminalSessionTicketDto,
} from './terminal.dto.js';
import { TerminalService } from './terminal.service.js';

const uuid = new ParseUUIDPipe();

/** Terminal interactiva a través del gateway (sesión 21, DESIGN §11). */
@ApiTags('terminal')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@SessionOnly()
@Controller('terminal')
export class TerminalController {
  constructor(private readonly terminal: TerminalService) {}

  /**
   * Ticket de un solo uso (60 s) para abrir una terminal en un servidor, CT o contenedor con el
   * acceso interactivo de administración. Exige `terminal.open` en ese asset (rol o regla de
   * acceso; sin él, 403 antes de pedir nada más) y reautenticación reciente; con un token de
   * API, nunca.
   */
  @Post('sessions')
  @CanOnAsset(
    'terminal.open',
    (request: FastifyRequest) => (request.body as { assetId?: unknown } | undefined)?.assetId,
  )
  @RecentAuth('terminal.open')
  @Header('Cache-Control', 'no-store')
  @ApiCreatedResponse({ type: TerminalSessionTicketDto })
  @ApiForbiddenResponse({
    description: 'Sin permiso, sin reautenticación reciente o con un token de API',
  })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description:
      'El destino no admite terminal (tipo, estado, sin acceso de administración) o la terminal no está configurada',
  })
  create(
    @Body() body: CreateTerminalSessionDto,
    @CurrentUser() user: AuthenticatedUser,
    @CurrentSession() session: RequestSession | undefined,
    @AuditCtx() actor: AuditActor,
  ): Promise<CreateTerminalSessionResponse> {
    return this.terminal.create(user, session, body.assetId, actor, body.action ?? null);
  }
}

/** Si la persona puede abrir terminal en un asset y si está disponible (el botón de la ficha). */
@ApiTags('terminal')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class AssetTerminalController {
  constructor(private readonly terminal: TerminalService) {}

  @Get(':id/terminal')
  @ApiOkResponse({ type: AssetTerminalStatusDto })
  @ApiNotFoundResponse()
  status(
    @Param('id', uuid) id: string,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<AssetTerminalStatus> {
    return this.terminal.status(user, id);
  }
}

/**
 * API interna del gateway: canjear el ticket, firmar su clave efímera, avisar de la apertura y
 * el cierre y el latido. Solo con el secreto compartido (`Authorization: Gateway …`); fuera de
 * OpenAPI.
 */
@ApiExcludeController()
@Public()
@UseGuards(GatewayAuthGuard)
@Controller('internal/gateway')
export class GatewayInternalController {
  constructor(private readonly terminal: TerminalService) {}

  @Post('sessions/redeem')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  redeem(@Body() body: RedeemTicketDto): Promise<RedeemedTerminalSessionDto> {
    return this.terminal.redeem(body);
  }

  /** Latido: sesiones vivas de este gateway → las que tiene que cortar. */
  @Post('heartbeat')
  @HttpCode(HttpStatus.OK)
  heartbeat(@Body() body: GatewayHeartbeatDto): Promise<GatewayHeartbeatResponseDto> {
    return this.terminal.heartbeat(body);
  }

  @Post('sessions/:id/certificate')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  certificate(
    @Param('id', uuid) id: string,
    @Body() body: TerminalCertificateRequestDto,
  ): Promise<TerminalCertificateDto> {
    return this.terminal.certificate(id, body.publicKey);
  }

  @Post('sessions/:id/opened')
  @HttpCode(HttpStatus.NO_CONTENT)
  opened(@Param('id', uuid) id: string, @Body() body: TerminalOpenedDto): Promise<void> {
    return this.terminal.opened(id, body);
  }

  @Post('sessions/:id/closed')
  @HttpCode(HttpStatus.NO_CONTENT)
  closed(@Param('id', uuid) id: string, @Body() body: TerminalClosedDto): Promise<void> {
    return this.terminal.closed(id, body);
  }
}
