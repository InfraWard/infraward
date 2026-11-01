import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { AlertChannel, AlertsStatus, AlertTestResult } from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { SessionOnly } from '../auth/public.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import {
  AlertChannelDto,
  AlertsStatusDto,
  AlertTestResultDto,
  CreateAlertChannelDto,
  UpdateAlertChannelDto,
} from './alerts.dto.js';
import { AlertsService } from './alerts.service.js';

/**
 * Canales de alertas fuera de la app (DESIGN §10): adónde sale lo que enseña la campana. Solo
 * admins, con la sesión web; crear, cambiar y borrar piden reautenticación reciente.
 */
@ApiTags('alerts')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Requiere alerts.manage (admin)' })
@Can('alerts.manage')
@SessionOnly()
@Controller('alerts')
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Get('status')
  @ApiOkResponse({ type: AlertsStatusDto })
  status(): Promise<AlertsStatus> {
    return this.alerts.status();
  }

  @Get('channels')
  @ApiOkResponse({ type: [AlertChannelDto] })
  list(): Promise<AlertChannel[]> {
    return this.alerts.list();
  }

  @Post('channels')
  @RecentAuth('alerts.channel_change')
  @ApiOkResponse({ type: AlertChannelDto })
  @ApiBadRequestResponse({ description: 'Destino que falta o no vale' })
  @ApiConflictResponse({ description: 'Demasiados canales o sin proveedor de secretos escribible' })
  create(
    @Body() body: CreateAlertChannelDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<AlertChannel> {
    return this.alerts.create(body, actor);
  }

  @Patch('channels/:id')
  @RecentAuth('alerts.channel_change')
  @ApiOkResponse({ type: AlertChannelDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: UpdateAlertChannelDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<AlertChannel> {
    return this.alerts.update(id, body, actor);
  }

  @Delete('channels/:id')
  @RecentAuth('alerts.channel_change')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<void> {
    await this.alerts.remove(id, actor);
  }

  /** Mensaje de prueba por el canal (lo envía el worker; se espera su resultado). */
  @Post('channels/:id/test')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: AlertTestResultDto })
  @ApiNotFoundResponse()
  test(
    @Param('id', ParseUUIDPipe) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<AlertTestResult> {
    return this.alerts.test(id, actor);
  }
}
