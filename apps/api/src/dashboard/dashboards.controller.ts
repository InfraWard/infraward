import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Put,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { DashboardDocument } from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { CurrentUser } from '../auth/current-user.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { DashboardDocumentDto, SaveDashboardDto } from './dashboards.dto.js';
import { DashboardsService } from './dashboards.service.js';

const uuid = new ParseUUIDPipe();
const STALE = { description: 'Alguien guardó otra versión antes (recarga)' };

/**
 * Paneles guardados (QoL-8, DESIGN §15): el personal de cada usuario y el de cada proyecto. Leer
 * el de un proyecto no exige permiso; cambiarlo, `projects.write` (y queda en la auditoría).
 */
@ApiTags('dashboard')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller()
export class DashboardsController {
  constructor(private readonly dashboards: DashboardsService) {}

  /** Tu panel (o el por defecto, con `isDefault`, si no lo has personalizado). */
  @Get('dashboards/me')
  @ApiOkResponse({ type: DashboardDocumentDto })
  mine(@CurrentUser() user: AuthenticatedUser): Promise<DashboardDocument> {
    return this.dashboards.getMine(user.id);
  }

  @Put('dashboards/me')
  @ApiOkResponse({ type: DashboardDocumentDto })
  @ApiBadRequestResponse({
    description: 'Diseño no válido (el motivo en el mensaje)',
  })
  @ApiConflictResponse(STALE)
  saveMine(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: SaveDashboardDto,
  ): Promise<DashboardDocument> {
    return this.dashboards.saveMine(user.id, body);
  }

  /** Vuelve al panel por defecto. */
  @Delete('dashboards/me')
  @ApiOkResponse({ type: DashboardDocumentDto })
  resetMine(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<DashboardDocument> {
    return this.dashboards.resetMine(user.id);
  }

  /** El panel del proyecto (o su plantilla, con `isDefault`), fijado a ese proyecto. */
  @Get('projects/:id/dashboard')
  @ApiOkResponse({ type: DashboardDocumentDto })
  @ApiNotFoundResponse()
  project(@Param('id', uuid) id: string): Promise<DashboardDocument> {
    return this.dashboards.getProject(id);
  }

  @Put('projects/:id/dashboard')
  @Can('projects.write')
  @ApiOkResponse({ type: DashboardDocumentDto })
  @ApiBadRequestResponse({
    description: 'Diseño no válido (el motivo en el mensaje)',
  })
  @ApiForbiddenResponse({ description: 'Sin el permiso projects.write' })
  @ApiNotFoundResponse()
  @ApiConflictResponse(STALE)
  saveProject(
    @Param('id', uuid) id: string,
    @Body() body: SaveDashboardDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<DashboardDocument> {
    return this.dashboards.saveProject(id, body, actor);
  }

  /** Vuelve a la plantilla del proyecto. */
  @Delete('projects/:id/dashboard')
  @Can('projects.write')
  @ApiOkResponse({ type: DashboardDocumentDto })
  @ApiForbiddenResponse({ description: 'Sin el permiso projects.write' })
  @ApiNotFoundResponse()
  resetProject(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<DashboardDocument> {
    return this.dashboards.resetProject(id, actor);
  }
}
