import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { DashboardSummary } from '@infraward/shared-types';
import { CurrentUser } from '../auth/current-user.decorator.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { DashboardQueryDto, DashboardSummaryDto } from './dashboard.dto.js';
import { DashboardService } from './dashboard.service.js';

@ApiTags('dashboard')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboard: DashboardService) {}

  /**
   * Panel de inicio: assets por tipo, pendientes de alta, CRITICAL/HIGH con parche, avisos
   * (sudoers desactualizado, recolecciones parciales, ejecuciones fallidas) y actividad reciente.
   * Con `projectId`, solo lo de ese proyecto.
   */
  @Get()
  @ApiOkResponse({ type: DashboardSummaryDto })
  summary(
    @Query() query: DashboardQueryDto,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<DashboardSummary> {
    return this.dashboard.summary(query.projectId, user.role);
  }
}
