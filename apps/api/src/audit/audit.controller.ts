import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { AuditPage } from '@infraward/shared-types';
import { Can } from '../auth/permissions.decorator.js';
import { AuditPageDto, AuditQueryDto } from './audit.dto.js';
import { AuditService } from './audit.service.js';

@ApiTags('audit')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Requiere el permiso audit.read' })
@Can('audit.read')
@Controller('audit')
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  /** Registro de auditoría, lo más reciente primero (paginación por cursor). */
  @Get()
  @ApiOkResponse({ type: AuditPageDto })
  list(@Query() query: AuditQueryDto): Promise<AuditPage> {
    return this.audit.list(query);
  }
}
