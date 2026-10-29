import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  BulkOperationResult,
  BulkPreviewResponse,
} from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import {
  BulkAssetIdsDto,
  BulkAssetTargetDto,
  BulkOperationResultDto,
  BulkPolicyDto,
  BulkPreviewResponseDto,
  BulkProjectDto,
  BulkTagsDto,
} from './bulk.dto.js';
import { BulkService } from './bulk.service.js';

/**
 * Operaciones en lote (QoL-6, DESIGN §15): cada una con el permiso de la acción de un asset,
 * una fila en la Actividad (`assets.bulk`, con sus jobs debajo) y un evento de auditoría.
 */
@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Sin el permiso de la acción' })
@ApiBadRequestResponse({
  description:
    'Sin assets, con assetIds y vulnerabilityIds a la vez o más de 500',
})
@Controller('assets/bulk')
export class BulkController {
  constructor(private readonly bulk: BulkService) {}

  /** Qué assets entrarían y, para dar de baja, todo su subárbol (la confirmación lo enseña). */
  @Post('preview')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: BulkPreviewResponseDto })
  @ApiNotFoundResponse({ description: 'Ningún asset afectado por esos CVE' })
  preview(@Body() body: BulkAssetTargetDto): Promise<BulkPreviewResponse> {
    return this.bulk.preview(body);
  }

  @Post('tags')
  @HttpCode(HttpStatus.OK)
  @Can('assets.write')
  @ApiOkResponse({ type: BulkOperationResultDto })
  tags(
    @Body() body: BulkTagsDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.bulk.tags(body, actor);
  }

  @Post('project')
  @HttpCode(HttpStatus.OK)
  @Can('projects.write')
  @ApiOkResponse({ type: BulkOperationResultDto })
  @ApiNotFoundResponse({ description: 'Proyecto no encontrado' })
  project(
    @Body() body: BulkProjectDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.bulk.project(body, actor);
  }

  @Post('policy')
  @HttpCode(HttpStatus.OK)
  @Can('policy.write')
  @ApiOkResponse({ type: BulkOperationResultDto })
  policy(
    @Body() body: BulkPolicyDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.bulk.policy(body, actor);
  }

  @Post('collect')
  @HttpCode(HttpStatus.ACCEPTED)
  @Can('assets.operate')
  @ApiOkResponse({ type: BulkOperationResultDto })
  collect(
    @Body() body: BulkAssetTargetDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.bulk.collect(body, actor);
  }

  @Post('scan')
  @HttpCode(HttpStatus.ACCEPTED)
  @Can('assets.operate')
  @ApiOkResponse({ type: BulkOperationResultDto })
  scan(
    @Body() body: BulkAssetTargetDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.bulk.scan(body, actor);
  }

  /** Retira los assets y sus subárboles (reversible); la purga sigue siendo de uno en uno. */
  @Post('retire')
  @HttpCode(HttpStatus.OK)
  @Can('assets.write')
  @ApiOkResponse({ type: BulkOperationResultDto })
  retire(
    @Body() body: BulkAssetIdsDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.bulk.retire(body, actor);
  }
}
