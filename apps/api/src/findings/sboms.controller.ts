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
  Query,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiProduces,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  AssetPackagesPage,
  EnqueueJobResponse,
} from '@infraward/shared-types';
import {
  AuditCtx,
  type AuditActor,
} from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { Can } from '../auth/permissions.decorator.js';
import { EnqueueJobResponseDto } from '../jobs/jobs.dto.js';
import {
  AssetPackagesPageDto,
  PackageListQueryDto,
  ReevaluateSbomsDto,
} from './sboms.dto.js';
import { SbomsService } from './sboms.service.js';

@ApiTags('sboms')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller()
export class SbomsController {
  constructor(
    private readonly sboms: SbomsService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Paquetes instalados según el SBOM del asset (servidor, CT o imagen; en un contenedor, los de
   * su imagen), ordenados por nombre, con el resumen del SBOM. Sin SBOM, lista vacía y `sbom: null`.
   */
  @Get('assets/:id/packages')
  @ApiOkResponse({ type: AssetPackagesPageDto })
  @ApiNotFoundResponse()
  packages(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: PackageListQueryDto,
  ): Promise<AssetPackagesPage> {
    return this.sboms.packages(id, query);
  }

  /** SBOM CycloneDX del asset tal como se guarda (sin las etiquetas de la imagen). */
  @Get('assets/:id/sbom')
  @Header('Content-Type', 'application/vnd.cyclonedx+json')
  @Header('Content-Disposition', 'attachment; filename="sbom.cdx.json"')
  @ApiProduces('application/vnd.cyclonedx+json')
  @ApiOkResponse({ description: 'CycloneDX JSON' })
  @ApiNotFoundResponse({ description: 'El asset no existe o no tiene SBOM' })
  cyclonedx(@Param('id', ParseUUIDPipe) id: string): Promise<string> {
    return this.sboms.cyclonedx(id);
  }

  /**
   * Re-evalúa ya todos los SBOMs guardados con la BD de Trivy, sin conectarse a ninguna máquina
   * (el worker lo hace también cada `SBOM_REEVALUATE_INTERVAL` horas). Con `downloadDb`, el worker
   * descarga antes la BD aunque no haya caducado: así salen los CVE publicados desde la última.
   */
  @Post('sboms/reevaluate')
  @Can('assets.operate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: EnqueueJobResponseDto })
  async reevaluate(
    @AuditCtx() actor: AuditActor,
    @Body() body: ReevaluateSbomsDto = {},
  ): Promise<EnqueueJobResponse> {
    const downloadDb = body?.downloadDb === true;
    const res = await this.sboms.reevaluate(downloadDb);
    await this.audit.tryRecord(actor, 'vulnerabilities.reevaluate_requested', {
      details: { jobId: res.id, downloadDb, deduplicated: !!res.deduplicated },
    });
    return res;
  }
}
