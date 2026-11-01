import { Controller, Get, Param, ParseUUIDPipe, Query } from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { JobRunLog, JobRunSummary, Page } from '@infraward/shared-types';
import { Can } from '../auth/permissions.decorator.js';
import {
  AssetRunListQueryDto,
  JobRunLogDto,
  JobRunPageDto,
} from './jobs.dto.js';
import { JobRunsService } from './job-runs.service.js';

const uuid = new ParseUUIDPipe();

/**
 * Recolecciones, descubrimientos y escaneos de un asset con su log (DESIGN §20, «Log de cada
 * ejecución»). La lista, como la Actividad y la ficha: cualquier sesión o token. El log, solo con
 * `assets.operate` (admin, editor, operador): lleva el final del stderr de los servidores y los
 * fallos de Ansible, que pueden contar más que la ficha.
 */
@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class AssetRunsController {
  constructor(private readonly runs: JobRunsService) {}

  /** Ejecuciones del asset (y, si es un contenedor, las de su imagen), de la más reciente. */
  @Get(':id/runs')
  @ApiOkResponse({ type: JobRunPageDto })
  @ApiNotFoundResponse({ description: 'El asset no existe' })
  list(
    @Param('id', uuid) id: string,
    @Query() query: AssetRunListQueryDto,
  ): Promise<Page<JobRunSummary>> {
    return this.runs.listForAsset(id, query);
  }

  /** Log de una ejecución del asset: pasos, comandos, stderr de lo que falló y resultado. */
  @Get(':id/runs/:runId/log')
  @Can('assets.operate')
  @ApiOkResponse({ type: JobRunLogDto })
  @ApiForbiddenResponse({ description: 'Requiere assets.operate (admin, editor u operador)' })
  @ApiNotFoundResponse({
    description: 'El asset no existe o la ejecución no es suya (o ya se borró)',
  })
  log(
    @Param('id', uuid) id: string,
    @Param('runId', uuid) runId: string,
  ): Promise<JobRunLog> {
    return this.runs.log(id, runId);
  }
}
