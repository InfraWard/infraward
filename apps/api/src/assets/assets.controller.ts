import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  Asset,
  AssetRelation,
  AssetRelations,
  AssetGraph,
  AssetSummary,
  AssetTreeSummaryNode,
  DeleteAssetResponse,
  DockerHostResources,
  Page,
  Snapshot,
  SnapshotSummary,
} from '@infraward/shared-types';
import { hasPermission } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { CurrentUser } from '../auth/current-user.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import {
  AssetDto,
  AssetListQueryDto,
  AssetPageDto,
  AssetRelationDto,
  AssetRelationsDto,
  AssetSummaryDto,
  AssetTreeSummaryNodeDto,
  CreateAssetDto,
  CreateAssetRelationDto,
  DeleteAssetQueryDto,
  DeleteAssetResponseDto,
  DockerHostResourcesDto,
  PageQueryDto,
  SnapshotDto,
  SnapshotPageDto,
  TreeQueryDto,
  UpdateAssetDto,
} from './assets.dto.js';
import { AssetsService } from './assets.service.js';
import { AssetGraphService } from './graph.service.js';
import {
  AssetGraphDto,
  AssetGraphQueryDto,
  TopologyQueryDto,
} from './graph.dto.js';

const uuid = new ParseUUIDPipe();

@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class AssetsController {
  constructor(
    private readonly assets: AssetsService,
    private readonly graphs: AssetGraphService,
  ) {}

  @Get()
  @ApiOkResponse({ type: AssetPageDto })
  @ApiBadRequestResponse()
  list(@Query() query: AssetListQueryDto): Promise<Page<Asset>> {
    return this.assets.list(query);
  }

  /**
   * Árbol del inventario: cada raíz con sus descendientes por relaciones `contains`. Con `q`, solo
   * lo que cumple la búsqueda y sus antepasados.
   */
  @Get('tree')
  @ApiOkResponse({ type: [AssetTreeSummaryNodeDto] })
  forest(@Query() query: TreeQueryDto): Promise<AssetTreeSummaryNode[]> {
    return query.q
      ? this.assets.searchForest(query.q, query.includeRetired)
      : this.assets.forest(query.includeRetired);
  }

  /**
   * Topología por niveles: raíces y sus hosts, más el contenido de los assets de `expand`; lo
   * demás se resume en su antepasado visible. Como mucho 500 nodos.
   */
  @Get('topology')
  @ApiOkResponse({ type: AssetGraphDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse({ description: 'No existe `rootId`' })
  topology(@Query() query: TopologyQueryDto): Promise<AssetGraph> {
    return this.graphs.topology(query);
  }

  @Get(':id')
  @ApiOkResponse({ type: AssetDto })
  @ApiNotFoundResponse()
  get(@Param('id', uuid) id: string): Promise<Asset> {
    return this.assets.get(id);
  }

  /** Subárbol con raíz en el asset (la raíz se devuelve aunque esté retirada). */
  @Get(':id/tree')
  @ApiOkResponse({ type: AssetTreeSummaryNodeDto })
  @ApiNotFoundResponse()
  subtree(
    @Param('id', uuid) id: string,
    @Query() query: TreeQueryDto,
  ): Promise<AssetTreeSummaryNode> {
    return this.assets.subtree(id, query.includeRetired);
  }

  @Post()
  @Can('assets.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiCreatedResponse({ type: AssetDto })
  @ApiBadRequestResponse()
  @ApiConflictResponse({ description: 'naturalKey duplicada para ese tipo' })
  create(
    @Body() body: CreateAssetDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<Asset> {
    return this.assets.create(body, actor);
  }

  @Patch(':id')
  @Can('assets.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiOkResponse({ type: AssetDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'naturalKey duplicada para ese tipo' })
  update(
    @Param('id', uuid) id: string,
    @Body() body: UpdateAssetDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<Asset> {
    return this.assets.update(id, body, actor);
  }

  /**
   * Retira el asset y todo su subárbol (`retired`, conserva el historial). Con `purge=true`
   * los borra físicamente junto con sus relaciones y snapshots.
   */
  @Delete(':id')
  @Can('assets.write')
  @RecentAuth('asset.purge', (request) => isPurge(request))
  @ApiOkResponse({ type: DeleteAssetResponseDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  remove(
    @Param('id', uuid) id: string,
    @Query() query: DeleteAssetQueryDto,
    @AuditCtx() actor: AuditActor,
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<DeleteAssetResponse> {
    // Retirar es reversible (assets.write); purgar no: solo con assets.purge.
    if (query.purge && !hasPermission(user.role, 'assets.purge'))
      throw new ForbiddenException('Purgar requiere el permiso assets.purge');
    return this.assets.remove(id, query.purge ?? false, actor);
  }

  /** Antepasados `contains`, de la raíz al padre (vacío en una raíz). */
  @Get(':id/ancestors')
  @ApiOkResponse({ type: [AssetSummaryDto] })
  @ApiNotFoundResponse()
  ancestors(@Param('id', uuid) id: string): Promise<AssetSummary[]> {
    return this.assets.ancestors(id);
  }

  /** Volúmenes, redes e imágenes de un host Docker con cuántos contenedores activos los usan. */
  @Get(':id/docker')
  @ApiOkResponse({ type: DockerHostResourcesDto })
  @ApiNotFoundResponse()
  docker(@Param('id', uuid) id: string): Promise<DockerHostResources> {
    return this.assets.dockerResources(id);
  }

  @Get(':id/relations')
  @ApiOkResponse({ type: AssetRelationsDto })
  @ApiNotFoundResponse()
  relations(@Param('id', uuid) id: string): Promise<AssetRelations> {
    return this.assets.relations(id);
  }

  /**
   * Mapa de relaciones centrado en el asset: vecinos por cualquier relación y en los dos
   * sentidos, hasta `depth` saltos (25 vecinos nuevos por nodo y 150 nodos como mucho).
   */
  @Get(':id/graph')
  @ApiOkResponse({ type: AssetGraphDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  graph(
    @Param('id', uuid) id: string,
    @Query() query: AssetGraphQueryDto,
  ): Promise<AssetGraph> {
    return this.graphs.graph(id, query);
  }

  /** Historial de recolecciones, de la más reciente a la más antigua (sin facts). */
  @Get(':id/snapshots')
  @ApiOkResponse({ type: SnapshotPageDto })
  @ApiNotFoundResponse()
  snapshots(
    @Param('id', uuid) id: string,
    @Query() query: PageQueryDto,
  ): Promise<Page<SnapshotSummary>> {
    return this.assets.snapshots(id, query);
  }
}

@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('asset-relations')
export class AssetRelationsController {
  constructor(private readonly assets: AssetsService) {}

  @Post()
  @Can('assets.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiCreatedResponse({ type: AssetRelationDto })
  @ApiNotFoundResponse({ description: 'No existe alguno de los assets' })
  @ApiConflictResponse({
    description:
      'Autorrelación, relación duplicada, segundo padre `contains` o ciclo',
  })
  create(@Body() body: CreateAssetRelationDto): Promise<AssetRelation> {
    return this.assets.createRelation(body);
  }

  @Delete(':id')
  @Can('assets.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  remove(@Param('id', uuid) id: string): Promise<void> {
    return this.assets.removeRelation(id);
  }
}

@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('snapshots')
export class SnapshotsController {
  constructor(private readonly assets: AssetsService) {}

  @Get(':id')
  @ApiOkResponse({ type: SnapshotDto })
  @ApiNotFoundResponse()
  get(@Param('id', uuid) id: string): Promise<Snapshot> {
    return this.assets.snapshot(id);
  }
}

/** `DELETE /assets/:id?purge=true` (la query sin transformar: solo `true` purga, ver DTO). */
function isPurge(request: FastifyRequest): boolean {
  return (request.query as Record<string, unknown> | undefined)?.purge === 'true';
}
