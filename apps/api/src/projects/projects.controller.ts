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
  Put,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  AssetProjects,
  Project,
  ProjectDetail,
  ProjectWithStats,
  TagInfo,
} from '@infraward/shared-types';
import {
  AuditCtx,
  type AuditActor,
} from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import {
  AssetProjectsDto,
  CreateProjectDto,
  ProjectDetailDto,
  ProjectDto,
  ProjectWithStatsDto,
  SetProjectMemberDto,
  SetTagStyleDto,
  TagInfoDto,
  UpdateProjectDto,
} from './projects.dto.js';
import { ProjectsService } from './projects.service.js';
import { TagParamPipe } from './tag-param.pipe.js';

const uuid = new ParseUUIDPipe();
const FORBIDDEN = { description: 'Sin el permiso necesario para su rol' };

/** Proyectos y su pertenencia (DESIGN §5). Leer no exige permiso. */
@ApiTags('projects')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller()
export class ProjectsController {
  constructor(private readonly projects: ProjectsService) {}

  /** Proyectos con su resumen (assets y vulnerabilidades, heredado incluido). */
  @Get('projects')
  @ApiOkResponse({ type: [ProjectWithStatsDto] })
  list(): Promise<ProjectWithStats[]> {
    return this.projects.list();
  }

  @Get('projects/:id')
  @ApiOkResponse({ type: ProjectDetailDto })
  @ApiNotFoundResponse()
  get(@Param('id', uuid) id: string): Promise<ProjectDetail> {
    return this.projects.get(id);
  }

  @Post('projects')
  @Can('projects.write')
  @ApiCreatedResponse({ type: ProjectDto })
  @ApiBadRequestResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  @ApiConflictResponse({ description: 'Ya hay un proyecto con ese nombre' })
  create(
    @Body() body: CreateProjectDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<Project> {
    return this.projects.create(body, actor);
  }

  @Patch('projects/:id')
  @Can('projects.write')
  @ApiOkResponse({ type: ProjectDto })
  @ApiBadRequestResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'Ya hay un proyecto con ese nombre' })
  update(
    @Param('id', uuid) id: string,
    @Body() body: UpdateProjectDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<Project> {
    return this.projects.update(id, body, actor);
  }

  /** Borra el proyecto con sus filas y su regla de política; los assets no se tocan. */
  @Delete('projects/:id')
  @Can('projects.write')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  @ApiNotFoundResponse()
  remove(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<void> {
    return this.projects.remove(id, actor);
  }

  /**
   * Mete un asset (y lo que contiene) en el proyecto (`include`) o lo saca aunque lo herede
   * (`exclude`).
   */
  @Put('projects/:id/members/:assetId')
  @Can('projects.write')
  @ApiOkResponse({ type: ProjectDetailDto })
  @ApiBadRequestResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  @ApiNotFoundResponse()
  setMember(
    @Param('id', uuid) id: string,
    @Param('assetId', uuid) assetId: string,
    @Body() body: SetProjectMemberDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<ProjectDetail> {
    return this.projects.setMember(id, assetId, body.mode, actor);
  }

  /** Quita la fila directa del asset (vuelve a heredar lo que diga su camino). */
  @Delete('projects/:id/members/:assetId')
  @Can('projects.write')
  @ApiOkResponse({ type: ProjectDetailDto })
  @ApiForbiddenResponse(FORBIDDEN)
  @ApiNotFoundResponse()
  removeMember(
    @Param('id', uuid) id: string,
    @Param('assetId', uuid) assetId: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<ProjectDetail> {
    return this.projects.removeMember(id, assetId, actor);
  }

  /** Proyectos de un asset con el motivo, y sus excepciones. */
  @Get('assets/:id/projects')
  @ApiOkResponse({ type: AssetProjectsDto })
  @ApiNotFoundResponse()
  assetProjects(@Param('id', uuid) id: string): Promise<AssetProjects> {
    return this.projects.assetProjects(id);
  }

  /** Tags en uso y con color (autocompletado y colores). */
  @Get('tags')
  @ApiTags('tags')
  @ApiOkResponse({ type: [TagInfoDto] })
  tags(): Promise<TagInfo[]> {
    return this.projects.tags();
  }

  /** Color de un tag (null lo quita). */
  @Put('tags/:tag/style')
  @ApiTags('tags')
  @Can('assets.write')
  @ApiOkResponse({ type: TagInfoDto })
  @ApiBadRequestResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  setTagStyle(
    @Param('tag', TagParamPipe) tag: string,
    @Body() body: SetTagStyleDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<TagInfo> {
    return this.projects.setTagStyle(tag, body.color, actor);
  }

  /** Borra el tag: se quita de todos los assets y se olvida su color. */
  @Delete('tags/:tag')
  @ApiTags('tags')
  @Can('assets.write')
  @ApiOkResponse({ schema: { properties: { assets: { type: 'integer' } } } })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  deleteTag(
    @Param('tag', TagParamPipe) tag: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<{ assets: number }> {
    return this.projects.deleteTag(tag, actor);
  }
}
