import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
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
  DomainServicePaths,
  NatForward,
  ServedDomains,
  ServicePathView,
} from '@infraward/shared-types';
import {
  AuditCtx,
  type AuditActor,
} from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import {
  DomainServicePathsDto,
  NatForwardDto,
  NatForwardInputDto,
  ServedDomainsDto,
  ServicePathDto,
  ServicePinRequestDto,
} from './service-paths.dto.js';
import { ServicePathsService } from './service-paths.service.js';

const uuid = new ParseUUIDPipe();
const FORBIDDEN = { description: 'Sin el permiso necesario para su rol' };

/** Qué servicio sirve cada dominio (QoL-5b). Leer no exige permiso. */
@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class ServicePathsController {
  constructor(private readonly paths: ServicePathsService) {}

  @Get(':id/service-path')
  @ApiOkResponse({ type: ServicePathDto, description: 'Camino de un registro DNS hasta el asset que lo sirve' })
  @ApiBadRequestResponse({ description: 'No es un registro DNS' })
  @ApiNotFoundResponse()
  pathOf(@Param('id', uuid) id: string): Promise<ServicePathView> {
    return this.paths.pathOf(id);
  }

  @Get(':id/service-paths')
  @ApiOkResponse({ type: DomainServicePathsDto, description: 'Caminos de los registros de un dominio' })
  @ApiBadRequestResponse({ description: 'No es un dominio' })
  @ApiNotFoundResponse()
  pathsOfDomain(@Param('id', uuid) id: string): Promise<DomainServicePaths> {
    return this.paths.pathsOfDomain(id);
  }

  @Get(':id/served-domains')
  @ApiOkResponse({ type: ServedDomainsDto, description: 'Registros que sirve el asset o que pasan por él' })
  @ApiNotFoundResponse()
  servedBy(@Param('id', uuid) id: string): Promise<ServedDomains> {
    return this.paths.servedBy(id);
  }

  /** Fija a mano el destino de un registro (cuando la cadena se corta o se deduce mal). */
  @Post(':id/service-path/pin')
  @Can('assets.write')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: ServicePathDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  pin(
    @Param('id', uuid) id: string,
    @Body() body: ServicePinRequestDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<ServicePathView> {
    return this.paths.pin(id, body.targetAssetId, actor);
  }

  @Delete(':id/service-path/pin')
  @Can('assets.write')
  @ApiOkResponse({ type: ServicePathDto })
  @ApiConflictResponse({ description: 'El registro no tiene destino fijado' })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  unpin(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<ServicePathView> {
    return this.paths.unpin(id, actor);
  }
}

/** Reenvíos NAT declarados a mano (Ajustes › Inventario). */
@ApiTags('settings')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('settings/nat-forwards')
export class NatForwardsController {
  constructor(private readonly paths: ServicePathsService) {}

  @Get()
  @ApiOkResponse({ type: [NatForwardDto] })
  list(): Promise<NatForward[]> {
    return this.paths.natForwards();
  }

  @Post()
  @Can('policy.write')
  @ApiCreatedResponse({ type: NatForwardDto })
  @ApiBadRequestResponse()
  @ApiConflictResponse({ description: 'Ya hay un reenvío para esa IP, puerto y protocolo' })
  @ApiForbiddenResponse(FORBIDDEN)
  create(
    @Body() body: NatForwardInputDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<NatForward> {
    return this.paths.createNat(body, actor);
  }

  @Put(':id')
  @Can('policy.write')
  @ApiOkResponse({ type: NatForwardDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'Ya hay un reenvío para esa IP, puerto y protocolo' })
  @ApiForbiddenResponse(FORBIDDEN)
  update(
    @Param('id', uuid) id: string,
    @Body() body: NatForwardInputDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<NatForward> {
    return this.paths.updateNat(id, body, actor);
  }

  @Delete(':id')
  @Can('policy.write')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  remove(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<void> {
    return this.paths.deleteNat(id, actor);
  }
}
