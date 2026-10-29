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
  ApiAcceptedResponse,
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  AcceptDnsTargetResponse,
  AssetDomains,
  Connector,
  ConnectorTestResponse,
  DeleteAssetResponse,
  DnsRecordCheck,
  EnqueueJobResponse,
  ExpiryWarningSettings,
} from '@infraward/shared-types';
import { DeleteAssetResponseDto } from '../assets/assets.dto.js';
import {
  AuditCtx,
  type AuditActor,
} from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { EnqueueJobResponseDto } from '../jobs/jobs.dto.js';
import {
  AcceptDnsTargetDto,
  AcceptDnsTargetResponseDto,
  AssetDomainsDto,
  ConnectorDto,
  ConnectorTestResponseDto,
  CreateConnectorDto,
  DnsRecordCheckDto,
  ExpiryWarningSettingsDto,
  ReplaceConnectorTokenDto,
} from './domains.dto.js';
import { DomainsService } from './domains.service.js';

const uuid = new ParseUUIDPipe();
const FORBIDDEN = { description: 'Sin el permiso necesario para su rol' };

/**
 * Conectores de dominios (DESIGN §13): cada uno es un asset `dns_provider` con su token en el
 * proveedor de secretos (solo la referencia en la BD; el token no vuelve a salir).
 */
@ApiTags('connectors')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('connectors')
export class ConnectorsController {
  constructor(private readonly domains: DomainsService) {}

  @Get()
  @Can('connectors.write')
  @ApiOkResponse({ type: [ConnectorDto] })
  @ApiForbiddenResponse(FORBIDDEN)
  list(): Promise<Connector[]> {
    return this.domains.list();
  }

  /** Alta: guarda el token, lo prueba y, si vale, encola la primera sincronización. */
  @Post()
  @Can('connectors.write')
  @ApiCreatedResponse({ type: ConnectorDto })
  @ApiBadRequestResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  @ApiConflictResponse({ description: 'Ningún proveedor de secretos admite escritura' })
  create(
    @Body() body: CreateConnectorDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<Connector> {
    return this.domains.create(body, actor);
  }

  @Get(':id')
  @Can('connectors.write')
  @ApiOkResponse({ type: ConnectorDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  get(@Param('id', uuid) id: string): Promise<Connector> {
    return this.domains.get(id);
  }

  @Put(':id/token')
  @Can('connectors.write')
  @ApiOkResponse({ type: ConnectorDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  replaceToken(
    @Param('id', uuid) id: string,
    @Body() body: ReplaceConnectorTokenDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<Connector> {
    return this.domains.replaceToken(id, body.apiToken, actor);
  }

  /** Prueba el token en el worker y espera el resultado (como mucho 20 s). */
  @Post(':id/test')
  @Can('connectors.write')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: ConnectorTestResponseDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  test(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<ConnectorTestResponse> {
    return this.domains.test(id, actor);
  }

  @Post(':id/sync')
  @Can('assets.operate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiAcceptedResponse({ type: EnqueueJobResponseDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  sync(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<EnqueueJobResponse> {
    return this.domains.sync(id, actor);
  }

  /** Baja del conector con sus dominios y registros; borra el token del proveedor de secretos. */
  @Delete(':id')
  @Can('connectors.write')
  @ApiOkResponse({ type: DeleteAssetResponseDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  remove(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<DeleteAssetResponse> {
    return this.domains.remove(id, actor);
  }
}

/** Dominios que llegan a un asset y comprobaciones de registros DNS. Leer no exige permiso. */
@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class AssetDomainsController {
  constructor(private readonly domains: DomainsService) {}

  @Get(':id/domains')
  @ApiOkResponse({ type: AssetDomainsDto })
  @ApiNotFoundResponse()
  domainsOf(@Param('id', uuid) id: string): Promise<AssetDomains> {
    return this.domains.domainsOf(id);
  }

  @Get(':id/dns-check')
  @ApiOkResponse({ type: DnsRecordCheckDto, description: 'null si no tiene comprobación' })
  @ApiNotFoundResponse()
  check(@Param('id', uuid) id: string): Promise<DnsRecordCheck | null> {
    return this.domains.check(id);
  }

  /** «Marcar como esperado»: el aviso se silencia mientras el registro no cambie de valor. */
  @Post(':id/dns-check/acceptance')
  @Can('assets.write')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: DnsRecordCheckDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'El registro no tiene aviso' })
  @ApiForbiddenResponse(FORBIDDEN)
  accept(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<DnsRecordCheck> {
    return this.domains.accept(id, actor);
  }

  @Delete(':id/dns-check/acceptance')
  @Can('assets.write')
  @ApiOkResponse({ type: DnsRecordCheckDto })
  @ApiNotFoundResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  reopen(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<DnsRecordCheck> {
    return this.domains.reopen(id, actor);
  }
}

/** «Marcar como esperados» en bloque los avisos informativos con un destino. */
@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('dns-checks')
export class DnsChecksController {
  constructor(private readonly domains: DomainsService) {}

  @Post('acceptance')
  @Can('assets.write')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: AcceptDnsTargetResponseDto })
  @ApiConflictResponse({ description: 'No hay avisos informativos con ese destino' })
  @ApiForbiddenResponse(FORBIDDEN)
  acceptTarget(
    @Body() body: AcceptDnsTargetDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<AcceptDnsTargetResponse> {
    return this.domains.acceptTarget(body.target, actor);
  }
}

/** Ajustes globales: umbrales de aviso de caducidad de dominios y certificados. */
@ApiTags('settings')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('settings')
export class SettingsController {
  constructor(private readonly domains: DomainsService) {}

  @Get('expiry-warnings')
  @ApiOkResponse({ type: ExpiryWarningSettingsDto })
  expiryWarnings(): Promise<ExpiryWarningSettings> {
    return this.domains.expiryWarnings();
  }

  @Put('expiry-warnings')
  @Can('policy.write')
  @ApiOkResponse({ type: ExpiryWarningSettingsDto })
  @ApiBadRequestResponse()
  @ApiForbiddenResponse(FORBIDDEN)
  setExpiryWarnings(
    @Body() body: ExpiryWarningSettingsDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<ExpiryWarningSettings> {
    return this.domains.setExpiryWarnings(body.days, actor);
  }
}
