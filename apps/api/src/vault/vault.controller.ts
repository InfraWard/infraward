import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  ParseUUIDPipe,
  Patch,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiConflictResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type {
  RevealVaultSecretResponse,
  VaultEntry,
  VaultEntryList,
  VaultSettings,
  VaultStatus,
  VaultVersion,
} from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { CurrentUser } from '../auth/current-user.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { SessionOnly } from '../auth/public.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import { VaultRevealThrottlerGuard } from './vault-reveal-throttler.guard.js';
import {
  CreateVaultEntryDto,
  ReplaceVaultSecretDto,
  RevealVaultSecretDto,
  RevealVaultSecretResponseDto,
  UpdateVaultEntryDto,
  VaultEntryDto,
  VaultEntryListDto,
  VaultEntryListQueryDto,
  VaultSettingsDto,
  VaultStatusDto,
  VaultVersionDto,
} from './vault.dto.js';
import { VaultService } from './vault.service.js';

const uuid = new ParseUUIDPipe();
const NO_STORE = 'no-store';

/**
 * Caja fuerte de credenciales (QoL-7, DESIGN §19). Gestionar (`vault.manage`: admin y editor) no
 * da acceso a los valores; revelar y restaurar versiones es solo de admins (`vault.admin`) con
 * reautenticación reciente. Todo con la sesión web (un token de API no entra) y sin caché.
 */
@ApiTags('vault')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({
  description: 'Requiere vault.manage (o vault.admin) y la sesión web',
})
@Can('vault.manage')
@SessionOnly()
@Controller('vault/entries')
export class VaultController {
  constructor(private readonly vault: VaultService) {}

  /** Solo metadatos: nunca el valor ni la referencia al secreto. */
  @Get()
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryListDto })
  list(@Query() query: VaultEntryListQueryDto): Promise<VaultEntryList> {
    return this.vault.list(query);
  }

  @Get(':id')
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  @ApiNotFoundResponse()
  get(@Param('id', uuid) id: string): Promise<VaultEntry> {
    return this.vault.get(id);
  }

  @Post()
  @Header('Cache-Control', NO_STORE)
  @ApiCreatedResponse({ type: VaultEntryDto })
  @ApiConflictResponse({ description: 'Caja fuerte sin configurar' })
  create(
    @Body() body: CreateVaultEntryDto,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.create(body, user, actor);
  }

  @Patch(':id')
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  @ApiNotFoundResponse()
  update(
    @Param('id', uuid) id: string,
    @Body() body: UpdateVaultEntryDto,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.update(id, body, user, actor);
  }

  /** Versión nueva del secreto (sin leer la anterior). */
  @Put(':id/secret')
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  @ApiNotFoundResponse()
  replaceSecret(
    @Param('id', uuid) id: string,
    @Body() body: ReplaceVaultSecretDto,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.replaceSecret(id, body, user, actor);
  }

  @Post(':id/rotated')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  markRotated(
    @Param('id', uuid) id: string,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.markRotated(id, user, actor);
  }

  /** A la papelera (recuperable hasta que pase el plazo de los ajustes). */
  @Delete(':id')
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  remove(
    @Param('id', uuid) id: string,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.remove(id, user, actor);
  }

  @Post(':id/restore')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  restore(
    @Param('id', uuid) id: string,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.restore(id, user, actor);
  }

  @Get(':id/versions')
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: [VaultVersionDto] })
  versions(@Param('id', uuid) id: string): Promise<VaultVersion[]> {
    return this.vault.versions(id);
  }

  @Post(':id/versions/:version/restore')
  @Can('vault.admin')
  @RecentAuth('vault.version_restore')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', NO_STORE)
  @ApiOkResponse({ type: VaultEntryDto })
  @ApiNotFoundResponse({ description: 'El almacén ya no conserva esa versión' })
  restoreVersion(
    @Param('id', uuid) id: string,
    @Param('version', ParseIntPipe) version: number,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultEntry> {
    return this.vault.restoreVersion(id, version, user, actor);
  }

  /** La única respuesta con el valor. */
  @Post(':id/reveal')
  @Can('vault.admin')
  @RecentAuth('vault.reveal')
  @UseGuards(VaultRevealThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', NO_STORE)
  @Header('Pragma', 'no-cache')
  @ApiOkResponse({ type: RevealVaultSecretResponseDto })
  @ApiTooManyRequestsResponse({ description: 'Demasiados revelados seguidos' })
  reveal(
    @Param('id', uuid) id: string,
    @Body() body: RevealVaultSecretDto,
    @CurrentUser() user: AuthenticatedUser,
    @AuditCtx() actor: AuditActor,
  ): Promise<RevealVaultSecretResponse> {
    return this.vault.reveal(id, body, user, actor);
  }
}

/** Estado del almacén y ajustes (plazo de rotación, aviso de revelados, papelera). */
@ApiTags('vault')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({ description: 'Requiere vault.manage (cambiar: vault.admin)' })
@Can('vault.manage')
@SessionOnly()
@Controller('vault')
export class VaultSettingsController {
  constructor(private readonly vault: VaultService) {}

  @Get('status')
  @ApiOkResponse({ type: VaultStatusDto })
  status(): Promise<VaultStatus> {
    return this.vault.status();
  }

  @Get('settings')
  @ApiOkResponse({ type: VaultSettingsDto })
  settings(): Promise<VaultSettings> {
    return this.vault.settings();
  }

  @Put('settings')
  @Can('vault.admin')
  @RecentAuth('vault.settings_change')
  @ApiOkResponse({ type: VaultSettingsDto })
  updateSettings(
    @Body() body: VaultSettingsDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<VaultSettings> {
    return this.vault.updateSettings(body, actor);
  }
}
