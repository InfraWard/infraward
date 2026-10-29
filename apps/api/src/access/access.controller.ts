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
  Query,
} from '@nestjs/common';
import {
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
import type { AccessPolicyRule, AssetAccess } from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import {
  AccessPoliciesQueryDto,
  AccessPolicyRuleDto,
  AssetAccessDto,
  CreateAccessPolicyDto,
} from './access.dto.js';
import { AccessService } from './access.service.js';

const uuid = new ParseUUIDPipe();

/**
 * Políticas de acceso interactivo (sesión 22, DESIGN §11): quién puede abrir terminal y dónde,
 * además de lo que da su rol. Solo admins (`users.manage`); conceder exige reautenticación.
 */
@ApiTags('access')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse()
@Can('users.manage')
@Controller()
export class AccessController {
  constructor(private readonly access: AccessService) {}

  @Get('access-policies')
  @ApiOkResponse({ type: [AccessPolicyRuleDto] })
  list(@Query() query: AccessPoliciesQueryDto): Promise<AccessPolicyRule[]> {
    return this.access.list(query);
  }

  /** Concede `terminal.open` a una persona o un rol en un asset, una etiqueta o un proyecto. */
  @Post('access-policies')
  @RecentAuth('access.grant')
  @ApiCreatedResponse({ type: AccessPolicyRuleDto })
  @ApiNotFoundResponse({ description: 'El usuario, el asset o el proyecto no existen' })
  @ApiConflictResponse({ description: 'La regla ya existe' })
  create(
    @Body() body: CreateAccessPolicyDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<AccessPolicyRule> {
    return this.access.create(body, actor);
  }

  /** Retira la regla: las terminales abiertas que dependían de ella se cortan al momento. */
  @Delete('access-policies/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  remove(@Param('id', uuid) id: string, @AuditCtx() actor: AuditActor): Promise<void> {
    return this.access.remove(id, actor);
  }

  /** Quién puede abrir terminal en el asset y por qué regla. */
  @Get('assets/:id/access')
  @ApiOkResponse({ type: AssetAccessDto })
  @ApiNotFoundResponse()
  assetAccess(@Param('id', uuid) id: string): Promise<AssetAccess> {
    return this.access.assetAccess(id);
  }
}
