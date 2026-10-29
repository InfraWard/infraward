import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
} from '@nestjs/common';
import {
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
  TemporaryPasswordResponse,
  UserSummary,
} from '@infraward/shared-types';
import { AuditCtx, type AuditActor } from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { RecentAuth } from '../auth/recent-auth.decorator.js';
import {
  CreateUserDto,
  TemporaryPasswordResponseDto,
  UpdateUserDto,
  UserSummaryDto,
} from './users.dto.js';
import { UsersService } from './users.service.js';

const uuid = new ParseUUIDPipe();

/** Gestión de usuarios (DESIGN §14). Nunca devuelve hashes; la temporal, una sola vez. */
@ApiTags('users')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiForbiddenResponse({
  description: 'Requiere users.manage (users.read para la lista)',
})
@Can('users.manage')
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  /** La lista también la ven quienes leen la auditoría (filtro por usuario). */
  @Get()
  @Can('users.read')
  @ApiOkResponse({ type: [UserSummaryDto] })
  async list(): Promise<UserSummary[]> {
    return (await this.users.list()).map((u) => this.users.summary(u));
  }

  /** Alta con una contraseña temporal de un solo uso que el usuario cambia al entrar. */
  @Post()
  @ApiCreatedResponse({ type: TemporaryPasswordResponseDto })
  @ApiBadRequestResponse()
  @ApiConflictResponse({
    description:
      'Ya existe un usuario con ese email, o el login local está desactivado',
  })
  create(
    @Body() body: CreateUserDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<TemporaryPasswordResponse> {
    return this.users.createWithTemporaryPassword(body, actor);
  }

  /** Cambiar el rol es sensible (la web solo manda `role` si cambia). */
  @Patch(':id')
  @RecentAuth('user.role_change', (request) => hasRole(request.body))
  @ApiOkResponse({ type: UserSummaryDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description:
      'Es el último administrador activo, el rol o el email lo gestiona el proveedor OIDC, o el email ya existe',
  })
  update(
    @Param('id', uuid) id: string,
    @Body() body: UpdateUserDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<UserSummary> {
    return this.users.update(id, body, actor);
  }

  /** No puede entrar y pierde sus sesiones al momento. */
  @Post(':id/deactivate')
  @RecentAuth('user.deactivate')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: UserSummaryDto })
  @ApiBadRequestResponse({ description: 'Tu propia cuenta' })
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'Es el último administrador activo' })
  deactivate(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<UserSummary> {
    return this.users.deactivate(id, actor);
  }

  @Post(':id/reactivate')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: UserSummaryDto })
  @ApiNotFoundResponse()
  reactivate(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<UserSummary> {
    return this.users.reactivate(id, actor);
  }

  /** Contraseña temporal nueva (un solo uso, obliga a cambiarla); cierra sus sesiones. */
  @Post(':id/reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: TemporaryPasswordResponseDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description:
      'Usuario creado por OIDC (sin contraseña) o login local desactivado',
  })
  resetPassword(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<TemporaryPasswordResponse> {
    return this.users.resetPassword(id, actor);
  }
}

function hasRole(body: unknown): boolean {
  return typeof body === 'object' && body !== null && 'role' in body;
}
