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
  ApiAcceptedResponse,
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
  AssetPolicy,
  EnqueueJobResponse,
  InventoryPolicyList,
  InventoryPolicyRule,
} from '@infraward/shared-types';
import {
  AuditCtx,
  type AuditActor,
} from '../audit/audit-context.decorator.js';
import { Can } from '../auth/permissions.decorator.js';
import { EnqueueJobResponseDto } from '../jobs/jobs.dto.js';
import {
  AssetPolicyDto,
  CreateInventoryPolicyDto,
  InventoryPolicyFieldsDto,
  InventoryPolicyListDto,
  InventoryPolicyRuleDto,
  ReconcileRequestDto,
  UpdateGlobalPolicyDto,
} from './inventory.dto.js';
import { InventoryService } from './inventory.service.js';

const uuid = new ParseUUIDPipe();

/** Política de inventario y reconciliación (DESIGN §10). */
@ApiTags('inventory')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller()
export class InventoryController {
  constructor(private readonly inventory: InventoryService) {}

  /** La política global y las reglas por asset y por etiqueta. */
  @Get('inventory-policies')
  @ApiOkResponse({ type: InventoryPolicyListDto })
  list(): Promise<InventoryPolicyList> {
    return this.inventory.list();
  }

  /** Cambia la política global (valores por defecto de todo el inventario). */
  @Put('inventory-policies/global')
  @Can('policy.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiOkResponse({ type: InventoryPolicyRuleDto })
  @ApiBadRequestResponse()
  updateGlobal(
    @Body() body: UpdateGlobalPolicyDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<InventoryPolicyRule> {
    return this.inventory.updateGlobal(body, actor);
  }

  /**
   * Regla de un asset (se hereda en todo lo que contiene, salvo que un descendiente tenga la suya)
   * o de una etiqueta. Cada campo null o ausente no se fija.
   */
  @Post('inventory-policies')
  @Can('policy.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiCreatedResponse({ type: InventoryPolicyRuleDto })
  @ApiBadRequestResponse({ description: 'Ningún campo fijado' })
  @ApiNotFoundResponse({ description: 'No existe el asset' })
  @ApiConflictResponse({
    description: 'Ya hay una regla para ese asset o esa etiqueta',
  })
  create(
    @Body() body: CreateInventoryPolicyDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<InventoryPolicyRule> {
    return this.inventory.create(body, actor);
  }

  @Patch('inventory-policies/:id')
  @Can('policy.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiOkResponse({ type: InventoryPolicyRuleDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  update(
    @Param('id', uuid) id: string,
    @Body() body: InventoryPolicyFieldsDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<InventoryPolicyRule> {
    return this.inventory.update(id, body, actor);
  }

  @Delete('inventory-policies/:id')
  @Can('policy.write')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiNoContentResponse()
  @ApiNotFoundResponse()
  @ApiConflictResponse({ description: 'La global no se borra' })
  remove(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<void> {
    return this.inventory.remove(id, actor);
  }

  /** Política efectiva del asset, de dónde sale cada campo y su reconciliación. */
  @Get('assets/:id/policy')
  @ApiOkResponse({ type: AssetPolicyDto })
  @ApiNotFoundResponse()
  assetPolicy(@Param('id', uuid) id: string): Promise<AssetPolicy> {
    return this.inventory.assetPolicy(id);
  }

  /** Fija la regla propia del asset (null en un campo = lo hereda). */
  @Put('assets/:id/policy')
  @Can('policy.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiOkResponse({ type: AssetPolicyDto })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  setAssetPolicy(
    @Param('id', uuid) id: string,
    @Body() body: InventoryPolicyFieldsDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<AssetPolicy> {
    return this.inventory.setAssetPolicy(id, body, actor);
  }

  /** Quita la regla propia: vuelve a heredar. */
  @Delete('assets/:id/policy')
  @Can('policy.write')
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiOkResponse({ type: AssetPolicyDto })
  @ApiNotFoundResponse()
  removeAssetPolicy(
    @Param('id', uuid) id: string,
    @AuditCtx() actor: AuditActor,
  ): Promise<AssetPolicy> {
    return this.inventory.removeAssetPolicy(id, actor);
  }

  /**
   * Reconcilia ahora: los nodos raíz con el intervalo vencido o, con `assetId`, ese nodo raíz.
   * Su recolección encadena el descubrimiento de los hijos (altas, cambios, desaparecidos).
   */
  @Post('inventory/reconcile')
  @Can('assets.operate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: EnqueueJobResponseDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description: 'No es un nodo raíz activo con conexión',
  })
  reconcile(
    @Body() body: ReconcileRequestDto,
    @AuditCtx() actor: AuditActor,
  ): Promise<EnqueueJobResponse> {
    return this.inventory.reconcile(body.assetId, actor);
  }
}
