import {
  Controller,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiCookieAuth,
  ApiConflictResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { EnqueueJobResponse } from '@infraward/shared-types';
import { Can } from '../auth/permissions.decorator.js';
import { EnqueueJobResponseDto } from '../jobs/jobs.dto.js';
import { CollectionService } from './collection.service.js';

@ApiTags('assets')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@Controller('assets')
export class CollectionController {
  constructor(private readonly collection: CollectionService) {}

  /**
   * Recoge el asset con Ansible (facts, paquetes, servicios, puertos y roles) y guarda un
   * snapshot. Un servidor se recoge por SSH; un CT de Proxmox descubierto, desde su nodo con
   * `pct exec`. Si el asset tiene un rol con descubridor (`proxmox-node`), al terminar se encola
   * su descubrimiento. El progreso y el resultado se consultan con `GET /jobs/:id`.
   */
  @Post(':id/collect')
  @Can('assets.operate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: EnqueueJobResponseDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description:
      'El asset no está dado de alta o no se puede recoger (sin conexión SSH, VM, CT parado…)',
  })
  collect(@Param('id', ParseUUIDPipe) id: string): Promise<EnqueueJobResponse> {
    return this.collection.collect(id);
  }

  /**
   * Descubre los hijos del asset con el descubridor de su rol (Proxmox: CT y VMs con `pvesh`,
   * solo lectura) y los reconcilia con el inventario: crea los nuevos, actualiza los conocidos,
   * marca `missing` los que ya no existen y encola la recolección de los CT en marcha.
   */
  @Post(':id/discover')
  @Can('assets.operate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiForbiddenResponse({ description: 'Sin el permiso necesario para su rol' })
  @ApiAcceptedResponse({ type: EnqueueJobResponseDto })
  @ApiNotFoundResponse()
  @ApiConflictResponse({
    description:
      'El asset no tiene un rol con descubridor o no es un servidor activo con conexión',
  })
  discover(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<EnqueueJobResponse> {
    return this.collection.discover(id);
  }
}
