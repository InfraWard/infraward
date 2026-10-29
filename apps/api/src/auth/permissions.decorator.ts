import { SetMetadata } from '@nestjs/common';
import type { AccessPermission, Permission } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';

export const PERMISSIONS_KEY = 'permissions';

/**
 * Restringe un endpoint (o un controlador) a quien tenga alguno de los permisos indicados según
 * su rol (`ROLE_PERMISSIONS` de shared-types). El del método sustituye al del controlador.
 */
export const Can = (...permissions: Permission[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);

export const ASSET_PERMISSION_KEY = 'assetPermission';

export interface AssetPermissionRule {
  permission: AccessPermission;
  /** De dónde sale el asset en la petición (cuerpo, parámetro…). */
  assetId: (request: FastifyRequest) => unknown;
}

/**
 * Permiso que depende del asset (sesión 22): lo da el rol o una AccessPolicy que alcance al
 * asset. Lo comprueba `PermissionsGuard`, antes que la reautenticación reciente: quien no puede
 * no llega a ver el diálogo de reautenticación.
 */
export const CanOnAsset = (
  permission: AccessPermission,
  assetId: AssetPermissionRule['assetId'],
) => SetMetadata(ASSET_PERMISSION_KEY, { permission, assetId } satisfies AssetPermissionRule);
