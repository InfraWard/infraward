import type { AccessPermission } from '@infraward/shared-types';
import type { AuthenticatedUser } from './authenticated-user.js';

/**
 * Quién decide un permiso que depende del asset (AccessPolicy, sesión 22): lo implementa
 * `AccessService` y lo usa `PermissionsGuard` con `@CanOnAsset()`. Token aparte para que el
 * guard (módulo de autenticación) no dependa del módulo de acceso.
 */
export const ACCESS_CHECKER = Symbol('ACCESS_CHECKER');

export interface AccessChecker {
  can(user: AuthenticatedUser, permission: AccessPermission, assetId: string): Promise<boolean>;
}
