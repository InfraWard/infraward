import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Optional,
} from '@nestjs/common';
import { ModuleRef, Reflector } from '@nestjs/core';
import {
  API_TOKEN_READ_ONLY,
  hasPermission,
  type Permission,
} from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';
import { ACCESS_CHECKER, type AccessChecker } from './access-checker.js';
import {
  ASSET_PERMISSION_KEY,
  PERMISSIONS_KEY,
  type AssetPermissionRule,
} from './permissions.decorator.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Métodos que no cambian nada: los únicos que admite un token de API de solo lectura. */
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Guard global (después del de sesión y del CSRF): aplica @Can(). Sin @Can basta con estar
 * autenticado (leer). El rol ya viene de la BD (lo lee el guard de sesión en cada petición). Un
 * token de API de solo lectura solo pasa en GET/HEAD (con los permisos de lectura de su rol).
 * Con @CanOnAsset() el permiso puede venir también de una AccessPolicy sobre el asset.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Optional() private readonly moduleRef?: ModuleRef,
  ) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    if (
      request.apiToken?.scope === 'read' &&
      !READ_METHODS.has(request.method.toUpperCase())
    )
      throw new ForbiddenException({
        statusCode: 403,
        code: API_TOKEN_READ_ONLY,
        message: 'El token es de solo lectura',
      });
    const required = this.reflector.getAllAndOverride<Permission[] | undefined>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );
    const onAsset = this.reflector.get<AssetPermissionRule | undefined>(
      ASSET_PERMISSION_KEY,
      context.getHandler(),
    );
    if (onAsset) return this.canOnAsset(request, onAsset);
    if (!required?.length) return true;
    const { user } = request;
    if (user && required.some((p) => hasPermission(user.role, p))) return true;
    throw new ForbiddenException();
  }

  private async canOnAsset(
    request: FastifyRequest,
    rule: AssetPermissionRule,
  ): Promise<boolean> {
    const { user } = request;
    if (!user) throw new ForbiddenException();
    if (hasPermission(user.role, rule.permission)) return true;
    const assetId = rule.assetId(request);
    const checker = this.moduleRef?.get<AccessChecker>(ACCESS_CHECKER, { strict: false });
    if (typeof assetId === 'string' && UUID.test(assetId) && checker) {
      if (await checker.can(user, rule.permission, assetId)) return true;
    }
    throw new ForbiddenException();
  }
}
