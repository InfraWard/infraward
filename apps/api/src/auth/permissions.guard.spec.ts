import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { Reflector, type ModuleRef } from '@nestjs/core';
import {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  USER_ROLES,
  type Permission,
  type UserRole,
} from '@infraward/shared-types';
import { PermissionsGuard } from './permissions.guard.js';

/** Petición cuyo usuario (leído de la BD por el guard de sesión) tiene `role`. */
function context(
  role: UserRole | undefined,
  extra: { method?: string; apiToken?: { scope: string } } = {},
): ExecutionContext {
  return {
    getHandler: () => undefined,
    getClass: () => undefined,
    switchToHttp: () => ({
      getRequest: () => ({
        user: role ? { id: '1', email: 'x@y.z', name: 'x', role } : undefined,
        method: extra.method ?? 'GET',
        apiToken: extra.apiToken,
      }),
    }),
  } as unknown as ExecutionContext;
}

function guard(required: Permission[] | undefined): PermissionsGuard {
  const reflector = new Reflector();
  vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue(required);
  vi.spyOn(reflector, 'get').mockReturnValue(undefined);
  return new PermissionsGuard(reflector);
}

/** Guard con @CanOnAsset('terminal.open', body.assetId) y un AccessChecker falso. */
function assetGuard(allowed: (userId: string, assetId: string) => boolean) {
  const reflector = new Reflector();
  vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
  vi.spyOn(reflector, 'get').mockReturnValue({
    permission: 'terminal.open',
    assetId: (r: { body?: { assetId?: unknown } }) => r.body?.assetId,
  });
  const can = vi.fn(async (user: { id: string }, _p: string, assetId: string) =>
    allowed(user.id, assetId),
  );
  const moduleRef = { get: () => ({ can }) } as unknown as ModuleRef;
  return { guard: new PermissionsGuard(reflector, moduleRef), can };
}

function assetContext(role: UserRole, body: unknown): ExecutionContext {
  return {
    getHandler: () => undefined,
    getClass: () => undefined,
    switchToHttp: () => ({
      getRequest: () => ({ user: { id: 'u1', role }, method: 'POST', body }),
    }),
  } as unknown as ExecutionContext;
}

const ASSET = '6f1c7a3e-2b4d-4c8e-9a1f-0123456789ab';

describe('PermissionsGuard con @CanOnAsset', () => {
  it('el rol basta (admin) sin preguntar a las reglas', async () => {
    const { guard: g, can } = assetGuard(() => false);
    await expect(g.canActivate(assetContext('admin', { assetId: ASSET }))).resolves.toBe(true);
    expect(can).not.toHaveBeenCalled();
  });

  it('una regla en ese asset deja pasar; sin ella, 403', async () => {
    const { guard: g } = assetGuard((_u, a) => a === ASSET);
    await expect(g.canActivate(assetContext('editor', { assetId: ASSET }))).resolves.toBe(true);
    await expect(
      g.canActivate(
        assetContext('editor', { assetId: '00000000-0000-4000-8000-000000000000' }),
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('sin asset válido en la petición, 403 sin preguntar', async () => {
    const { guard: g, can } = assetGuard(() => true);
    for (const body of [{}, { assetId: 'x' }, { assetId: 5 }, undefined])
      await expect(g.canActivate(assetContext('editor', body))).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    expect(can).not.toHaveBeenCalled();
  });
});

describe('PermissionsGuard', () => {
  describe('token de API de solo lectura', () => {
    const read = { scope: 'read' };

    it('lee (GET/HEAD) con los permisos de su rol', () => {
      expect(guard(undefined).canActivate(context('admin', { apiToken: read }))).toBe(true);
      expect(
        guard(['audit.read']).canActivate(context('admin', { method: 'HEAD', apiToken: read })),
      ).toBe(true);
      expect(() =>
        guard(['audit.read']).canActivate(context('viewer', { apiToken: read })),
      ).toThrow(ForbiddenException);
    });

    it('cualquier escritura → 403 api_token_read_only, aunque el rol pueda', () => {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        expect(() =>
          guard(undefined).canActivate(context('admin', { method, apiToken: read })),
        ).toThrow(expect.objectContaining({ response: expect.objectContaining({ code: 'api_token_read_only' }) }));
      }
    });

    it('un token con el alcance del rol escribe lo que el rol permita', () => {
      expect(
        guard(['assets.write']).canActivate(
          context('editor', { method: 'POST', apiToken: { scope: 'role' } }),
        ),
      ).toBe(true);
      expect(() =>
        guard(['assets.write']).canActivate(
          context('operator', { method: 'POST', apiToken: { scope: 'role' } }),
        ),
      ).toThrow(ForbiddenException);
    });
  });

  it('sin @Can deja pasar a cualquiera autenticado', () => {
    expect(guard(undefined).canActivate(context('viewer'))).toBe(true);
  });

  it('deja pasar si el rol tiene alguno de los permisos', () => {
    expect(guard(['assets.operate']).canActivate(context('operator'))).toBe(true);
    expect(guard(['users.manage', 'users.read']).canActivate(context('auditor'))).toBe(true);
  });

  it('sin el permiso o sin autenticar → 403', () => {
    expect(() => guard(['assets.write']).canActivate(context('operator'))).toThrow(
      ForbiddenException,
    );
    expect(() => guard(['assets.purge']).canActivate(context('editor'))).toThrow(
      ForbiddenException,
    );
    expect(() => guard(['assets.operate']).canActivate(context(undefined))).toThrow(
      ForbiddenException,
    );
  });
});

describe('ROLE_PERMISSIONS', () => {
  it('la matriz de roles y permisos (DESIGN §14)', () => {
    const matrix = Object.fromEntries(
      USER_ROLES.map((r) => [r, PERMISSIONS.filter((p) => ROLE_PERMISSIONS[r].includes(p))]),
    );
    expect(matrix).toEqual({
      admin: [...PERMISSIONS],
      editor: [
        'assets.operate',
        'assets.write',
        'projects.write',
        'policy.write',
        'secrets.status',
        'connectors.write',
        'vault.manage',
      ],
      operator: ['assets.operate'],
      auditor: ['secrets.status', 'audit.read', 'users.read'],
      viewer: [],
    });
  });

  it('solo admin purga, gestiona usuarios y revela credenciales de la caja fuerte', () => {
    for (const p of ['assets.purge', 'users.manage', 'vault.admin'] as const)
      expect(USER_ROLES.filter((r) => ROLE_PERMISSIONS[r].includes(p))).toEqual(['admin']);
  });
});
