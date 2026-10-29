import {
  ForbiddenException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ApiTokensService } from './api-tokens.service.js';
import {
  ALLOW_MFA_PENDING,
  ALLOW_MFA_SETUP,
  ALLOW_PASSWORD_CHANGE,
  IS_PUBLIC,
  SESSION_ONLY,
} from './public.decorator.js';
import { SessionGuard } from './session.guard.js';
import type { SessionService } from './session.service.js';

const config = { get: () => true } as unknown as ConfigService<EnvironmentVariables, true>;
const user = {
  id: 'u1',
  email: 'a@b.c',
  name: 'A',
  role: 'admin',
  totpSecretRef: 'secret://local/infraward/users/u1/totp/x#secret',
};
/** Lo que el guard deja en `request.user` (nunca la referencia del secreto). */
const requestUser = { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', mfaEnabled: true };

function setup(
  meta: Record<string, boolean>,
  resolved: unknown,
  tokenResolved: unknown = null,
) {
  const reflector = new Reflector();
  vi.spyOn(reflector, 'getAllAndOverride').mockImplementation(
    (key: unknown) => meta[key as string] ?? undefined,
  );
  const sessions = { resolve: vi.fn(async () => resolved) };
  const apiTokens = { resolve: vi.fn(async () => tokenResolved) };
  const guard = new SessionGuard(
    sessions as unknown as SessionService,
    apiTokens as unknown as ApiTokensService,
    reflector,
    config,
  );
  return { guard, sessions, apiTokens };
}

function ctx(
  cookies: Record<string, string>,
  headers: Record<string, string> = {},
) {
  const request: Record<string, unknown> = { cookies, headers, ip: '10.0.0.9' };
  const context = {
    getHandler: () => undefined,
    getClass: () => undefined,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { context, request };
}

const session = (
  purpose: string,
  overrides: { authMethod?: string; user?: Record<string, unknown> } = {},
) => ({
  session: {
    id: 's1',
    purpose,
    csrfToken: 'c',
    expiresAt: new Date(),
    authMethod: overrides.authMethod ?? 'password',
    reauthenticatedAt: null,
  },
  user: { ...user, ...overrides.user },
});

describe('SessionGuard', () => {
  it('@Public() pasa sin mirar la cookie', async () => {
    const { guard, sessions } = setup({ [IS_PUBLIC]: true }, null);
    await expect(guard.canActivate(ctx({}).context)).resolves.toBe(true);
    expect(sessions.resolve).not.toHaveBeenCalled();
  });

  it('sin cookie, o con una sesión que no resuelve (caducada, revocada, desactivado) → 401', async () => {
    const { guard } = setup({}, null);
    await expect(guard.canActivate(ctx({}).context)).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(
      guard.canActivate(ctx({ '__Host-iw_session': 'x' }).context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('con sesión válida deja el usuario (rol de la BD) y la sesión en la request', async () => {
    const { guard, sessions } = setup({}, session('full'));
    const { context, request } = ctx({ '__Host-iw_session': 'tok' });
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(sessions.resolve).toHaveBeenCalledWith('tok');
    expect(request.user).toEqual(requestUser);
    expect(request.authSession).toMatchObject({ id: 's1', purpose: 'full' });
  });

  it('la sesión de una temporal solo vale donde se permite', async () => {
    const limited = setup({}, session('password_change'));
    await expect(
      limited.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).rejects.toMatchObject({
      constructor: ForbiddenException,
      response: { code: 'password_change_required' },
    });
    const allowed = setup({ [ALLOW_PASSWORD_CHANGE]: true }, session('password_change'));
    await expect(
      allowed.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).resolves.toBe(true);
  });

  it('la sesión intermedia del login (falta el código) solo vale donde se permite', async () => {
    const pending = setup({}, session('mfa'));
    await expect(
      pending.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).rejects.toMatchObject({
      constructor: ForbiddenException,
      response: { code: 'mfa_pending' },
    });
    // Ni siquiera donde vale la de una temporal.
    const temp = setup({ [ALLOW_PASSWORD_CHANGE]: true, [ALLOW_MFA_SETUP]: true }, session('mfa'));
    await expect(
      temp.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).rejects.toMatchObject({ response: { code: 'mfa_pending' } });
    const allowed = setup({ [ALLOW_MFA_PENDING]: true }, session('mfa'));
    await expect(
      allowed.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).resolves.toBe(true);
  });

  it('admin que entró con contraseña sin TOTP: solo donde se permite configurarlo', async () => {
    const noTotp = { user: { totpSecretRef: null } };
    const blocked = setup({}, session('full', noTotp));
    await expect(
      blocked.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).rejects.toMatchObject({
      constructor: ForbiddenException,
      response: { code: 'mfa_setup_required' },
    });
    const allowed = setup({ [ALLOW_MFA_SETUP]: true }, session('full', noTotp));
    await expect(
      allowed.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).resolves.toBe(true);
    // Por OIDC no (el MFA lo pone el proveedor), ni quien no es admin.
    const oidc = setup({}, session('full', { ...noTotp, authMethod: 'oidc' }));
    await expect(
      oidc.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).resolves.toBe(true);
    const editor = setup({}, session('full', { user: { totpSecretRef: null, role: 'editor' } }));
    await expect(
      editor.guard.canActivate(ctx({ '__Host-iw_session': 'tok' }).context),
    ).resolves.toBe(true);
  });

  describe('token de API (Bearer)', () => {
    const tokenResolved = {
      token: { id: 't1', scope: 'read', prefix: 'iwt_abcdefgh' },
      user,
    };

    it('deja el usuario y el token, sin sesión (sin CSRF)', async () => {
      const { guard, sessions, apiTokens } = setup({}, null, tokenResolved);
      const { context, request } = ctx({}, { authorization: 'Bearer iwt_x' });
      await expect(guard.canActivate(context)).resolves.toBe(true);
      expect(apiTokens.resolve).toHaveBeenCalledWith('iwt_x', '10.0.0.9');
      expect(sessions.resolve).not.toHaveBeenCalled();
      expect(request.user).toEqual(requestUser);
      expect(request.apiToken).toEqual({
        id: 't1',
        scope: 'read',
        prefix: 'iwt_abcdefgh',
      });
      expect(request.authSession).toBeUndefined();
    });

    it('un Bearer inválido es 401 aunque venga una cookie válida', async () => {
      const { guard, sessions } = setup({}, session('full'), null);
      await expect(
        guard.canActivate(
          ctx({ '__Host-iw_session': 'tok' }, { authorization: 'Bearer iwt_mal' })
            .context,
        ),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(sessions.resolve).not.toHaveBeenCalled();
    });

    it('otras cabeceras Authorization (Basic, Bearer ajeno) se ignoran: vale la cookie', async () => {
      for (const authorization of ['Basic eDp5', 'Bearer eyJhbGciOi.jwt.ajeno']) {
        const { guard, apiTokens, sessions } = setup({}, session('full'), tokenResolved);
        const { context, request } = ctx({ '__Host-iw_session': 'tok' }, { authorization });
        await expect(guard.canActivate(context)).resolves.toBe(true);
        expect(apiTokens.resolve).not.toHaveBeenCalled();
        expect(sessions.resolve).toHaveBeenCalledWith('tok');
        expect(request.apiToken).toBeUndefined();
      }
      // Sin cookie, la de siempre: 401.
      const { guard } = setup({}, null, tokenResolved);
      await expect(
        guard.canActivate(ctx({}, { authorization: 'Basic eDp5' }).context),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('@SessionOnly() con un token → 403 session_required', async () => {
      const { guard } = setup({ [SESSION_ONLY]: true }, null, tokenResolved);
      await expect(
        guard.canActivate(ctx({}, { authorization: 'Bearer iwt_x' }).context),
      ).rejects.toMatchObject({
        constructor: ForbiddenException,
        response: { code: 'session_required' },
      });
    });
  });
});
