import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import type { AuditService } from '../audit/audit.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { RECENT_AUTH, type RecentAuthRule } from './recent-auth.decorator.js';
import { isRecentlyAuthenticated, RecentAuthGuard } from './recent-auth.guard.js';

const config = {
  get: () => 600,
} as unknown as ConfigService<EnvironmentVariables, true>;

function setup(rule: RecentAuthRule | undefined, request: Record<string, unknown>) {
  const reflector = new Reflector();
  vi.spyOn(reflector, 'get').mockImplementation((key: unknown) =>
    key === RECENT_AUTH ? rule : undefined,
  );
  const audit = { record: vi.fn(async () => undefined) };
  const guard = new RecentAuthGuard(
    reflector,
    audit as unknown as AuditService,
    config,
  );
  const context = {
    getHandler: () => undefined,
    switchToHttp: () => ({ getRequest: () => ({ ip: '10.0.0.9', ...request }) }),
  } as unknown as ExecutionContext;
  return { guard, context, audit };
}

const user = { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', mfaEnabled: true };
const session = (
  reauthenticatedAt: Date | null,
  authMethod: 'password' | 'oidc' = 'password',
) => ({ id: 's1', purpose: 'full', authMethod, reauthenticatedAt });
const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000);
const purge: RecentAuthRule = { action: 'asset.purge' };

describe('RecentAuthGuard', () => {
  it('sin @RecentAuth, o si la condición no se cumple, pasa sin mirar nada', async () => {
    const none = setup(undefined, {});
    await expect(none.guard.canActivate(none.context)).resolves.toBe(true);
    const skipped = setup({ action: 'asset.purge', when: () => false }, {});
    await expect(skipped.guard.canActivate(skipped.context)).resolves.toBe(true);
    expect(skipped.audit.record).not.toHaveBeenCalled();
  });

  it('reautenticada hace menos de REAUTH_MAX_AGE: pasa', async () => {
    const { guard, context } = setup(purge, {
      user,
      authSession: session(minutesAgo(9)),
    });
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it.each([
    ['nunca', null],
    ['hace 11 minutos', minutesAgo(11)],
  ])('reautenticada %s: 403 recent_auth_required con el método TOTP y auditado', async (_l, at) => {
    const { guard, context, audit } = setup(purge, { user, authSession: session(at) });
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      constructor: ForbiddenException,
      response: {
        code: 'recent_auth_required',
        method: 'totp',
        action: 'asset.purge',
      },
    });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ actorId: 'u1' }),
      'auth.reauth_required',
      expect.objectContaining({
        outcome: 'failure',
        details: expect.objectContaining({ action: 'asset.purge' }),
      }),
    );
  });

  it('sesión OIDC: el método es oidc (login en el proveedor)', async () => {
    const { guard, context } = setup(purge, {
      user: { ...user, mfaEnabled: false },
      authSession: session(minutesAgo(30), 'oidc'),
    });
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      response: { code: 'recent_auth_required', method: 'oidc' },
    });
  });

  it('usuario local sin TOTP: 403 mfa_required_for_action aunque acabe de entrar', async () => {
    const { guard, context } = setup(
      { action: 'api_token.create_write' },
      { user: { ...user, role: 'editor', mfaEnabled: false }, authSession: session(new Date()) },
    );
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      response: { code: 'mfa_required_for_action', action: 'api_token.create_write' },
    });
  });

  it('con un token de API: siempre 403, sin método (solo desde la web)', async () => {
    const { guard, context } = setup(purge, {
      user,
      apiToken: { id: 't1', scope: 'role', prefix: 'iwt_abcdefgh' },
    });
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      response: { code: 'recent_auth_required', method: null },
    });
  });

  it('un auth_time del futuro lejano no vale', () => {
    const now = Date.now();
    expect(isRecentlyAuthenticated({ reauthenticatedAt: new Date(now + 30_000) }, 600_000, now)).toBe(true);
    expect(isRecentlyAuthenticated({ reauthenticatedAt: new Date(now + 3_600_000) }, 600_000, now)).toBe(false);
  });
});
