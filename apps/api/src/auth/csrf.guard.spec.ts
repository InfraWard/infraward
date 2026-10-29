import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { CsrfGuard } from './csrf.guard.js';

const config = {
  get: (key: string) =>
    ({
      PUBLIC_URL: 'https://infraward.example.com',
      NODE_ENV: 'production',
      WEB_ORIGIN: undefined,
    })[key],
} as unknown as ConfigService<EnvironmentVariables, true>;

function ctx(
  method: string,
  headers: Record<string, string>,
  csrfToken?: string,
): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        method,
        headers,
        authSession: csrfToken ? { id: 's', purpose: 'full', csrfToken } : undefined,
      }),
    }),
  } as unknown as ExecutionContext;
}

describe('CsrfGuard', () => {
  const guard = new CsrfGuard(config);
  const web = { origin: 'https://infraward.example.com' };

  it('las lecturas pasan siempre', () => {
    expect(guard.canActivate(ctx('GET', { origin: 'https://evil.example' }, 'x'))).toBe(true);
  });

  it('con sesión, exige el token CSRF exacto', () => {
    expect(guard.canActivate(ctx('POST', { ...web, 'x-csrf-token': 'tok' }, 'tok'))).toBe(true);
    for (const headers of [web, { ...web, 'x-csrf-token': 'otro' }, { ...web, 'x-csrf-token': 'tok2' }])
      expect(() => guard.canActivate(ctx('DELETE', headers, 'tok'))).toThrow(ForbiddenException);
  });

  it('rechaza un Origin ajeno o una petición entre sitios, también sin sesión (login)', () => {
    expect(() =>
      guard.canActivate(ctx('POST', { origin: 'https://evil.example', 'x-csrf-token': 'tok' }, 'tok')),
    ).toThrow(ForbiddenException);
    expect(() => guard.canActivate(ctx('POST', { origin: 'https://evil.example' }))).toThrow(
      ForbiddenException,
    );
    expect(() => guard.canActivate(ctx('POST', { 'sec-fetch-site': 'cross-site' }))).toThrow(
      ForbiddenException,
    );
  });

  it('sin navegador ni sesión (el script de alta con curl) pasa', () => {
    expect(guard.canActivate(ctx('POST', {}))).toBe(true);
    expect(guard.canActivate(ctx('POST', { ...web, 'sec-fetch-site': 'same-origin' }))).toBe(true);
  });
});
