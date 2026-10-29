import { TestBed } from '@angular/core/testing';
import { provideRouter, Router, UrlSegment, UrlTree } from '@angular/router';
import {
  authGuard,
  guestGuard,
  mfaSetupGuard,
  mfaVerifyGuard,
  passwordChangeGuard,
  safeReturnUrl,
} from './auth.guards';
import { AuthService } from './auth.service';

describe('guards', () => {
  let authenticated: boolean;
  let mustChange: boolean;
  let mfaPending: boolean;
  let mfaSetup: boolean;

  beforeEach(() => {
    authenticated = false;
    mustChange = false;
    mfaPending = false;
    mfaSetup = false;
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        {
          provide: AuthService,
          useValue: {
            isAuthenticated: () => authenticated,
            mustChangePassword: () => mustChange,
            mfaPending: () => mfaPending,
            mfaSetupRequired: () => mfaSetup,
          },
        },
      ],
    });
  });

  // El tercer argumento (snapshot parcial) no lo usan los guards.
  const snap = {} as Parameters<typeof authGuard>[2];
  const run = <T>(fn: () => T) => TestBed.runInInjectionContext(fn);
  const seg = (...paths: string[]) => paths.map((p) => new UrlSegment(p, {}));
  const url = (tree: unknown) =>
    TestBed.inject(Router).serializeUrl(tree as UrlTree);

  it('authGuard: sin sesión lleva al login recordando la ruta', () => {
    const res = run(() => authGuard({}, seg('assets', 'abc'), snap));
    expect(url(res)).toBe('/login?returnUrl=%2Fassets%2Fabc');
    expect(url(run(() => authGuard({}, [], snap)))).toBe('/login');
  });

  it('authGuard: con sesión deja pasar', () => {
    authenticated = true;
    expect(run(() => authGuard({}, seg('inventory'), snap))).toBe(true);
  });

  it('authGuard: con la sesión de una temporal, a cambiarla; y solo entonces', () => {
    authenticated = true;
    mustChange = true;
    expect(url(run(() => authGuard({}, seg('inventory'), snap)))).toBe('/change-password');
    expect(run(() => passwordChangeGuard({}, [], snap))).toBe(true);
    mustChange = false;
    expect(url(run(() => passwordChangeGuard({}, [], snap)))).toBe('/dashboard');
    authenticated = false;
    expect(url(run(() => passwordChangeGuard({}, [], snap)))).toBe('/login');
  });

  it('a medio login (falta el código): todo lleva al segundo paso, y solo entonces vale', () => {
    authenticated = true;
    mfaPending = true;
    expect(url(run(() => authGuard({}, seg('inventory'), snap)))).toBe('/login/mfa');
    expect(url(run(() => guestGuard({}, [], snap)))).toBe('/login/mfa');
    expect(url(run(() => passwordChangeGuard({}, [], snap)))).toBe('/login/mfa');
    expect(run(() => mfaVerifyGuard({}, [], snap))).toBe(true);
    mfaPending = false;
    expect(url(run(() => mfaVerifyGuard({}, [], snap)))).toBe('/dashboard');
  });

  it('un admin local sin TOTP: a configurarlo antes de nada (tras cambiar la temporal)', () => {
    authenticated = true;
    mfaSetup = true;
    expect(url(run(() => authGuard({}, seg('settings'), snap)))).toBe('/mfa-setup');
    expect(run(() => mfaSetupGuard({}, [], snap))).toBe(true);
    mustChange = true;
    expect(url(run(() => mfaSetupGuard({}, [], snap)))).toBe('/change-password');
    mustChange = false;
    mfaSetup = false;
    expect(url(run(() => mfaSetupGuard({}, [], snap)))).toBe('/dashboard');
    authenticated = false;
    expect(url(run(() => mfaSetupGuard({}, [], snap)))).toBe('/login');
  });

  it('guestGuard: con sesión, el login lleva al inventario', () => {
    expect(run(() => guestGuard({}, [], snap))).toBe(true);
    authenticated = true;
    expect(url(run(() => guestGuard({}, [], snap)))).toBe('/dashboard');
  });

  it('safeReturnUrl solo admite rutas internas', () => {
    expect(safeReturnUrl('/assets/1')).toBe('/assets/1');
    for (const bad of [undefined, null, '', 'https://evil.example', '//evil.example', 'javascript:alert(1)'])
      expect(safeReturnUrl(bad)).toBe('/dashboard');
  });
});
