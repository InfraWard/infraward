import { inject } from '@angular/core';
import { Router, type CanMatchFn } from '@angular/router';
import type { Permission } from '@infraward/shared-types';
import { AuthService } from './auth.service';

/**
 * Rutas privadas: sin sesión, al login recordando adónde se quería ir; a medio login (falta el
 * código), al segundo paso; con la sesión de una contraseña temporal, a cambiarla; un admin local
 * sin TOTP, a configurarlo.
 */
export const authGuard: CanMatchFn = (_route, segments) => {
  const auth = inject(AuthService);
  if (auth.isAuthenticated()) {
    const pending = pendingStep(auth);
    return pending ? inject(Router).createUrlTree([pending]) : true;
  }
  const returnUrl = '/' + segments.map((s) => s.path).join('/');
  return inject(Router).createUrlTree(['/login'], {
    queryParams: returnUrl === '/' ? {} : { returnUrl },
  });
};

/** Página de inicio (tras el login, o si se llega donde no toca). */
export const HOME_URL = '/dashboard';

/** Rutas que exigen un permiso (escriben): sin él, vuelta al inicio. */
export const permissionGuard =
  (permission: Permission): CanMatchFn =>
  () =>
    inject(AuthService).can(permission)
      ? true
      : inject(Router).createUrlTree([HOME_URL]);

/** Paso obligado antes de usar la app (o null): código, contraseña nueva o alta de TOTP. */
export function pendingStep(auth: AuthService): string | null {
  if (auth.mfaPending()) return '/login/mfa';
  if (auth.mustChangePassword()) return '/change-password';
  if (auth.mfaSetupRequired()) return '/mfa-setup';
  return null;
}

/** Guard de la página de un paso obligado: solo cuando es ese el paso pendiente. */
const stepGuard =
  (step: string): CanMatchFn =>
  () => {
    const auth = inject(AuthService);
    if (!auth.isAuthenticated()) return inject(Router).createUrlTree(['/login']);
    const pending = pendingStep(auth);
    return pending === step ? true : inject(Router).createUrlTree([pending ?? HOME_URL]);
  };

/** El cambio obligado de contraseña solo con la sesión de una temporal. */
export const passwordChangeGuard: CanMatchFn = stepGuard('/change-password');
/** El segundo paso del login (código TOTP o de recuperación). */
export const mfaVerifyGuard: CanMatchFn = stepGuard('/login/mfa');
/** El alta obligada de TOTP de un admin local. */
export const mfaSetupGuard: CanMatchFn = stepGuard('/mfa-setup');

/** El login solo sin sesión (a medio login, al paso que falta). */
export const guestGuard: CanMatchFn = () => {
  const auth = inject(AuthService);
  if (!auth.isAuthenticated()) return true;
  return inject(Router).createUrlTree([pendingStep(auth) ?? HOME_URL]);
};

/** Solo rutas internas como destino tras el login (evita redirecciones abiertas). */
export function safeReturnUrl(value: string | null | undefined): string {
  return value && value.startsWith('/') && !value.startsWith('//')
    ? value
    : HOME_URL;
}
