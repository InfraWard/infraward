import {
  HttpContextToken,
  HttpErrorResponse,
  type HttpInterceptorFn,
} from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import {
  CSRF_HEADER,
  MFA_PENDING,
  MFA_REQUIRED_FOR_ACTION,
  MFA_SETUP_REQUIRED,
  PASSWORD_CHANGE_REQUIRED,
  RECENT_AUTH_REQUIRED,
  type RecentAuthError,
} from '@infraward/shared-types';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { API_BASE_URL } from '../api/api-base-url';
import { AuthService } from './auth.service';
import { ReauthService } from './reauth.service';

/** La petición ya se repitió tras reautenticarse: si vuelve a fallar, no se pregunta otra vez. */
const REAUTH_RETRY = new HttpContextToken(() => false);

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Peticiones a la API (nunca a otros orígenes): la cookie de sesión va sola (mismo origen) y aquí
 * se añade el token CSRF a las que modifican datos. Un 401 con sesión significa caducada o
 * revocada (p. ej. usuario desactivado): se cierra y se vuelve al login conservando la ruta. Un
 * 403 `password_change_required` lleva a cambiar la contraseña temporal; `mfa_pending`, al
 * segundo paso del login; `mfa_setup_required`, a configurar el TOTP. El 403 de una acción
 * sensible (`recent_auth_required`, `mfa_required_for_action`) abre el diálogo de
 * reautenticación y, si se confirma con un código, repite la petición una vez.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const api = inject(API_BASE_URL);
  if (!isApiUrl(req.url, api)) return next(req);
  const auth = inject(AuthService);
  const router = inject(Router);
  const reauth = inject(ReauthService);
  const csrf = SAFE_METHODS.has(req.method) ? null : auth.csrfToken();
  const sent = csrf ? req.clone({ setHeaders: { [CSRF_HEADER]: csrf } }) : req;
  return next(sent).pipe(
    catchError((err: unknown) => {
      const code =
        err instanceof HttpErrorResponse && err.status === 403
          ? (err.error as { code?: string } | null)?.code
          : undefined;
      if (
        (code === RECENT_AUTH_REQUIRED || code === MFA_REQUIRED_FOR_ACTION) &&
        !req.context.get(REAUTH_RETRY)
      ) {
        const body = (err as HttpErrorResponse).error as RecentAuthError;
        return from(reauth.request(body)).pipe(
          switchMap((ok) =>
            ok
              ? next(sent.clone({ context: sent.context.set(REAUTH_RETRY, true) }))
              : throwError(() => err),
          ),
        );
      }
      if (code === MFA_PENDING) void router.navigate(['/login/mfa']);
      if (code === MFA_SETUP_REQUIRED)
        void auth.verify().then(() => router.navigate(['/mfa-setup']));
      if (err instanceof HttpErrorResponse) {
        if (err.status === 401 && auth.isAuthenticated()) {
          auth.clear();
          const returnUrl = router.url.startsWith('/login')
            ? undefined
            : router.url;
          void router.navigate(['/login'], {
            queryParams: { ...(returnUrl ? { returnUrl } : {}), expired: 1 },
          });
        } else if (
          err.status === 403 &&
          (err.error as { code?: string } | null)?.code ===
            PASSWORD_CHANGE_REQUIRED
        ) {
          void router.navigate(['/change-password']);
        }
      }
      return throwError(() => err);
    }),
  );
};

function isApiUrl(url: string, api: string): boolean {
  return url === api || url.startsWith(`${api}/`);
}
