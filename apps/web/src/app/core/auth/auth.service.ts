import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import {
  hasPermission,
  type MfaCodeRequest,
  type ReauthResponse,
  type SensitiveAction,
  type AuthProviders,
  type ChangeEmailRequest,
  type ChangePasswordRequest,
  type LoginRequest,
  type LogoutResponse,
  type Permission,
  type SessionInfo,
  type UserProfile,
} from '@infraward/shared-types';
import { firstValueFrom } from 'rxjs';
import { API_BASE_URL } from '../api/api-base-url';
import { BROWSER_NAVIGATION } from './browser-navigation';

let primed: SessionInfo | null = null;

/** Solo para tests: sesión con la que arrancan los AuthService que se creen a continuación. */
export function primeSessionForTests(session: SessionInfo | null): void {
  primed = session;
}

/**
 * Sesión del usuario (DESIGN §14). El token de sesión vive en una cookie httpOnly que JavaScript
 * no puede leer; aquí solo hay el perfil, la caducidad y el token CSRF (que sin la cookie no
 * sirve), en memoria. Al cargar la página se recupera con GET /auth/session.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);
  private readonly navigation = inject(BROWSER_NAVIGATION);
  private readonly session = signal<SessionInfo | null>(primed);

  readonly user = computed(() => this.session()?.user ?? null);
  readonly isAdmin = computed(() => this.user()?.role === 'admin');

  /** ¿Puede su rol hacerlo? (misma tabla que la API: ROLE_PERMISSIONS). */
  can(permission: Permission): boolean {
    return hasPermission(this.user()?.role, permission);
  }
  /** Entró con una contraseña temporal: solo puede cambiarla. */
  /** Puede cambiar su propio email (lo decide la API: con OIDC configurado, solo un admin). */
  readonly canChangeEmail = computed(() => this.session()?.canChangeEmail ?? false);
  readonly mustChangePassword = computed(
    () => this.session()?.mustChangePassword ?? false,
  );
  /** Contraseña buena; falta el código TOTP o de recuperación (segundo paso del login). */
  readonly mfaPending = computed(() => this.session()?.mfaPending ?? false);
  /** Admin local sin TOTP: tiene que configurarlo antes de seguir. */
  readonly mfaSetupRequired = computed(
    () => this.session()?.mfaSetupRequired ?? false,
  );
  /** Cómo confirma su identidad para una acción sensible. */
  readonly reauthMethod = computed(() => this.session()?.reauthMethod ?? 'totp');
  /** Cuándo caduca la sesión (ms desde epoch) o null sin sesión. */
  readonly expiresAt = computed(() => {
    const at = this.session()?.expiresAt;
    return at ? Date.parse(at) : null;
  });

  /** Token CSRF de la sesión (cabecera X-CSRF-Token) o null sin sesión. */
  csrfToken(): string | null {
    return this.isAuthenticated() ? this.session()!.csrfToken : null;
  }

  isAuthenticated(): boolean {
    const current = this.session();
    if (!current) return false;
    if (Date.parse(current.expiresAt) <= Date.now()) {
      this.clear();
      return false;
    }
    return true;
  }

  /** Recupera la sesión de la cookie (al cargar la app). Sin sesión o sin API, queda vacía. */
  async restore(): Promise<void> {
    try {
      this.session.set(
        await firstValueFrom(
          this.http.get<SessionInfo>(`${this.api}/auth/session`),
        ),
      );
    } catch {
      this.session.set(null);
    }
  }

  /** Comprueba que la sesión sigue viva (p. ej. al volver a la pestaña); un 401 la cierra. */
  async verify(): Promise<void> {
    if (!this.session()) return;
    try {
      this.session.set(
        await firstValueFrom(
          this.http.get<SessionInfo>(`${this.api}/auth/session`),
        ),
      );
    } catch (err) {
      if (err instanceof HttpErrorResponse && err.status === 401) this.clear();
    }
  }

  async login(credentials: LoginRequest): Promise<SessionInfo> {
    const session = await firstValueFrom(
      this.http.post<SessionInfo>(`${this.api}/auth/login`, credentials),
    );
    this.session.set(session);
    return session;
  }

  /** Cómo se puede entrar (público). Sin API, solo el formulario de siempre. */
  async providers(): Promise<AuthProviders> {
    try {
      return await firstValueFrom(
        this.http.get<AuthProviders>(`${this.api}/auth/providers`),
      );
    } catch {
      return { local: true, oidc: null };
    }
  }

  /**
   * Entra con el proveedor OIDC: navegación completa a la API, que redirige al proveedor y, a la
   * vuelta, abre la sesión (cookie httpOnly) y devuelve el navegador a `returnUrl`.
   */
  startOidcLogin(returnUrl: string): void {
    this.navigation.assign(
      `${this.api}/auth/oidc/login?returnUrl=${encodeURIComponent(returnUrl)}`,
    );
  }

  /**
   * Cierra la sesión en la API (borra la cookie) y aquí. Si vino del proveedor OIDC y este lo
   * admite, el navegador sale a cerrar también la del proveedor (que vuelve a /login): devuelve
   * true en ese caso.
   */
  async logout(): Promise<boolean> {
    let providerLogoutUrl: string | null = null;
    if (this.session()) {
      try {
        ({ providerLogoutUrl } = await firstValueFrom(
          this.http.post<LogoutResponse>(`${this.api}/auth/logout`, null),
        ));
      } catch {
        // Caducada o sin API: aquí se cierra igual.
      }
    }
    this.clear();
    if (!providerLogoutUrl) return false;
    this.navigation.assign(providerLogoutUrl);
    return true;
  }

  /**
   * Segundo paso del login (código TOTP o de recuperación): la API cambia la sesión intermedia
   * por una nueva (otra cookie y otro token CSRF).
   */
  async verifyMfa(code: string): Promise<SessionInfo> {
    const session = await firstValueFrom(
      this.http.post<SessionInfo>(`${this.api}/auth/mfa/verify`, {
        code,
      } satisfies MfaCodeRequest),
    );
    this.session.set(session);
    return session;
  }

  /** Confirma la identidad con un código para las acciones sensibles (step-up local). */
  async reauthenticate(code: string, action?: SensitiveAction): Promise<ReauthResponse> {
    const res = await firstValueFrom(
      this.http.post<ReauthResponse>(`${this.api}/auth/reauth`, { code, action }),
    );
    this.session.update((s) =>
      s ? { ...s, reauthenticatedUntil: res.reauthenticatedUntil } : s,
    );
    return res;
  }

  /**
   * Confirma la identidad en el proveedor OIDC (step-up): navegación completa; el proveedor
   * vuelve a pedir las credenciales y el navegador regresa a `returnUrl?reauth=ok|failed`.
   */
  startOidcReauth(returnUrl: string): void {
    this.navigation.assign(
      `${this.api}/auth/oidc/reauth?returnUrl=${encodeURIComponent(returnUrl)}`,
    );
  }

  /** Olvida la sesión sin llamar a la API (ya no vale: 401). */
  clear(): void {
    this.session.set(null);
  }

  /**
   * Cambia la contraseña propia (la actual no hace falta con la sesión de una temporal). La API
   * cierra todas las sesiones y abre una nueva: nuevo token CSRF.
   */
  async changePassword(request: ChangePasswordRequest): Promise<void> {
    this.session.set(
      await firstValueFrom(
        this.http.post<SessionInfo>(`${this.api}/auth/password`, request),
      ),
    );
  }

  /** Cambia el email propio (pide la contraseña actual). La sesión sigue abierta. */
  async changeEmail(request: ChangeEmailRequest): Promise<UserProfile> {
    const user = await firstValueFrom(
      this.http.post<UserProfile>(`${this.api}/auth/email`, request),
    );
    this.session.update((s) => (s ? { ...s, user } : s));
    return user;
  }

  async updateName(name: string): Promise<UserProfile> {
    const user = await firstValueFrom(
      this.http.patch<UserProfile>(`${this.api}/auth/me`, { name }),
    );
    this.session.update((s) => (s ? { ...s, user } : s));
    return user;
  }
}
