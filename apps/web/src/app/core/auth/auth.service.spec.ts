import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import type { SessionInfo } from '@infraward/shared-types';
import { testSession } from '../../testing/session';
import { AuthService, primeSessionForTests } from './auth.service';
import { BROWSER_NAVIGATION } from './browser-navigation';

describe('AuthService', () => {
  let http: HttpTestingController;
  let session: SessionInfo;
  let assign: ReturnType<typeof vi.fn>;

  function setup(): AuthService {
    assign = vi.fn();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: BROWSER_NAVIGATION, useValue: { assign } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    return TestBed.inject(AuthService);
  }

  beforeEach(() => {
    primeSessionForTests(null);
    session = testSession('admin', 'csrf-1');
  });
  afterEach(() => {
    http.verify();
    vi.useRealTimers();
  });

  async function login(auth: AuthService): Promise<void> {
    const done = auth.login({ email: session.user.email, password: 's3cret' });
    const req = http.expectOne('/api/auth/login');
    expect(req.request.body).toEqual({ email: session.user.email, password: 's3cret' });
    req.flush(session);
    await done;
  }

  it('guarda en memoria el perfil y el token CSRF; nada en el almacenamiento del navegador', async () => {
    const auth = setup();
    await login(auth);
    expect(auth.user()).toEqual(session.user);
    expect(auth.isAdmin()).toBe(true);
    expect(auth.csrfToken()).toBe('csrf-1');
    expect(auth.isAuthenticated()).toBe(true);
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.getItem('infraward.session')).toBeNull();
  });

  it('recupera la sesión de la cookie al cargar (GET /auth/session)', async () => {
    const auth = setup();
    expect(auth.isAuthenticated()).toBe(false);
    const done = auth.restore();
    http.expectOne('/api/auth/session').flush(session);
    await done;
    expect(auth.user()?.email).toBe(session.user.email);
  });

  it('sin cookie (401) o sin API, arranca sin sesión', async () => {
    const auth = setup();
    const done = auth.restore();
    http
      .expectOne('/api/auth/session')
      .flush(null, { status: 401, statusText: 'Unauthorized' });
    await done;
    expect(auth.isAuthenticated()).toBe(false);
  });

  it('una sesión caducada no vale', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-10T10:00:00Z') });
    session.expiresAt = '2026-10-10T10:01:00.000Z';
    const auth = setup();
    await login(auth);
    vi.setSystemTime(new Date('2026-10-10T10:01:01Z'));
    expect(auth.isAuthenticated()).toBe(false);
    expect(auth.csrfToken()).toBeNull();
  });

  it('la sesión de una temporal solo sirve para cambiarla', async () => {
    session.mustChangePassword = true;
    const auth = setup();
    await login(auth);
    expect(auth.mustChangePassword()).toBe(true);
    const done = auth.changePassword({ currentPassword: '', newPassword: 'una-nueva-larga' });
    const req = http.expectOne('/api/auth/password');
    expect(req.request.body).toEqual({ currentPassword: '', newPassword: 'una-nueva-larga' });
    req.flush({ ...session, csrfToken: 'csrf-2', mustChangePassword: false });
    await done;
    expect(auth.mustChangePassword()).toBe(false);
    expect(auth.csrfToken()).toBe('csrf-2');
  });

  it('logout llama a la API y olvida la sesión (aunque la API falle)', async () => {
    const auth = setup();
    await login(auth);
    const done = auth.logout();
    http.expectOne('/api/auth/logout').flush(null, { status: 500, statusText: 'Error' });
    expect(await done).toBe(false);
    expect(auth.user()).toBeNull();
    expect(assign).not.toHaveBeenCalled();
  });

  it('logout de una sesión OIDC: sale a cerrar también la del proveedor', async () => {
    const auth = setup();
    await login(auth);
    const done = auth.logout();
    http
      .expectOne('/api/auth/logout')
      .flush({ providerLogoutUrl: 'https://idp.example/logout?id_token_hint=x' });
    expect(await done).toBe(true);
    expect(auth.user()).toBeNull();
    expect(assign).toHaveBeenCalledWith('https://idp.example/logout?id_token_hint=x');
  });

  it('logout de una sesión local: se queda en la app', async () => {
    const auth = setup();
    await login(auth);
    const done = auth.logout();
    http.expectOne('/api/auth/logout').flush({ providerLogoutUrl: null });
    expect(await done).toBe(false);
    expect(assign).not.toHaveBeenCalled();
  });

  it('providers: lo que diga la API o, sin API, solo el formulario', async () => {
    const auth = setup();
    let done = auth.providers();
    http.expectOne('/api/auth/providers').flush({ local: false, oidc: { name: 'Keycloak' } });
    expect(await done).toEqual({ local: false, oidc: { name: 'Keycloak' } });
    done = auth.providers();
    http.expectOne('/api/auth/providers').flush(null, { status: 502, statusText: 'Bad Gateway' });
    expect(await done).toEqual({ local: true, oidc: null });
  });

  it('startOidcLogin navega a la API con la ruta de vuelta', () => {
    const auth = setup();
    auth.startOidcLogin('/assets?x=1');
    expect(assign).toHaveBeenCalledWith('/api/auth/oidc/login?returnUrl=%2Fassets%3Fx%3D1');
  });

  it('verify: un 401 al volver a la pestaña cierra la sesión', async () => {
    const auth = setup();
    await login(auth);
    const done = auth.verify();
    http.expectOne('/api/auth/session').flush(null, { status: 401, statusText: 'Unauthorized' });
    await done;
    expect(auth.isAuthenticated()).toBe(false);
  });

  it('updateName actualiza el perfil', async () => {
    const auth = setup();
    await login(auth);
    const done = auth.updateName('Ana');
    http.expectOne('/api/auth/me').flush({ ...session.user, name: 'Ana' });
    await done;
    expect(auth.user()?.name).toBe('Ana');
  });

  it('changeEmail manda la contraseña actual y actualiza el perfil', async () => {
    const auth = setup();
    await login(auth);
    const done = auth.changeEmail({ email: 'nueva@example.com', currentPassword: 'secreta' });
    const req = http.expectOne('/api/auth/email');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ email: 'nueva@example.com', currentPassword: 'secreta' });
    req.flush({ ...session.user, email: 'nueva@example.com' });
    await done;
    expect(auth.user()?.email).toBe('nueva@example.com');
  });
});
