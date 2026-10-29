import {
  HttpClient,
  provideHttpClient,
  withInterceptors,
} from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { ReauthService } from './reauth.service';

describe('authInterceptor', () => {
  let http: HttpClient;
  let ctrl: HttpTestingController;
  let auth: {
    csrfToken: ReturnType<typeof vi.fn>;
    isAuthenticated: ReturnType<typeof vi.fn>;
    clear: ReturnType<typeof vi.fn>;
  };
  let router: Router;

  beforeEach(() => {
    auth = {
      csrfToken: vi.fn(() => 'csrf'),
      isAuthenticated: vi.fn(() => true),
      clear: vi.fn(),
    };
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: AuthService, useValue: auth },
      ],
    });
    http = TestBed.inject(HttpClient);
    ctrl = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
  });

  afterEach(() => ctrl.verify());

  it('añade el token CSRF a las escrituras a la API, nunca un Authorization', () => {
    http.post('/api/assets', {}).subscribe();
    http.delete('/api/assets/1').subscribe();
    for (const req of ctrl.match((r) => r.url.startsWith('/api/assets'))) {
      expect(req.request.headers.get('x-csrf-token')).toBe('csrf');
      expect(req.request.headers.has('Authorization')).toBe(false);
      req.flush({});
    }
  });

  it('las lecturas no llevan el token CSRF', () => {
    http.get('/api/assets/tree').subscribe();
    const req = ctrl.expectOne('/api/assets/tree');
    expect(req.request.headers.has('x-csrf-token')).toBe(false);
    req.flush([]);
  });

  it('nunca envía el token CSRF a otros orígenes ni a rutas que solo empiezan igual', () => {
    http.post('https://example.org/api/assets', {}).subscribe();
    http.post('/apis/otra', {}).subscribe();
    for (const url of ['https://example.org/api/assets', '/apis/otra']) {
      const req = ctrl.expectOne(url);
      expect(req.request.headers.has('x-csrf-token')).toBe(false);
      req.flush({});
    }
  });

  it('un 401 con sesión la cierra y lleva al login con la ruta actual y el aviso', async () => {
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    vi.spyOn(router, 'url', 'get').mockReturnValue('/assets/123');
    const call = firstValueFrom(http.get('/api/assets/123'));
    ctrl.expectOne('/api/assets/123').flush(null, { status: 401, statusText: 'Unauthorized' });
    await expect(call).rejects.toMatchObject({ status: 401 });
    expect(auth.clear).toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(['/login'], {
      queryParams: { returnUrl: '/assets/123', expired: 1 },
    });
  });

  it('el 401 del login (sin sesión) no navega: son credenciales malas', async () => {
    auth.isAuthenticated.mockReturnValue(false);
    const navigate = vi.spyOn(router, 'navigate');
    const call = firstValueFrom(http.post('/api/auth/login', {}));
    ctrl.expectOne('/api/auth/login').flush(null, { status: 401, statusText: 'Unauthorized' });
    await expect(call).rejects.toMatchObject({ status: 401 });
    expect(auth.clear).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('un 403 password_change_required lleva a cambiar la contraseña', async () => {
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const call = firstValueFrom(http.get('/api/assets/tree'));
    ctrl
      .expectOne('/api/assets/tree')
      .flush({ code: 'password_change_required' }, { status: 403, statusText: 'Forbidden' });
    await expect(call).rejects.toMatchObject({ status: 403 });
    expect(navigate).toHaveBeenCalledWith(['/change-password']);
  });

  describe('acciones sensibles (step-up)', () => {
    const recent = {
      statusCode: 403,
      code: 'recent_auth_required',
      action: 'asset.purge',
      method: 'totp',
      message: 'Purgar un asset: confirma tu identidad para continuar',
    };
    const flush403 = (body: object) =>
      ctrl.expectOne('/api/assets/1?purge=true').flush(body, { status: 403, statusText: 'Forbidden' });

    it('pide confirmar la identidad y, si se confirma, repite la petición una vez', async () => {
      const reauth = TestBed.inject(ReauthService);
      const call = firstValueFrom(http.delete('/api/assets/1?purge=true'));
      flush403(recent);
      await Promise.resolve();
      expect(reauth.prompt()).toEqual({ action: 'asset.purge', kind: 'totp' });
      reauth.complete(true);
      await new Promise((r) => setTimeout(r));
      ctrl.expectOne('/api/assets/1?purge=true').flush({ mode: 'purged' });
      await expect(call).resolves.toEqual({ mode: 'purged' });
    });

    it('si se cancela, llega el error original; y la repetición no vuelve a preguntar', async () => {
      const reauth = TestBed.inject(ReauthService);
      const cancelled = firstValueFrom(http.delete('/api/assets/1?purge=true'));
      flush403(recent);
      await Promise.resolve();
      reauth.complete(false);
      await expect(cancelled).rejects.toMatchObject({ status: 403 });

      const retried = firstValueFrom(http.delete('/api/assets/1?purge=true'));
      flush403(recent);
      await Promise.resolve();
      reauth.complete(true);
      await new Promise((r) => setTimeout(r));
      flush403(recent);
      await expect(retried).rejects.toMatchObject({ status: 403 });
      expect(reauth.prompt()).toBeNull();
    });

    it('OIDC y sin TOTP: el diálogo sabe qué ofrecer', async () => {
      const reauth = TestBed.inject(ReauthService);
      void firstValueFrom(http.delete('/api/assets/1?purge=true')).catch(() => undefined);
      flush403({ ...recent, method: 'oidc' });
      await Promise.resolve();
      expect(reauth.prompt()).toMatchObject({ kind: 'oidc' });
      reauth.complete(false);
      void firstValueFrom(http.delete('/api/assets/1?purge=true')).catch(() => undefined);
      flush403({ ...recent, code: 'mfa_required_for_action' });
      await Promise.resolve();
      expect(reauth.prompt()).toMatchObject({ kind: 'setup' });
      reauth.complete(false);
    });

    it('mfa_pending lleva al segundo paso del login', async () => {
      const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
      const call = firstValueFrom(http.get('/api/assets/tree'));
      ctrl
        .expectOne('/api/assets/tree')
        .flush({ code: 'mfa_pending' }, { status: 403, statusText: 'Forbidden' });
      await expect(call).rejects.toMatchObject({ status: 403 });
      expect(navigate).toHaveBeenCalledWith(['/login/mfa']);
    });
  });
});
