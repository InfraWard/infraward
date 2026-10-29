import { HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import type { AuthProviders } from '@infraward/shared-types';
import { AuthService } from '../../core/auth/auth.service';
import { Login, oidcErrorMessage } from './login';

describe('Login', () => {
  let login: ReturnType<typeof vi.fn>;
  let startOidcLogin: ReturnType<typeof vi.fn>;

  async function render(
    returnUrl?: string,
    providers: AuthProviders = { local: true, oidc: null },
    inputs: Record<string, string> = {},
  ) {
    login = vi.fn();
    startOidcLogin = vi.fn();
    TestBed.configureTestingModule({
      imports: [Login],
      providers: [
        provideRouter([]),
        {
          provide: AuthService,
          useValue: { login, startOidcLogin, providers: async () => providers },
        },
      ],
    });
    const fixture = TestBed.createComponent(Login);
    if (returnUrl) fixture.componentRef.setInput('returnUrl', returnUrl);
    for (const [name, value] of Object.entries(inputs))
      fixture.componentRef.setInput(name, value);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture;
  }

  const keycloak: AuthProviders = { local: true, oidc: { name: 'Keycloak' } };

  function fill(el: HTMLElement, email: string, password: string) {
    const set = (sel: string, v: string) => {
      const input = el.querySelector<HTMLInputElement>(sel)!;
      input.value = v;
      input.dispatchEvent(new Event('input'));
    };
    set('#email', email);
    set('#password', password);
  }

  it('entra y vuelve a la ruta pedida', async () => {
    const fixture = await render('/assets/1');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    login.mockResolvedValue({});
    fill(fixture.nativeElement, 'admin@example.com', 'pw');
    await fixture.componentInstance.submit();
    expect(login).toHaveBeenCalledWith({ email: 'admin@example.com', password: 'pw' });
    expect(navigate).toHaveBeenCalledWith('/assets/1');
  });

  it('con TOTP, pasa al segundo paso con el destino; un admin sin TOTP, a configurarlo', async () => {
    const fixture = await render('/assets/1');
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const navigateByUrl = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    login.mockResolvedValue({ mfaPending: true });
    fill(fixture.nativeElement, 'admin@example.com', 'pw');
    await fixture.componentInstance.submit();
    expect(navigate).toHaveBeenCalledWith(['/login/mfa'], { queryParams: { returnUrl: '/assets/1' } });
    expect(navigateByUrl).not.toHaveBeenCalled();
    login.mockResolvedValue({ mfaPending: false, mfaSetupRequired: true });
    fill(fixture.nativeElement, 'admin@example.com', 'pw');
    await fixture.componentInstance.submit();
    expect(navigateByUrl).toHaveBeenCalledWith('/mfa-setup');
  });

  it('no redirige fuera de la app aunque returnUrl lo pida', async () => {
    const fixture = await render('https://evil.example');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    login.mockResolvedValue({});
    fill(fixture.nativeElement, 'admin@example.com', 'pw');
    await fixture.componentInstance.submit();
    expect(navigate).toHaveBeenCalledWith('/dashboard');
  });

  it('401: mensaje genérico y borra la contraseña', async () => {
    const fixture = await render();
    login.mockRejectedValue(new HttpErrorResponse({ status: 401 }));
    fill(fixture.nativeElement, 'admin@example.com', 'mala');
    await fixture.componentInstance.submit();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[role=alert]')?.textContent).toContain('Email o contraseña incorrectos');
    // El campo visible se comprueba en el navegador real (Playwright); aquí, el control.
    expect(fixture.componentInstance['form'].controls.password.value).toBe('');
  });

  it('429: indica cuánto esperar', async () => {
    const fixture = await render();
    login.mockRejectedValue(
      new HttpErrorResponse({ status: 429, headers: new HttpHeaders({ 'Retry-After': '42' }) }),
    );
    fill(fixture.nativeElement, 'admin@example.com', 'pw');
    await fixture.componentInstance.submit();
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Espera 42 s');
  });

  it('no envía un formulario inválido', async () => {
    const fixture = await render();
    fill(fixture.nativeElement, 'no-es-email', '');
    await fixture.componentInstance.submit();
    expect(login).not.toHaveBeenCalled();
  });

  it('explica en línea qué campo falla y avisa de Bloq. Mayús.', async () => {
    const fixture = await render();
    const el = fixture.nativeElement as HTMLElement;
    fill(el, 'no-es-email', '');
    await fixture.componentInstance.submit();
    await fixture.whenStable();
    expect(el.textContent).toContain('Ese email no es válido.');
    expect(el.textContent).toContain('Escribe tu contraseña.');
    // El botón no se deshabilita: al pulsarlo se ve qué falta.
    expect(el.querySelector<HTMLButtonElement>('button[type=submit]')!.disabled).toBe(false);

    fill(el, 'admin@example.com', 'x');
    const key = new KeyboardEvent('keyup', { key: 'A', bubbles: true });
    Object.defineProperty(key, 'getModifierState', { value: (k: string) => k === 'CapsLock' });
    el.querySelector('#password')!.dispatchEvent(key);
    await fixture.whenStable();
    expect(el.querySelector('[data-capslock]')?.textContent).toContain('Bloq. Mayús');
  });

  it('con proveedor OIDC: botón «Entrar con …» que sale con la ruta de vuelta', async () => {
    const fixture = await render('/assets/1', keycloak);
    const el = fixture.nativeElement as HTMLElement;
    const button = el.querySelector<HTMLButtonElement>('[data-action="oidc-login"] button')!;
    expect(button.textContent).toContain('Entrar con Keycloak');
    expect(el.querySelector('#email')).not.toBeNull();
    button.click();
    expect(startOidcLogin).toHaveBeenCalledWith('/assets/1');
  });

  it('login local desactivado: sin formulario salvo «Acceso de emergencia»', async () => {
    const fixture = await render(undefined, { local: false, oidc: { name: 'Keycloak' } });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('#email')).toBeNull();
    expect(el.textContent).toContain('Accede con tu cuenta de Keycloak');
    el.querySelector<HTMLButtonElement>('[data-action="emergency"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(el.querySelector('#email')).not.toBeNull();
    expect(el.querySelector('[data-action="emergency"]')).toBeNull();
  });

  it('sin proveedor OIDC no hay botón', async () => {
    const fixture = await render();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-action="oidc-login"]')).toBeNull();
  });

  it('vuelta de un login OIDC fallido: mensaje según el código', async () => {
    const fixture = await render(undefined, keycloak, { oidcError: 'denied' });
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-oidc-error]')?.textContent).toContain(
      'Tu cuenta de Keycloak no tiene acceso a InfraWard',
    );
  });

  it('vuelta del cierre de sesión en el proveedor', async () => {
    const fixture = await render(undefined, keycloak, { loggedOut: '1' });
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-logged-out]')).not.toBeNull();
  });

  it('oidcErrorMessage: códigos conocidos y genérico para el resto', () => {
    expect(oidcErrorMessage('email_conflict', 'X')).toContain('no se puede enlazar');
    expect(oidcErrorMessage('unavailable', 'Keycloak')).toContain('Keycloak no responde');
    expect(oidcErrorMessage('email_unverified', 'Keycloak')).toContain('verificado');
    expect(oidcErrorMessage('<script>', 'Keycloak')).toBe(oidcErrorMessage('failed', 'Keycloak'));
  });
});
