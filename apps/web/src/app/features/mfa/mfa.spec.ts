import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { MessageService } from '@openng/optimus-ui/api';
import { of, throwError } from 'rxjs';
import { MfaApi } from '../../core/api/mfa-api';
import { AuthService } from '../../core/auth/auth.service';
import { ReauthDialog } from '../../core/auth/reauth-dialog';
import { ReauthService } from '../../core/auth/reauth.service';
import { MfaSetupFlow } from './mfa-setup-flow';
import { MfaVerify } from './mfa-verify';

const error = (status: number) => new HttpErrorResponse({ status });

describe('MfaVerify (segundo paso del login)', () => {
  let auth: Record<string, ReturnType<typeof vi.fn>>;

  async function render(returnUrl?: string) {
    auth = { verifyMfa: vi.fn(), clear: vi.fn(), logout: vi.fn(async () => false) };
    TestBed.configureTestingModule({
      imports: [MfaVerify],
      providers: [provideRouter([]), { provide: AuthService, useValue: auth }],
    });
    const fixture = TestBed.createComponent(MfaVerify);
    if (returnUrl) fixture.componentRef.setInput('returnUrl', returnUrl);
    fixture.detectChanges();
    // ngModel se registra de forma asíncrona.
    await fixture.whenStable();
    return fixture;
  }

  function type(fixture: Awaited<ReturnType<typeof render>>, value: string) {
    const input = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('#mfa-code')!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }

  it('con un código bueno entra y vuelve a la ruta pedida (o a cambiar la temporal)', async () => {
    const fixture = await render('/assets/1');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    auth['verifyMfa'].mockResolvedValue({ mustChangePassword: false });
    type(fixture, ' 123456 ');
    await fixture.componentInstance.submit();
    expect(auth['verifyMfa']).toHaveBeenCalledWith('123456');
    expect(navigate).toHaveBeenCalledWith('/assets/1');
    auth['verifyMfa'].mockResolvedValue({ mustChangePassword: true });
    type(fixture, '654321');
    await fixture.componentInstance.submit();
    expect(navigate).toHaveBeenLastCalledWith('/change-password');
  });

  it('código incorrecto: mensaje y el código se borra; al quinto (401), al login con aviso', async () => {
    const fixture = await render();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    auth['verifyMfa'].mockRejectedValue(error(400));
    type(fixture, '000000');
    await fixture.componentInstance.submit();
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-mfa-error]')?.textContent).toContain('no es correcto');
    expect((fixture.componentInstance as unknown as { code: string }).code).toBe('');
    auth['verifyMfa'].mockRejectedValue(error(401));
    type(fixture, '000000');
    await fixture.componentInstance.submit();
    expect(auth['clear']).toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(['/login'], { queryParams: { mfaFailed: 1 } });
  });

  it('admite un código de recuperación', async () => {
    const fixture = await render();
    vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    (fixture.nativeElement as HTMLElement)
      .querySelector<HTMLButtonElement>('[data-action="toggle-recovery"] button')!
      .click();
    fixture.detectChanges();
    await fixture.whenStable();
    auth['verifyMfa'].mockResolvedValue({ mustChangePassword: false });
    type(fixture, 'abcd-efgh-jkmn-pqrs');
    await fixture.componentInstance.submit();
    expect(auth['verifyMfa']).toHaveBeenCalledWith('abcd-efgh-jkmn-pqrs');
  });
});

describe('ReauthDialog (step-up)', () => {
  let auth: Record<string, ReturnType<typeof vi.fn>>;

  async function render() {
    auth = {
      reauthenticate: vi.fn(),
      startOidcReauth: vi.fn(),
      providers: vi.fn(async () => ({ local: true, oidc: { name: 'Keycloak' } })),
    };
    TestBed.configureTestingModule({
      imports: [ReauthDialog],
      providers: [provideRouter([]), { provide: AuthService, useValue: auth }],
    });
    const fixture = TestBed.createComponent(ReauthDialog);
    fixture.detectChanges();
    return { fixture, reauth: TestBed.inject(ReauthService) };
  }

  const body = () => document.body;

  it('con un código confirma la identidad y devuelve true (el interceptor repite)', async () => {
    const { fixture, reauth } = await render();
    const result = reauth.request({ code: 'recent_auth_required', action: 'asset.purge', method: 'totp' });
    fixture.detectChanges();
    await fixture.whenStable();
    expect(body().textContent).toContain('Purgar un asset');
    const input = body().querySelector<HTMLInputElement>('#reauth-code')!;
    input.value = '123456';
    input.dispatchEvent(new Event('input'));
    auth['reauthenticate'].mockResolvedValue({ reauthenticatedUntil: '2026-10-20T10:00:00Z' });
    body().querySelector<HTMLButtonElement>('[data-action="reauth-submit"] button')!.click();
    await expect(result).resolves.toBe(true);
    expect(auth['reauthenticate']).toHaveBeenCalledWith('123456', 'asset.purge');
  });

  it('código incorrecto: se queda abierto con el error', async () => {
    const { fixture, reauth } = await render();
    void reauth.request({ code: 'recent_auth_required', action: 'user.deactivate', method: 'totp' });
    fixture.detectChanges();
    await fixture.whenStable();
    const input = body().querySelector<HTMLInputElement>('#reauth-code')!;
    input.value = '000000';
    input.dispatchEvent(new Event('input'));
    auth['reauthenticate'].mockRejectedValue(error(400));
    body().querySelector<HTMLButtonElement>('[data-action="reauth-submit"] button')!.click();
    await new Promise((r) => setTimeout(r));
    fixture.detectChanges();
    expect(body().querySelector('[data-reauth-error]')?.textContent).toContain('no es correcto');
    expect(reauth.prompt()).not.toBeNull();
    reauth.complete(false);
  });

  it('OIDC: sale al proveedor volviendo a la misma página', async () => {
    const { fixture, reauth } = await render();
    vi.spyOn(TestBed.inject(Router), 'url', 'get').mockReturnValue('/assets/9?tab=resumen');
    void reauth.request({ code: 'recent_auth_required', action: 'asset.purge', method: 'oidc' });
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(body().textContent).toContain('Continuar con Keycloak');
    body().querySelector<HTMLButtonElement>('[data-action="reauth-oidc"] button')!.click();
    expect(auth['startOidcReauth']).toHaveBeenCalledWith('/assets/9?tab=resumen');
    reauth.complete(false);
  });
});

describe('MfaSetupFlow (alta de TOTP)', () => {
  it('enseña el QR y la clave, confirma con un código y enseña los códigos de recuperación', async () => {
    const api = {
      setup: vi.fn(() =>
        of({ otpauthUri: 'otpauth://totp/x', secret: 'JBSWY3DPEHPK3PXP', qrDataUrl: 'data:image/png;base64,AAAA' }),
      ),
      enable: vi.fn(() => of({ recoveryCodes: ['aaaa-bbbb-cccc-dddd', 'eeee-ffff-gggg-hhhh'] })),
    };
    TestBed.configureTestingModule({
      imports: [MfaSetupFlow],
      providers: [{ provide: MfaApi, useValue: api }, MessageService],
    });
    const fixture = TestBed.createComponent(MfaSetupFlow);
    const enabled = vi.fn();
    fixture.componentInstance.enabled.subscribe(enabled);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector<HTMLImageElement>('[data-qr]')!.src).toContain('data:image/png;base64');
    expect(el.querySelector('[data-secret]')!.textContent).toBe('JBSW Y3DP EHPK 3PXP');

    const input = el.querySelector<HTMLInputElement>('#mfa-setup-code')!;
    input.value = '12345';
    input.dispatchEvent(new Event('input'));
    el.querySelector<HTMLButtonElement>('[data-action="mfa-enable"] button')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(api.enable).not.toHaveBeenCalled();
    expect(el.querySelector('[data-mfa-error]')!.textContent).toContain('6 cifras');

    input.value = '123456';
    input.dispatchEvent(new Event('input'));
    el.querySelector<HTMLButtonElement>('[data-action="mfa-enable"] button')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(api.enable).toHaveBeenCalledWith('123456');
    expect(enabled).toHaveBeenCalled();
    expect(el.querySelector('[data-recovery-codes]')!.textContent).toContain('aaaa-bbbb-cccc-dddd');
    // El secreto ya no está en pantalla.
    expect(el.querySelector('[data-secret]')).toBeNull();
  });

  it('si el alta falla (p. ej. falta reautenticarse), lo dice y deja reintentar', async () => {
    const api = { setup: vi.fn(() => throwError(() => error(500))), enable: vi.fn() };
    TestBed.configureTestingModule({
      imports: [MfaSetupFlow],
      providers: [{ provide: MfaApi, useValue: api }],
    });
    const fixture = TestBed.createComponent(MfaSetupFlow);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No se pudo empezar');
  });
});
