import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { primeSessionForTests } from '../../core/auth/auth.service';
import { testSession } from '../../testing/session';
import { ChangePassword } from './change-password';

describe('ChangePassword', () => {
  beforeEach(() => primeSessionForTests(testSession('viewer', 'csrf', true)));

  async function render() {
    TestBed.configureTestingModule({
      imports: [ChangePassword],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(ChangePassword);
    fixture.detectChanges();
    await fixture.whenStable();
    return {
      fixture,
      http: TestBed.inject(HttpTestingController),
      el: fixture.nativeElement as HTMLElement,
      component: fixture.componentInstance as unknown as {
        form: { setValue(v: { newPassword: string; repeat: string }): void };
        submit(): Promise<void>;
      },
    };
  }

  it('exige longitud y que coincidan, sin llamar a la API', async () => {
    const { fixture, http, el, component } = await render();
    component.form.setValue({ newPassword: 'corta', repeat: 'corta' });
    await component.submit();
    fixture.detectChanges();
    expect(el.textContent).toContain('Al menos 12 caracteres');
    component.form.setValue({ newPassword: 'una-contraseña-larga', repeat: 'otra-contraseña-larga' });
    await component.submit();
    fixture.detectChanges();
    expect(el.textContent).toContain('no coinciden');
    http.expectNone('/api/auth/password');
  });

  it('guarda sin pedir la temporal y entra en la app', async () => {
    const { http, component } = await render();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    component.form.setValue({ newPassword: 'una-contraseña-larga', repeat: 'una-contraseña-larga' });
    const done = component.submit();
    const req = http.expectOne('/api/auth/password');
    expect(req.request.body).toEqual({ currentPassword: '', newPassword: 'una-contraseña-larga' });
    req.flush(testSession('viewer', 'csrf-2'));
    await done;
    expect(navigate).toHaveBeenCalledWith('/dashboard');
  });
});
