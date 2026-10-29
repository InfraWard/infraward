import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { storeSession } from '../../testing/session';
import { EnrollStart } from './enroll-start';
import { IssuedCommands } from './issued-commands';

describe('EnrollStart', () => {
  beforeEach(() => sessionStorage.clear());

  it('avisa de sudo y python3, envía la opción --install-sudo y va al stepper con los comandos', async () => {
    storeSession();
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const fixture = TestBed.createComponent(EnrollStart);
    fixture.detectChanges();
    // Con un proveedor sano con CA SSH, se preselecciona el modo CA.
    http.expectOne('/api/secrets/providers').flush([
      { id: 'openbao', healthy: true, capabilities: ['write', 'ssh_certificates'] },
    ]);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('python3');
    expect(el.textContent).toContain('Proxmox no trae sudo de serie');
    expect(el.textContent).toContain('Certificados de vida corta (CA SSH de OpenBao)');

    const component = fixture.componentInstance as unknown as {
      form: { patchValue(v: object): void; getRawValue(): { authMode: string } };
      submit(): Promise<void>;
    };
    expect(component.form.getRawValue().authMode).toBe('ca_certificate');
    component.form.patchValue({ host: '192.0.2.10', port: 2222, name: '', installSudo: true });
    const done = component.submit();
    const req = http.expectOne('/api/assets/enroll');
    // Sin tocar la opción no se envía el modo: la API elige CA con la misma regla.
    expect(req.request.body).toEqual({
      host: '192.0.2.10',
      port: 2222,
      installSudo: true,
    });
    req.flush({
      asset: { id: 'a1' },
      enrollment: { id: 'e1', assetId: 'a1', command: 'curl …' },
    });
    await done;
    expect(navigate).toHaveBeenCalledWith(['/assets', 'a1', 'enrollment']);
    expect(TestBed.inject(IssuedCommands).get('a1')?.command).toBe('curl …');
    http.verify();
  });

  it('sin proveedor con CA SSH: clave estática y la opción CA marcada como no disponible', async () => {
    storeSession();
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(EnrollStart);
    fixture.detectChanges();
    http.expectOne('/api/secrets/providers').flush([
      { id: 'local', healthy: true, capabilities: ['write'] },
    ]);
    await fixture.whenStable();
    const component = fixture.componentInstance as unknown as {
      form: { getRawValue(): { authMode: string } };
    };
    expect(component.form.getRawValue().authMode).toBe('static_key');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('ningún proveedor de secretos activo tiene CA SSH');
    // La opción CA no se puede elegir.
    expect(el.querySelector('#authCa')).toBeNull();
    expect(el.querySelector('#authStatic')).not.toBeNull();
    http.verify();
  });

  it('elegir la clave estática con CA disponible la envía; cada opción se explica en una línea', async () => {
    storeSession();
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const fixture = TestBed.createComponent(EnrollStart);
    fixture.detectChanges();
    const component = fixture.componentInstance as unknown as {
      form: {
        patchValue(v: object): void;
        getRawValue(): { authMode: string | null };
        controls: { authMode: { setValue(v: string): void; markAsDirty(): void } };
      };
      submit(): Promise<void>;
    };
    // Mientras no se sabe si hay CA, ninguna opción marcada.
    expect(component.form.getRawValue().authMode).toBeNull();
    http.expectOne('/api/secrets/providers').flush([
      { id: 'openbao', healthy: true, capabilities: ['ssh_certificates'] },
    ]);
    await fixture.whenStable();
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('label[for="authCa"] small')?.textContent?.trim()).toBe(
      'Sin claves permanentes: cada tarea entra con un certificado que caduca en minutos.',
    );
    expect(el.querySelector('label[for="authStatic"] small')?.textContent?.trim()).toBe(
      'Una clave fija en authorized_keys; admite el alta manual.',
    );
    expect(el.querySelector('label[for="authStatic"]')?.textContent).toContain('alternativa');

    component.form.controls.authMode.setValue('static_key');
    component.form.controls.authMode.markAsDirty();
    component.form.patchValue({ host: 'srv1.example.com' });
    const done = component.submit();
    const req = http.expectOne('/api/assets/enroll');
    expect(req.request.body).toMatchObject({ authMode: 'static_key' });
    req.flush({ asset: { id: 'a2' }, enrollment: { id: 'e2', assetId: 'a2', command: 'x' } });
    await done;
    http.verify();
  });

  it('rechaza hosts que ssh tomaría como opción', async () => {
    storeSession();
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(EnrollStart);
    const form = (fixture.componentInstance as unknown as {
      form: { controls: { host: { setValue(v: string): void; valid: boolean } } };
    }).form;
    form.controls.host.setValue('-oProxyCommand=x');
    expect(form.controls.host.valid).toBe(false);
    form.controls.host.setValue('srv1.example.com');
    expect(form.controls.host.valid).toBe(true);
  });

  it('organización y política: tags, proyecto y la plantilla «Sin imágenes» van en el alta', async () => {
    storeSession();
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const fixture = TestBed.createComponent(EnrollStart);
    fixture.detectChanges();
    http.expectOne('/api/secrets/providers').flush([]);
    await fixture.whenStable();
    const component = fixture.componentInstance as unknown as {
      form: { patchValue(v: object): void };
      toggleOrganize(open: boolean): void;
      tags: { set(v: string[]): void };
      projectIds: { set(v: string[]): void };
      applyPreset(id: string): void;
      submit(): Promise<void>;
    };
    component.toggleOrganize(true);
    fixture.detectChanges();
    http.expectOne('/api/projects').flush([]);
    http.expectOne('/api/tags').flush([]);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-scan-exclusions]')).not.toBeNull();
    component.tags.set(['prueba']);
    component.projectIds.set(['11111111-1111-4111-8111-111111111111']);
    component.applyPreset('no-images');
    component.form.patchValue({ host: 'srv1' });
    const done = component.submit();
    const req = http.expectOne('/api/assets/enroll');
    expect(req.request.body).toMatchObject({
      host: 'srv1',
      tags: ['prueba'],
      projectIds: ['11111111-1111-4111-8111-111111111111'],
      policy: { scanExclusions: { types: ['image'] } },
    });
    req.flush({ asset: { id: 'a3' }, enrollment: { id: 'e3', assetId: 'a3', command: 'x' } });
    await done;
    http.verify();
  });

  it('acceso de administración: solo admins, solo en modo CA y desmarcado por defecto', async () => {
    storeSession('admin');
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const fixture = TestBed.createComponent(EnrollStart);
    fixture.detectChanges();
    http.expectOne('/api/secrets/providers').flush([
      { id: 'openbao', healthy: true, capabilities: ['write', 'ssh_certificates'] },
    ]);
    await fixture.whenStable();
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-field="adminAccess"]')?.textContent).toContain(
      'Permitir acceso interactivo de administración',
    );
    const component = fixture.componentInstance as unknown as {
      form: {
        patchValue(v: object): void;
        controls: { authMode: { setValue(v: string): void; markAsDirty(): void }; adminAccess: { disabled: boolean; value: boolean } };
      };
      submit(): Promise<void>;
    };
    expect(component.form.controls.adminAccess.value).toBe(false);
    expect(component.form.controls.adminAccess.disabled).toBe(false);
    // Con clave estática se desmarca y se deshabilita.
    component.form.patchValue({ adminAccess: true });
    component.form.controls.authMode.setValue('static_key');
    expect(component.form.controls.adminAccess.disabled).toBe(true);
    expect(component.form.controls.adminAccess.value).toBe(false);
    component.form.controls.authMode.setValue('ca_certificate');
    component.form.patchValue({ host: '192.0.2.20', adminAccess: true });
    const done = component.submit();
    const req = http.expectOne('/api/assets/enroll');
    expect(req.request.body).toMatchObject({
      host: '192.0.2.20',
      authMode: 'ca_certificate',
      adminAccess: 'operator',
    });
    req.flush({ asset: { id: 'a2' }, enrollment: { id: 'e2', assetId: 'a2', command: 'curl …' } });
    await done;
    http.verify();
  });

  it('sin users.manage, la casilla no sale', async () => {
    storeSession('editor');
    TestBed.configureTestingModule({
      imports: [EnrollStart],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(EnrollStart);
    fixture.detectChanges();
    http.expectOne('/api/secrets/providers').flush([
      { id: 'openbao', healthy: true, capabilities: ['write', 'ssh_certificates'] },
    ]);
    await fixture.whenStable();
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-field="adminAccess"]')).toBeNull();
  });
});
