import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { AuditEvent, AuthProviders, UserSummary } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { primeSessionForTests } from '../../core/auth/auth.service';
import { storeSession, testSession } from '../../testing/session';
import { ProfileCard } from './profile-card';
import { auditFilters, auditQuery, AuditLog } from './audit-log';
import { Settings } from './settings';
import { UsersSettings } from './users-settings';

const ana: UserSummary = {
  id: '00000000-0000-4000-8000-0000000000a1',
  email: 'ana@example.com',
  name: 'Ana',
  role: 'viewer',
  origin: 'local',
  oidcLinked: false,
  mfaEnabled: false,
  emergency: false,
  active: true,
  mustChangePassword: false,
  lastLoginAt: null,
  createdAt: '2026-10-13T00:00:00.000Z',
};

function configure(component: unknown) {
  TestBed.configureTestingModule({
    imports: [component as never],
    providers: [
      provideRouter([]),
      provideHttpClient(),
      provideHttpClientTesting(),
      ConfirmationService,
      MessageService,
    ],
  });
  return TestBed.inject(HttpTestingController);
}

/** Respuestas por defecto de lo que pide la página General. */
function flushGeneral(http: HttpTestingController): void {
  for (const req of http.match('/api/inventory-policies'))
    req.flush({
      global: { id: 'g', scope: 'global', reconcileIntervalMinutes: 360, scanEnabled: true, scanPeriodic: true },
      rules: [],
    });
}

describe('auditFilters', () => {
  it('categorías como lista con comas o repetidas en la URL', () => {
    expect(auditFilters({ category: 'connector,dns' }).category).toEqual(['connector', 'dns']);
    expect(auditFilters({ category: ['connector', 'dns'] }).category).toEqual(['connector', 'dns']);
    expect(auditFilters({ category: ['nada'], q: ['x', 'y'] })).toMatchObject({ category: [], q: 'x' });
  });
});

describe('Settings', () => {
  it('un viewer ve Perfil (por defecto) e Inventario, sin pestañas de admin', async () => {
    storeSession('viewer');
    const http = configure(Settings);
    const fixture = TestBed.createComponent(Settings);
    fixture.componentRef.setInput('tab', 'users');
    fixture.detectChanges();
    await fixture.whenStable();
    flushGeneral(http);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-tab="users"]')).toBeNull();
    expect(el.querySelector('[data-tab="audit"]')).toBeNull();
    expect(el.querySelector('[data-tab="policy"]')).not.toBeNull();
    expect(el.querySelector('[data-block="profile"]')).not.toBeNull();
    expect(el.querySelector('[data-viewer-notice]')).not.toBeNull();
    // La política va en su propia pestaña, no junto al perfil.
    expect(el.querySelector('[data-block="policy"]')).toBeNull();
    http.expectNone('/api/users');
    http.expectNone('/api/secrets/providers');
  });

  it('la pestaña Inventario tiene la política (y no el perfil)', async () => {
    storeSession('viewer');
    const http = configure(Settings);
    const fixture = TestBed.createComponent(Settings);
    fixture.componentRef.setInput('tab', 'policy');
    fixture.detectChanges();
    await fixture.whenStable();
    flushGeneral(http);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-block="policy"]')).not.toBeNull();
    expect(el.querySelector('[data-block="profile"]')).toBeNull();
  });

  it.each([
    ['auditor', ['providers', 'audit'], ['users'], false],
    ['editor', ['providers'], ['users', 'audit'], false],
    ['operator', [], ['users', 'providers', 'audit'], true],
  ] as const)('%s ve justo las pestañas de su rol', async (role, shown, hidden, notice) => {
    storeSession(role);
    const http = configure(Settings);
    const fixture = TestBed.createComponent(Settings);
    fixture.detectChanges();
    await fixture.whenStable();
    flushGeneral(http);
    http.match('/api/secrets/providers').forEach((r) => r.flush([]));
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    for (const tab of shown) expect(el.querySelector(`[data-tab="${tab}"]`)).not.toBeNull();
    for (const tab of hidden) expect(el.querySelector(`[data-tab="${tab}"]`)).toBeNull();
    expect(!!el.querySelector('[data-viewer-notice]')).toBe(notice);
  });

  it('un admin ve las pestañas Usuarios, Secretos y Auditoría', async () => {
    storeSession('admin');
    const http = configure(Settings);
    const fixture = TestBed.createComponent(Settings);
    fixture.detectChanges();
    await fixture.whenStable();
    flushGeneral(http);
    http.match('/api/secrets/providers').forEach((r) => r.flush([]));
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    for (const tab of ['users', 'providers', 'audit'])
      expect(el.querySelector(`[data-tab="${tab}"]`)).not.toBeNull();
  });
});

describe('UsersSettings', () => {
  beforeEach(() => storeSession('admin'));

  async function render(
    providers: AuthProviders = { local: true, oidc: null },
    users: UserSummary[] = [ana, { ...ana, id: 'u1', email: 'admin@example.com', name: 'Admin', role: 'admin' }],
  ) {
    const http = configure(UsersSettings);
    const fixture = TestBed.createComponent(UsersSettings);
    fixture.detectChanges();
    http.expectOne('/api/users').flush(users);
    http.expectOne('/api/auth/providers').flush(providers);
    await fixture.whenStable();
    fixture.detectChanges();
    return { http, fixture, el: fixture.nativeElement as HTMLElement };
  }

  const keycloak: AuthProviders = { local: true, oidc: { name: 'Keycloak' } };
  const oidcUser: UserSummary = {
    ...ana,
    id: '00000000-0000-4000-8000-0000000000b2',
    email: 'bea@example.com',
    origin: 'oidc',
    oidcLinked: true,
    role: 'editor',
  };

  it('muestra cómo entra cada usuario: local, OIDC, local enlazada y emergencia', async () => {
    const linked = { ...ana, id: 'l', email: 'lu@example.com', oidcLinked: true };
    const emergency = { ...ana, id: 'e', email: 'sos@example.com', role: 'admin' as const, emergency: true };
    const { el } = await render(keycloak, [ana, oidcUser, linked, emergency]);
    const access = (email: string) =>
      [...el.querySelectorAll(`[data-user="${email}"] [data-access] p-tag`)]
        .map((tag) => tag.textContent!.trim())
        .join(' ');
    expect(access('ana@example.com')).toBe('Local');
    expect(access('bea@example.com')).toBe('OIDC');
    expect(access('lu@example.com')).toBe('Local + OIDC');
    expect(access('sos@example.com')).toBe('Local Emergencia');
  });

  it('2FA: insignia y «Restablecer» (a otro, con confirmación); a uno mismo, no', async () => {
    const withMfa = { ...ana, mfaEnabled: true };
    const me = { ...ana, id: 'u1', email: 'admin@example.com', name: 'Admin', role: 'admin' as const, mfaEnabled: true };
    const { http, el } = await render(undefined, [withMfa, me]);
    expect(el.querySelector('[data-user="ana@example.com"] [data-mfa]')).not.toBeNull();
    expect(el.querySelector('[data-user="admin@example.com"] [data-action="reset-mfa"]')).toBeNull();
    const confirm = TestBed.inject(ConfirmationService);
    const spy = vi.spyOn(confirm, 'confirm').mockImplementation((c) => {
      c.accept?.();
      return confirm;
    });
    el.querySelector<HTMLButtonElement>('[data-user="ana@example.com"] [data-action="reset-mfa"] button')!.click();
    expect(spy.mock.calls[0][0].message).toContain('sesiones se cerrarán');
    http.expectOne({ method: 'POST', url: `/api/users/${ana.id}/mfa/reset` }).flush({ ...ana });
    http.expectOne('/api/users').flush([ana, me]);
  });

  it('un usuario OIDC no tiene «Restablecer contraseña» y su rol no se edita a mano', async () => {
    const { fixture, el } = await render(keycloak, [ana, oidcUser]);
    expect(el.querySelector('[data-user="bea@example.com"] [data-action="reset-password"]')).toBeNull();
    expect(el.querySelector('[data-user="ana@example.com"] [data-action="reset-password"]')).not.toBeNull();
    el.querySelector<HTMLButtonElement>('[data-user="bea@example.com"] [data-action="edit-user"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(document.body.querySelector('[data-role-managed]')?.textContent).toContain(
      'El rol lo decide Keycloak',
    );
  });

  it('editar: el email se cambia en locales y no en OIDC ni en la de emergencia', async () => {
    const emergency = { ...ana, id: 'e', email: 'sos@example.com', role: 'admin' as const, emergency: true };
    const { http, fixture, el } = await render(keycloak, [ana, oidcUser, emergency]);
    const edit = async (email: string) => {
      el.querySelector<HTMLButtonElement>(`[data-user="${email}"] [data-action="edit-user"] button`)!.click();
      fixture.detectChanges();
      await fixture.whenStable();
      fixture.detectChanges();
      return document.body.querySelector<HTMLInputElement>('#user-email')!;
    };
    expect((await edit('bea@example.com')).disabled).toBe(true);
    expect(document.body.querySelector('[data-email-managed]')?.textContent).toContain('proveedor');
    expect((await edit('sos@example.com')).disabled).toBe(true);
    expect(document.body.querySelector('[data-email-managed]')?.textContent).toContain('emergencia');

    const input = await edit('ana@example.com');
    expect(input.disabled).toBe(false);
    input.value = 'ana.nueva@example.com';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    document.body.querySelector<HTMLButtonElement>('[data-action="save-user"] button')!.click();
    const req = http.expectOne(`/api/users/${ana.id}`);
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ email: 'ana.nueva@example.com' });
    req.flush({ ...ana, email: 'ana.nueva@example.com' });
  });

  it('con el login local desactivado: sin altas y solo la de emergencia restablece contraseña', async () => {
    const emergency = { ...ana, id: 'e', email: 'sos@example.com', role: 'admin' as const, emergency: true };
    const { el } = await render({ local: false, oidc: { name: 'Keycloak' } }, [ana, emergency]);
    expect(el.querySelector('[data-action="new-user"]')).toBeNull();
    expect(el.querySelector('[data-oidc-only]')?.textContent).toContain('al entrar con Keycloak');
    expect(el.querySelector('[data-user="ana@example.com"] [data-action="reset-password"]')).toBeNull();
    expect(el.querySelector('[data-user="sos@example.com"] [data-action="reset-password"]')).not.toBeNull();
  });

  it('lista con estado; no puedes desactivarte a ti mismo', async () => {
    const { el } = await render();
    const row = el.querySelector('[data-user="ana@example.com"]')!;
    expect(row.textContent).toContain('Activo');
    const self = el.querySelector('[data-user="admin@example.com"]')!;
    expect(self.textContent).toContain('(tú)');
    expect(self.querySelector('[data-action="deactivate"] button')?.hasAttribute('disabled')).toBe(true);
  });

  it('alta: muestra la contraseña temporal una sola vez', async () => {
    const { http, fixture, el } = await render();
    el.querySelector<HTMLButtonElement>('[data-action="new-user"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    const body = document.body;
    const email = body.querySelector<HTMLInputElement>('#user-email')!;
    const name = body.querySelector<HTMLInputElement>('#user-name')!;
    email.value = 'beto@example.com';
    email.dispatchEvent(new Event('input'));
    name.value = 'Beto';
    name.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    body.querySelector<HTMLButtonElement>('[data-action="save-user"] button')!.click();
    const req = http.expectOne((r) => r.method === 'POST' && r.url === '/api/users');
    expect(req.request.body).toEqual({ email: 'beto@example.com', name: 'Beto', role: 'viewer' });
    req.flush({
      user: { ...ana, id: 'b', email: 'beto@example.com', name: 'Beto', mustChangePassword: true },
      temporaryPassword: 'ABCDE-FGHJK-LMNPQ-RSTUV',
      expiresAt: '2026-10-14T00:00:00.000Z',
    });
    http.expectOne('/api/users').flush([ana]);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(body.querySelector('[data-temporary-password]')?.textContent).toBe('ABCDE-FGHJK-LMNPQ-RSTUV');
    body.querySelector<HTMLButtonElement>('[data-action="close-temporary"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(body.querySelector('[data-temporary-password]')).toBeNull();
  });

  it('desactivar pide confirmación y llama a la API', async () => {
    const { http, el } = await render();
    const confirm = TestBed.inject(ConfirmationService);
    const spy = vi.spyOn(confirm, 'confirm').mockImplementation((c) => {
      c.accept?.();
      return confirm;
    });
    el.querySelector<HTMLButtonElement>('[data-user="ana@example.com"] [data-action="deactivate"] button')!.click();
    expect(spy.mock.calls[0][0].message).toContain('sesiones abiertas se cerrarán');
    http.expectOne(`/api/users/${ana.id}/deactivate`).flush({ ...ana, active: false });
    http.expectOne('/api/users').flush([{ ...ana, active: false }]);
  });
});

describe('AuditLog', () => {
  beforeEach(() => storeSession('admin'));

  it('auditFilters valida la URL y auditQuery pasa los días completos', () => {
    const f = auditFilters({
      category: 'user,nada,auth',
      actor: 'no-uuid',
      outcome: 'failure',
      q: 'ana',
      from: '2026-10-01',
      to: 'ayer',
    });
    expect(f).toEqual({ category: ['user', 'auth'], actor: null, outcome: 'failure', q: 'ana', from: '2026-10-01', to: '' });
    const q = auditQuery(f);
    expect(q).toMatchObject({ category: ['user', 'auth'], outcome: 'failure', q: 'ana', limit: 50 });
    expect(new Date(q.from!).getDate()).toBe(1);
    expect(q.to).toBeUndefined();
  });

  it('muestra quién, qué, sobre qué e IP, y carga más con el cursor', async () => {
    const http = configure(AuditLog);
    const fixture = TestBed.createComponent(AuditLog);
    fixture.detectChanges();
    http.expectOne('/api/users').flush([ana]);
    const event: AuditEvent = {
      id: 'e1',
      occurredAt: '2026-10-13T10:00:00.000Z',
      actorId: null,
      actorEmail: 'ana@example.com',
      action: 'auth.login_failed',
      outcome: 'failure',
      targetType: 'user',
      targetId: ana.id,
      targetLabel: 'ana@example.com',
      ip: '198.51.100.23',
      details: { reason: 'bad_password' },
    };
    http.expectOne((r) => r.url === '/api/audit').flush({ items: [event], nextCursor: 'c1' });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const row = el.querySelector('[data-event="auth.login_failed"]')!;
    expect(row.textContent).toContain('Inicio de sesión fallido');
    expect(row.textContent).toContain('198.51.100.23');
    expect(row.textContent).toContain('contraseña incorrecta');
    el.querySelector<HTMLButtonElement>('[data-action="more"] button')!.click();
    const next = http.expectOne((r) => r.url === '/api/audit' && r.params.get('cursor') === 'c1');
    next.flush({ items: [{ ...event, id: 'e2', action: 'user.created', outcome: 'success', details: { role: 'viewer' } }], nextCursor: null });
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-event]')).toHaveLength(2);
    expect(el.querySelector('[data-action="more"]')).toBeNull();
  });
});

describe('ProfileCard', () => {
  it('una cuenta OIDC no tiene contraseña que cambiar y su rol viene del proveedor', async () => {
    const session = testSession('editor');
    primeSessionForTests({
      ...session,
      user: { ...session.user, origin: 'oidc', oidcLinked: true },
      canChangeEmail: false,
    });
    configure(ProfileCard);
    const fixture = TestBed.createComponent(ProfileCard);
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-action="change-password"]')).toBeNull();
    expect(el.querySelector('[data-action="change-email"]')).toBeNull();
    expect(el.querySelector('[data-email-managed]')).not.toBeNull();
    expect(el.querySelector('[data-no-password]')).not.toBeNull();
    expect(el.querySelector('[data-role-from-provider]')).not.toBeNull();
    expect(el.querySelector('[data-access]')?.textContent).toContain('OIDC');
  });

  it('una cuenta local sigue pudiendo cambiar la contraseña', async () => {
    storeSession('viewer');
    configure(ProfileCard);
    const fixture = TestBed.createComponent(ProfileCard);
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-action="change-password"]')).not.toBeNull();
    expect(el.querySelector('[data-action="change-email"]')).not.toBeNull();
    expect(el.querySelector('[data-role-from-provider]')).toBeNull();
  });

  it('con OIDC configurado, una cuenta local no cambia su email (lo hace un admin)', async () => {
    primeSessionForTests({ ...testSession('viewer'), canChangeEmail: false });
    configure(ProfileCard);
    const fixture = TestBed.createComponent(ProfileCard);
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-action="change-email"]')).toBeNull();
    expect(el.querySelector('[data-email-managed]')?.textContent).toContain('administrador');
    expect(el.querySelector('[data-action="change-password"]')).not.toBeNull();
  });

  it('el nombre se edita en el sitio y el email y la contraseña, en diálogos', async () => {
    storeSession('viewer');
    configure(ProfileCard);
    const fixture = TestBed.createComponent(ProfileCard);
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    // Sin abrir nada, ni formularios ni campos de contraseña a la vista.
    expect(el.querySelector('#profile-name')).toBeNull();
    expect(document.body.querySelector('#current-password')).toBeNull();
    expect(el.querySelector('.avatar')?.textContent?.trim()).toBe('V');
    el.querySelector<HTMLButtonElement>('[data-action="edit-name"] button')!.click();
    fixture.detectChanges();
    expect(el.querySelector<HTMLInputElement>('#profile-name')?.value).toBe('Viewer');
    el.querySelector<HTMLButtonElement>('[data-action="change-password"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(document.body.querySelector('[data-dialog="change-password"] #current-password')).not.toBeNull();
  });
});
