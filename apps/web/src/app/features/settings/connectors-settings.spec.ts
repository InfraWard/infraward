import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { Connector } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { ConnectorsSettings } from './connectors-settings';
import { ExpiryWarningsSettings } from './expiry-warnings-settings';
import { Settings } from './settings';

const TOKEN = 'CENTINELA-token-0123456789abcdefghij';

const connector = (extra: Partial<Connector> = {}): Connector => ({
  id: '00000000-0000-4000-8000-0000000000c1',
  name: 'Cloudflare pruebas',
  kind: 'cloudflare',
  status: 'active',
  secretProvider: 'local',
  hasToken: true,
  verify: {
    ok: true,
    checkedAt: '2026-10-14T10:00:00.000Z',
    error: null,
    tokenStatus: 'active',
    tokenExpiresAt: null,
    accounts: ['Pruebas'],
    zones: 2,
    warnings: [],
  },
  lastSync: { at: '2026-10-14T10:01:00.000Z', zones: 2, records: 14, complete: true, warnings: [] },
  domains: 2,
  records: 14,
  createdAt: '2026-10-14T10:00:00.000Z',
  ...extra,
});

const noop = (): void => undefined;
globalThis.ResizeObserver ??= class {
  observe = noop;
  unobserve = noop;
  disconnect = noop;
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

describe('ConnectorsSettings', () => {
  it('lista los conectores con su estado, dónde está el token (nunca el token) y sus acciones', async () => {
    storeSession('admin');
    const http = configure(ConnectorsSettings);
    const fixture = TestBed.createComponent(ConnectorsSettings);
    fixture.detectChanges();
    http.expectOne('/api/connectors').flush([
      connector(),
      connector({
        id: '00000000-0000-4000-8000-0000000000c2',
        name: 'Malo',
        verify: { ...connector().verify!, ok: false, error: 'HTTP 401 (código 1000)' },
      }),
    ]);
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const ok = el.querySelector('[data-connector="Cloudflare pruebas"]')!;
    expect(ok.querySelector('[data-verify="ok"]')).not.toBeNull();
    expect(ok.textContent).toContain('guardado en local');
    expect(ok.textContent).toContain('14');
    const bad = el.querySelector('[data-connector="Malo"]')!;
    expect(bad.querySelector('[data-verify-error]')?.textContent).toContain('HTTP 401');
    // Sin token válido no se sincroniza.
    expect(
      (bad.querySelector('[data-action="sync"] button') as HTMLButtonElement).disabled,
    ).toBe(true);
    http.verify();
  });

  it('crea con el token en un campo de contraseña, lo vacía al enviar y lo manda una sola vez', async () => {
    storeSession('admin');
    const http = configure(ConnectorsSettings);
    const fixture = TestBed.createComponent(ConnectorsSettings);
    fixture.detectChanges();
    http.expectOne('/api/connectors').flush([]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    (el.querySelector('[data-action="new-connector"] button') as HTMLButtonElement).click();
    fixture.detectChanges();
    await fixture.whenStable();
    const token = document.querySelector('#connector-token') as HTMLInputElement;
    expect(token.type).toBe('password');
    expect(token.autocomplete).toBe('off');
    expect(document.querySelector('[data-token-help]')?.textContent).toContain('Zone · DNS · Read');
    // Los proveedores salen del catálogo (hoy solo Cloudflare, ya elegido).
    expect(document.querySelector('[data-kind="cloudflare"]')?.getAttribute('aria-checked')).toBe('true');
    const name = document.querySelector('#connector-name') as HTMLInputElement;
    name.value = 'Producción';
    name.dispatchEvent(new Event('input'));
    token.value = TOKEN;
    token.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (document.querySelector('[data-action="save-connector"] button') as HTMLButtonElement).click();
    const req = http.expectOne('/api/connectors');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ kind: 'cloudflare', name: 'Producción', apiToken: TOKEN });
    expect(fixture.componentInstance['draft'].token).toBe('');
    req.flush(connector({ name: 'Producción' }));
    http.expectOne('/api/connectors').flush([connector({ name: 'Producción' })]);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).not.toContain(TOKEN);
    http.verify();
  });

  it('un operador no ve la pestaña; un editor sí', async () => {
    for (const [role, visible] of [['operator', false], ['editor', true]] as const) {
      TestBed.resetTestingModule();
      storeSession(role);
      const http = configure(Settings);
      const fixture = TestBed.createComponent(Settings);
      fixture.componentRef.setInput('tab', 'connectors');
      fixture.detectChanges();
      await fixture.whenStable();
      const el = fixture.nativeElement as HTMLElement;
      expect(!!el.querySelector('[data-tab="connectors"]')).toBe(visible);
      if (visible) http.match('/api/connectors').forEach((r) => r.flush([]));
      else http.expectNone('/api/connectors');
      http.match(() => true).forEach((r) => r.flush([]));
    }
  });
});

describe('ExpiryWarningsSettings', () => {
  it('muestra los umbrales, añade uno y guarda ordenado', async () => {
    storeSession('admin');
    const http = configure(ExpiryWarningsSettings);
    const fixture = TestBed.createComponent(ExpiryWarningsSettings);
    fixture.detectChanges();
    http.expectOne('/api/settings/expiry-warnings').flush({ days: [30, 7] });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect([...el.querySelectorAll('[data-threshold]')].map((t) => t.getAttribute('data-threshold'))).toEqual(['30', '7']);
    const c = fixture.componentInstance as unknown as { draft: number | null; add(): void; save(): void };
    c.draft = 60;
    c.add();
    c.save();
    const req = http.expectOne('/api/settings/expiry-warnings');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ days: [60, 30, 7] });
    req.flush({ days: [60, 30, 7] });
    http.verify();
  });

  it('un lector los ve sin poder cambiarlos', () => {
    storeSession('viewer');
    const http = configure(ExpiryWarningsSettings);
    const fixture = TestBed.createComponent(ExpiryWarningsSettings);
    fixture.detectChanges();
    http.expectOne('/api/settings/expiry-warnings').flush({ days: [30, 7] });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('[data-threshold]')).toHaveLength(2);
    expect(el.querySelector('[data-action="save-thresholds"]')).toBeNull();
  });
});
