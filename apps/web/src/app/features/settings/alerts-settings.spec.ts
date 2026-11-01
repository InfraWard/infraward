import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { AlertChannel } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { AlertsSettings, parseRecipients } from './alerts-settings';
import { Settings } from './settings';

const URL_TOKEN = 'https://hooks.example.com/services/CENTINELA-url-token';
const SECRET = 'CENTINELA-secreto-de-firma';

const channel = (extra: Partial<AlertChannel> = {}): AlertChannel => ({
  id: '00000000-0000-4000-8000-0000000000a1',
  name: 'n8n',
  type: 'webhook',
  enabled: true,
  kinds: null,
  includeAdminOnly: false,
  host: 'hooks.example.com',
  recipients: null,
  hasSecret: true,
  secretProvider: 'local',
  lastSuccessAt: null,
  lastErrorAt: null,
  lastError: null,
  createdAt: '2026-10-29T10:00:00.000Z',
  updatedAt: '2026-10-29T10:00:00.000Z',
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

describe('parseRecipients', () => {
  it('separa por comas, espacios o líneas y quita repetidos', () => {
    expect(parseRecipients('a@x.y, b@x.y\nc@x.y;a@x.y ')).toEqual(['a@x.y', 'b@x.y', 'c@x.y']);
  });
});

describe('AlertsSettings', () => {
  async function render() {
    storeSession('admin');
    const http = configure(AlertsSettings);
    const fixture = TestBed.createComponent(AlertsSettings);
    fixture.detectChanges();
    return { http, fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('lista los canales con su estado, el host (nunca la URL) y avisa sin SMTP', async () => {
    const { http, fixture, el } = await render();
    http.expectOne('/api/alerts/channels').flush([
      channel({ lastSuccessAt: '2026-10-29T11:00:00.000Z' }),
      channel({
        id: '00000000-0000-4000-8000-0000000000a2',
        name: 'guardia',
        type: 'email',
        host: null,
        recipients: ['g@example.com'],
        hasSecret: false,
        secretProvider: null,
        kinds: ['vulnerability_kev'],
        lastErrorAt: '2026-10-29T12:00:00.000Z',
        lastError: 'SMTP: 535',
      }),
    ]);
    http.expectOne('/api/alerts/status').flush({ smtpConfigured: false, allowPrivate: false, allowHttp: false });
    fixture.detectChanges();
    await fixture.whenStable();
    const hook = el.querySelector('[data-channel="n8n"]')!;
    expect(hook.querySelector('[data-state="ok"]')).not.toBeNull();
    expect(hook.textContent).toContain('hooks.example.com · firmado');
    const mail = el.querySelector('[data-channel="guardia"]')!;
    expect(mail.querySelector('[data-state="error"]')).not.toBeNull();
    expect(mail.querySelector('[data-last-error]')?.textContent).toContain('SMTP: 535');
    expect(mail.textContent).toContain('CVE críticos en KEV y expuestos');
    expect(el.querySelector('[data-smtp-missing]')).not.toBeNull();
    http.verify();
  });

  it('crea un webhook con la URL y el secreto en campos de contraseña, y los vacía al enviar', async () => {
    const { http, fixture, el } = await render();
    http.expectOne('/api/alerts/channels').flush([]);
    http.expectOne('/api/alerts/status').flush({ smtpConfigured: true, allowPrivate: false, allowHttp: false });
    fixture.detectChanges();
    (el.querySelector('[data-action="new-channel"] button') as HTMLButtonElement).click();
    fixture.detectChanges();
    await fixture.whenStable();
    const type = (id: string, value: string) => {
      const input = document.querySelector(id) as HTMLInputElement;
      input.value = value;
      input.dispatchEvent(new Event('input'));
      return input;
    };
    type('#channel-name', 'n8n');
    expect(type('#channel-url', URL_TOKEN).type).toBe('password');
    expect(type('#channel-secret', SECRET).type).toBe('password');
    fixture.detectChanges();
    (document.querySelector('[data-action="save-channel"] button') as HTMLButtonElement).click();
    const req = http.expectOne('/api/alerts/channels');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({
      name: 'n8n',
      type: 'webhook',
      url: URL_TOKEN,
      secret: SECRET,
      kinds: null,
      includeAdminOnly: false,
      enabled: true,
    });
    const draft = (fixture.componentInstance as unknown as { draft: { url: string; secret: string } }).draft;
    expect(draft.url).toBe('');
    expect(draft.secret).toBe('');
    req.flush(channel());
    http.expectOne('/api/alerts/channels').flush([channel()]);
    fixture.detectChanges();
    expect(document.body.textContent).not.toContain('CENTINELA');
    http.verify();
  });

  it('«Enviar prueba» enseña el resultado', async () => {
    const { http, fixture, el } = await render();
    http.expectOne('/api/alerts/channels').flush([channel()]);
    http.expectOne('/api/alerts/status').flush({ smtpConfigured: true, allowPrivate: false, allowHttp: false });
    fixture.detectChanges();
    const messages = TestBed.inject(MessageService);
    const add = vi.spyOn(messages, 'add');
    (el.querySelector('[data-action="test-channel"] button') as HTMLButtonElement).click();
    http.expectOne('/api/alerts/channels/00000000-0000-4000-8000-0000000000a1/test').flush({
      ok: false,
      error: 'HTTP 404',
    });
    expect(add).toHaveBeenCalledWith(expect.objectContaining({ severity: 'error', detail: 'n8n: HTTP 404' }));
    http.expectOne('/api/alerts/channels').flush([channel()]);
    http.verify();
  });

  it('solo un admin ve la pestaña', async () => {
    for (const [role, visible] of [['editor', false], ['admin', true]] as const) {
      TestBed.resetTestingModule();
      storeSession(role);
      const http = configure(Settings);
      const fixture = TestBed.createComponent(Settings);
      fixture.componentRef.setInput('tab', 'alerts');
      fixture.detectChanges();
      await fixture.whenStable();
      const el = fixture.nativeElement as HTMLElement;
      expect(!!el.querySelector('[data-tab="alerts"]')).toBe(visible);
      if (!visible) http.expectNone('/api/alerts/channels');
      http.match(() => true).forEach((r) => r.flush([]));
    }
  });
});
