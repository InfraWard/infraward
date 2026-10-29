import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import type { ApiTokenSummary } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { ApiTokensSettings, expiryIso } from './api-tokens-settings';

const DAY = 24 * 60 * 60 * 1000;
const token = (extra: Partial<ApiTokenSummary> = {}): ApiTokenSummary => ({
  id: 't1',
  name: 'curl',
  prefix: 'iwt_abcdefgh',
  scope: 'read',
  createdAt: '2026-10-18T10:00:00.000Z',
  expiresAt: '2026-11-17T10:00:00.000Z',
  lastUsedAt: null,
  lastUsedIp: null,
  revokedAt: null,
  active: true,
  ...extra,
});

describe('expiryIso', () => {
  const now = Date.parse('2026-10-18T10:00:00Z');
  it('días desde ahora o una fecha (mañana como pronto, un año como mucho)', () => {
    expect(expiryIso(30, '', now)).toBe(new Date(now + 30 * DAY).toISOString());
    expect(expiryIso('custom', '2026-10-17', now)).toBeNull();
    expect(expiryIso('custom', '2028-01-01', now)).toBeNull();
    expect(expiryIso('custom', 'mal', now)).toBeNull();
    expect(expiryIso('custom', '2026-12-01', now)).not.toBeNull();
  });
});

describe('ApiTokensSettings', () => {
  afterEach(() => sessionStorage.clear());

  async function render(role: 'admin' | 'viewer') {
    storeSession(role);
    TestBed.configureTestingModule({
      imports: [ApiTokensSettings],
      providers: [provideHttpClient(), provideHttpClientTesting(), MessageService, ConfirmationService],
    });
    const fixture = TestBed.createComponent(ApiTokensSettings);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    http.expectOne('/api/auth/tokens').flush([token(), token({ id: 't2', name: 'viejo', active: false, revokedAt: '2026-10-01T00:00:00.000Z' })]);
    if (role === 'admin')
      http.expectOne('/api/api-tokens').flush([
        token({ id: 't3', name: 'ci', user: { id: 'u2', email: 'ana@example.com', name: 'Ana' } }),
      ]);
    fixture.detectChanges();
    await fixture.whenStable();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  it('lista los propios con prefijo, alcance, último uso y estado; el lector no ve los de todos', async () => {
    const { el, http } = await render('viewer');
    const row = el.querySelector('tr[data-token="curl"]')!;
    expect(row.textContent).toContain('iwt_abcdefgh…');
    expect(row.textContent).toContain('Solo lectura');
    expect(row.textContent).toContain('Nunca');
    expect(row.textContent).toContain('Vigente');
    expect(el.querySelector('tr[data-token="viejo"]')!.textContent).toContain('Revocado');
    expect(el.querySelector('tr[data-token="viejo"] [data-action="revoke-token"]')).toBeNull();
    expect(el.querySelector('[data-block="all-api-tokens"]')).toBeNull();
    http.verify();
  });

  it('crea un token y lo enseña una sola vez, con el ejemplo de curl', async () => {
    const { el, fixture, http } = await render('viewer');
    el.querySelector<HTMLButtonElement>('[data-action="new-token"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    const name = document.querySelector<HTMLInputElement>('[data-field="name"]')!;
    name.value = 'copias';
    name.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    document.querySelector<HTMLButtonElement>('[data-action="create-token"] button')!.click();
    const req = http.expectOne({ method: 'POST', url: '/api/auth/tokens' });
    expect(req.request.body).toMatchObject({ name: 'copias', scope: 'read' });
    const expires = Date.parse(req.request.body.expiresAt);
    expect(Math.round((expires - Date.now()) / DAY)).toBe(30);
    const secret = 'iwt_' + 'x'.repeat(43);
    req.flush({ token: token({ id: 't9', name: 'copias' }), secret });
    http.expectOne('/api/auth/tokens').flush([token({ id: 't9', name: 'copias' })]);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(document.querySelector('[data-issued-token]')!.textContent).toBe(secret);
    expect(document.querySelector('[data-dialog="issued-token"]')!.textContent).toContain(
      'Authorization: Bearer',
    );
    document.querySelector<HTMLButtonElement>('[data-action="close-issued"] button')!.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(document.querySelector('[data-issued-token]')).toBeNull();
  });

  it('un admin ve los de todos y revoca uno ajeno con confirmación', async () => {
    const { el, http } = await render('admin');
    const confirm = vi.spyOn(TestBed.inject(ConfirmationService), 'confirm');
    const all = el.querySelector('[data-block="all-api-tokens"]')!;
    const row = all.querySelector('tr[data-token="ci"]')!;
    expect(row.textContent).toContain('ana@example.com');
    row.querySelector<HTMLButtonElement>('[data-action="revoke-token"] button')!.click();
    const options = confirm.mock.calls[0]![0];
    expect(options.header).toContain('de ana@example.com');
    options.accept!();
    http.expectOne({ method: 'DELETE', url: '/api/api-tokens/t3' }).flush(token({ id: 't3', active: false }));
    http.expectOne('/api/auth/tokens').flush([]);
    http.expectOne('/api/api-tokens').flush([]);
  });
});
