import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { VaultEntry, VaultEntryList } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { copyEphemeral } from './clipboard';
import { VaultEntries } from './vault-entries';
import { VaultRevealDialog } from './vault-reveal-dialog';

const SECRET = 'centinela-web-Zx9#';

const entry = (extra: Partial<VaultEntry> = {}): VaultEntry => ({
  id: 'e1',
  kind: 'console',
  name: 'root (consola)',
  username: 'root',
  url: null,
  notes: null,
  asset: { id: 'a1', name: 'pve1', type: 'server', roles: ['proxmox-node'] },
  hasSecret: true,
  currentVersion: 1,
  lastRotatedAt: '2026-10-01T00:00:00.000Z',
  rotationDays: null,
  effectiveRotationDays: 180,
  rotationState: 'ok',
  rotationDueAt: '2027-03-30T00:00:00.000Z',
  createdAt: '2026-10-01T00:00:00.000Z',
  createdBy: 'admin@example.com',
  updatedAt: '2026-10-01T00:00:00.000Z',
  updatedBy: 'admin@example.com',
  deletedAt: null,
  deletedBy: null,
  purgeAt: null,
  ...extra,
});

/** Portapapeles falso (el de jsdom no existe). */
function fakeClipboard(initial = '') {
  let text = initial;
  return {
    get text() {
      return text;
    },
    writeText: vi.fn(async (t: string) => {
      text = t;
    }),
    readText: vi.fn(async () => text),
  } as unknown as Clipboard & { text: string };
}

describe('copyEphemeral', () => {
  afterEach(() => vi.useRealTimers());

  it('copia y lo vacía pasado el plazo si sigue ahí', async () => {
    vi.useFakeTimers();
    const clip = fakeClipboard();
    await copyEphemeral(SECRET, 30, clip);
    expect(clip.text).toBe(SECRET);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(clip.text).toBe('');
  });

  it('no borra lo que el usuario copió después', async () => {
    vi.useFakeTimers();
    const clip = fakeClipboard();
    await copyEphemeral(SECRET, 30, clip);
    await clip.writeText('otra cosa');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(clip.text).toBe('otra cosa');
  });
});

@Component({
  imports: [VaultRevealDialog],
  template: `<app-vault-reveal-dialog [entry]="entry()" (closed)="entry.set(null)" />`,
})
class RevealHost {
  readonly entry = signal<VaultEntry | null>(entry());
}

describe('VaultRevealDialog', () => {
  afterEach(() => {
    vi.useRealTimers();
    sessionStorage.clear();
  });

  it('enseña el valor unos segundos y después no queda en el DOM', async () => {
    vi.useFakeTimers();
    storeSession('admin');
    TestBed.configureTestingModule({
      imports: [RevealHost],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(RevealHost);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    const body = () => document.body.textContent ?? '';
    const reason = document.querySelector<HTMLInputElement>('[data-field="reason"]')!;
    reason.value = 'Consola de emergencia';
    reason.dispatchEvent(new Event('input'));
    document.querySelector<HTMLButtonElement>('[data-action="reveal-show"] button')!.click();
    const req = http.expectOne('/api/vault/entries/e1/reveal');
    expect(req.request.body).toEqual({ purpose: 'show', reason: 'Consola de emergencia' });
    req.flush({ value: SECRET, version: 1, expiresInSeconds: 30 });
    fixture.detectChanges();
    expect(body()).toContain(SECRET);
    await vi.advanceTimersByTimeAsync(30_000);
    fixture.detectChanges();
    expect(body()).not.toContain(SECRET);
    // Y el diálogo se cierra solo.
    expect(fixture.componentInstance.entry()).toBeNull();
    expect(JSON.stringify({ ...sessionStorage, ...localStorage })).not.toContain(SECRET);
  });
});

describe('VaultEntries', () => {
  afterEach(() => sessionStorage.clear());

  async function render(role: 'admin' | 'editor') {
    storeSession(role);
    TestBed.configureTestingModule({
      imports: [VaultEntries],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        MessageService,
        ConfirmationService,
      ],
    });
    const fixture = TestBed.createComponent(VaultEntries);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    await new Promise((r) => setTimeout(r, 250));
    const list: VaultEntryList = {
      items: [entry(), entry({ id: 'e2', name: 'iDRAC', kind: 'ipmi', hasSecret: false, rotationState: 'overdue' })],
      overdue: 1,
    };
    http.expectOne((r) => r.url === '/api/vault/entries').flush(list);
    fixture.detectChanges();
    await fixture.whenStable();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('el admin puede revelar las que tienen secreto; el editor no ve el botón', async () => {
    const admin = await render('admin');
    expect(admin.el.querySelectorAll('[data-action="reveal"]')).toHaveLength(1);
    expect(admin.el.querySelector('[data-block="overdue"]')?.textContent).toContain('1 credencial');
    TestBed.resetTestingModule();
    const editor = await render('editor');
    expect(editor.el.querySelectorAll('[data-action="reveal"]')).toHaveLength(0);
    expect(editor.el.querySelector('[data-entry="iDRAC"]')?.textContent).toContain('sin secreto');
  });
});
