import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { NotificationPage } from '@infraward/shared-types';
import { storeSession } from '../testing/session';
import { NotificationsBell } from './notifications-bell';

const PAGE: NotificationPage = {
  items: [
    {
      id: 'n1',
      kind: 'asset_created',
      assetId: 'pve',
      assetName: 'pve-pruebas',
      message: 'pve-pruebas: 1 nuevo — test (lxc)',
      items: [{ id: 'ct', name: 'test', type: 'lxc' }],
      total: 1,
      createdAt: '2026-10-12T10:00:00Z',
      unread: true,
    },
  ],
  total: 1,
  unread: 1,
};

describe('NotificationsBell', () => {
  beforeEach(() => storeSession('viewer'));
  afterEach(() => sessionStorage.clear());

  it('cuenta las no leídas al entrar, las lista al abrir y las marca como leídas', async () => {
    TestBed.configureTestingModule({
      imports: [NotificationsBell],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(NotificationsBell);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;

    http.expectOne('/api/notifications/unread-count').flush({ unread: 3 });
    await fixture.whenStable();
    expect(el.querySelector('[data-unread]')?.textContent?.trim()).toBe('3');

    el.querySelector<HTMLButtonElement>('[data-action="notifications"] button')!.click();
    http.expectOne((r) => r.url === '/api/notifications').flush(PAGE);
    await fixture.whenStable();
    const panel = document.querySelector('[data-notifications]')!;
    expect(panel.textContent).toContain('pve-pruebas: 1 nuevo — test (lxc)');
    expect(panel.querySelector('a')?.getAttribute('href')).toBe('/assets/ct');
    expect(panel.querySelector('li.unread')).not.toBeNull();

    document
      .querySelector<HTMLButtonElement>('[data-action="notifications-seen"] button')!
      .click();
    http.expectOne('/api/notifications/seen').flush({ unread: 0 });
    await fixture.whenStable();
    expect(el.querySelector('[data-unread]')).toBeNull();
    expect(document.querySelector('[data-notifications] li.unread')).toBeNull();
    http.verify();
  });
});
