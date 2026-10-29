import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { AccessSettings } from './access-settings';

const RULE = {
  id: 'r1',
  permission: 'terminal.open',
  subject: { type: 'role', role: 'editor' },
  scope: 'tag',
  assetId: null,
  assetName: null,
  tag: 'web',
  projectId: null,
  projectName: null,
  createdAt: '2026-10-22T10:00:00.000Z',
  createdBy: { id: 'u1', email: 'admin@example.com' },
};

describe('AccessSettings', () => {
  it('lista las reglas, concede por etiqueta a un rol y retira', async () => {
    storeSession('admin');
    TestBed.configureTestingModule({
      imports: [AccessSettings],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting(), MessageService],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AccessSettings);
    fixture.detectChanges();
    http.expectOne('/api/tags').flush([{ tag: 'web', assets: 3, color: null }]);
    http.expectOne('/api/projects').flush([]);
    http.expectOne('/api/users').flush([]);
    http.expectOne('/api/access-policies').flush([RULE]);
    await fixture.whenStable();
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-access-rule="r1"]')?.textContent).toMatch(/Rol Editor[\s\S]*etiqueta web/);

    const component = fixture.componentInstance as unknown as {
      subject: string;
      scope: string;
      tag: string;
      grant(): Promise<void>;
      revoke(rule: object): Promise<void>;
    };
    component.subject = 'role:operator';
    component.scope = 'tag';
    component.tag = 'web';
    const granted = component.grant();
    const post = http.expectOne((r) => r.method === 'POST' && r.url === '/api/access-policies');
    expect(post.request.body).toEqual({
      permission: 'terminal.open',
      subjectType: 'role',
      role: 'operator',
      scope: 'tag',
      tag: 'web',
    });
    post.flush({ ...RULE, id: 'r2' });
    await new Promise((r) => setTimeout(r));
    http.expectOne('/api/access-policies').flush([RULE]);
    await granted;

    const revoked = component.revoke(RULE);
    http.expectOne((r) => r.method === 'DELETE' && r.url === '/api/access-policies/r1').flush(null);
    await new Promise((r) => setTimeout(r));
    http.expectOne('/api/access-policies').flush([]);
    await revoked;
    http.verify();
  });
});
