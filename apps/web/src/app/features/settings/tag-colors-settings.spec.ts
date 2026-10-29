import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { TagColorsSettings } from './tag-colors-settings';

describe('TagColorsSettings', () => {
  it('borrar un tag pide confirmación, llama a la API y recarga la lista', async () => {
    storeSession('editor');
    TestBed.configureTestingModule({
      imports: [TagColorsSettings],
      providers: [provideHttpClient(), provideHttpClientTesting(), ConfirmationService, MessageService],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(TagColorsSettings);
    fixture.detectChanges();
    http.expectOne('/api/tags').flush([{ tag: 'web', assets: 3, color: null }]);
    await fixture.whenStable();
    fixture.detectChanges();
    const confirm = vi.spyOn(TestBed.inject(ConfirmationService), 'confirm');
    (fixture.nativeElement as HTMLElement)
      .querySelector<HTMLButtonElement>('[data-tag-color="web"] [data-action="delete-tag"] button')!
      .click();
    expect(confirm.mock.calls[0]![0].message).toContain('Se quita de 3 assets');
    http.expectNone((r) => r.method === 'DELETE');
    confirm.mock.calls[0]![0].accept!();
    http.expectOne({ method: 'DELETE', url: '/api/tags/web' }).flush({ assets: 3 });
    http.expectOne('/api/tags').flush([]);
    http.verify();
  });
});
