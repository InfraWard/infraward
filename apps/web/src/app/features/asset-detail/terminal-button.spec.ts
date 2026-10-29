import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { storeSession } from '../../testing/session';
import { TerminalButton } from './terminal-button';

async function render(status: object) {
  storeSession('editor');
  TestBed.configureTestingModule({
    imports: [TerminalButton],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(TerminalButton);
  fixture.componentRef.setInput('assetId', 'ct1');
  fixture.detectChanges();
  http.expectOne('/api/assets/ct1/terminal').flush(status);
  await fixture.whenStable();
  fixture.detectChanges();
  return fixture.nativeElement as HTMLElement;
}

describe('TerminalButton', () => {
  it('sin permiso, no se enseña', async () => {
    const el = await render({ allowed: false, available: false, reason: null, host: null, account: null });
    expect(el.querySelector('[data-action="terminal"]')).toBeNull();
  });

  it('con permiso pero sin acceso de administración: deshabilitado con el motivo', async () => {
    const el = await render({
      allowed: true,
      available: false,
      reason: 'pve-pruebas no tiene el acceso interactivo de administración activado',
      host: null,
      account: null,
    });
    expect(el.querySelector<HTMLButtonElement>('[data-action="terminal"] button')?.disabled).toBe(true);
  });

  it('disponible: abre la terminal en otra pestaña sin opener', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const el = await render({
      allowed: true,
      available: true,
      reason: null,
      host: { id: 'pve', name: 'pve-pruebas' },
      account: 'infraward-admin',
    });
    el.querySelector<HTMLButtonElement>('[data-action="terminal"] button')!.click();
    expect(open).toHaveBeenCalledWith('/assets/ct1/terminal', '_blank', 'noopener');
  });
});
