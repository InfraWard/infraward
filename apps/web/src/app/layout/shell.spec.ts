import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { storeSession } from '../testing/session';
import { Shell } from './shell';

describe('Shell', () => {
  beforeEach(() => {
    storeSession('admin');
    localStorage.clear();
  });
  afterEach(() => sessionStorage.clear());

  async function render() {
    TestBed.configureTestingModule({
      imports: [Shell],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('menú lateral con sus secciones (la caja fuerte, con vault.manage) y el usuario en la barra', async () => {
    const { el } = await render();
    const links = [...el.querySelectorAll('[data-sidebar] a')];
    expect(links.map((a) => a.textContent?.trim())).toEqual([
      'Panel',
      'Inventario',
      'Proyectos',
      'Vulnerabilidades',
      'Actividad',
      'Caja fuerte',
      'Ajustes',
    ]);
    expect(links.map((a) => a.getAttribute('href'))).toEqual([
      '/dashboard',
      '/inventory',
      '/projects',
      '/vulnerabilities',
      '/activity',
      '/vault',
      '/settings',
    ]);
    const user = el.querySelector('[data-action="user-menu"]');
    expect(user?.textContent).toContain('Admin');
    expect(user?.querySelector('button')?.getAttribute('aria-label')).toContain(
      'admin@example.com',
    );
    const mark = el.querySelector('.brand img') as HTMLImageElement | null;
    expect(mark?.getAttribute('src')).toBe('logo.svg');
  });

  it('sin vault.manage, el menú no enseña la caja fuerte', async () => {
    storeSession('viewer');
    const { el } = await render();
    const links = [...el.querySelectorAll('[data-sidebar] a')].map((a) => a.getAttribute('href'));
    expect(links).not.toContain('/vault');
  });

  it('se pliega a solo iconos y lo recuerda', async () => {
    const { fixture, el } = await render();
    el.querySelector<HTMLButtonElement>('[data-action="toggle-menu"] button')!.click();
    await fixture.whenStable();
    expect(el.querySelector('[data-sidebar]')?.classList).toContain('collapsed');
    expect(localStorage.getItem('infraward.nav.collapsed')).toBe('1');
  });
});
