import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { ProjectList } from './project-list';

const PROJECT = {
  id: 'p1',
  name: 'Tienda',
  description: 'La web de la tienda',
  color: '#0d9488',
  createdAt: '',
  updatedAt: '',
  stats: {
    assets: 12,
    assetsByType: { server: 1, lxc: 2, container: 5, image: 3, volume: 1, network: 2 },
    openFindings: { CRITICAL: 4, HIGH: 10, MEDIUM: 20, LOW: 5, UNKNOWN: 1 },
    fixableFindings: { CRITICAL: 2, HIGH: 3 },
    openVulnerabilities: 30,
  },
};

async function render() {
  storeSession('admin');
  TestBed.configureTestingModule({
    imports: [ProjectList],
    providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting(), MessageService],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(ProjectList);
  fixture.detectChanges();
  http.expectOne('/api/projects').flush([PROJECT]);
  await fixture.whenStable();
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement };
}

describe('ProjectList', () => {
  beforeEach(() => localStorage.removeItem('infraward:projects:view'));

  it('cuadrícula por defecto: anillo con los C/H con parche, cifras y tipos por icono (4 y «+N»)', async () => {
    const { el } = await render();
    const card = el.querySelector('[data-project-grid] [data-project="Tienda"]')!;
    expect(card.querySelector('app-severity-ring')?.textContent).toContain('5');
    expect(card.querySelector('[data-kpi="assets"]')?.textContent).toContain('12');
    expect(card.querySelector('[data-kpi="critical"]')?.textContent).toContain('4');
    expect(card.querySelectorAll('app-asset-type-chips li[data-type]')).toHaveLength(4);
    expect(card.querySelector('app-asset-type-chips .more')?.textContent).toContain('+3');
  });

  it('la lista se elige y se recuerda', async () => {
    const first = await render();
    (first.fixture.componentInstance as unknown as { setView(v: string): void }).setView('list');
    first.fixture.detectChanges();
    expect(first.el.querySelector('[data-project-list] [data-project="Tienda"]')).not.toBeNull();
    expect(localStorage.getItem('infraward:projects:view')).toBe('list');
    TestBed.resetTestingModule();
    const again = await render();
    expect(again.el.querySelector('[data-project-list]')).not.toBeNull();
    expect(again.el.querySelector('[data-project-grid]')).toBeNull();
  });
});
