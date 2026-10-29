import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import type { SearchSuggestions } from '@infraward/shared-types';
import { storeSession } from '../testing/session';
import { GlobalSearch, searchGroups, searchTarget } from './global-search';

const suggestions: SearchSuggestions = {
  assets: [
    {
      id: 'a1',
      name: 'pruebas',
      type: 'lxc',
      status: 'active',
      address: '172.20.10.191',
      parentName: 'Pruebas Limpia',
    },
  ],
  vulnerabilities: [
    { vulnerabilityId: 'CVE-2023-45853', severity: 'CRITICAL', title: 'zlib' },
    { vulnerabilityId: 'CVE-2023-45283', severity: 'HIGH', title: null },
  ],
  packages: [{ name: 'openssl', vulnerabilities: 61, assets: 5 }],
};

describe('searchGroups', () => {
  it('un CVE escrito entero va primero (Enter abre su ficha), con sus datos si los hay', () => {
    const groups = searchGroups('cve-2023-45853', suggestions);
    expect(groups.map((g) => g.label)).toEqual(['Ir a', 'Inventario', 'Vulnerabilidades', 'Paquetes']);
    expect(groups[0]!.items).toEqual([
      { kind: 'cve', id: 'CVE-2023-45853', severity: 'CRITICAL', title: 'zlib', vulnerabilityId: 'CVE-2023-45853' },
    ]);
    // Sin repetirlo en la lista.
    expect(groups[2]!.items).toEqual([
      { kind: 'cve', id: 'CVE-2023-45283', severity: 'HIGH', title: null },
    ]);
  });

  it('un CVE que no está en el inventario también se puede abrir', () => {
    expect(searchGroups('CVE-2099-99999', null)[0]!.items[0]).toMatchObject({
      kind: 'cve',
      id: 'CVE-2099-99999',
      severity: null,
    });
  });

  it('otro texto: buscarlo en el inventario (Enter) o en vulnerabilidades, y los recursos que coinciden; vacío: nada', () => {
    expect(searchGroups(' ssl ', null)).toEqual([
      {
        label: 'Ir a',
        items: [
          { kind: 'text', text: 'ssl', scope: 'inventory' },
          { kind: 'text', text: 'ssl', scope: 'vulnerabilities' },
        ],
      },
    ]);
    const groups = searchGroups('prue', suggestions);
    expect(groups[1]).toEqual({
      label: 'Inventario',
      items: [{ kind: 'asset', asset: suggestions.assets[0] }],
    });
    expect(searchGroups('  ', suggestions)).toEqual([]);
  });
});

describe('searchTarget', () => {
  it('recurso → su ficha; CVE → su ficha; paquete o texto → la lista con todo lo abierto; texto en el inventario → el árbol filtrado', () => {
    expect(searchTarget({ kind: 'asset', asset: suggestions.assets[0]! })).toEqual({
      commands: ['/assets', 'a1'],
    });
    expect(searchTarget({ kind: 'text', text: 'pve', scope: 'inventory' })).toEqual({
      commands: ['/inventory'],
      queryParams: { q: 'pve' },
    });
    expect(searchTarget({ kind: 'cve', id: 'CVE-1', severity: null, title: null })).toEqual({
      commands: ['/vulnerabilities', 'CVE-1'],
    });
    expect(searchTarget({ kind: 'package', name: 'openssl', vulnerabilities: 1, assets: 1 })).toEqual({
      commands: ['/vulnerabilities'],
      queryParams: { q: 'openssl', min: 'any', fixable: '0' },
    });
    expect(searchTarget({ kind: 'text', text: 'ssl', scope: 'vulnerabilities' }).queryParams).toEqual({
      q: 'ssl',
      min: 'any',
      fixable: '0',
    });
  });
});

describe('GlobalSearch', () => {
  beforeEach(() => storeSession('viewer'));
  afterEach(() => sessionStorage.clear());

  function render() {
    TestBed.configureTestingModule({
      imports: [GlobalSearch],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const fixture = TestBed.createComponent(GlobalSearch);
    fixture.detectChanges();
    return {
      fixture,
      component: fixture.componentInstance,
      http: TestBed.inject(HttpTestingController),
      router: TestBed.inject(Router),
      el: fixture.nativeElement as HTMLElement,
    };
  }

  it('pide sugerencias y, al elegir, navega y vacía el campo', async () => {
    const { component, http, router, fixture } = render();
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    (component as unknown as { value: { set(v: string): void } }).value.set('openssl');
    component.complete({ query: 'openssl', originalEvent: new Event('input') });
    http.expectOne('/api/search/suggest?q=openssl').flush(suggestions);
    const groups = (component as unknown as { groups(): { label: string }[] }).groups();
    expect(groups.map((g) => g.label)).toEqual(['Ir a', 'Inventario', 'Vulnerabilidades', 'Paquetes']);

    component.go({ kind: 'package', name: 'openssl', vulnerabilities: 61, assets: 5 });
    expect(navigate).toHaveBeenCalledWith(['/vulnerabilities'], {
      queryParams: { q: 'openssl', min: 'any', fixable: '0' },
    });
    await new Promise((r) => setTimeout(r));
    await fixture.whenStable();
    expect((component as unknown as { value(): string }).value()).toBe('');
  });

  it('«/» enfoca la barra, salvo escribiendo en otro campo', () => {
    const { el } = render();
    document.body.appendChild(el);
    const input = el.querySelector<HTMLInputElement>('input#global-search')!;
    document.dispatchEvent(new KeyboardEvent('keydown', { key: '/' }));
    expect(document.activeElement).toBe(input);

    input.blur();
    const other = document.createElement('input');
    document.body.appendChild(other);
    other.focus();
    other.dispatchEvent(new KeyboardEvent('keydown', { key: '/', bubbles: true }));
    expect(document.activeElement).toBe(other);
    other.remove();
    el.remove();
  });
});
