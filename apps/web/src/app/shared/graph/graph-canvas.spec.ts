import { TestBed } from '@angular/core/testing';
import type { ElementDefinition } from 'cytoscape';
import { GRAPH_ENGINE, GraphCanvas } from './graph-canvas';

/** Cytoscape simulado: cuenta los layouts y las selecciones. */
function fakeEngine() {
  const calls = { layouts: 0, selected: [] as string[] };
  const collection = () => {
    const c = {
      map: () => [],
      forEach: () => undefined,
      unselect: () => c,
      remove: () => c,
    };
    return c;
  };
  const cy = {
    on: () => undefined,
    nodes: collection,
    elements: collection,
    batch: (fn: () => void) => fn(),
    add: () => undefined,
    layout: () => ({ one: () => undefined, run: () => calls.layouts++ }),
    getElementById: (id: string) => ({ select: () => calls.selected.push(id) }),
    style: () => undefined,
    resize: () => undefined,
    destroy: () => undefined,
    zoom: () => 1,
    center: () => undefined,
    fit: () => undefined,
  };
  return { calls, factory: () => Promise.resolve((() => cy) as never) };
}

// jsdom no tiene ResizeObserver.
const noop = (): void => undefined;
globalThis.ResizeObserver ??= class {
  observe = noop;
  unobserve = noop;
  disconnect = noop;
};

const els = (ids: string[]): ElementDefinition[] =>
  ids.map((id) => ({ group: 'nodes', data: { id, label: id } }));

describe('GraphCanvas', () => {
  it('seleccionar un nodo no vuelve a lanzar el layout (no reencuadra); cambiar los elementos sí', async () => {
    const { calls, factory } = fakeEngine();
    TestBed.configureTestingModule({
      imports: [GraphCanvas],
      providers: [{ provide: GRAPH_ENGINE, useValue: factory }],
    });
    const fixture = TestBed.createComponent(GraphCanvas);
    fixture.componentRef.setInput('elements', els(['a', 'b']));
    await fixture.whenStable();
    await new Promise((r) => setTimeout(r));
    await fixture.whenStable();
    expect(calls.layouts).toBe(1);

    fixture.componentRef.setInput('selectedId', 'b');
    await fixture.whenStable();
    expect(calls.layouts).toBe(1);
    expect(calls.selected).toContain('b');

    fixture.componentRef.setInput('elements', els(['a', 'b', 'c']));
    await fixture.whenStable();
    expect(calls.layouts).toBe(2);
  });

  it('pantalla completa: sin la API del navegador ocupa la ventana y vuelve con Esc', async () => {
    const { factory } = fakeEngine();
    TestBed.configureTestingModule({
      imports: [GraphCanvas],
      providers: [{ provide: GRAPH_ENGINE, useValue: factory }],
    });
    const fixture = TestBed.createComponent(GraphCanvas);
    fixture.componentRef.setInput('elements', els(['a']));
    await fixture.whenStable();
    const host = fixture.nativeElement as HTMLElement;
    host.querySelector<HTMLElement>('[data-fullscreen] button')!.click();
    await fixture.whenStable();
    expect(host.classList).toContain('pseudo-fullscreen');
    expect(host.querySelector('[data-fullscreen] button')?.getAttribute('aria-label')).toBe(
      'Salir de pantalla completa',
    );
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await fixture.whenStable();
    expect(host.classList).not.toContain('pseudo-fullscreen');
  });
});
