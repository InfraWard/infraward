import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { AssetGraph } from '@infraward/shared-types';
import { GraphCanvas } from '../../shared/graph/graph-canvas';
import { FakeGraphCanvas, graphNode } from '../../testing/graph';
import { InventoryTopology } from './inventory-topology';

const hostLevel: AssetGraph = {
  centerId: null,
  truncated: false,
  nodes: [
    graphNode('pve', { type: 'server' }),
    graphNode('ct', {
      name: 'pruebas',
      type: 'lxc',
      parentId: 'pve',
      hidden: { container: 3, volume: 1, network: 1, image: 2 },
      hiddenCritical: 1,
    }),
    graphNode('debian', { type: 'lxc', parentId: 'pve' }),
  ],
  edges: [],
};

const expanded: AssetGraph = {
  ...hostLevel,
  nodes: [
    ...hostLevel.nodes.map((n) => (n.id === 'ct' ? { ...n, hidden: {}, hiddenCritical: 0 } : n)),
    graphNode('web1', { parentId: 'ct', runtimeState: 'running' }),
    graphNode('cache', { parentId: 'ct', critical: 1, runtimeState: 'stopped' }),
    graphNode('app', { type: 'network', parentId: 'ct' }),
  ],
  edges: [
    { id: 'a1', source: 'web1', target: 'app', type: 'attached_to', count: 1 },
    { id: 'a2', source: 'cache', target: 'app', type: 'attached_to', count: 1 },
  ],
};

describe('InventoryTopology', () => {
  async function setup(inputs: Record<string, unknown> = {}) {
    TestBed.configureTestingModule({
      imports: [InventoryTopology],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.overrideComponent(InventoryTopology, {
      remove: { imports: [GraphCanvas] },
      add: { imports: [FakeGraphCanvas] },
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(InventoryTopology);
    for (const [k, v] of Object.entries(inputs)) fixture.componentRef.setInput(k, v);
    await fixture.whenStable();
    http.expectOne('/api/projects').flush([]);
    return { http, fixture, el: fixture.nativeElement as HTMLElement };
  }

  const ids = (el: HTMLElement) =>
    [...el.querySelectorAll<HTMLElement>('[data-graph-node]')].map((n) => n.dataset['graphNode']);

  it('nivel host con el resumen de cada CT; expandir carga su contenido dentro', async () => {
    const { http, fixture, el } = await setup({ rootId: 'pve' });
    http.expectOne('/api/assets/topology?rootId=pve&includeRetired=false').flush(hostLevel);
    await fixture.whenStable();
    expect(ids(el)).toEqual(['pve', 'ct', 'debian']);
    expect(el.querySelector('[data-graph-node="ct"]')?.textContent).toContain(
      '3 contenedores · 1 volumen · 1 red · 2 imágenes · 1 crítica',
    );
    expect(el.querySelector('[data-root-chip]')?.textContent).toContain('Solo: pve');

    el.querySelector<HTMLElement>('[data-graph-node="ct"]')!.click();
    await fixture.whenStable();
    el.querySelector<HTMLElement>('app-graph-node-panel [data-expand] button')!.click();
    await fixture.whenStable();
    http
      .expectOne('/api/assets/topology?rootId=pve&expand=ct&includeRetired=false')
      .flush(expanded);
    await fixture.whenStable();
    expect(el.querySelector('[data-graph-node="web1"]')?.getAttribute('data-parent')).toBe('ct');
    expect(el.querySelectorAll('[data-graph-edge="attached_to"]')).toHaveLength(2);
    // Ya expandido: la tarjeta ofrece contraer.
    expect(el.querySelector('app-graph-node-panel [data-collapse]')).not.toBeNull();
  });

  it('doble clic expande lo que tiene contenido y «Expandir un nivel» expande todos', async () => {
    const { http, fixture, el } = await setup();
    http.expectOne('/api/assets/topology?includeRetired=false').flush(hostLevel);
    await fixture.whenStable();
    el.querySelector('[data-graph-node="ct"]')!.dispatchEvent(new MouseEvent('dblclick'));
    await fixture.whenStable();
    http.expectOne('/api/assets/topology?expand=ct&includeRetired=false').flush(expanded);
    await fixture.whenStable();
    el.querySelector<HTMLElement>('[data-collapse-all] button')!.click();
    await fixture.whenStable();
    http.expectOne('/api/assets/topology?includeRetired=false').flush(hostLevel);
  });

  it('resaltar críticas atenúa lo que no las tiene', async () => {
    const { http, fixture, el } = await setup();
    http.expectOne('/api/assets/topology?includeRetired=false').flush(expanded);
    await fixture.whenStable();
    el.querySelector<HTMLElement>('p-toggleswitch')!.click();
    await fixture.whenStable();
    const dim = [...el.querySelectorAll<HTMLElement>('[data-graph-node].dim')].map(
      (n) => n.dataset['graphNode'],
    );
    expect(dim).toEqual(['debian', 'web1', 'app']);
  });

  it('el proyecto va a la API', async () => {
    const { http } = await setup({ project: 'p1' });
    http.expectOne('/api/assets/topology?projectId=p1&includeRetired=false').flush(hostLevel);
  });
});
