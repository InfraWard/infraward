import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { GraphCanvas } from '../../shared/graph/graph-canvas';
import { FakeGraphCanvas, graphNode, web1Graph } from '../../testing/graph';
import { AssetRelationMap } from './asset-relation-map';

describe('AssetRelationMap', () => {
  async function setup() {
    TestBed.configureTestingModule({
      imports: [AssetRelationMap],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.overrideComponent(AssetRelationMap, {
      remove: { imports: [GraphCanvas] },
      add: { imports: [FakeGraphCanvas] },
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AssetRelationMap);
    fixture.componentRef.setInput('assetId', 'web1');
    await fixture.whenStable();
    return { http, fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('pinta el mapa de web1: su CT, su imagen, su red y su volumen, con la leyenda', async () => {
    const { http, fixture, el } = await setup();
    http.expectOne('/api/assets/web1/graph?depth=1').flush(web1Graph());
    await fixture.whenStable();
    const nodes = [...el.querySelectorAll('[data-graph-node]')].map((n) =>
      n.textContent?.trim(),
    );
    expect(nodes).toEqual(['web1', 'pruebas\n+3 más', 'nginx:1.25', 'app\n+2 más', 'webdata']);
    expect(
      [...el.querySelectorAll('[data-graph-edge]')].map((e) => e.textContent),
    ).toEqual(['contiene', 'instancia de', 'conectado a', 'monta']);
    const legend = el.querySelector('app-graph-legend')!.textContent!;
    for (const t of ['Contenedor', 'CT (LXC)', 'Imagen', 'Red', 'Volumen', 'monta'])
      expect(legend).toContain(t);
  });

  it('cambiar la profundidad vuelve a pedir el mapa', async () => {
    const { http, fixture } = await setup();
    http.expectOne('/api/assets/web1/graph?depth=1').flush(web1Graph());
    fixture.componentRef.setInput('depth', 3);
    await fixture.whenStable();
    http.expectOne('/api/assets/web1/graph?depth=3').flush(web1Graph());
  });

  it('un nodo abre su tarjeta; «Centrar aquí» recentra y «Volver a» regresa', async () => {
    const { http, fixture, el } = await setup();
    http.expectOne('/api/assets/web1/graph?depth=1').flush(web1Graph());
    await fixture.whenStable();

    el.querySelector<HTMLElement>('[data-graph-node="net"]')!.click();
    await fixture.whenStable();
    const panel = el.querySelector('app-graph-node-panel')!;
    expect(panel.textContent).toContain('app');
    expect(panel.querySelector('[data-hidden-summary]')?.textContent).toContain(
      '2 contenedores',
    );
    // El centro no se puede recentrar; los demás sí.
    panel.querySelector<HTMLElement>('[data-recenter] button')!.click();
    await fixture.whenStable();
    http.expectOne('/api/assets/net/graph?depth=1').flush({
      centerId: 'net',
      truncated: true,
      nodes: [
        graphNode('net', { name: 'app', type: 'network' }),
        graphNode('web1', { depth: 1 }),
        graphNode('web2', { depth: 1 }),
      ],
      edges: [],
    });
    await fixture.whenStable();
    expect(el.querySelector('[data-centered]')?.textContent).toContain('app');
    expect(el.querySelector('[data-truncated]')).not.toBeNull();
    expect(el.querySelector('app-graph-node-panel')).toBeNull();

    el.querySelector<HTMLElement>('[data-back] button')!.click();
    await fixture.whenStable();
    http.expectOne('/api/assets/web1/graph?depth=1').flush(web1Graph());
    await fixture.whenStable();
    expect(el.querySelector('[data-back]')).toBeNull();
    expect(el.querySelector('[data-centered]')).toBeNull();
  });

  it('doble clic en un nodo abre su ficha', async () => {
    const { http, fixture, el } = await setup();
    http.expectOne('/api/assets/web1/graph?depth=1').flush(web1Graph());
    await fixture.whenStable();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    el.querySelector('[data-graph-node="ct"]')!.dispatchEvent(new MouseEvent('dblclick'));
    expect(navigate).toHaveBeenCalledWith(['/assets', 'ct']);
  });

  it('error al cargar', async () => {
    const { http, fixture, el } = await setup();
    http
      .expectOne('/api/assets/web1/graph?depth=1')
      .flush({ message: 'x' }, { status: 500, statusText: 'Error' });
    await fixture.whenStable();
    expect(el.querySelector('p-message')?.textContent).toBeTruthy();
    expect(el.querySelector('app-graph-canvas')).toBeNull();
  });
});
