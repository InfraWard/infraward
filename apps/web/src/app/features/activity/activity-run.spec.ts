import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { JobRunLog, JobRunSummary, Page } from '@infraward/shared-types';
import { storeSession } from '../../testing/session';
import { ActivityRun, RUN_POLL_MS } from './activity-run';

const ID = '00000000-0000-4000-8000-0000000000d1';
const PARENT = '00000000-0000-4000-8000-0000000000c1';
const CHILD = '00000000-0000-4000-8000-0000000000e1';

function run(extra: Partial<JobRunSummary> = {}): JobRunSummary {
  return {
    id: ID,
    name: 'asset.discover',
    queue: 'discovery',
    assetId: 'pve',
    assetName: 'pve-pruebas',
    assetType: 'server',
    state: 'completed',
    progress: 100,
    message: '3 hijos, 1 nuevo',
    error: null,
    parentJobId: PARENT,
    parent: {
      id: PARENT,
      name: 'asset.collect',
      assetId: 'pve',
      assetName: 'pve-pruebas',
      assetType: 'server',
      state: 'completed',
      message: null,
    },
    origin: 'chain',
    worker: 'worker-1',
    createdAt: '2026-10-31T10:00:00.000Z',
    startedAt: '2026-10-31T10:00:01.000Z',
    finishedAt: '2026-10-31T10:00:13.000Z',
    durationMs: 12_000,
    hasLog: true,
    ...extra,
  };
}

const log = (r: JobRunSummary): JobRunLog => ({
  run: r,
  attempts: [
    {
      attempt: 1,
      worker: 'worker-1',
      startedAt: '2026-10-31T10:00:01.000Z',
      updatedAt: '2026-10-31T10:00:13.000Z',
      truncated: false,
      dropped: 0,
      bytes: 100,
      entries: [
        { at: '2026-10-31T10:00:01.000Z', level: 'info', kind: 'step', message: 'Listando los CT' },
        { at: '2026-10-31T10:00:13.000Z', level: 'info', kind: 'result', message: 'Terminado: 3 hijos' },
      ],
    },
  ],
});

function setup(role: Parameters<typeof storeSession>[0] = 'operator') {
  storeSession(role);
  TestBed.configureTestingModule({
    imports: [ActivityRun],
    providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(ActivityRun);
  fixture.componentRef.setInput('id', ID);
  fixture.detectChanges();
  return { http, fixture, el: fixture.nativeElement as HTMLElement };
}

describe('ActivityRun', () => {
  afterEach(() => {
    sessionStorage.clear();
    vi.useRealTimers();
  });

  it('enseña la tarea que la encoló, las que lanzó y su log', async () => {
    const { http, fixture, el } = setup();
    http.expectOne(`/api/jobs/runs/${ID}`).flush(run({ children: { total: 1, running: 0, failed: 1 } }));
    const children = http.expectOne((r) => r.url === '/api/jobs');
    expect(children.request.params.get('parentJobId')).toBe(ID);
    children.flush({
      items: [
        run({
          id: CHILD,
          name: 'asset.collect',
          assetName: 'ct-101',
          state: 'failed',
          error: 'Sin conexión SSH',
          parentJobId: ID,
          parent: null,
        }),
      ],
      total: 1,
    } satisfies Page<JobRunSummary>);
    fixture.detectChanges();
    http.expectOne(`/api/jobs/runs/${ID}/log`).flush(log(run()));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(el.querySelector('h1')!.textContent).toContain('Descubrimiento');
    expect(el.querySelector('[data-run-asset]')!.getAttribute('href')).toBe('/assets/pve');
    const origin = el.querySelector('[data-fact="origin"]')!;
    expect(origin.textContent).toContain('Encadenada');
    expect(el.querySelector('[data-run-parent]')!.textContent).toContain('Recolección de pve-pruebas');
    expect(el.querySelector('[data-run-parent]')!.getAttribute('href')).toBe(`/activity/${PARENT}`);
    expect(el.querySelector('[data-fact="message"]')!.textContent).toContain('3 hijos, 1 nuevo');

    const child = el.querySelector(`[data-child="${CHILD}"]`)!;
    expect(child.textContent).toContain('ct-101');
    expect(child.textContent).toContain('Sin conexión SSH');
    expect(child.querySelector('a')!.getAttribute('href')).toBe(`/activity/${CHILD}`);
    expect(el.querySelector('[data-run-children]')!.textContent).toContain('1 fallida');
    expect(el.querySelector('[data-run-children-all]')!.getAttribute('href')).toBe(
      `/activity?parentJobId=${ID}`,
    );

    expect(el.querySelector('[data-log]')!.textContent).toContain('Terminado: 3 hijos');
    // Sin enlace de la Actividad en el historial: «←» lleva a la Actividad.
    expect(el.querySelector('[data-back]')!.textContent).toContain('Actividad');
    expect(el.querySelector('[data-back]')!.getAttribute('href')).toBe('/activity');
    http.verify();
  });

  it('se refresca mientras está en curso y para al terminar', async () => {
    vi.useFakeTimers();
    const { http, fixture, el } = setup();
    http.expectOne(`/api/jobs/runs/${ID}`).flush(run({ state: 'active', progress: 40, message: 'Listando los CT', finishedAt: null }));
    fixture.detectChanges();
    http.expectOne(`/api/jobs/runs/${ID}/log`).flush(log(run({ state: 'active' })));
    fixture.detectChanges();
    expect(el.querySelector('[data-run-progress]')!.textContent).toContain('40 % · Listando los CT');

    await vi.advanceTimersByTimeAsync(RUN_POLL_MS);
    http.expectOne(`/api/jobs/runs/${ID}`).flush(run());
    http.expectOne(`/api/jobs/runs/${ID}/log`).flush(log(run()));
    fixture.detectChanges();
    expect(el.querySelector('[data-run-state]')!.textContent).toContain('Terminado');

    await vi.advanceTimersByTimeAsync(RUN_POLL_MS * 3);
    http.verify();
  });

  it('si falló, el error sale una sola vez (ni en el log ni como último mensaje)', () => {
    const { http, fixture, el } = setup();
    const failed = run({
      state: 'failed',
      error: 'No se pudo leer la host key de 10.0.0.5:22',
      message: 'Fallo: No se pudo leer la host key de 10.0.0.5:22',
    });
    http.expectOne(`/api/jobs/runs/${ID}`).flush(failed);
    fixture.detectChanges();
    http.expectOne(`/api/jobs/runs/${ID}/log`).flush(log(failed));
    fixture.detectChanges();
    expect(el.querySelector('[data-run-failure]')!.textContent).toContain('host key');
    expect(el.querySelector('[data-log-error]')).toBeNull();
    expect(el.querySelector('[data-log-state]')).toBeNull();
    expect(el.querySelector('[data-fact="message"]')).toBeNull();
    expect(el.querySelector('[data-log-debug]')).not.toBeNull();
    http.verify();
  });

  it('sin assets.operate ve el detalle, pero no el log (ni lo pide)', () => {
    const { http, fixture, el } = setup('viewer');
    http.expectOne(`/api/jobs/runs/${ID}`).flush(run());
    fixture.detectChanges();
    expect(el.querySelector('[data-log-forbidden]')!.textContent).toContain('requiere permiso');
    http.expectNone((r) => r.url.endsWith('/log'));
    http.verify();
  });

  it('una operación en lote: su resumen y sus tareas, sin pedir log', () => {
    const { http, fixture, el } = setup();
    http.expectOne(`/api/jobs/runs/${ID}`).flush(
      run({
        name: 'assets.bulk',
        queue: 'system',
        assetId: null,
        assetType: null,
        assetName: 'web, cache',
        message: 'Escanear · 2 assets · 2 tareas · por ana@example.com',
        parentJobId: null,
        parent: null,
        origin: null,
        children: { total: 2, running: 0, failed: 0 },
      }),
    );
    http.expectOne((r) => r.url === '/api/jobs').flush({ items: [], total: 2 });
    fixture.detectChanges();
    expect(el.querySelector('[data-fact="message"]')!.textContent).toContain('por ana@example.com');
    expect(el.querySelector('[data-log-bulk]')).not.toBeNull();
    http.expectNone((r) => r.url.endsWith('/log'));
    http.verify();
  });

  it('del lote que la lanzó enseña el resumen completo', () => {
    const { http, fixture, el } = setup('viewer');
    http.expectOne(`/api/jobs/runs/${ID}`).flush(
      run({
        origin: 'bulk',
        parent: {
          id: PARENT,
          name: 'assets.bulk',
          assetId: null,
          assetName: 'pve, web',
          assetType: null,
          state: 'completed',
          message: 'Recolectar · 2 assets · por ana@example.com',
        },
      }),
    );
    fixture.detectChanges();
    expect(el.querySelector('[data-fact="origin"]')!.textContent).toContain('En lote');
    expect(el.querySelector('[data-run-parent]')!.textContent).toContain('Recolectar · 2 assets');
    expect(el.querySelector('[data-run-parent-summary]')!.textContent).toContain('por ana@example.com');
  });

  it('si ya no existe, lo dice', () => {
    const { http, fixture, el } = setup();
    http
      .expectOne(`/api/jobs/runs/${ID}`)
      .flush({ message: 'Ejecución no encontrada' }, { status: 404, statusText: 'Not Found' });
    fixture.detectChanges();
    expect(el.querySelector('[data-run-error]')!.textContent).toContain('Ejecución no encontrada');
  });
});
