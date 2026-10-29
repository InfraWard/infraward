import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { JobRunSummary } from '@infraward/shared-types';
import { storeSession } from '../../testing/session';
import { Activity, ACTIVITY_POLL_MS, activityQuery, workersSummary } from './activity';

const run = (state: JobRunSummary['state'], extra: Partial<JobRunSummary> = {}): JobRunSummary => ({
  id: `j-${state}`,
  name: 'asset.collect',
  queue: 'discovery',
  assetId: 'pve',
  assetName: 'pve-pruebas',
  assetType: 'server',
  state,
  progress: state === 'active' ? 60 : 100,
  message: state === 'active' ? 'Ejecutando el playbook' : null,
  error: state === 'failed' ? 'Sin conexión SSH' : null,
  parentJobId: null,
  worker: state === 'queued' ? null : 'worker-1',
  createdAt: '2026-10-10T10:00:00.000Z',
  startedAt: '2026-10-10T10:00:01.000Z',
  finishedAt: state === 'active' ? null : '2026-10-10T10:00:13.000Z',
  durationMs: 12_000,
  ...extra,
});

describe('activityQuery', () => {
  it('solo pasa filtros válidos', () => {
    expect(
      activityQuery({ state: 'failed', name: 'image.scan', assetId: 'x' }, { offset: 0, limit: 25 }),
    ).toEqual({ state: 'failed', name: 'image.scan', assetId: undefined, limit: 25, offset: 0 });
    expect(activityQuery({ state: 'rara', name: 'nada' }, { offset: 25, limit: 25 })).toMatchObject({
      state: undefined,
      name: undefined,
      offset: 25,
    });
  });
});

describe('activityQuery: operaciones en lote', () => {
  it('pasa el padre solo si es un UUID', () => {
    const id = '0d2b7a5e-1111-4222-8333-444455556666';
    expect(activityQuery({ parentJobId: id }, { offset: 0, limit: 25 }).parentJobId).toBe(id);
    expect(activityQuery({ parentJobId: 'x' }, { offset: 0, limit: 25 }).parentJobId).toBeUndefined();
  });
});

describe('Activity', () => {
  beforeEach(() => {
    storeSession('viewer');
    vi.useFakeTimers();
  });
  afterEach(() => {
    sessionStorage.clear();
    vi.useRealTimers();
  });

  it('se refresca mientras hay algo en curso y para cuando termina', async () => {
    TestBed.configureTestingModule({
      imports: [Activity],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(Activity);
    fixture.componentRef.setInput('state', 'running');
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    const list = () =>
      http.expectOne((r) => r.url === '/api/jobs' && r.params.get('state') === 'running');

    list().flush({ items: [run('active')], total: 1 });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-run="j-active"]')?.textContent).toContain(
      '60 % · Ejecutando el playbook',
    );

    await vi.advanceTimersByTimeAsync(ACTIVITY_POLL_MS);
    list().flush({ items: [run('failed')], total: 1 });
    fixture.detectChanges();
    expect(el.querySelector('[data-error]')?.textContent).toContain('Sin conexión SSH');
    expect(el.querySelector('[data-duration]')?.textContent?.trim()).toBe('12 s');

    // Nada pendiente: no vuelve a pedir (las réplicas sí se miran, con su propia cadencia).
    await vi.advanceTimersByTimeAsync(ACTIVITY_POLL_MS * 5);
    flushWorkers(http);
    http.verify();
  });

  it('una operación en lote enseña su mensaje y enlaza a sus tareas; el chip quita el filtro', async () => {
    TestBed.configureTestingModule({
      imports: [Activity],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(Activity);
    const op = '0d2b7a5e-1111-4222-8333-444455556666';
    fixture.componentRef.setInput('parentJobId', op);
    fixture.detectChanges();
    const req = http.expectOne((r) => r.url === '/api/jobs');
    expect(req.request.params.get('parentJobId')).toBe(op);
    req.flush({
      items: [
        run('completed', {
          id: op,
          name: 'assets.bulk',
          queue: 'system',
          assetId: null,
          assetType: null,
          assetName: 'web, cache y 1 más',
          message: 'Escanear · 3 assets · 3 tareas · por admin@example.com',
          children: { total: 3, running: 0, failed: 1 },
        }),
      ],
      total: 1,
    });
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const row = el.querySelector(`tr[data-run="${op}"]`)!;
    expect(row.textContent).toContain('Operación en lote');
    expect(row.querySelector('[data-bulk-message]')!.textContent).toContain('Escanear · 3 assets');
    const children = row.querySelector('[data-children]')!;
    expect(children.textContent).toContain('3 tareas');
    expect(children.textContent).toContain('1 fallida');
    expect(children.querySelector('a')!.getAttribute('href')).toContain(`parentJobId=${op}`);
    expect(el.querySelector('[data-filter="parent"]')).not.toBeNull();
    flushWorkers(http);
    http.verify();
  });

  it('cada ejecución dice qué réplica la ejecuta; lo que espera turno, por qué; y las réplicas conectadas', async () => {
    TestBed.configureTestingModule({
      imports: [Activity],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(Activity);
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    http.expectOne('/api/jobs/workers').flush([
      { name: 'worker-1', host: 'h1', queues: ['collect', 'discovery'], uptimeSeconds: 60, leader: true },
      { name: 'worker-2', host: 'h2', queues: ['collect'], uptimeSeconds: 30, leader: false },
    ]);
    http.expectOne((r) => r.url === '/api/jobs').flush({
      items: [
        run('active', { id: 'a', worker: 'worker-2' }),
        run('queued', {
          id: 'q',
          message: 'Esperando turno en pve-pruebas (2 jobs en curso, máximo 2)',
        }),
      ],
      total: 2,
    });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-run="a"] [data-worker]')!.textContent).toContain('worker-2');
    expect(el.querySelector('[data-run="q"] [data-worker]')!.textContent).toContain('—');
    expect(el.querySelector('[data-run="q"] [data-wait]')!.textContent).toContain(
      'Esperando turno en pve-pruebas',
    );
    expect(el.querySelector('[data-workers]')!.textContent).toContain('2 workers conectados');
  });
});

describe('workersSummary', () => {
  it('cuenta las réplicas y detalla sus colas y el líder', () => {
    expect(
      workersSummary([
        { name: 'worker-1', host: 'h1', queues: ['collect', 'scan'], uptimeSeconds: 1, leader: true },
      ]),
    ).toEqual({ label: '1 worker conectado', detail: 'worker-1 en h1 (líder): collect, scan' });
    expect(workersSummary([]).label).toBe('Ningún worker conectado');
  });
});

function flushWorkers(http: HttpTestingController): void {
  // Las que siguen abiertas (switchMap cancela la anterior al volver a mirar).
  for (const req of http.match('/api/jobs/workers')) if (!req.cancelled) req.flush([]);
}
