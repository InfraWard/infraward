import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { JobRunLog, JobRunSummary, Page } from '@infraward/shared-types';
import { storeSession } from '../../testing/session';
import { logOffset, visibleEntries } from '../../shared/job-log';
import { AssetRuns } from './asset-runs';

const ID = '00000000-0000-4000-8000-000000000001';
const RUN_OK = '00000000-0000-4000-8000-0000000000a1';
const RUN_KO = '00000000-0000-4000-8000-0000000000a2';

function run(id: string, state: JobRunSummary['state'], extra: Partial<JobRunSummary> = {}): JobRunSummary {
  return {
    id,
    name: 'asset.collect',
    queue: 'collect',
    assetId: ID,
    assetName: 'srv',
    assetType: 'server',
    state,
    progress: 100,
    message: null,
    error: state === 'failed' ? 'No se pudo leer la host key de 10.0.0.5:22' : null,
    parentJobId: null,
    parent: null,
    origin: 'manual',
    worker: 'worker-1',
    createdAt: '2026-10-31T10:00:00.000Z',
    startedAt: '2026-10-31T10:00:01.000Z',
    finishedAt: '2026-10-31T10:00:13.000Z',
    durationMs: 12_000,
    hasLog: true,
    ...extra,
  };
}

function setup(role: Parameters<typeof storeSession>[0] = 'operator') {
  storeSession(role);
  TestBed.configureTestingModule({
    imports: [AssetRuns],
    providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(AssetRuns);
  fixture.componentRef.setInput('assetId', ID);
  fixture.detectChanges();
  return { http, fixture, el: fixture.nativeElement as HTMLElement };
}

describe('AssetRuns', () => {
  it('sin assets.operate ve la lista, pero no el log (ni lo pide)', () => {
    const { http, fixture, el } = setup('viewer');
    http
      .expectOne((r) => r.url === `/api/assets/${ID}/runs`)
      .flush({ items: [run(RUN_KO, 'failed')], total: 1 } satisfies Page<JobRunSummary>);
    fixture.detectChanges();
    el.querySelector<HTMLElement>(`tr[data-run="${RUN_KO}"]`)!.click();
    fixture.detectChanges();
    expect(el.querySelector('[data-log-forbidden]')?.textContent).toContain('requiere permiso');
    http.expectNone((r) => r.url.endsWith('/log'));
    http.verify();
  });

  it('lista las ejecuciones con estado y duración, y resalta las fallidas', () => {
    const { http, fixture, el } = setup();
    const page: Page<JobRunSummary> = { items: [run(RUN_KO, 'failed'), run(RUN_OK, 'completed')], total: 2 };
    http.expectOne((r) => r.url === `/api/assets/${ID}/runs`).flush(page);
    fixture.detectChanges();
    const rows = el.querySelectorAll('tr[data-run]');
    expect(rows).toHaveLength(2);
    expect(rows[0]!.classList).toContain('failed');
    expect(rows[1]!.classList).not.toContain('failed');
    expect(rows[0]!.textContent).toContain('Recolección');
    expect(rows[0]!.textContent).toContain('Fallido');
    expect(rows[0]!.textContent).toContain('12 s');
    http.verify();
  });

  it('al elegir una, muestra su log por niveles (y el detalle solo si se pide)', () => {
    const { http, fixture, el } = setup();
    http
      .expectOne((r) => r.url === `/api/assets/${ID}/runs`)
      .flush({ items: [run(RUN_KO, 'failed')], total: 1 });
    fixture.detectChanges();
    (el.querySelector(`tr[data-run="${RUN_KO}"]`) as HTMLElement).click();
    fixture.detectChanges();
    const log: JobRunLog = {
      run: run(RUN_KO, 'failed'),
      attempts: [
        {
          attempt: 1,
          worker: 'worker-1',
          startedAt: '2026-10-31T10:00:01.000Z',
          updatedAt: '2026-10-31T10:00:13.000Z',
          truncated: true,
          dropped: 7,
          bytes: 2048,
          entries: [
            { at: '2026-10-31T10:00:01.000Z', level: 'info', kind: 'step', message: 'asset.collect en worker-1 (intento 1)' },
            { at: '2026-10-31T10:00:02.500Z', level: 'warn', kind: 'command', message: 'ssh-keyscan 10.0.0.5:22', durationMs: 3000, exitCode: 1 },
            { at: '2026-10-31T10:00:03.000Z', level: 'debug', kind: 'output', message: 'Tarea: Facts' },
            { at: '2026-10-31T10:00:13.000Z', level: 'error', kind: 'result', message: 'Fallido: No se pudo leer la host key' },
          ],
        },
      ],
    };
    http.expectOne(`/api/assets/${ID}/runs/${RUN_KO}/log`).flush(log);
    fixture.detectChanges();
    const pre = el.querySelector('[data-log]')!;
    expect(pre.querySelectorAll('.line')).toHaveLength(3);
    expect(pre.querySelector('.level-error')?.textContent).toContain('ERROR');
    expect(pre.querySelector('.kind-command')?.textContent).toContain('$ ssh-keyscan 10.0.0.5:22');
    expect(pre.querySelector('.kind-command')?.textContent).toContain('(3 s, código 1)');
    expect(pre.textContent).toContain('+0:01.5');
    expect(el.querySelector('[data-log-error]')?.textContent).toContain('host key');
    expect(el.textContent).toContain('se omitieron 7 líneas');
    expect(el.querySelector('[data-open-activity]')!.getAttribute('href')).toBe(`/activity/${RUN_KO}`);
    http.verify();
  });

  it('sin log: lo explica', () => {
    const { http, fixture, el } = setup();
    http
      .expectOne((r) => r.url === `/api/assets/${ID}/runs`)
      .flush({ items: [run(RUN_OK, 'completed', { hasLog: false })], total: 1 });
    fixture.detectChanges();
    (el.querySelector(`tr[data-run="${RUN_OK}"]`) as HTMLElement).click();
    fixture.detectChanges();
    http
      .expectOne(`/api/assets/${ID}/runs/${RUN_OK}/log`)
      .flush({ run: run(RUN_OK, 'completed', { hasLog: false }), attempts: [] } satisfies JobRunLog);
    fixture.detectChanges();
    expect(el.querySelector('[data-log-empty]')?.textContent).toContain('no tiene log');
  });
});

describe('logOffset / visibleEntries', () => {
  it('desplazamiento desde el inicio del intento', () => {
    expect(logOffset('2026-10-31T10:01:05.250Z', '2026-10-31T10:00:00.000Z')).toBe('+1:05.3');
    expect(logOffset('2026-10-31T10:00:00.000Z', '2026-10-31T10:00:01.000Z')).toBe('+0:00.0');
  });

  it('oculta el detalle salvo que se pida', () => {
    const attempt = {
      attempt: 1,
      worker: null,
      startedAt: '',
      updatedAt: '',
      truncated: false,
      dropped: 0,
      bytes: 0,
      entries: [
        { at: '', level: 'debug' as const, kind: 'output' as const, message: 'd' },
        { at: '', level: 'info' as const, kind: 'step' as const, message: 'i' },
      ],
    };
    expect(visibleEntries(attempt, false).map((e) => e.message)).toEqual(['i']);
    expect(visibleEntries(attempt, true)).toHaveLength(2);
  });
});
