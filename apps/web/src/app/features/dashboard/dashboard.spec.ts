import { provideHttpClient } from '@angular/common/http';
import type { Type } from '@angular/core';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import {
  DeferBlockBehavior,
  DeferBlockState,
  type ComponentFixture,
} from '@angular/core/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  DEFAULT_DASHBOARD,
  type AttentionData,
  type DashboardDocument,
  type DashboardWidget,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { DashboardBoard } from './dashboard-board';
import { Dashboard } from './dashboard';

const PROJECT = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

const defaultDoc: DashboardDocument = {
  layout: DEFAULT_DASHBOARD,
  isDefault: true,
  version: 0,
  updatedAt: null,
  updatedBy: null,
};

/** Datos de ejemplo de cada widget del panel por defecto. */
const DATA: Record<string, unknown> = {
  'vulnerability-counts': {
    urgent: 17,
    high: 98,
    medium: 12,
    kev: 2,
    cves: 127,
  },
  'pending-enrollment': { count: 1, assets: [] },
  'running-jobs': { count: 0 },
  'top-vulnerabilities': {
    total: 127,
    items: [
      {
        vulnerabilityId: 'CVE-2024-6387',
        severity: 'HIGH',
        priority: {
          score: 81,
          band: 'urgent',
          reasons: [
            { code: 'kev', ransomware: false },
            { code: 'port', ports: [22], process: 'sshd' },
          ],
        },
        kev: true,
        assets: 3,
      },
    ],
  },
  'asset-counts': {
    groupBy: 'type',
    counts: { server: 3, lxc: 2, container: 7, volume: 2 },
    total: 14,
  },
  attention: {
    items: [
      {
        kind: 'sudoersOutdated',
        count: 1,
        assets: [
          { id: 'old', name: 'viejo', type: 'server', status: 'active' },
        ],
      },
      { kind: 'domainsExpiring', count: 2, assets: [] },
    ],
    expiryWarningDays: [45, 7],
  } satisfies AttentionData,
  'recent-activity': { items: [], running: 0 },
};

async function setup<T>(component: Type<T>, narrow = false) {
  // Sin matchMedia (jsdom) el tablero se cree ancho; en estrecho, sin gridstack.
  globalThis.matchMedia = ((query: string) => ({
    matches: !narrow,
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  })) as unknown as typeof matchMedia;
  TestBed.configureTestingModule({
    imports: [component],
    providers: [
      provideRouter([]),
      provideHttpClient(),
      provideHttpClientTesting(),
      ConfirmationService,
      MessageService,
    ],
    deferBlockBehavior: DeferBlockBehavior.Manual,
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(component);
  fixture.detectChanges();
  return { http, fixture, el: fixture.nativeElement as HTMLElement };
}

/** Pinta los widgets (los `@defer` por viewport) y responde a la petición de cada uno. */
async function renderWidgets(
  fixture: ComponentFixture<unknown>,
  http: HttpTestingController,
  data: Record<string, unknown> = DATA,
) {
  for (const block of await fixture.getDeferBlocks())
    await block.render(DeferBlockState.Complete);
  fixture.detectChanges();
  const requests = http.match((r) =>
    r.url.startsWith('/api/dashboard/widgets/'),
  );
  for (const r of requests)
    r.flush(data[r.request.url.split('/').at(-1)!] ?? {});
  fixture.detectChanges();
  await fixture.whenStable();
  return requests;
}

const realMatchMedia = globalThis.matchMedia;

describe('Dashboard', () => {
  beforeEach(() => storeSession('viewer'));
  afterEach(() => {
    sessionStorage.clear();
    globalThis.matchMedia = realMatchMedia;
  });

  it('el panel por defecto: una petición por widget y cada elemento enlaza a su sección filtrada', async () => {
    const { http, fixture, el } = await setup(Dashboard);
    http.expectOne('/api/dashboards/me').flush(defaultDoc);
    fixture.detectChanges();
    const requests = await renderWidgets(fixture, http);
    // Uno por widget, cada uno a su endpoint: nada de un resumen con todo.
    expect(requests.map((r) => r.request.url.split('/').at(-1)).sort()).toEqual(
      DEFAULT_DASHBOARD.widgets.map((w) => w.type).sort(),
    );
    const href = (selector: string) =>
      el.querySelector(selector)?.getAttribute('href');
    const vulns = el.querySelector('[data-widget="vulnerability-counts"]')!;
    expect(vulns.textContent).toContain('115');
    expect(vulns.textContent).toContain('2 en KEV');
    expect(vulns.querySelector('a')?.getAttribute('href')).toBe(
      '/vulnerabilities',
    );
    const top = el.querySelector('[data-top-cve="CVE-2024-6387"]')!;
    expect(top.querySelector('[data-priority]')?.textContent?.trim()).toBe(
      '81',
    );
    expect(top.textContent).toContain('expuesto en 22 (sshd)');
    expect(href('[data-widget="pending-enrollment"] a')).toBe(
      '/inventory?status=pending_enrollment',
    );
    expect(href('[data-widget="running-jobs"] a')).toBe(
      '/activity?state=running',
    );
    expect(href('[data-count="container"]')).toBe('/inventory?type=container');
    // Volúmenes no salen en el árbol: se cuentan, sin enlace a un filtro vacío.
    expect(el.querySelector('[data-count="volume"]')?.tagName).toBe('SPAN');
    expect(href('[data-warning="sudoersOutdated"] a')).toBe(
      '/inventory?attention=sudoers',
    );
    expect(
      el.querySelector('[data-warning="sudoersOutdated"]')?.textContent,
    ).toContain('viejo');
    expect(
      el.querySelector('[data-warning="domainsExpiring"]')?.textContent,
    ).toContain('menos de 45 días');
    expect(el.querySelector('[data-dashboard-state]')?.textContent).toContain(
      'Panel por defecto',
    );
    http.match('/api/projects').forEach((r) => r.flush([]));
    // Sin jobs en curso no hay sondeo.
    http.verify();
  });

  it('con ?project= y en el panel de un proyecto, todos los widgets piden ese proyecto', async () => {
    const { http, fixture } = await setup(DashboardBoard);
    fixture.componentRef.setInput('project', PROJECT);
    fixture.detectChanges();
    http.expectOne(`/api/projects/${PROJECT}/dashboard`).flush(defaultDoc);
    fixture.detectChanges();
    const requests = await renderWidgets(fixture, http);
    expect(requests.length).toBe(DEFAULT_DASHBOARD.widgets.length);
    for (const r of requests)
      expect(r.request.params.get('projectId')).toBe(PROJECT);
    http.match('/api/projects').forEach((r) => r.flush([]));
  });

  it('personalizar sin arrastrar (pantalla estrecha): mover, ensanchar y guardar con la versión', async () => {
    storeSession('admin');
    const { http, fixture, el } = await setup(DashboardBoard, true);
    fixture.componentRef.setInput('canEdit', true);
    fixture.detectChanges();
    const saved: DashboardDocument = {
      ...defaultDoc,
      isDefault: false,
      version: 3,
    };
    http.expectOne('/api/dashboards/me').flush(saved);
    fixture.detectChanges();
    (
      el.querySelector('[data-action="customize"] button') as HTMLButtonElement
    ).click();
    fixture.detectChanges();
    const board = fixture.componentInstance as unknown as {
      onAction(w: DashboardWidget, a: string): void;
      draft(): DashboardWidget[];
    };
    const top = board.draft().find((w) => w.id === 'top')!;
    board.onAction(top, 'before');
    board.onAction(
      board.draft().find((w) => w.id === 'top')!,
      'wider',
    );
    board.onAction(
      board.draft().find((w) => w.id === 'running')!,
      'remove',
    );
    fixture.detectChanges();
    (
      el.querySelector(
        '[data-action="save-dashboard"] button',
      ) as HTMLButtonElement
    ).click();
    const put = http.expectOne(
      (r) => r.method === 'PUT' && r.url === '/api/dashboards/me',
    );
    const body = put.request.body as {
      version: number;
      layout: { widgets: DashboardWidget[] };
    };
    expect(body.version).toBe(3);
    const ids = body.layout.widgets.map((w) => w.id);
    expect(ids).not.toContain('running');
    // «Lo más prioritario» sube un puesto (antes de «Tareas en curso», ya quitado) y es una columna más ancho.
    expect(ids).toEqual([
      'vulns',
      'pending',
      'top',
      'types',
      'attention',
      'activity',
    ]);
    expect(body.layout.widgets.find((w) => w.id === 'top')!.w).toBe(5);
    put.flush({ ...saved, version: 4, layout: body.layout });
    fixture.detectChanges();
    expect(el.querySelector('[data-action="save-dashboard"]')).toBeNull();
    http.match(() => true).forEach((r) => r.flush({}));
  });

  it('si alguien guardó antes (409), lo dice y ofrece recargar', async () => {
    storeSession('admin');
    const { http, fixture, el } = await setup(DashboardBoard, true);
    fixture.componentRef.setInput('canEdit', true);
    fixture.detectChanges();
    http.expectOne('/api/dashboards/me').flush(defaultDoc);
    fixture.detectChanges();
    (
      el.querySelector('[data-action="customize"] button') as HTMLButtonElement
    ).click();
    fixture.detectChanges();
    (
      el.querySelector(
        '[data-action="save-dashboard"] button',
      ) as HTMLButtonElement
    ).click();
    http
      .expectOne((r) => r.method === 'PUT')
      .flush(
        { message: 'El panel ha cambiado desde que lo abriste.' },
        { status: 409, statusText: 'Conflict' },
      );
    fixture.detectChanges();
    expect(el.textContent).toContain(
      'El panel ha cambiado desde que lo abriste.',
    );
    expect(el.textContent).toContain('Recargar el panel');
    http.match(() => true).forEach((r) => r.flush({}));
  });

  it('resumen de assets y vulnerabilidades con parche, como la tarjeta del proyecto', async () => {
    const { http, fixture, el } = await setup(DashboardBoard);
    fixture.componentRef.setInput('project', PROJECT);
    fixture.detectChanges();
    http.expectOne(`/api/projects/${PROJECT}/dashboard`).flush({
      ...defaultDoc,
      layout: {
        schema: 1,
        widgets: [
          {
            id: 'a',
            type: 'asset-summary',
            x: 0,
            y: 0,
            w: 4,
            h: 3,
            filters: { projectId: PROJECT },
            options: {},
          },
          {
            id: 'f',
            type: 'fixable-vulnerabilities',
            x: 4,
            y: 0,
            w: 4,
            h: 3,
            filters: { projectId: PROJECT },
            options: {},
          },
        ],
      },
    });
    fixture.detectChanges();
    await renderWidgets(fixture, http, {
      'asset-summary': {
        groupBy: 'type',
        counts: { server: 1, lxc: 2 },
        total: 3,
      },
      'fixable-vulnerabilities': {
        openFindings: { CRITICAL: 4, HIGH: 9, MEDIUM: 3, LOW: 0, UNKNOWN: 0 },
        fixableFindings: { CRITICAL: 2, HIGH: 5 },
        openVulnerabilities: 11,
      },
    });
    const assets = el.querySelector('[data-widget="asset-summary"]')!;
    expect(assets.querySelector('.dw-value')?.textContent?.trim()).toBe('3');
    expect(assets.querySelector('[data-type="lxc"]')?.textContent).toContain(
      '2',
    );
    expect(assets.querySelector('a')?.getAttribute('href')).toBe(
      `/inventory?project=${PROJECT}`,
    );
    const fixable = el.querySelector(
      '[data-widget="fixable-vulnerabilities"]',
    )!;
    expect(fixable.querySelector('.dw-value')?.textContent?.trim()).toBe('7');
    expect(fixable.textContent).toContain('2 C · 5 H');
    expect(fixable.textContent).toContain('11 CVE abiertos');
    expect(fixable.querySelector('[data-severity="CRITICAL"]')).not.toBeNull();
    http.match('/api/projects').forEach((r) => r.flush([]));
  });

  it('un lector ve el panel del proyecto sin «Personalizar»', async () => {
    const { http, fixture, el } = await setup(DashboardBoard);
    fixture.componentRef.setInput('project', PROJECT);
    fixture.detectChanges();
    http.expectOne(`/api/projects/${PROJECT}/dashboard`).flush(defaultDoc);
    fixture.detectChanges();
    expect(el.querySelector('[data-action="customize"]')).toBeNull();
    expect(el.querySelector('[data-dashboard-state]')?.textContent).toContain(
      'Plantilla del proyecto',
    );
  });
});
