import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type {
  AssetTreeSummaryNode,
  BulkOperationResult,
  Severity,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { exportColumns, InventoryTree } from './inventory-tree';

const none: Record<Severity, number> = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
const leaf = (id: string, extra: Partial<AssetTreeSummaryNode> = {}): AssetTreeSummaryNode => ({
  id,
  name: id,
  type: 'container',
  status: 'active',
  discoveredName: null,
  roles: [],
  tags: [],
  projects: [],
  address: null,
  ips: [],
  runtimeState: null,
  runtimeDetail: null,
  openFindings: none,
  fixableFindings: { CRITICAL: 0, HIGH: 0 },
  sudoersOutdated: false,
  collectionWarnings: 0,
  duplicateOf: null,
  machineIdClone: false,
  expiresAt: null,
  dnsWarning: null,
  sshCaOutdated: false,
  sshdRisk: null,
  scanDisabled: false,
  children: [],
  ...extra,
});

const FOREST = [leaf('web1'), leaf('web2'), leaf('db', { tags: ['prod'] })];

describe('exportColumns', () => {
  it('cada columna visible del árbol da sus columnas de la exportación, en orden', () => {
    expect(exportColumns(['name', 'type'])).toEqual([
      'name',
      'path',
      'discoveredName',
      'roles',
      'tags',
      'projects',
      'type',
    ]);
    expect(exportColumns(['vulns', 'name'])).toEqual([
      'name',
      'path',
      'discoveredName',
      'roles',
      'tags',
      'projects',
      'maxSeverity',
      'critical',
      'high',
      'fixableCritical',
      'fixableHigh',
    ]);
  });
});

describe('InventoryTree: selección, lote y exportación', () => {
  afterEach(() => {
    try {
      localStorage.clear();
    } catch {
      // sin almacenamiento
    }
  });

  async function render(role: 'admin' | 'viewer' | 'operator' = 'admin') {
    storeSession(role);
    TestBed.configureTestingModule({
      imports: [InventoryTree],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        MessageService,
        ConfirmationService,
      ],
    });
    const fixture = TestBed.createComponent(InventoryTree);
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/tags').flush([]);
    http.expectOne('/api/projects').flush([]);
    http.expectOne('/api/assets/tree').flush(FOREST);
    await fixture.whenStable();
    http.match('/api/settings/expiry-warnings').forEach((r) => r.flush({ days: [30, 7] }));
    await fixture.whenStable();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  function check(el: HTMLElement, name: string): void {
    el.querySelector<HTMLInputElement>(`tr[data-asset="${name}"] [data-select] input`)!.click();
  }

  it('un lector no ve casillas ni barra de lote', async () => {
    const { el } = await render('viewer');
    expect(el.querySelector('[data-select]')).toBeNull();
    expect(el.querySelector('[data-select-all]')).toBeNull();
  });

  it('marcar dos assets y escanear: una llamada con sus ids, el resultado y la recarga', async () => {
    const { fixture, http, el } = await render('admin');
    check(el, 'web1');
    check(el, 'db');
    await fixture.whenStable();
    const bar = el.querySelector('[data-bulk-bar]')!;
    expect(bar.textContent).toContain('2');
    expect(bar.textContent).toContain('assets seleccionados');
    expect(el.querySelector('tr[data-asset="web1"]')!.classList).toContain('selected-row');

    (bar.querySelector('[data-bulk="scan"] button') as HTMLButtonElement).click();
    const req = http.expectOne('/api/assets/bulk/scan');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ assetIds: ['web1', 'db'] });
    const result: BulkOperationResult = {
      operationId: 'op-1',
      action: 'scan',
      applied: [{ id: 'web1', name: 'web1', type: 'container' }],
      skipped: [{ id: 'db', name: 'db', type: 'container', reason: 'Solo se escanean contenedores activos' }],
      jobs: ['j1'],
    };
    req.flush(result);
    http.expectOne('/api/assets/tree').flush(FOREST);
    await fixture.whenStable();
    const message = el.querySelector('[data-bulk-result]')!;
    expect(message.textContent).toContain('Escanear');
    expect(message.textContent).toContain('1 omitido');
    expect(message.querySelector('[data-bulk-skipped]')!.textContent).toContain(
      'db: Solo se escanean contenedores activos',
    );
    expect(message.querySelector('[data-bulk-activity]')!.getAttribute('href')).toBe(
      '/activity/op-1',
    );
    // La selección se vacía.
    expect(el.querySelector('[data-bulk-bar]')).toBeNull();
  });

  it('«Seleccionar todo lo visible» respeta el filtro de texto; cambiar el filtro vacía la selección', async () => {
    const { fixture, el } = await render('admin');
    fixture.componentInstance.applyFilter('web');
    await fixture.whenStable();
    el.querySelector<HTMLInputElement>('[data-select-all] input')!.click();
    await fixture.whenStable();
    const bar = el.querySelector('[data-bulk-bar]')!;
    expect(bar.querySelector('strong')!.textContent).toBe('2');
    fixture.componentInstance.applyFilter('db');
    await fixture.whenStable();
    expect(el.querySelector('[data-bulk-bar]')).toBeNull();
  });

  it('el operador solo ve recolectar y escanear', async () => {
    const { fixture, el } = await render('operator');
    check(el, 'web1');
    await fixture.whenStable();
    const actions = [...el.querySelectorAll('[data-bulk]')].map((b) => b.getAttribute('data-bulk'));
    expect(actions).toEqual(['collect', 'scan']);
  });

  it('dar de baja confirma con la lista y los descendientes antes de llamar a la API', async () => {
    const { fixture, http, el } = await render('admin');
    const confirm = vi.spyOn(TestBed.inject(ConfirmationService), 'confirm');
    check(el, 'web1');
    await fixture.whenStable();
    (el.querySelector('[data-bulk="retire"] button') as HTMLButtonElement).click();
    http.expectOne('/api/assets/bulk/preview').flush({
      assets: [{ id: 'web1', name: 'web1', type: 'container' }],
      retire: { total: 2, descendants: [{ id: 'v', name: 'datos', type: 'volume' }] },
    });
    expect(confirm).toHaveBeenCalledTimes(1);
    const options = confirm.mock.calls[0]![0];
    expect(options.header).toBe('¿Dar de baja 2 assets?');
    expect(options.message).toContain('web1');
    expect(options.message).toContain('datos');
    http.expectNone('/api/assets/bulk/retire');
    options.accept!();
    http.expectOne('/api/assets/bulk/retire').flush({
      operationId: 'op',
      action: 'retire',
      applied: [{ id: 'web1', name: 'web1', type: 'container' }],
      skipped: [],
      jobs: [],
      revocations: [],
    });
    http.expectOne('/api/assets/tree').flush(FOREST);
  });

  it('ocultar una columna la quita de la tabla y de la exportación', async () => {
    const { fixture, el } = await render('admin');
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    const tree = fixture.componentInstance as unknown as {
      setVisibleColumns(keys: string[]): void;
      export(format: 'csv' | 'json'): void;
    };
    tree.setVisibleColumns(['type', 'vulns']);
    await fixture.whenStable();
    const headers = [...el.querySelectorAll('thead th[data-col]')].map((th) => th.getAttribute('data-col'));
    expect(headers).toEqual(['name', 'type', 'vulns']);
    fixture.componentInstance.applyFilter('web');
    tree.export('csv');
    const anchor = click.mock.contexts[0] as HTMLAnchorElement;
    const url = new URL(anchor.href);
    expect(url.pathname).toBe('/api/assets/export');
    expect(url.searchParams.get('format')).toBe('csv');
    expect(url.searchParams.get('q')).toBe('web');
    expect(url.searchParams.get('columns')).toBe(
      'name,path,discoveredName,roles,tags,projects,type,maxSeverity,critical,high,fixableCritical,fixableHigh',
    );
    expect(anchor.hasAttribute('download')).toBe(true);
    click.mockRestore();
  });
});
