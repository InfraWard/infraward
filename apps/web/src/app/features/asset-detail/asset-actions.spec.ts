import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { Asset, JobRunSummary, Page } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { ACTIONS_POLL_MS, AssetActions, scanMessage } from './asset-actions';

const server: Asset = {
  id: 'pve',
  type: 'server',
  name: 'pve-pruebas',
  discoveredName: 'pve-pruebas',
  displayName: null,
  projects: [],
  status: 'active',
  naturalKey: 'machine-id:abc',
  roles: ['proxmox-node'],
  tags: [],
  facts: {},
  connection: { host: '172.20.10.190', port: 22, user: 'infraward' },
  credentials: {},
  sshAuth: 'static_key',
  hostKeyFingerprint: null,
  adminAccess: null,
  duplicateOfId: null,
  effectivePolicy: {
    values: { reconcileIntervalMinutes: 360, scanEnabled: true, scanPeriodic: true },
    sources: {
      reconcileIntervalMinutes: { kind: 'global' },
      scanEnabled: { kind: 'global' },
      scanPeriodic: { kind: 'global' },
    },
  },
  missingRuns: 0,
  missingSince: null,
  retiredAuto: false,
  createdAt: '2026-10-10T00:00:00.000Z',
  updatedAt: '2026-10-10T00:00:00.000Z',
};

const run = (extra: Partial<JobRunSummary> = {}): JobRunSummary => ({
  id: 'j1',
  name: 'asset.collect',
  queue: 'discovery',
  assetId: 'pve',
  assetName: 'pve-pruebas',
  assetType: 'server',
  state: 'active',
  progress: 40,
  message: 'Recogiendo facts',
  error: null,
  parentJobId: null,
  worker: 'worker-1',
  createdAt: '2026-10-10T00:00:00.000Z',
  startedAt: '2026-10-10T00:00:01.000Z',
  finishedAt: null,
  durationMs: 1000,
  ...extra,
});

const page = (items: JobRunSummary[]): Page<JobRunSummary> => ({ items, total: items.length });

async function setup() {
  TestBed.configureTestingModule({
    imports: [AssetActions],
    providers: [
      provideRouter([{ path: 'inventory', children: [] }]),
      provideHttpClient(),
      provideHttpClientTesting(),
      ConfirmationService,
      MessageService,
    ],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(AssetActions);
  fixture.componentRef.setInput('asset', server);
  const changed = vi.fn();
  fixture.componentInstance.changed.subscribe(changed);
  fixture.detectChanges();
  await fixture.whenStable();
  const el = fixture.nativeElement as HTMLElement;
  const button = (id: string) =>
    el.querySelector<HTMLButtonElement>(`[data-action="${id}"] button`)!;
  const runningRequest = () =>
    http.expectOne(
      (r) =>
        r.url === '/api/jobs' &&
        r.params.get('assetId') === 'pve' &&
        r.params.get('state') === 'running',
    );
  return { http, fixture, el, button, runningRequest, changed };
}

describe('AssetActions', () => {
  beforeEach(() => storeSession('admin'));
  afterEach(() => {
    sessionStorage.clear();
    vi.useRealTimers();
  });

  it('con un job en curso deshabilita las acciones, muestra su progreso y recarga al terminar', async () => {
    vi.useFakeTimers();
    const { fixture, el, button, runningRequest, changed } = await setup();
    runningRequest().flush(page([run()]));
    fixture.detectChanges();

    expect(button('collect').disabled).toBe(true);
    expect(button('retire').disabled).toBe(true);
    expect(el.querySelector('[data-running-job]')?.textContent).toContain(
      'Recolección en curso · 40 % · Recogiendo facts',
    );

    await vi.advanceTimersByTimeAsync(ACTIONS_POLL_MS);
    runningRequest().flush(page([]));
    fixture.detectChanges();
    expect(button('collect').disabled).toBe(false);
    expect(el.querySelector('[data-running-job]')).toBeNull();
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['operator', ['collect', 'scan'], false],
    ['editor', ['collect', 'scan', 'retire'], false],
    ['admin', ['collect', 'scan', 'retire', 'purge'], true],
  ] as const)('%s solo ve las acciones de su rol', async (role, visible, purge) => {
    storeSession(role);
    const { fixture, el, http, runningRequest } = await setup();
    runningRequest().flush(page([]));
    // El operador no pide el estado de los proveedores (no tiene secrets.status).
    if (role === 'operator') http.expectNone('/api/secrets/providers');
    fixture.detectChanges();
    for (const id of visible) expect(el.querySelector(`[data-action="${id}"]`)).not.toBeNull();
    expect(!!el.querySelector('[data-action="purge"]')).toBe(purge);
    if (role === 'operator') expect(el.querySelector('[data-action="retire"]')).toBeNull();
  });

  it('recolectar encola el job y vuelve a mirar los jobs del asset', async () => {
    const { http, fixture, button, runningRequest } = await setup();
    runningRequest().flush(page([]));
    fixture.detectChanges();

    button('collect').click();
    http
      .expectOne({ method: 'POST', url: '/api/assets/pve/collect' })
      .flush({ id: 'j2', name: 'asset.collect', queue: 'discovery' });
    await fixture.whenStable();
    runningRequest().flush(page([run({ id: 'j2', state: 'queued', progress: 0 })]));
    fixture.detectChanges();
    expect(button('collect').disabled).toBe(true);
  });

  it('dar de baja y purgar van al final, separadas de las demás', async () => {
    const { fixture, el, runningRequest } = await setup();
    runningRequest().flush(page([]));
    fixture.detectChanges();
    const children = [...el.querySelector('[data-actions]')!.children];
    const ids = children.map((c) => c.querySelector('[data-action]')?.getAttribute('data-action') ?? c.className);
    expect(ids.slice(-3)).toEqual(['spacer', 'retire', 'purge']);
  });

  it('dar de baja pide confirmación antes de llamar a la API', async () => {
    const { http, fixture, button, runningRequest } = await setup();
    runningRequest().flush(page([]));
    fixture.detectChanges();
    const confirm = vi.spyOn(TestBed.inject(ConfirmationService), 'confirm');

    button('retire').click();
    expect(confirm).toHaveBeenCalledTimes(1);
    http.expectNone((r) => r.method === 'DELETE');

    confirm.mock.calls[0]![0].accept!();
    http
      .expectOne({ method: 'DELETE', url: '/api/assets/pve' })
      .flush({ mode: 'retired', affectedIds: ['pve'], revocations: [] });
    await fixture.whenStable();
  });

  it('purgar exige escribir el nombre del asset', async () => {
    const { http, fixture, el, button, runningRequest } = await setup();
    runningRequest().flush(page([]));
    fixture.detectChanges();

    button('purge').click();
    fixture.detectChanges();
    await fixture.whenStable();
    const dialog = document.querySelector('[data-dialog="purge"]') ?? el;
    const confirmButton = () =>
      document.querySelector<HTMLButtonElement>('[data-action="confirm-purge"] button')!;
    expect(dialog).not.toBeNull();
    expect(confirmButton().disabled).toBe(true);

    const input = document.querySelector<HTMLInputElement>('#purgeName')!;
    input.value = 'pve';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(confirmButton().disabled).toBe(true);
    http.expectNone((r) => r.method === 'DELETE');

    input.value = 'pve-pruebas';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(confirmButton().disabled).toBe(false);
    confirmButton().click();
    http
      .expectOne((r) => r.method === 'DELETE' && r.params.get('purge') === 'true')
      .flush({ mode: 'purged', affectedIds: ['pve'], revocations: [] });
    await fixture.whenStable();
  });
});

describe('scanMessage', () => {
  it('dice qué se analiza: el SBOM del sistema, las imágenes o los dos', () => {
    const host = { name: 'host.scan' };
    const image = { name: 'image.scan' };
    expect(scanMessage([host])).toBe('Se analizará con Trivy el SBOM del sistema.');
    expect(scanMessage([image])).toBe('Se analizará con Trivy 1 imagen.');
    expect(scanMessage([image, image])).toBe('Se analizarán con Trivy 2 imágenes.');
    expect(scanMessage([host, image])).toBe(
      'Se analizarán con Trivy el SBOM del sistema y 1 imagen.',
    );
    expect(scanMessage([])).toBe('Nada que analizar.');
  });
});
