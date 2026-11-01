import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import type { Asset, AssetTreeSummaryNode } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { AssetDetail } from './asset-detail';

const none = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

const web1: Asset = {
  id: 'web1',
  type: 'container',
  name: 'web1',
  discoveredName: 'web1',
  displayName: null,
  projects: [],
  status: 'active',
  naturalKey: 'docker:abc',
  roles: [],
  tags: [],
  facts: {
    docker: { image: 'nginx:1.25', state: 'exited', ports: [] },
    infraward: { warnings: ['ss no disponible: sin puertos'], sudoersOutdated: false },
  },
  connection: null,
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

const node: AssetTreeSummaryNode = {
  id: 'web1',
  name: 'web1',
  type: 'container',
  status: 'active',
  discoveredName: null,
  roles: [],
  tags: [],
  projects: [],
  address: '8080→80/tcp',
  ips: [],
  runtimeState: 'stopped',
  runtimeDetail: 'exited',
  openFindings: { ...none, CRITICAL: 3, HIGH: 7 },
  fixableFindings: { CRITICAL: 2, HIGH: 4 },
  kernelNotRunningFindings: 12,
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
};

describe('AssetDetail', () => {
  beforeEach(() => storeSession('viewer'));
  afterEach(() => sessionStorage.clear());

  it('migas con la ruta completa, cabecera con estado de ejecución y Resumen por defecto', async () => {
    TestBed.configureTestingModule({
      imports: [AssetDetail],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        MessageService,
      ],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AssetDetail);
    fixture.componentRef.setInput('id', 'web1');
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;

    http.expectOne('/api/assets/web1').flush(web1);
    http.expectOne('/api/assets/web1/relations').flush({
      incoming: [],
      outgoing: [
        {
          id: 'r1',
          parentId: 'web1',
          childId: 'img',
          type: 'instance_of',
          createdAt: web1.createdAt,
          peer: { id: 'img', name: 'nginx:1.25', type: 'image', status: 'active' },
        },
      ],
    });
    http.expectOne('/api/assets/web1/ancestors').flush([
      { id: 'pve', name: 'pve-pruebas', type: 'server', status: 'active' },
      { id: 'ct', name: 'pruebas', type: 'lxc', status: 'active' },
    ]);
    http.expectOne('/api/assets/web1/docker').flush({ volumes: [], networks: [], images: [] });
    http.expectOne('/api/assets/web1/tree').flush(node);
    await fixture.whenStable();

    const crumbs = [...el.querySelectorAll('.crumbs li')]
      .map((li) => li.textContent?.trim())
      .filter(Boolean);
    expect(crumbs).toEqual(['Inventario', 'pve-pruebas', 'pruebas', 'web1']);

    const head = el.querySelector('[data-head]')!.textContent!;
    expect(head).toContain('Parado');
    expect(head).not.toContain('Activo');
    expect(el.querySelector('[data-address]')?.textContent).toBe('8080→80/tcp');
    expect(el.querySelector('[data-warning="collection"]')?.textContent).toContain(
      'ss no disponible',
    );

    const tabs = [...el.querySelectorAll('[role="tab"]')].map((t) => t.textContent?.trim());
    expect(tabs[0]).toBe('Resumen');
    expect(tabs.at(-1)).toBe('Datos en bruto');
    // El Resumen: vulnerabilidades con parche, contenedor y dependencias; los ids, plegados.
    expect(el.querySelector('[data-section="vulns"]')?.textContent).toContain('2 C · 4 H');
    expect(el.querySelector('[data-kernel-not-running]')?.textContent).toContain(
      'Sin contar 12 hallazgos de kernels instalados',
    );
    expect(el.querySelector('[data-section="container"]')?.textContent).toContain('nginx:1.25');
    const depends = el.querySelector('[data-section="depends"]')!.textContent!;
    expect(depends).toContain('Dentro de');
    expect(depends).toContain('pruebas');
    expect(depends).toContain('Imagen');
    expect(el.querySelector('[data-section="identifiers"]')?.textContent).toContain(
      'Identificadores',
    );
    // Política de inventario: valor efectivo y de dónde sale; se reconcilia con su raíz.
    http.expectOne('/api/assets/web1/policy').flush({
      effective: {
        values: { reconcileIntervalMinutes: 60, scanEnabled: false, scanPeriodic: true },
        sources: {
          reconcileIntervalMinutes: { kind: 'inherited', assetId: 'pve', assetName: 'pve-pruebas' },
          scanEnabled: { kind: 'inherited', assetId: 'pve', assetName: 'pve-pruebas' },
          scanPeriodic: { kind: 'tag', tag: 'lab' },
        },
      },
      rule: null,
      reconcileRoot: { id: 'pve', name: 'pve-pruebas' },
      reconciledAt: null,
      nextReconcileAt: null,
    });
    await fixture.whenStable();
    const policy = el.querySelector('[data-section="policy"]')!.textContent!;
    expect(policy).toContain('desactivado');
    expect(policy).toContain('heredada de pve-pruebas');
    expect(policy).toContain('por la etiqueta lab');
    expect(policy).toContain('Con su nodo raíz');
    // El intervalo solo se enseña en las raíces; un viewer no puede cambiarla.
    expect(el.querySelector('[data-policy="reconcileIntervalMinutes"]')).toBeNull();
    expect(el.querySelector('[data-action="edit-policy"]')).toBeNull();
    // Notas y proyectos: un viewer los ve, sin poder cambiarlos.
    http.expectOne('/api/tags').flush([]);
    http.expectOne('/api/projects').flush([]);
    http.expectOne('/api/assets/web1/projects').flush({
      projects: [
        {
          id: 'p1',
          name: 'Homelab',
          description: null,
          color: '#0d9488',
          createdAt: '',
          updatedAt: '',
          source: { kind: 'inherited', from: { id: 'pve', name: 'pve-pruebas', type: 'server', status: 'active' } },
        },
      ],
      excluded: [],
    });
    await fixture.whenStable();
    expect(el.querySelector('[data-section="notes"]')?.textContent).toContain('Sin notas');
    expect(el.querySelector('[data-action="edit-notes"]')).toBeNull();
    expect(
      el.querySelector('[data-section="projects"] [data-project="Homelab"]')?.textContent,
    ).toMatch(/Homelab\s*· heredado de pve-pruebas/);
    expect(el.querySelector('[data-action="exclude"]')).toBeNull();
    expect(el.querySelector('[data-action="rename"]')).toBeNull();
    expect(el.querySelector('[data-action="add-tag"]')).toBeNull();
    // Las demás pestañas no piden nada hasta que se abren.
    // Los umbrales de caducidad se piden una vez y se comparten.
    http.match('/api/settings/expiry-warnings').forEach((r) => r.flush({ days: [30, 7] }));
    // Un contenedor puede servir dominios (QoL-5b): sin ninguno, la tarjeta no sale.
    http.expectOne('/api/assets/web1/served-domains').flush({ records: [] });
    // Sin permiso de terminal en este asset (rol sin terminal.open ni regla): ni el botón.
    http
      .expectOne('/api/assets/web1/terminal')
      .flush({ allowed: false, available: false, reason: null, host: null, account: null });
    await fixture.whenStable();
    expect(el.querySelector('[data-section="served-domains"]')).toBeNull();
    expect(el.querySelector('[data-action="terminal"]')).toBeNull();
    http.verify();
    fixture.componentInstance.selectTab('findings');
    await fixture.whenStable();
    http.expectOne((r) => r.url === '/api/assets/web1/vulnerabilities');
    // Los umbrales de caducidad se piden una vez y se comparten.
    http.match('/api/settings/expiry-warnings').forEach((r) => r.flush({ days: [30, 7] }));
    http.verify();
  });

  async function renderServer(
    role: 'admin' | 'viewer',
    extra: Partial<Asset>,
    tab?: string,
  ) {
    sessionStorage.clear();
    storeSession(role);
    TestBed.configureTestingModule({
      imports: [AssetDetail],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        ConfirmationService,
        MessageService,
      ],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AssetDetail);
    fixture.componentRef.setInput('id', 'limpia');
    if (tab) fixture.componentRef.setInput('tab', tab);
    await fixture.whenStable();
    const server: Asset = {
      ...web1,
      id: 'limpia',
      type: 'server',
      name: 'Pruebas Limpia',
      facts: {},
      ...extra,
    };
    http.expectOne('/api/assets/limpia').flush(server);
    http.expectOne('/api/assets/limpia/relations').flush({ incoming: [], outgoing: [] });
    http.expectOne('/api/assets/limpia/ancestors').flush([]);
    http.expectOne('/api/assets/limpia/docker').flush({ volumes: [], networks: [], images: [] });
    http.expectOne('/api/assets/limpia/tree').flush({
      ...node,
      id: 'limpia',
      type: 'server',
      runtimeState: null,
      duplicateOf: extra.duplicateOfId ?? null,
    });
    // Acciones (solo admin): jobs en curso del asset.
    for (const req of http.match((r) => r.url === '/api/jobs'))
      req.flush({ items: [], total: 0 });
    await fixture.whenStable();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('puertos en el resumen: como máximo 8, expuestos primero, y «Ver los N puertos» abre la pestaña', async () => {
    const port = (n: number, address: string) => ({ port: n, proto: 'tcp', address, process: `p${n}`, pid: n });
    const ports = [
      ...[5432, 6379, 11211, 9000, 9100].map((n) => port(n, '127.0.0.1')),
      port(3306, '192.0.2.10'),
      ...[22, 80, 443, 8006, 8443].flatMap((n) => [port(n, '0.0.0.0'), port(n, '::')]),
    ];
    const { fixture, el } = await renderServer('viewer', { facts: { ports } });
    const rows = [...el.querySelectorAll('[data-section="ports"] tbody tr')].map((r) =>
      r.getAttribute('data-port'),
    );
    expect(rows).toEqual([
      '22/tcp',
      '80/tcp',
      '443/tcp',
      '8006/tcp',
      '8443/tcp',
      '3306/tcp',
      '5432/tcp',
      '6379/tcp',
    ]);
    const more = el.querySelector<HTMLAnchorElement>('[data-section="ports"] a')!;
    // N = filas de la pestaña «Puertos (N)» (IPv4 e IPv6 por separado).
    expect(more.textContent).toBe('Ver los 16 puertos');
    more.click();
    await fixture.whenStable();
    expect((fixture.componentInstance as unknown as { shownTab(): string }).shownTab()).toBe('ports');
  });

  it('«Generar el comando» del aviso de sudoers genera un comando nuevo antes de abrir el stepper', async () => {
    const { fixture, el } = await renderServer('admin', {
      connection: { host: '192.0.2.10', port: 22, user: 'inventory' },
      facts: { infraward: { warnings: [], sudoersOutdated: true, sudoersVersion: 2 } },
    });
    const http = TestBed.inject(HttpTestingController);
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    // El diálogo lo pinta el shell: se lee lo que se le pide y se acepta.
    const confirm = vi.spyOn(TestBed.inject(ConfirmationService), 'confirm');
    const link = el.querySelector<HTMLAnchorElement>(
      '[data-warning="sudoers"] [data-action="regenerate"]',
    )!;
    expect(link.textContent).toBe('Generar el comando');
    link.click();
    await fixture.whenStable();
    // Servidor activo: es una actualización, no un alta nueva; nada se genera sin aceptar.
    const options = confirm.mock.calls[0][0];
    expect(options).toMatchObject({
      header: 'Actualizar el servidor',
      acceptLabel: 'Generar el comando',
    });
    expect(navigate).not.toHaveBeenCalled();
    http.expectNone('/api/assets/limpia/enrollment/token');
    options.accept!();
    await fixture.whenStable();
    const req = http.expectOne('/api/assets/limpia/enrollment/token');
    expect(req.request.method).toBe('POST');
    req.flush({ id: 'e9', assetId: 'limpia', command: 'curl …' });
    await fixture.whenStable();
    expect(navigate).toHaveBeenCalledWith(['/assets', 'limpia', 'enrollment']);
  });

  it('duplicado: aviso con enlace al original y, para admin, purgar uno de los dos', async () => {
    const original = { id: 'pve', name: 'pve-pruebas', type: 'server' as const, status: 'active' as const };
    const { fixture, el } = await renderServer('admin', {
      duplicateOfId: 'pve',
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
      duplicateOf: original,
      duplicates: [],
    });
    const warning = el.querySelector('[data-warning="duplicate"]')!;
    expect(warning.textContent).toContain('Este servidor ya está en el inventario como');
    expect(warning.querySelector('[data-duplicate-link]')?.getAttribute('href')).toBe('/assets/pve');
    expect(warning.querySelector('[data-action="purge-self"]')).not.toBeNull();
    const purgeOther = warning.querySelector<HTMLButtonElement>(
      '[data-action="purge-original"] button',
    )!;
    expect(purgeOther.textContent).toContain('Purgar pve-pruebas');
    purgeOther.click();
    await fixture.whenStable();
    // El diálogo de purga pide el nombre del otro asset.
    expect(document.body.textContent).toContain('Escribe pve-pruebas para confirmar');
  });

  it('duplicado para un viewer: el aviso, sin botones', async () => {
    const { el } = await renderServer('viewer', {
      duplicateOfId: 'pve',
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
      duplicateOf: { id: 'pve', name: 'pve-pruebas', type: 'server', status: 'active' },
      duplicates: [],
    });
    const warning = el.querySelector('[data-warning="duplicate"]')!;
    expect(warning.textContent).toContain('pve-pruebas');
    expect(warning.querySelector('p-button')).toBeNull();
  });

  it('el original avisa de que también aparece con otro nombre', async () => {
    const { el } = await renderServer('admin', {
      duplicates: [{ id: 'copia', name: 'copia', type: 'server', status: 'active' }],
    });
    expect(el.querySelector('[data-warning="duplicate"]')).toBeNull();
    const warning = el.querySelector('[data-warning="duplicated-by"]')!;
    expect(warning.textContent).toContain('también aparece en el inventario como');
    expect(warning.querySelector('[data-action="purge-duplicate"]')).not.toBeNull();
  });

  it('la pestaña va en la URL (?tab=): se abre la pedida y, si el asset no la tiene, el Resumen', async () => {
    const selected = (el: HTMLElement) =>
      el.querySelector('[role="tab"][aria-selected="true"]')?.textContent?.trim();
    const { el, fixture } = await renderServer('viewer', {}, 'findings');
    expect(selected(el)).toBe('Vulnerabilidades');

    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    fixture.componentInstance.selectTab('relations');
    expect(navigate).toHaveBeenCalledWith([], expect.objectContaining({
      queryParams: { tab: 'relations' },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    }));
    fixture.componentInstance.selectTab('overview');
    expect(navigate).toHaveBeenLastCalledWith([], expect.objectContaining({
      queryParams: { tab: null },
    }));

    TestBed.resetTestingModule();
    // Un servidor sin puertos no tiene esa pestaña.
    const other = await renderServer('viewer', {}, 'ports');
    expect(selected(other.el)).toBe('Resumen');
  });
});

