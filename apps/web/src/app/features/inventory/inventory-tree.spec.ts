import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type {

  AssetTreeSummaryNode,
  ProjectWithStats,
  Severity,
  TagInfo,
} from '@infraward/shared-types';
import { storeSession } from '../../testing/session';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { InventoryTree } from './inventory-tree';

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

const tags: TagInfo[] = [{ tag: 'prod', assets: 1, color: '#dc2626' }];
const projects: ProjectWithStats[] = [
  {
    id: '11111111-1111-4111-8111-111111111111',
    name: 'Homelab',
    description: null,
    color: '#0d9488',
    createdAt: '',
    updatedAt: '',
    stats: {
      assetsByType: {},
      assets: 0,
      openFindings: none,
      fixableFindings: { CRITICAL: 0, HIGH: 0 },
      openVulnerabilities: 0,
    },
  },
];
const HOMELAB = projects[0].id;

describe('InventoryTree', () => {
  async function render() {
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
    // Tags (colores) y proyectos (filtro y puntos de color), compartidos.
    http.expectOne('/api/tags').flush(tags);
    http.expectOne('/api/projects').flush(projects);
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  it('pinta las raíces con enlace a la ficha y abre las ramas con «Expandir»', async () => {
    const { fixture, http, el } = await render();
    http.expectOne('/api/assets/tree').flush([
      leaf('pve', {
        type: 'server',
        roles: ['proxmox-node'],
        children: [leaf('web1', { openFindings: { ...none, CRITICAL: 1, HIGH: 2 } })],
      }),
    ]);
    await fixture.whenStable();
    expect(el.querySelector('tr[data-asset="pve"] a')?.getAttribute('href')).toBe('/assets/pve');
    expect(el.querySelector('tr[data-asset="pve"]')?.textContent).toContain('proxmox-node');
    expect(el.querySelector('tr[data-asset="web1"]')).toBeNull();
    expect(el.textContent).toContain('2 assets');

    fixture.componentInstance.expandAll();
    await fixture.whenStable();
    expect(el.querySelector('tr[data-asset="web1"]')?.textContent).toContain('CRITICAL');
    // Los umbrales de caducidad se piden una vez y se comparten.
    http.match('/api/settings/expiry-warnings').forEach((r) => r.flush({ days: [30, 7] }));
    http.verify();
  });

  it('cada celda cae bajo su cabecera: misma tabla, mismo orden y el contenido que toca', async () => {
    const { fixture, http, el } = await render();
    http.expectOne('/api/assets/tree').flush([
      leaf('pve', {
        type: 'server',
        roles: ['proxmox-node'],
        tags: ['prod'],
        address: '172.20.10.190',
        children: [
          leaf('cache', {
            address: '6379/tcp',
            runtimeState: 'stopped',
            runtimeDetail: 'created',
            openFindings: { ...none, CRITICAL: 2, HIGH: 5, LOW: 9 },
            fixableFindings: { CRITICAL: 1, HIGH: 3 },
          }),
        ],
      }),
    ]);
    fixture.componentInstance.expandAll();
    await fixture.whenStable();

    const headers = [...el.querySelectorAll('thead th')];
    expect(headers.map((th) => th.textContent?.trim())).toEqual([
      'Nombre',
      'Tipo',
      'Dirección',
      'Estado',
      'Vulnerabilidades',
    ]);
    for (const name of ['pve', 'cache']) {
      const row = el.querySelector(`tr[data-asset="${name}"]`)!;
      // Con cabecera y cuerpo en tablas distintas, los anchos de columna no se comparten.
      expect(row.closest('table')).toBe(headers[0].closest('table'));
      const cells = [...row.querySelectorAll(':scope > td')];
      expect(cells.map((td) => td.getAttribute('data-col'))).toEqual(
        headers.map((th) => th.getAttribute('data-col')),
      );
    }
    const cell = (name: string, col: string) =>
      el.querySelector(`tr[data-asset="${name}"] > td[data-col="${col}"]`)!.textContent!.trim();
    expect(cell('pve', 'name')).toContain('proxmox-node');
    expect(cell('pve', 'type')).toBe('Servidor');
    expect(cell('pve', 'address')).toBe('172.20.10.190');
    expect(cell('pve', 'status')).toBe('Activo');
    expect(cell('pve', 'vulns')).toBe('');
    expect(cell('cache', 'type')).toBe('Contenedor');
    expect(cell('cache', 'address')).toBe('6379/tcp');
    // Parado aunque en el inventario siga activo.
    expect(cell('cache', 'status')).toBe('Parado');
    expect(cell('cache', 'vulns')).toContain('CRITICAL');
    expect(cell('cache', 'vulns')).toContain('1 C · 3 H');
    expect(cell('cache', 'vulns')).not.toContain('16');
  });

  it('«Mostrar retirados» vuelve a pedir el árbol con includeRetired', async () => {
    const { fixture, http } = await render();
    http.expectOne('/api/assets/tree').flush([]);
    fixture.componentInstance.setIncludeRetired(true);
    http.expectOne('/api/assets/tree?includeRetired=true').flush([]);
    // Los umbrales de caducidad se piden una vez y se comparten.
    http.match('/api/settings/expiry-warnings').forEach((r) => r.flush({ days: [30, 7] }));
    expect(() => http.verify()).not.toThrow();
  });

  it('?q= con sintaxis: tag exacto y nombre parcial, con chips y el texto en el buscador', async () => {
    const { fixture, http, el } = await render();
    fixture.componentRef.setInput('q', 'tag:prueba nombre:hola');
    http.expectOne('/api/assets/tree').flush([
      leaf('pve', {
        type: 'server',
        children: [
          leaf('hola-web', { tags: ['prueba'] }),
          leaf('hola-db', { tags: ['prueba-2'] }),
          leaf('cache', { tags: ['prueba'] }),
        ],
      }),
      leaf('otro', { type: 'server', tags: ['prueba'] }),
    ]);
    for (let i = 0; i < 3; i++) {
      await fixture.whenStable();
      await new Promise((r) => setTimeout(r));
    }
    expect(el.querySelector<HTMLInputElement>('[data-query-text] input')?.value).toBe(
      'tag:prueba nombre:hola',
    );
    expect(el.querySelector('tr[data-asset="hola-web"]')).not.toBeNull();
    expect(el.querySelector('tr[data-asset="pve"]')).not.toBeNull();
    expect(el.querySelector('tr[data-asset="hola-db"]')).toBeNull();
    expect(el.querySelector('tr[data-asset="cache"]')).toBeNull();
    expect(el.querySelector('tr[data-asset="otro"]')).toBeNull();
    const chips = [...el.querySelectorAll('[data-query-chip] .raw')].map((c) => c.textContent);
    expect(chips).toEqual(['tag:prueba', 'nombre:hola']);
    expect(el.querySelector('[data-query-matches]')?.textContent).toContain('1 coincide');
  });

  it('el texto suelto busca solo en el nombre (no en tags) y una clave rara se marca', async () => {
    const { fixture, http, el } = await render();
    fixture.componentRef.setInput('q', 'prueba foo:bar');
    http.expectOne('/api/assets/tree').flush([leaf('web', { type: 'server', tags: ['prueba'] })]);
    for (let i = 0; i < 3; i++) {
      await fixture.whenStable();
      await new Promise((r) => setTimeout(r));
    }
    expect(el.querySelector('tr[data-asset="web"]')).toBeNull();
    const warn = el.querySelector('[data-query-chip].warn');
    expect(warn?.getAttribute('title')).toContain('Clave desconocida');
  });

  it('muestra un error si falla la carga', async () => {
    const { fixture, http, el } = await render();
    http.expectOne('/api/assets/tree').flush(null, { status: 500, statusText: 'Error' });
    await fixture.whenStable();
    expect(el.textContent).toContain('No se pudo cargar el inventario');
  });

  it('?project= deja los assets del proyecto (y sus antepasados) con un chip y puntos de color', async () => {
    const { fixture, http, el } = await render();
    fixture.componentRef.setInput('project', HOMELAB);
    http.expectOne('/api/assets/tree').flush([
      leaf('pve', {
        type: 'server',
        children: [leaf('ct', { type: 'lxc', projects: [HOMELAB] }), leaf('fuera')],
      }),
      leaf('otro', { type: 'server' }),
    ]);
    await fixture.whenStable();
    expect(el.querySelector('[data-quick-filter]')?.textContent).toContain(
      'Proyecto: Homelab (1)',
    );
    expect(el.querySelector('tr[data-asset="ct"]')).not.toBeNull();
    expect(el.querySelector('tr[data-asset="pve"]')).not.toBeNull();
    expect(el.querySelector('tr[data-asset="fuera"]')).toBeNull();
    expect(el.querySelector('tr[data-asset="otro"]')).toBeNull();
    expect(
      el.querySelector('tr[data-asset="ct"] [data-project-dot]')?.getAttribute('aria-label'),
    ).toBe('Proyecto Homelab');
  });

  it('nombre descubierto y tags con color; un lector no ve las acciones', async () => {
    storeSession('viewer');
    const { fixture, http, el } = await render();
    http.expectOne('/api/assets/tree').flush([
      leaf('pve', { name: 'Proxmox casa', discoveredName: 'pve', tags: ['prod'] }),
    ]);
    await fixture.whenStable();
    const row = el.querySelector('tr[data-id="pve"]')!;
    expect(row.querySelector('a')?.textContent?.trim()).toBe('Proxmox casa');
    expect(row.querySelector('[data-discovered]')?.textContent).toContain('descubierto: pve');
    const chip = row.querySelector<HTMLElement>('[data-tag="prod"]')!;
    expect(chip.style.getPropertyValue('--tag-color')).toBe('#dc2626');
    expect(row.querySelector('[data-action="rename"]')).toBeNull();
    expect(row.querySelector('[data-action="add-tag"]')).toBeNull();
    expect(row.querySelector('[data-tag="prod"] .remove')).toBeNull();
  });

  it('ni un admin renombra ni edita tags desde el árbol: solo se ven (se cambian en la ficha)', async () => {
    storeSession('admin');
    const { fixture, http, el } = await render();
    http
      .expectOne('/api/assets/tree')
      .flush([leaf('web1', { tags: ['prod'] }), leaf('web2', { name: 'Web 2', discoveredName: 'web2' })]);
    await fixture.whenStable();
    for (const action of ['rename', 'restore-name', 'add-tag'])
      expect(el.querySelector(`[data-action="${action}"]`)).toBeNull();
    expect(el.querySelector('[data-tag="prod"]')).not.toBeNull();
    expect(el.querySelector('[data-tag="prod"] .remove')).toBeNull();
    expect(el.querySelector('tr[data-id="web2"] [data-discovered]')?.textContent).toContain('web2');
  });
});
