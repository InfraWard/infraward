import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { AssetTreeSummaryNode } from '@infraward/shared-types';
import { AssetHierarchy, buildHierarchy, HIERARCHY_MAX_CHILDREN } from './asset-hierarchy';

const none = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

function tree(
  id: string,
  children: AssetTreeSummaryNode[] = [],
  extra: Partial<AssetTreeSummaryNode> = {},
): AssetTreeSummaryNode {
  return {
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
    children,
    ...extra,
  };
}

const ancestors = [{ id: 'pve', name: 'pve', type: 'server' as const, status: 'active' as const }];

describe('AssetHierarchy', () => {
  it('antepasados → el asset (resaltado) → hijos y nietos plegados, con «y N más»', () => {
    const many = Array.from({ length: HIERARCHY_MAX_CHILDREN + 3 }, (_, i) =>
      tree(`c${i}`, i === 0 ? [tree('nieto', [tree('bisnieto')])] : []),
    );
    const [root] = buildHierarchy(ancestors, tree('ct', many, { type: 'lxc' }));
    expect(root.data?.name).toBe('pve');
    const ct = root.children![0];
    expect(ct.data).toMatchObject({ name: 'ct', current: true });
    expect(ct.styleClass).toBe('current');
    expect(ct.children).toHaveLength(HIERARCHY_MAX_CHILDREN + 1);
    expect(ct.children!.at(-1)?.data).toMatchObject({ name: 'y 3 más', more: 3, id: null });
    const c0 = ct.children![0];
    expect(c0.expanded).toBe(false);
    expect(c0.children![0].data?.name).toBe('nieto');
    // Más abajo de los nietos no se baja.
    expect(c0.children![0].children).toEqual([]);
  });

  it('estado de ejecución o de inventario, y los parados o retirados atenuados', () => {
    const [root] = buildHierarchy([], tree('x', [
      tree('parado', [], { runtimeState: 'stopped' }),
      tree('ido', [], { status: 'retired' }),
    ]));
    expect(root.children!.map((c) => [c.data?.state, c.data?.inactive])).toEqual([
      ['Parado', true],
      ['Retirado', true],
    ]);
  });

  it('pinta el organigrama con enlaces a cada ficha', async () => {
    TestBed.configureTestingModule({
      imports: [AssetHierarchy],
      providers: [provideRouter([])],
    });
    const fixture = TestBed.createComponent(AssetHierarchy);
    fixture.componentRef.setInput('ancestors', ancestors);
    fixture.componentRef.setInput('node', tree('ct', [tree('web1')], { type: 'lxc' }));
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('p-organization-chart')).not.toBeNull();
    const links = [...el.querySelectorAll<HTMLAnchorElement>('a[data-node]')];
    expect(links.map((a) => [a.dataset['node'], a.getAttribute('href')])).toEqual([
      ['pve', '/assets/pve'],
      ['ct', '/assets/ct'],
      ['web1', '/assets/web1'],
    ]);
    expect(el.querySelector('a[data-node="ct"]')?.getAttribute('aria-current')).toBe('page');
  });
});
