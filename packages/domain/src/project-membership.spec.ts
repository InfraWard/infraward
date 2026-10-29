import { describe, expect, it } from 'vitest';
import {
  resolveProjects,
  type MembershipInput,
  type ProjectAssetInput,
} from './project-membership.js';

const asset = (
  id: string,
  parentId: string | null,
  extra: Partial<ProjectAssetInput> = {},
): ProjectAssetInput => ({
  id,
  type: 'server',
  status: 'active',
  parentId,
  ...extra,
});

const include = (projectId: string, assetId: string): MembershipInput => ({
  projectId,
  assetId,
  mode: 'include',
});
const exclude = (projectId: string, assetId: string): MembershipInput => ({
  projectId,
  assetId,
  mode: 'exclude',
});

// pve → ct1 → web1 → vol1; pve → ct2; imagen nginx (de web1) y redis (de otro host)
const tree = [
  asset('pve', null),
  asset('ct1', 'pve', { type: 'lxc' }),
  asset('web1', 'ct1', { type: 'container' }),
  asset('vol1', 'web1', { type: 'volume' }),
  asset('ct2', 'pve', { type: 'lxc' }),
  asset('otro', null),
  asset('nginx', null, { type: 'image' }),
  asset('redis', null, { type: 'image' }),
];
const holders = new Map([
  ['nginx', ['web1']],
  ['redis', ['otro']],
]);

describe('resolveProjects', () => {
  it('sin filas: ningún proyecto', () => {
    const p = resolveProjects({ assets: tree, memberships: [], imageHolders: holders });
    expect([...p.values()].every((l) => l.length === 0)).toBe(true);
  });

  it('meter un nodo mete todo lo que contiene y las imágenes de sus contenedores', () => {
    const p = resolveProjects({
      assets: tree,
      memberships: [include('homelab', 'pve')],
      imageHolders: holders,
    });
    for (const id of ['pve', 'ct1', 'web1', 'vol1', 'ct2', 'nginx'])
      expect(p.get(id)).toEqual(['homelab']);
    expect(p.get('otro')).toEqual([]);
    expect(p.get('redis')).toEqual([]);
  });

  it('una excepción saca el subárbol solo de ese proyecto y un include más abajo lo vuelve a meter', () => {
    const p = resolveProjects({
      assets: tree,
      memberships: [
        include('homelab', 'pve'),
        include('web', 'pve'),
        exclude('homelab', 'ct1'),
        include('homelab', 'vol1'),
      ],
      imageHolders: holders,
    });
    expect(p.get('ct1')).toEqual(['web']);
    expect(p.get('web1')).toEqual(['web']);
    expect(p.get('vol1')).toEqual(['homelab', 'web']);
    expect(p.get('ct2')).toEqual(['homelab', 'web']);
    // nginx solo la usa web1 (fuera de homelab).
    expect(p.get('nginx')).toEqual(['web']);
  });

  it('varios proyectos a la vez; imágenes con filas propias y holders retirados', () => {
    const p = resolveProjects({
      assets: [
        ...tree.filter((a) => a.id !== 'otro'),
        asset('otro', null, { status: 'retired' }),
      ],
      memberships: [
        include('a', 'pve'),
        include('b', 'otro'),
        include('c', 'redis'),
        exclude('a', 'nginx'),
      ],
      imageHolders: holders,
    });
    expect(p.get('nginx')).toEqual([]);
    // otro está retirado: no aporta b a redis; c es fila propia.
    expect(p.get('redis')).toEqual(['c']);
    expect(p.get('otro')).toEqual(['b']);
  });

  it('un ciclo en los datos no cuelga', () => {
    const p = resolveProjects({
      assets: [asset('x', 'y'), asset('y', 'x')],
      memberships: [include('p', 'y')],
      imageHolders: new Map(),
    });
    expect(p.get('x')).toEqual(['p']);
    expect(p.get('y')).toEqual(['p']);
  });
});
