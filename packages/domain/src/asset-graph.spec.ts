import type { AssetRelationType, AssetType } from '@infraward/shared-types';
import { describe, expect, it } from 'vitest';
import {
  buildTopology,
  expandGraph,
  type GraphRelationRow,
  type TopologyAsset,
  type TopologyRelation,
} from './asset-graph.js';

// pve → ct1 → web1, web2, cache, vol1, net1; ct1 stores nginx, redis
// web1, web2 → nginx; cache → redis; web1 → vol1; web1, web2, cache → net1
const types: Record<string, AssetType> = {
  pve: 'server',
  ct1: 'lxc',
  ct2: 'lxc',
  web1: 'container',
  web2: 'container',
  cache: 'container',
  vol1: 'volume',
  net1: 'network',
  nginx: 'image',
  redis: 'image',
};
const rel = (
  parentId: string,
  type: AssetRelationType,
  childId: string,
): GraphRelationRow => ({
  id: `${parentId}-${type}-${childId}`,
  parentId,
  childId,
  type,
  parentType: types[parentId] ?? 'container',
  childType: types[childId] ?? 'container',
});
const lab = [
  rel('pve', 'contains', 'ct1'),
  rel('pve', 'contains', 'ct2'),
  rel('ct1', 'contains', 'web1'),
  rel('ct1', 'contains', 'web2'),
  rel('ct1', 'contains', 'cache'),
  rel('ct1', 'contains', 'vol1'),
  rel('ct1', 'contains', 'net1'),
  rel('ct1', 'stores', 'nginx'),
  rel('ct1', 'stores', 'redis'),
  rel('web1', 'instance_of', 'nginx'),
  rel('web2', 'instance_of', 'nginx'),
  rel('cache', 'instance_of', 'redis'),
  rel('web1', 'mounts', 'vol1'),
  rel('web1', 'attached_to', 'net1'),
  rel('web2', 'attached_to', 'net1'),
  rel('cache', 'attached_to', 'net1'),
];

function fetcher(rows: GraphRelationRow[]) {
  const calls: string[][] = [];
  const fetch = (ids: string[]) => {
    calls.push(ids);
    return Promise.resolve(
      rows.filter((r) => ids.includes(r.parentId) || ids.includes(r.childId)),
    );
  };
  return { fetch, calls };
}

describe('expandGraph', () => {
  it('a un salto, un contenedor ve su CT, su imagen, su volumen y su red', async () => {
    const { fetch, calls } = fetcher(lab);
    const g = await expandGraph('web1', fetch, { depth: 1 });
    expect(Object.fromEntries(g.depths)).toEqual({
      web1: 0,
      ct1: 1,
      nginx: 1,
      vol1: 1,
      net1: 1,
    });
    expect(g.edges.map((e) => e.type).sort()).toEqual(
      [
        'attached_to',
        'contains',
        'contains',
        'contains',
        'instance_of',
        'mounts',
        'stores',
      ].sort(),
    );
    // Las aristas entre nodos ya cargados aparecen (ct1 contiene vol1 y net1, guarda nginx).
    expect(g.edges.some((e) => e.id === 'ct1-contains-vol1')).toBe(true);
    // El borde cuenta lo que queda fuera: ct1 tiene pve, web2, cache y redis sin cargar.
    expect(g.hidden.get('ct1')).toEqual({ server: 1, container: 2, image: 1 });
    expect(g.hidden.get('web1')).toBeUndefined();
    expect(g.truncated).toBe(false);
    expect(calls).toHaveLength(2);
  });

  it('a dos saltos llega a los vecinos por la red y la imagen compartidas', async () => {
    const { fetch } = fetcher(lab);
    const g = await expandGraph('web1', fetch, { depth: 2 });
    for (const id of ['pve', 'web2', 'cache', 'redis'])
      expect(g.depths.get(id)).toBe(2);
    expect(g.hidden.get('ct1')).toBeUndefined();
    expect(g.hidden.get('pve')).toEqual({ lxc: 1 });
  });

  it('respeta el tope de vecinos por nodo y prioriza las relaciones que definen al nodo', async () => {
    const rows = [
      ...Array.from({ length: 5 }, (_, i) => rel('host', 'stores', `img${i}`)),
      rel('host', 'contains', 'c1'),
    ].map((r) =>
      r.type === 'stores' ? { ...r, childType: 'image' as const } : r,
    );
    const g = await expandGraph('host', fetcher(rows).fetch, {
      depth: 1,
      maxNeighbors: 2,
    });
    expect([...g.depths.keys()]).toEqual(['host', 'c1', 'img0']);
    expect(g.hidden.get('host')).toEqual({ image: 4 });
  });

  it('corta en el tope de nodos y lo marca', async () => {
    const { fetch } = fetcher(lab);
    const g = await expandGraph('ct1', fetch, { depth: 3, maxNodes: 4 });
    expect(g.depths.size).toBe(4);
    expect(g.truncated).toBe(true);
  });

  it('no cuenta como oculto un vecino que otro nodo sí cargó', async () => {
    const rows = [
      rel('a', 'depends_on', 'b'),
      rel('a', 'depends_on', 'c'),
      rel('b', 'depends_on', 'c'),
    ];
    const g = await expandGraph('a', fetcher(rows).fetch, {
      depth: 1,
      maxNeighbors: 1,
    });
    // a carga b; c no cupo desde a. En el borde, b ve a c, que sigue fuera.
    expect(g.hidden.get('a')).toEqual({ container: 1 });
    const g2 = await expandGraph('a', fetcher(rows).fetch, {
      depth: 2,
      maxNeighbors: 1,
    });
    expect(g2.depths.get('c')).toBe(2);
    expect(g2.hidden.get('a')).toBeUndefined();
  });

  it('no se enreda con ciclos', async () => {
    const rows = [
      rel('a', 'depends_on', 'b'),
      rel('b', 'depends_on', 'a'),
      rel('b', 'depends_on', 'c'),
      rel('c', 'depends_on', 'a'),
    ];
    const g = await expandGraph('a', fetcher(rows).fetch, { depth: 3 });
    expect(Object.fromEntries(g.depths)).toEqual({ a: 0, b: 1, c: 1 });
    expect(g.edges).toHaveLength(4);
  });
});

describe('buildTopology', () => {
  const asset = (id: string, parentId: string | null): TopologyAsset => ({
    id,
    type: types[id] ?? 'server',
    parentId,
  });
  const assets = [
    asset('pve', null),
    asset('ct1', 'pve'),
    asset('ct2', 'pve'),
    asset('web1', 'ct1'),
    asset('web2', 'ct1'),
    asset('cache', 'ct1'),
    asset('vol1', 'ct1'),
    asset('net1', 'ct1'),
    asset('nginx', null),
    asset('redis', null),
    asset('dns', null),
  ];
  const relations: TopologyRelation[] = [
    ...lab.filter((r) => r.type !== 'contains'),
    { id: 'dns-r', parentId: 'dns', childId: 'web1', type: 'resolves_to' },
  ];
  const critical = new Map([
    ['web1', 2],
    ['web2', 2],
    ['cache', 1],
    ['nginx', 2],
  ]);

  it('un conector de dominios: sus dominios son grupos con los registros dentro', () => {
    const t = buildTopology({
      assets: [
        { id: 'cf', type: 'dns_provider', parentId: null },
        { id: 'dom', type: 'domain', parentId: 'cf' },
        { id: 'r1', type: 'dns_record', parentId: 'dom' },
        { id: 'r2', type: 'dns_record', parentId: 'dom' },
        { id: 'srv', type: 'server', parentId: null },
      ],
      relations: [{ id: 'x', parentId: 'r1', childId: 'srv', type: 'resolves_to' }],
      critical: new Map(),
      expand: new Set(),
    });
    expect(t.nodes.map((n) => n.id).sort()).toEqual(['cf', 'dom', 'srv']);
    expect(t.nodes.find((n) => n.id === 'dom')!.hidden).toEqual({ dns_record: 2 });
    // La relación del registro se agrega entre su dominio y el servidor.
    expect(t.edges).toEqual([
      expect.objectContaining({ source: 'dom', target: 'srv', type: 'resolves_to', count: 1 }),
    ]);
  });

  it('sin expandir muestra el nivel host con el resumen de su contenido', () => {
    const t = buildTopology({ assets, relations, critical, expand: new Set() });
    expect(t.nodes.map((n) => n.id).sort()).toEqual([
      'ct1',
      'ct2',
      'dns',
      'pve',
    ]);
    const ct1 = t.nodes.find((n) => n.id === 'ct1')!;
    expect(ct1.parentId).toBe('pve');
    expect(ct1.hidden).toEqual({
      container: 3,
      volume: 1,
      network: 1,
      image: 2,
    });
    // Las imágenes no suman: sus CVE ya cuentan en los contenedores que las usan.
    expect(ct1.hiddenCritical).toBe(5);
    // dns → web1 (oculto) se agrega en su antepasado visible.
    expect(t.edges).toEqual([
      {
        id: 'dns:ct1:resolves_to',
        source: 'dns',
        target: 'ct1',
        type: 'resolves_to',
        count: 1,
      },
    ]);
  });

  it('al expandir un host muestra su contenido dentro y sus imágenes', () => {
    const t = buildTopology({
      assets,
      relations,
      critical,
      expand: new Set(['ct1']),
    });
    const node = (id: string) => t.nodes.find((n) => n.id === id);
    for (const id of ['web1', 'web2', 'cache', 'vol1', 'net1'])
      expect(node(id)?.parentId).toBe('ct1');
    expect(node('nginx')?.parentId).toBe('ct1');
    expect(node('ct1')?.hidden).toEqual({});
    expect(t.edges.some((e) => e.type === 'stores')).toBe(false);
    expect(t.edges.find((e) => e.id === 'dns-r')).toMatchObject({
      source: 'dns',
      target: 'web1',
    });
    expect(t.edges.filter((e) => e.type === 'attached_to')).toHaveLength(3);
  });

  it('una imagen guardada en varios hosts queda fuera de los grupos', () => {
    const t = buildTopology({
      assets: [...assets, asset('web3', 'ct2')],
      relations: [
        ...relations,
        { id: 's2', parentId: 'ct2', childId: 'nginx', type: 'stores' },
        { id: 'i3', parentId: 'web3', childId: 'nginx', type: 'instance_of' },
      ],
      critical,
      expand: new Set(['ct1', 'ct2']),
    });
    const nginx = t.nodes.find((n) => n.id === 'nginx')!;
    expect(nginx.parentId).toBeNull();
    expect(
      t.edges.filter((e) => e.target === 'nginx' && e.type === 'stores'),
    ).toHaveLength(2);
  });

  it('corta en el tope de nodos y lo marca', () => {
    const t = buildTopology({
      assets,
      relations,
      critical,
      expand: new Set(['ct1']),
      maxNodes: 5,
    });
    expect(t.nodes).toHaveLength(5);
    expect(t.truncated).toBe(true);
  });
});
