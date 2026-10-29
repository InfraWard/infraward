import type { AssetGraph } from '@infraward/shared-types';
import { graphNode, web1Graph } from '../../testing/graph';
import { assetTypeIconUri } from './graph-icons';
import {
  graphStylesheet,
  hiddenSummary,
  readPalette,
  statusFilterOf,
  toElements,
} from './graph-model';

const nodesOf = (els: ReturnType<typeof toElements>) =>
  els.filter((e) => e.group === 'nodes');
const edgesOf = (els: ReturnType<typeof toElements>) =>
  els.filter((e) => e.group === 'edges');

// pve ⊃ ct ⊃ web1, cache; nginx (dentro de ct); dns fuera
const topology: AssetGraph = {
  centerId: null,
  truncated: false,
  nodes: [
    graphNode('pve', { type: 'server' }),
    graphNode('ct', { type: 'lxc', parentId: 'pve' }),
    graphNode('ct2', { type: 'lxc', parentId: 'pve', hidden: { container: 3, volume: 1 }, hiddenCritical: 2 }),
    graphNode('web1', { parentId: 'ct', runtimeState: 'running' }),
    graphNode('cache', { parentId: 'ct', critical: 1, runtimeState: 'stopped' }),
    graphNode('nginx', { type: 'image', parentId: 'ct' }),
    graphNode('dns', { type: 'dns_record' }),
  ],
  edges: [
    { id: 'c1', source: 'pve', target: 'ct', type: 'contains', count: 1 },
    { id: 'i1', source: 'web1', target: 'nginx', type: 'instance_of', count: 1 },
    { id: 'dns:ct2:resolves_to', source: 'dns', target: 'ct2', type: 'resolves_to', count: 3 },
  ],
};

describe('graph-model', () => {
  it('mapa: el centro destacado, «+N más» en los nodos con vecinos sin cargar y el tipo en las aristas', () => {
    const els = toElements(web1Graph());
    const byId = new Map(nodesOf(els).map((e) => [e.data.id, e]));
    expect(byId.get('web1')?.classes).toContain('center');
    expect(byId.get('ct')?.data['label']).toBe('pruebas\n+3 más');
    expect(byId.get('img')?.data['label']).toBe('nginx:1.25');
    // Sin grupos en el mapa: todo suelto, con su salto.
    expect(nodesOf(els).every((e) => e.data['parent'] === undefined)).toBe(true);
    expect(byId.get('vol')?.data['depth']).toBe(1);
    expect(edgesOf(els).map((e) => e.data['label'])).toEqual([
      'contiene',
      'instancia de',
      'conectado a',
      'monta',
    ]);
  });

  it('topología: agrupa por host, quita «contiene» que ya dice el grupo y resume lo oculto', () => {
    const els = toElements(topology, { compound: true });
    const byId = new Map(nodesOf(els).map((e) => [e.data.id, e]));
    expect(byId.get('web1')?.data['parent']).toBe('ct');
    expect(byId.get('ct')?.data['parent']).toBe('pve');
    expect(byId.get('ct')?.classes).toContain('group');
    expect(byId.get('ct2')?.data['label']).toBe(
      'ct2\n3 contenedores · 1 volumen · 2 críticas',
    );
    expect(edgesOf(els).map((e) => e.data['label'])).toEqual([
      'instancia de',
      'resuelve a ×3',
    ]);
  });

  it('filtra por tipo y estado: un grupo filtrado deja sus hijos sueltos y se lleva sus aristas', () => {
    const els = toElements(topology, {
      compound: true,
      hiddenTypes: new Set(['lxc']),
      statuses: new Set(['active']),
    });
    const ids = nodesOf(els).map((e) => e.data.id);
    expect(ids).toEqual(['pve', 'web1', 'nginx', 'dns']);
    expect(nodesOf(els).find((e) => e.data.id === 'web1')?.data['parent']).toBeUndefined();
    expect(edgesOf(els).map((e) => e.data['type'])).toEqual(['instance_of']);
    expect(statusFilterOf(graphNode('x', { runtimeState: 'stopped' }))).toBe('stopped');
    expect(statusFilterOf(graphNode('x', { status: 'missing' }))).toBe('missing');
  });

  it('resaltar críticas atenúa lo demás, pero no los grupos que contienen algo crítico', () => {
    const els = toElements(topology, { compound: true, highlightCritical: true });
    const dim = nodesOf(els)
      .filter((e) => (e.classes as string[]).includes('dim'))
      .map((e) => e.data.id);
    expect(dim).toEqual(['web1', 'nginx', 'dns']);
    expect(edgesOf(els).every((e) => String(e.classes).includes('dim'))).toBe(true);
  });

  it('resumen de lo oculto en singular y plural', () => {
    expect(hiddenSummary(graphNode('x', { hidden: { network: 1, image: 2 } }))).toBe(
      '1 red · 2 imágenes',
    );
    expect(hiddenSummary(graphNode('x', { hiddenCritical: 1 }))).toBe('1 crítica');
  });

  it('el estilo lleva el icono y el color de cada tipo y lee los tokens del tema', () => {
    document.documentElement.style.setProperty('--p-sky-500', '#0ea5e9');
    const palette = readPalette(false, document.documentElement);
    expect(palette.types.container).toBe('#0ea5e9');
    const style = graphStylesheet(palette) as { selector: string; style: Record<string, unknown> }[];
    const container = style.find((s) => s.selector === 'node.type-container');
    expect(container?.style['background-color']).toBe('#0ea5e9');
    expect(container?.style['background-image']).toBe(assetTypeIconUri('container', '#ffffff'));
    expect(decodeURIComponent(assetTypeIconUri('volume', '#fff'))).toMatch(
      /^data:image\/svg\+xml;utf8,<svg xmlns="http:\/\/www.w3.org\/2000\/svg" width="64" height="64" viewBox="0 0 16 16" fill="#fff"><path/,
    );
  });

  it('«resuelve a» (registro DNS → servidor) y «usa el certificado» tienen trazo y color propios', () => {
    const palette = readPalette(false, document.documentElement);
    const style = graphStylesheet(palette) as { selector: string; style: Record<string, unknown> }[];
    const resolves = style.find((s) => s.selector === 'edge.rel-resolves_to');
    expect(resolves?.style).toMatchObject({
      'line-color': palette.types.dns_record,
      'line-style': 'dashed',
    });
    expect(style.find((s) => s.selector === 'edge.rel-secured_by')?.style['line-style']).toBe('dotted');
    expect(style.some((s) => s.selector === 'node.type-dns_provider')).toBe(true);
  });
});

describe('graph-model: camino de un dominio (QoL-5b)', () => {
  it('resalta los nodos del camino y las aristas entre eslabones seguidos', () => {
    const graph: AssetGraph = {
      centerId: 'rec',
      truncated: false,
      nodes: [
        graphNode('rec', { type: 'dns_record' }),
        graphNode('ct', { type: 'lxc' }),
        graphNode('npm', {}),
        graphNode('app', {}),
        graphNode('cert', { type: 'certificate' }),
      ],
      edges: [
        { id: 'e1', source: 'rec', target: 'ct', type: 'resolves_to', count: 1 },
        { id: 'e2', source: 'ct', target: 'npm', type: 'routes_to', count: 1 },
        { id: 'c1', source: 'ct', target: 'npm', type: 'contains', count: 1 },
        { id: 'e3', source: 'npm', target: 'app', type: 'routes_to', count: 1 },
        { id: 'e4', source: 'rec', target: 'app', type: 'served_by', count: 1 },
        { id: 'e5', source: 'rec', target: 'cert', type: 'secured_by', count: 1 },
      ],
      servicePath: ['rec', 'ct', 'npm', 'app'],
    };
    const els = toElements(graph);
    const onPath = (e: { classes?: string | string[] }) =>
      (Array.isArray(e.classes) ? e.classes : (e.classes ?? '').split(' ')).includes('on-path');
    expect(nodesOf(els).filter(onPath).map((e) => e.data.id)).toEqual(['rec', 'ct', 'npm', 'app']);
    expect(edgesOf(els).filter(onPath).map((e) => e.data.id)).toEqual(['e:e1', 'e:e2', 'e:e3', 'e:e4']);
    expect(edgesOf(els).find((e) => e.data.id === 'e:e2')?.data['label']).toBe('envía a');
  });
});
