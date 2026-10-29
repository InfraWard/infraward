import { describe, expect, it } from 'vitest';
import { buildTree } from './asset-tree.js';

const node = (id: string, name = id) => ({ id, name });

describe('buildTree', () => {
  it('anida padre → hijos → nietos', () => {
    const tree = buildTree([
      { node: node('pve'), parentId: null },
      { node: node('ct-101'), parentId: 'pve' },
      { node: node('nginx'), parentId: 'ct-101' },
    ]);
    expect(tree).toEqual([
      {
        id: 'pve',
        name: 'pve',
        children: [
          {
            id: 'ct-101',
            name: 'ct-101',
            children: [{ id: 'nginx', name: 'nginx', children: [] }],
          },
        ],
      },
    ]);
  });

  it('admite varias raíces y no depende del orden de las filas', () => {
    const tree = buildTree([
      { node: node('c'), parentId: 'b' },
      { node: node('b'), parentId: null },
      { node: node('a'), parentId: null },
    ]);
    expect(tree.map((n) => n.id)).toEqual(['a', 'b']);
    expect(tree[1].children.map((n) => n.id)).toEqual(['c']);
  });

  it('ordena los hermanos por nombre', () => {
    const tree = buildTree([
      { node: node('root'), parentId: null },
      { node: node('3', 'zeta'), parentId: 'root' },
      { node: node('1', 'alfa'), parentId: 'root' },
      { node: node('2', 'Beta'), parentId: 'root' },
    ]);
    expect(tree[0].children.map((n) => n.name)).toEqual([
      'alfa',
      'Beta',
      'zeta',
    ]);
  });

  it('un nodo cuyo padre no está en la lista queda como raíz', () => {
    const tree = buildTree([{ node: node('x'), parentId: 'desconocido' }]);
    expect(tree).toEqual([{ id: 'x', name: 'x', children: [] }]);
  });

  it('no modifica los nodos de entrada', () => {
    const input = node('a');
    buildTree([{ node: input, parentId: null }]);
    expect(input).toEqual({ id: 'a', name: 'a' });
  });
});
