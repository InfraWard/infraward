import { Component, input, output } from '@angular/core';
import type { AssetGraph, GraphNode } from '@infraward/shared-types';
import type { ElementDefinition } from 'cytoscape';

/**
 * Sustituto de `app-graph-canvas` para los tests: jsdom no tiene canvas. Pinta un botón por nodo
 * (clic = seleccionar, doble clic = activar) y deja ver los elementos que recibe.
 */
@Component({
  selector: 'app-graph-canvas',
  template: `
    @for (e of nodes(); track e.data.id) {
      <button
        type="button"
        [attr.data-graph-node]="e.data.id"
        [attr.data-parent]="e.data['parent'] ?? null"
        [attr.class]="classOf(e)"
        (click)="nodeSelected.emit(e.data.id!)"
        (dblclick)="nodeActivated.emit(e.data.id!)"
      >
        {{ e.data['label'] }}
      </button>
    }
    @for (e of edges(); track e.data.id) {
      <span [attr.data-graph-edge]="e.data['type']">{{ e.data['label'] }}</span>
    }
    <ng-content />
  `,
})
export class FakeGraphCanvas {
  readonly elements = input.required<ElementDefinition[]>();
  readonly layout = input('concentric');
  readonly selectedId = input<string | null>(null);
  readonly label = input('');
  readonly nodeSelected = output<string | null>();
  readonly nodeActivated = output<string>();
  protected classOf(e: ElementDefinition): string {
    return Array.isArray(e.classes) ? e.classes.join(' ') : (e.classes ?? '');
  }
  protected nodes() {
    return this.elements().filter((e) => e.group === 'nodes');
  }
  protected edges() {
    return this.elements().filter((e) => e.group === 'edges');
  }
}

/** Nodo de grafo de prueba. */
export function graphNode(
  id: string,
  extra: Partial<GraphNode> = {},
): GraphNode {
  return {
    id,
    name: id,
    type: 'container',
    status: 'active',
    address: null,
    runtimeState: null,
    critical: 0,
    maxSeverity: null,
    parentId: null,
    depth: 0,
    hidden: {},
    hiddenCritical: 0,
    ...extra,
  };
}

/** Mapa de web1 a un salto: su CT, su imagen, su red y su volumen. */
export function web1Graph(): AssetGraph {
  return {
    centerId: 'web1',
    truncated: false,
    nodes: [
      graphNode('web1', { parentId: 'ct', address: '8080→80/tcp', runtimeState: 'running' }),
      graphNode('ct', { name: 'pruebas', type: 'lxc', depth: 1, hidden: { server: 1, container: 2 } }),
      graphNode('img', { name: 'nginx:1.25', type: 'image', depth: 1 }),
      graphNode('net', { name: 'app', type: 'network', depth: 1, hidden: { container: 2 } }),
      graphNode('vol', { name: 'webdata', type: 'volume', depth: 1 }),
    ],
    edges: [
      { id: 'r1', source: 'ct', target: 'web1', type: 'contains', count: 1 },
      { id: 'r2', source: 'web1', target: 'img', type: 'instance_of', count: 1 },
      { id: 'r3', source: 'web1', target: 'net', type: 'attached_to', count: 1 },
      { id: 'r4', source: 'web1', target: 'vol', type: 'mounts', count: 1 },
    ],
  };
}
