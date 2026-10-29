import { Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import type {
  AssetStatus,
  AssetSummary,
  AssetTreeSummaryNode,
  AssetType,
} from '@infraward/shared-types';
import type { TreeNode } from '@openng/optimus-ui/api';
import { OrganizationChartModule } from '@openng/optimus-ui/organizationchart';
import {
  ASSET_STATUS_LABELS,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  RUNTIME_LABELS,
} from '../../shared/labels';

/** Hijos que se muestran por nodo; el resto se resume en «y N más». */
export const HIERARCHY_MAX_CHILDREN = 12;

export interface HierarchyData {
  id: string | null;
  name: string;
  type: AssetType | null;
  /** Texto de estado («En marcha», «Retirado»…), o null si está activo sin estado de ejecución. */
  state: string | null;
  inactive: boolean;
  current: boolean;
  /** Nodo «y N más» (sin enlace). */
  more?: number;
}

/**
 * Jerarquía `contains` del asset con el organigrama de OptimusNG: sus antepasados (de la raíz al
 * padre), él resaltado, y sus hijos y nietos (los nietos plegados). Cada nodo enlaza a su ficha.
 */
export function buildHierarchy(
  ancestors: AssetSummary[],
  node: AssetTreeSummaryNode,
): TreeNode<HierarchyData>[] {
  const data = (
    a: Pick<AssetTreeSummaryNode, 'id' | 'name' | 'type' | 'status'> &
      Partial<Pick<AssetTreeSummaryNode, 'runtimeState'>>,
    current = false,
  ): HierarchyData => ({
    id: a.id,
    name: a.name,
    type: a.type,
    state: stateLabel(a.status, a.runtimeState ?? null),
    inactive: a.status === 'missing' || a.status === 'retired' || a.runtimeState === 'stopped',
    current,
  });
  const children = (
    list: AssetTreeSummaryNode[],
    level: number,
  ): TreeNode<HierarchyData>[] => {
    const shown = list.slice(0, HIERARCHY_MAX_CHILDREN).map((c) => ({
      key: c.id,
      data: data(c),
      // Los nietos van plegados; más abajo no se baja (para eso está la ficha de cada uno).
      expanded: false,
      children: level < 2 ? children(c.children, level + 1) : [],
    }));
    const rest = list.length - shown.length;
    return rest > 0
      ? [
          ...shown,
          {
            key: `more:${level}:${list[0]?.id}`,
            data: {
              id: null,
              name: `y ${rest} más`,
              type: null,
              state: null,
              inactive: false,
              current: false,
              more: rest,
            },
            styleClass: 'more',
          },
        ]
      : shown;
  };
  let tree: TreeNode<HierarchyData> = {
    key: node.id,
    data: data(node, true),
    expanded: true,
    styleClass: 'current',
    children: children(node.children, 1),
  };
  for (const a of [...ancestors].reverse())
    tree = { key: a.id, data: data(a), expanded: true, children: [tree] };
  return [tree];
}

function stateLabel(
  status: AssetStatus,
  runtime: AssetTreeSummaryNode['runtimeState'],
): string | null {
  if (status !== 'active') return ASSET_STATUS_LABELS[status];
  return runtime ? RUNTIME_LABELS[runtime] : null;
}

@Component({
  selector: 'app-asset-hierarchy',
  imports: [RouterLink, OrganizationChartModule],
  template: `
    <div class="scroller" data-hierarchy>
      <p-organization-chart [value]="tree()" [collapsible]="true">
        <ng-template let-node pTemplate="default">
          @let d = node.data;
          @if (d.id) {
            <a
              class="card"
              [class.current]="d.current"
              [class.inactive]="d.inactive"
              [routerLink]="['/assets', d.id]"
              [attr.aria-current]="d.current ? 'page' : null"
              [attr.data-node]="d.name"
            >
              <i class="bi {{ icons[d.type] }}" aria-hidden="true"></i>
              <span class="name">{{ d.name }}</span>
              <span class="meta">{{ types[d.type] }}@if (d.state) { · {{ d.state }}}</span>
            </a>
          } @else {
            <span class="card more" data-more>{{ d.name }}</span>
          }
        </ng-template>
      </p-organization-chart>
    </div>
    <p class="hint">Solo la jerarquía «contiene». Las imágenes, volúmenes y redes están en el <em>Mapa</em>.</p>
  `,
  styles: `
    .scroller {
      overflow-x: auto;
      padding: 0.5rem 0;
      max-width: 100%;
    }
    :host ::ng-deep .p-organizationchart {
      min-width: max-content;
      margin: 0 auto;
      /* Línea más larga bajo cada nodo: ahí va la flecha de plegar, sin pisar la tarjeta. */
      --p-organizationchart-connector-height: 2.25rem;
    }
    :host ::ng-deep .p-organizationchart-node-toggle-button {
      bottom: -1.75rem;
      display: grid;
      place-items: center;
      background: var(--p-content-background);
      border: 1px solid var(--p-content-border-color);
    }
    :host ::ng-deep .p-organizationchart-node-toggle-button-icon { display: block; }
    :host ::ng-deep .p-organizationchart-node {
      padding: 0;
      border: none;
      background: transparent;
    }
    .card {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.15rem;
      min-width: 7rem;
      max-width: 11rem;
      padding: 0.5rem 0.75rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: 8px;
      background: var(--p-content-background);
      color: var(--p-text-color);
      text-decoration: none;
    }
    a.card:hover { border-color: var(--p-primary-color); }
    .card i { font-size: 1.1rem; color: var(--p-primary-color); }
    .card.current {
      border: 2px solid var(--p-primary-color);
      background: color-mix(in srgb, var(--p-primary-color) 10%, var(--p-content-background));
      font-weight: 600;
    }
    .card.inactive { opacity: 0.6; border-style: dashed; }
    .card.more { color: var(--p-text-muted-color); font-style: italic; }
    .name { overflow-wrap: anywhere; text-align: center; }
    .meta { font-size: 0.8rem; color: var(--p-text-muted-color); font-weight: 400; text-align: center; }
    .hint { margin: 0.5rem 0 0; font-size: 0.85rem; color: var(--p-text-muted-color); }
  `,
})
export class AssetHierarchy {
  readonly ancestors = input.required<AssetSummary[]>();
  readonly node = input.required<AssetTreeSummaryNode>();

  protected readonly icons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly types: Readonly<Record<string, string>> = ASSET_TYPE_LABELS;
  protected readonly tree = computed(() =>
    buildHierarchy(this.ancestors(), this.node()),
  );
}
