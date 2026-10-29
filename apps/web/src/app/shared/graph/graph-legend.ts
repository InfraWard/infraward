import { Component, computed, input } from '@angular/core';
import type {
  AssetGraph,
  AssetRelationType,
  AssetType,
} from '@infraward/shared-types';
import {
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  RELATION_LABELS,
} from '../labels';
import { ASSET_TYPE_COLORS } from './graph-model';

/** Leyenda de un mapa: los tipos de asset y de relación que aparecen en él. */
@Component({
  selector: 'app-graph-legend',
  template: `
    <ul class="legend" aria-label="Leyenda">
      @for (t of types(); track t) {
        <li>
          <span class="swatch" [style.background]="'var(--graph-type-' + t + ')'">
            <i class="bi {{ icons[t] }}" aria-hidden="true"></i>
          </span>
          {{ labels[t] }}
        </li>
      }
      @for (r of relations(); track r) {
        <li class="rel"><span class="line rel-{{ r }}" aria-hidden="true"></span>{{ relationLabels[r] }}</li>
      }
      @if (critical()) {
        <li><span class="swatch critical" aria-hidden="true"></span>con CVE críticos</li>
      }
    </ul>
  `,
  styles: `
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem 0.9rem;
      margin: 0.5rem 0 0;
      padding: 0;
      list-style: none;
      font-size: 0.85rem;
      color: var(--p-text-muted-color);
    }
    li { display: flex; align-items: center; gap: 0.35rem; }
    .swatch {
      display: inline-grid;
      place-items: center;
      width: 1.1rem;
      height: 1.1rem;
      border-radius: 4px;
      color: #fff;
      font-size: 0.7rem;
    }
    .swatch.critical { background: transparent; border: 2px solid var(--p-app-danger-color); }
    .line { width: 1.4rem; border-top: 2px solid var(--p-content-border-color); }
    .rel-instance_of { border-top-color: var(--graph-type-image); }
    .rel-mounts { border-top: 2px dashed var(--graph-type-volume); }
    .rel-attached_to { border-top: 2px dashed var(--graph-type-network); }
    .rel-stores { border-top-style: dotted; }
    .rel-resolves_to { border-top: 2px dashed var(--graph-type-dns_record); }
    .rel-secured_by { border-top: 2px dotted var(--graph-type-certificate); }
    .rel-served_by { border-top: 3px solid var(--graph-type-dns_record); }
    .rel-routes_to { border-top: 2px solid var(--p-primary-color); }
  `,
  host: { '[style]': 'typeVars' },
})
export class GraphLegend {
  readonly graph = input.required<AssetGraph>();

  protected readonly icons = ASSET_TYPE_ICONS;
  protected readonly labels = ASSET_TYPE_LABELS;
  protected readonly relationLabels = RELATION_LABELS;
  /** Los colores de cada tipo, como los del lienzo (500 en claro, 400 en oscuro). */
  protected readonly typeVars = Object.entries(ASSET_TYPE_COLORS)
    .map(
      ([t, c]) =>
        `--graph-type-${t}: light-dark(var(--p-${c}-500), var(--p-${c}-400))`,
    )
    .join(';');

  protected readonly types = computed(() => [
    ...new Set<AssetType>(this.graph().nodes.map((n) => n.type)),
  ]);
  protected readonly relations = computed(() => [
    ...new Set<AssetRelationType>(this.graph().edges.map((e) => e.type)),
  ]);
  protected readonly critical = computed(() =>
    this.graph().nodes.some((n) => n.critical || n.hiddenCritical),
  );
}
