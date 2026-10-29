import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  model,
  signal,
} from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  GRAPH_MAX_DEPTH,
  GRAPH_MAX_NODES,
  type AssetGraph,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { catchError, map, of, startWith, switchMap } from 'rxjs';
import { InventoryApi } from '../../core/api/inventory-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { GraphCanvas } from '../../shared/graph/graph-canvas';
import { GraphLegend } from '../../shared/graph/graph-legend';
import { toElements } from '../../shared/graph/graph-model';
import { GraphNodePanel } from '../../shared/graph/graph-node-panel';

type MapState =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; graph: AssetGraph };

/**
 * Mapa de relaciones de la ficha: el asset en el centro y sus vecinos por cualquier relación,
 * en anillos por saltos (1–3). «Centrar aquí» recentra sin salir de la ficha (con vuelta atrás);
 * «Abrir ficha» o doble clic llevan a la del nodo.
 */
@Component({
  selector: 'app-asset-relation-map',
  imports: [
    FormsModule,
    ButtonModule,
    MessageModule,
    SelectButtonModule,
    GraphCanvas,
    GraphLegend,
    GraphNodePanel,
  ],
  template: `
    <div class="toolbar">
      <div class="trail">
        @if (trail().length) {
          <p-button
            icon="bi bi-arrow-left"
            [label]="'Volver a ' + trail()[trail().length - 1].name"
            severity="secondary"
            [text]="true"
            size="small"
            (onClick)="back()"
            data-back
          />
        }
        @if (centerName(); as name) {
          @if (center() !== assetId()) {
            <span class="muted" data-centered>Centrado en <strong>{{ name }}</strong></span>
          }
        }
      </div>
      <div class="depth" role="group" aria-labelledby="map-depth-label">
        <span id="map-depth-label">Profundidad</span>
        <p-selectbutton
          [options]="depths"
          optionLabel="label"
          optionValue="value"
          [ngModel]="depth()"
          (ngModelChange)="depth.set($event)"
          [allowEmpty]="false"
          size="small"
          aria-label="Saltos desde el asset"
          data-depth
        />
      </div>
    </div>

    @switch (loaded().state) {
      @case ('error') {
        <p-message severity="error" [text]="errorMessage()" />
      }
      @default {
        @if (graph()?.truncated) {
          <p-message severity="warn" size="small" styleClass="truncated" data-truncated>
            Hay más de {{ maxNodes }} assets a {{ depth() }} saltos: se muestran los más cercanos.
            Baja la profundidad o céntrate en otro nodo.
          </p-message>
        }
        <div class="stage">
          <app-graph-canvas
            [elements]="elements()"
            layout="concentric"
            [selectedId]="selectedId()"
            [label]="ariaLabel()"
            (nodeSelected)="selectedId.set($event)"
            (nodeActivated)="open($event)"
          >
            @if (selectedNode(); as node) {
              <app-graph-node-panel
                class="panel"
                [node]="node"
                [canRecenter]="node.id !== center()"
                (closed)="selectedId.set(null)"
                (recenter)="recenter($event)"
              />
            }
          </app-graph-canvas>
        </div>
        @if (graph(); as g) {
          <app-graph-legend [graph]="g" />
        }
        <p class="hint muted">
          Toca un nodo para ver qué es y centrar el mapa en él; doble clic para abrir su ficha.
          La vista <em>Lista</em> tiene las mismas relaciones en texto.
        </p>
      }
    }
  `,
  styles: `
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1rem;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.5rem;
    }
    .trail { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; min-height: 2rem; }
    .depth { display: flex; gap: 0.5rem; align-items: center; }
    .muted { color: var(--p-text-muted-color); }
    .stage { position: relative; }
    .panel { position: absolute; top: 0.5rem; left: 0.5rem; z-index: 3; max-height: calc(100% - 1rem); overflow: auto; }
    .hint { margin: 0.5rem 0 0; font-size: 0.85rem; }
    :host ::ng-deep .truncated { margin-bottom: 0.5rem; }
    @media (max-width: 640px) {
      .panel { top: auto; right: 0.5rem; bottom: 0.5rem; width: auto; max-height: 55%; }
      app-graph-canvas { --graph-height: clamp(20rem, 55dvh, 30rem); }
    }
  `,
})
export class AssetRelationMap {
  readonly assetId = input.required<string>();
  readonly depth = model(1);

  private readonly api = inject(InventoryApi);
  private readonly router = inject(Router);

  protected readonly maxNodes = GRAPH_MAX_NODES;
  protected readonly depths = Array.from({ length: GRAPH_MAX_DEPTH }, (_, i) => ({
    label: i === 0 ? '1 salto' : `${i + 1} saltos`,
    value: i + 1,
  }));

  /** Asset del centro: el de la ficha hasta que se recentra en otro. */
  protected readonly center = linkedSignal(() => this.assetId());
  /** Centros anteriores, para volver. */
  protected readonly trail = linkedSignal<string, { id: string; name: string }[]>({
    source: () => this.assetId(),
    computation: () => [],
  });
  protected readonly selectedId = signal<string | null>(null);

  protected readonly loaded = toSignal(
    toObservable(
      computed(() => ({ id: this.center(), depth: this.depth() })),
    ).pipe(
      switchMap(({ id, depth }) =>
        this.api.graph(id, depth).pipe(
          map((graph): MapState => ({ state: 'ready', graph })),
          catchError((err: unknown) =>
            of<MapState>({
              state: 'error',
              message: apiErrorMessage(err, 'No se pudo cargar el mapa.'),
            }),
          ),
          startWith<MapState>({ state: 'loading' }),
        ),
      ),
    ),
    { initialValue: { state: 'loading' } as MapState },
  );

  /** El último grafo cargado (se mantiene mientras carga el siguiente). */
  protected readonly graph = linkedSignal<MapState, AssetGraph | null>({
    source: () => this.loaded(),
    computation: (state, previous) =>
      state.state === 'ready' ? state.graph : state.state === 'loading' ? (previous?.value ?? null) : null,
  });
  protected readonly elements = computed(() => {
    const g = this.graph();
    return g ? toElements(g) : [];
  });
  protected readonly selectedNode = computed(
    () => this.graph()?.nodes.find((n) => n.id === this.selectedId()) ?? null,
  );
  protected readonly centerName = computed(
    () => this.graph()?.nodes.find((n) => n.id === this.center())?.name ?? null,
  );
  protected readonly errorMessage = computed(() => {
    const l = this.loaded();
    return l.state === 'error' ? l.message : '';
  });
  protected readonly ariaLabel = computed(() => {
    const g = this.graph();
    if (!g) return 'Mapa de relaciones';
    return `Mapa de relaciones de ${this.centerName() ?? 'este asset'}: ${g.nodes.length - 1} assets relacionados a ${this.depth()} ${this.depth() === 1 ? 'salto' : 'saltos'}.`;
  });

  recenter(id: string): void {
    const name = this.centerName();
    if (id === this.center()) return;
    this.trail.update((t) => [...t, { id: this.center(), name: name ?? '…' }]);
    this.center.set(id);
    this.selectedId.set(null);
  }

  back(): void {
    const t = this.trail();
    const previous = t[t.length - 1];
    if (!previous) return;
    this.trail.set(t.slice(0, -1));
    this.center.set(previous.id);
    this.selectedId.set(null);
  }

  open(id: string): void {
    void this.router.navigate(['/assets', id]);
  }
}
