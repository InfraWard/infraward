import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  output,
  signal,
} from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  ASSET_TYPES,
  TOPOLOGY_MAX_NODES,
  type AssetGraph,
  type AssetType,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { ChipModule } from '@openng/optimus-ui/chip';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { catchError, map, of, startWith, switchMap } from 'rxjs';
import { InventoryApi } from '../../core/api/inventory-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { GraphCanvas } from '../../shared/graph/graph-canvas';
import { GraphLegend } from '../../shared/graph/graph-legend';
import {
  GRAPH_STATUS_FILTERS,
  GRAPH_STATUS_LABELS,
  hiddenTotal,
  toElements,
  type GraphStatusFilter,
} from '../../shared/graph/graph-model';
import { GraphNodePanel } from '../../shared/graph/graph-node-panel';
import { ProjectFilter } from '../../shared/project-filter';
import { ASSET_TYPE_LABELS } from '../../shared/labels';

type TopologyState =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; graph: AssetGraph };

/** Estados que se ven al abrir (los retirados no se piden). */
const DEFAULT_STATUSES: GraphStatusFilter[] = GRAPH_STATUS_FILTERS.filter(
  (s) => s !== 'retired',
);

/**
 * Topología del inventario (o de un proyecto, o del subárbol de un asset) por niveles: primero
 * los servidores y sus CT/VM, cada uno con el resumen de lo que tiene dentro; al expandir un host
 * se cargan sus contenedores, volúmenes, redes e imágenes, agrupados dentro de él.
 */
@Component({
  selector: 'app-inventory-topology',
  imports: [
    FormsModule,
    ButtonModule,
    ChipModule,
    MessageModule,
    MultiSelectModule,
    ToggleSwitchModule,
    GraphCanvas,
    GraphLegend,
    GraphNodePanel,
    ProjectFilter,
  ],
  template: `
    <div class="toolbar">
      <app-project-filter [value]="project()" (changed)="projectChange.emit($event)" />
      <p-multiselect
        [options]="typeOptions()"
        optionLabel="label"
        optionValue="value"
        [ngModel]="shownTypes()"
        (ngModelChange)="setShownTypes($event)"
        placeholder="Ningún tipo"
        selectedItemsLabel="{0} tipos"
        [maxSelectedLabels]="2"
        ariaLabel="Tipos que se muestran"
        appendTo="body"
        data-filter="types"
      />
      <p-multiselect
        [options]="statusOptions"
        optionLabel="label"
        optionValue="value"
        [ngModel]="statuses()"
        (ngModelChange)="statuses.set($event)"
        placeholder="Ningún estado"
        selectedItemsLabel="{0} estados"
        [maxSelectedLabels]="1"
        ariaLabel="Estados que se muestran"
        appendTo="body"
        data-filter="statuses"
      />
      <span class="switch">
        <p-toggleswitch inputId="critical" [ngModel]="highlightCritical()" (ngModelChange)="highlightCritical.set($event)" />
        <label for="critical">Resaltar CVE críticos</label>
      </span>
      <span class="spacer"></span>
      <p-button
        label="Expandir un nivel"
        icon="bi bi-arrows-angle-expand"
        severity="secondary"
        size="small"
        [disabled]="!expandableIds().length || (graph()?.nodes?.length ?? 0) >= maxNodes"
        (onClick)="expandAll()"
        data-expand-all
      />
      <p-button
        label="Contraer"
        icon="bi bi-arrows-angle-contract"
        severity="secondary"
        size="small"
        [disabled]="!expanded().size"
        (onClick)="expanded.set(emptySet)"
        data-collapse-all
      />
    </div>

    @if (rootName(); as name) {
      <p-chip [label]="'Solo: ' + name" icon="bi bi-funnel" [removable]="true" (onRemove)="rootChange.emit(null)" styleClass="root-chip" data-root-chip />
    }

    @switch (loaded().state) {
      @case ('error') {
        <p-message severity="error" [text]="errorMessage()" />
      }
      @default {
        @if (graph(); as g) {
          @if (g.truncated) {
            <p-message severity="warn" size="small" styleClass="truncated" data-truncated>
              Se muestran {{ maxNodes }} assets como mucho: contrae algún host o filtra por proyecto.
            </p-message>
          }
          @if (!g.nodes.length) {
            <p class="muted">No hay assets que mostrar.</p>
          }
        }
        <div class="stage">
          <app-graph-canvas
            [elements]="elements()"
            layout="fcose"
            [selectedId]="selectedId()"
            [label]="ariaLabel()"
            (nodeSelected)="selectedId.set($event)"
            (nodeActivated)="activate($event)"
          >
            @if (selectedNode(); as node) {
              <app-graph-node-panel
                class="panel"
                [node]="node"
                [expandable]="!expanded().has(node.id)"
                [collapsible]="expanded().has(node.id)"
                (closed)="selectedId.set(null)"
                (expand)="expand($event)"
                (collapse)="collapse($event)"
              />
            }
          </app-graph-canvas>
        </div>
        @if (graph(); as g) {
          <app-graph-legend [graph]="g" />
          <p class="hint muted">
            {{ visibleCount() }} de {{ g.nodes.length }} assets. Toca un host para ver lo que tiene dentro y expandirlo;
            doble clic expande (o abre la ficha si no hay nada más que cargar).
          </p>
        }
      }
    }
  `,
  styles: `
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .switch { display: inline-flex; gap: 0.5rem; align-items: center; }
    .spacer { flex: 1; }
    .muted { color: var(--p-text-muted-color); }
    .stage { position: relative; }
    .panel { position: absolute; top: 0.5rem; left: 0.5rem; z-index: 3; max-height: calc(100% - 1rem); overflow: auto; }
    .hint { margin: 0.5rem 0 0; font-size: 0.85rem; }
    app-graph-canvas { --graph-height: clamp(24rem, 70dvh, 52rem); }
    :host ::ng-deep .root-chip, :host ::ng-deep .truncated { margin-bottom: 0.5rem; }
    @media (max-width: 640px) {
      .spacer { display: none; }
      .panel { top: auto; right: 0.5rem; bottom: 0.5rem; width: auto; max-height: 55%; }
      app-graph-canvas { --graph-height: clamp(22rem, 60dvh, 34rem); }
    }
  `,
})
export class InventoryTopology {
  readonly project = input<string | null>(null);
  /** Solo el subárbol de este asset. */
  readonly rootId = input<string | null>(null);
  readonly projectChange = output<string | null>();
  readonly rootChange = output<string | null>();

  private readonly api = inject(InventoryApi);
  private readonly router = inject(Router);

  protected readonly maxNodes = TOPOLOGY_MAX_NODES;
  protected readonly emptySet: ReadonlySet<string> = new Set();
  protected readonly statusOptions = GRAPH_STATUS_FILTERS.map((s) => ({
    value: s,
    label: GRAPH_STATUS_LABELS[s],
  }));

  /** Hosts expandidos (se vacía al cambiar de proyecto o de raíz). */
  protected readonly expanded = linkedSignal<unknown, ReadonlySet<string>>({
    source: () => [this.project(), this.rootId()],
    computation: () => new Set(),
  });
  protected readonly hiddenTypes = signal<ReadonlySet<AssetType>>(new Set());
  protected readonly statuses = signal<GraphStatusFilter[]>(DEFAULT_STATUSES);
  protected readonly highlightCritical = signal(false);
  protected readonly selectedId = signal<string | null>(null);

  protected readonly loaded = toSignal(
    toObservable(
      computed(() => ({
        projectId: this.project() ?? undefined,
        rootId: this.rootId() ?? undefined,
        expand: [...this.expanded()],
        includeRetired: this.statuses().includes('retired'),
      })),
    ).pipe(
      switchMap((query) =>
        this.api.topology(query).pipe(
          map((graph): TopologyState => ({ state: 'ready', graph })),
          catchError((err: unknown) =>
            of<TopologyState>({
              state: 'error',
              message: apiErrorMessage(err, 'No se pudo cargar la topología.'),
            }),
          ),
          startWith<TopologyState>({ state: 'loading' }),
        ),
      ),
    ),
    { initialValue: { state: 'loading' } as TopologyState },
  );

  protected readonly graph = linkedSignal<TopologyState, AssetGraph | null>({
    source: () => this.loaded(),
    computation: (state, previous) =>
      state.state === 'ready'
        ? state.graph
        : state.state === 'loading'
          ? (previous?.value ?? null)
          : null,
  });
  protected readonly elements = computed(() => {
    const g = this.graph();
    return g
      ? toElements(g, {
          compound: true,
          hiddenTypes: this.hiddenTypes(),
          statuses: new Set(this.statuses()),
          highlightCritical: this.highlightCritical(),
        })
      : [];
  });
  protected readonly visibleCount = computed(
    () => this.elements().filter((e) => e.group === 'nodes').length,
  );
  /** Tipos presentes (y los ocultos, para poder volver a mostrarlos). */
  protected readonly typeOptions = computed(() => {
    const present = new Set<AssetType>([
      ...(this.graph()?.nodes.map((n) => n.type) ?? []),
      ...this.hiddenTypes(),
    ]);
    return ASSET_TYPES.filter((t) => present.has(t)).map((t) => ({
      value: t,
      label: ASSET_TYPE_LABELS[t],
    }));
  });
  protected readonly shownTypes = computed(() =>
    this.typeOptions()
      .map((o) => o.value)
      .filter((t) => !this.hiddenTypes().has(t)),
  );
  protected readonly selectedNode = computed(
    () => this.graph()?.nodes.find((n) => n.id === this.selectedId()) ?? null,
  );
  protected readonly expandableIds = computed(
    () =>
      this.graph()
        ?.nodes.filter((n) => hiddenTotal(n) > 0 && !this.expanded().has(n.id))
        .map((n) => n.id) ?? [],
  );
  protected readonly rootName = computed(() => {
    const id = this.rootId();
    return id ? (this.graph()?.nodes.find((n) => n.id === id)?.name ?? '…') : null;
  });
  protected readonly errorMessage = computed(() => {
    const l = this.loaded();
    return l.state === 'error' ? l.message : '';
  });
  protected readonly ariaLabel = computed(() => {
    const g = this.graph();
    return g
      ? `Topología del inventario: ${this.visibleCount()} assets agrupados por host.`
      : 'Topología del inventario';
  });

  setShownTypes(shown: AssetType[]): void {
    const all = this.typeOptions().map((o) => o.value);
    this.hiddenTypes.set(new Set(all.filter((t) => !shown.includes(t))));
  }

  expand(id: string): void {
    this.expanded.update((s) => new Set([...s, id]));
  }

  collapse(id: string): void {
    this.expanded.update((s) => {
      const next = new Set(s);
      next.delete(id);
      return next;
    });
  }

  expandAll(): void {
    this.expanded.update((s) => new Set([...s, ...this.expandableIds()]));
  }

  /** Doble clic: expande si hay algo dentro sin cargar; si no, abre la ficha. */
  activate(id: string): void {
    const node = this.graph()?.nodes.find((n) => n.id === id);
    if (node && hiddenTotal(node) > 0 && !this.expanded().has(id))
      this.expand(id);
    else void this.router.navigate(['/assets', id]);
  }
}
