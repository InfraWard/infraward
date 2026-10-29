import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  computed,
  effect,
  inject,
  input,
  signal,
  untracked,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import {
  filterTree,
  matchesInventoryQuery,
  matchesQuickFilter,
  parseSearchQuery,
  type AssetTreeSummaryNode,
  type ExportFormat,
  type InventoryExportColumn,
} from '@infraward/shared-types';
import type { MenuItem } from '@openng/optimus-ui/api';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { MenuModule } from '@openng/optimus-ui/menu';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import type { TreeNode } from '@openng/optimus-ui/api';
import type {
  TreeTableNodeCollapseEvent,
  TreeTableNodeExpandEvent,
} from '@openng/optimus-ui/types/treetable';
import { ButtonModule } from '@openng/optimus-ui/button';
import { ChipModule } from '@openng/optimus-ui/chip';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { TreeTableModule } from '@openng/optimus-ui/treetable';
import { AuthService } from '../../core/auth/auth.service';
import { API_BASE_URL } from '../../core/api/api-base-url';
import { download, inventoryExportUrl } from '../../core/api/export-urls';
import { InventoryApi } from '../../core/api/inventory-api';
import { BulkActions, canBulk } from '../../shared/bulk-actions';
import { OrganizationStore } from '../../core/organization-store';
import { ProjectFilter } from '../../shared/project-filter';
import { QueryInput } from '../../shared/query-input';
import { TagEditor } from '../../shared/tag-editor';
import {
  ASSET_STATUS_LABELS,
  ASSET_STATUS_SEVERITY,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  RUNTIME_ICONS,
  RUNTIME_LABELS,
  RUNTIME_SEVERITY,
  SEVERITY_TAG,
  type TagSeverity,
} from '../../shared/labels';
import { InventoryState } from './inventory-state';
import { InventoryTopology } from './inventory-topology';
import { ExpiryThresholds } from '../../core/expiry-thresholds';
import {
  branchKeys,
  fixableLabel,
  quickFilter,
  quickFilterLabel,
  toTreeNodes,
  type InventoryRow,
} from './tree-nodes';

/** Columnas del árbol: la cabecera y cada celda llevan el mismo `data-col`. */
export const INVENTORY_COLUMNS = [
  { key: 'name', label: 'Nombre', width: 'auto' },
  { key: 'type', label: 'Tipo', width: '7.5rem' },
  { key: 'address', label: 'Dirección', width: '14rem' },
  { key: 'status', label: 'Estado', width: '12.5rem' },
  { key: 'vulns', label: 'Vulnerabilidades', width: '17rem' },
] as const;
export type InventoryColumnKey = (typeof INVENTORY_COLUMNS)[number]['key'];

/** Qué columnas de la exportación salen de cada columna visible del árbol. */
export const EXPORT_COLUMNS_BY_COLUMN: Record<InventoryColumnKey, InventoryExportColumn[]> = {
  name: ['name', 'path', 'discoveredName', 'roles', 'tags', 'projects'],
  type: ['type'],
  address: ['address'],
  status: ['status', 'runtimeState', 'expiresAt'],
  vulns: ['maxSeverity', 'critical', 'high', 'fixableCritical', 'fixableHigh'],
};

/** Columnas de la exportación para las columnas visibles (en el orden del árbol). */
export function exportColumns(visible: readonly InventoryColumnKey[]): InventoryExportColumn[] {
  return INVENTORY_COLUMNS.filter((c) => visible.includes(c.key)).flatMap(
    (c) => EXPORT_COLUMNS_BY_COLUMN[c.key],
  );
}

@Component({
  selector: 'app-inventory-tree',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    TreeTableModule,
    ButtonModule,
    ChipModule,
    TagModule,
    TooltipModule,
    QueryInput,
    ToggleSwitchModule,
    MessageModule,
    ProjectFilter,
    TagEditor,
    SelectButtonModule,
    InventoryTopology,
    CheckboxModule,
    MenuModule,
    MultiSelectModule,
    BulkActions,
  ],
  templateUrl: './inventory-tree.html',
  styleUrl: './inventory-tree.scss',
})
export class InventoryTree {
  private readonly api = inject(InventoryApi);
  protected readonly state = inject(InventoryState);
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly store = inject(OrganizationStore);
  private readonly expiry = inject(ExpiryThresholds);
  private readonly apiBase = inject(API_BASE_URL);

  /**
   * Filtro rápido de la URL (enlaces del panel y de proyectos): `?type=`, `?status=`,
   * `?attention=`, `?project=`.
   */
  readonly type = input<string>();
  readonly status = input<string>();
  readonly attention = input<string>();
  readonly project = input<string>();
  /** `?view=topology`: la topología en lugar del árbol. */
  readonly view = input<string>();
  /** `?root=`: la topología solo del subárbol de este asset. */
  readonly root = input<string>();
  protected readonly topology = computed(() => this.view() === 'topology');
  protected readonly views = [
    { value: 'tree', label: 'Árbol', icon: 'bi-list-nested' },
    { value: 'topology', label: 'Topología', icon: 'bi-bounding-box-circles' },
  ];
  /**
   * `?q=`: búsqueda con la sintaxis de filtros (`tag:prod nombre:web`; el texto suelto, en el
   * nombre). Se escribe en la URL para poder compartirla.
   */
  readonly q = input<string>();
  protected readonly query = computed(() =>
    parseSearchQuery(this.state.filter(), 'inventory'),
  );
  private readonly queryContext = computed(() => ({
    projects: this.store.projects().map((p) => ({ id: p.id, name: p.name })),
  }));
  /** Lo que cumple el filtro rápido y la búsqueda (sin los antepasados que lo sitúan). */
  private readonly matcher = computed(() => {
    const f = this.quick();
    const query = this.query();
    const ctx = this.queryContext();
    const days = this.expiry.days();
    if (!f && !query.terms.length) return null;
    return (node: AssetTreeSummaryNode) =>
      (!f || matchesQuickFilter(node, f, days)) &&
      matchesInventoryQuery(node, query, ctx);
  });
  /** Roles del inventario cargado, para el autocompletado de `rol:`. */
  protected readonly queryValues = computed(() => {
    const roles = new Set<string>();
    const walk = (nodes: readonly AssetTreeSummaryNode[]) => {
      for (const n of nodes) {
        n.roles.forEach((r) => roles.add(r));
        walk(n.children);
      }
    };
    walk(this.forest());
    return { role: [...roles].sort().map((value) => ({ value })) };
  });
  private urlTimer: ReturnType<typeof setTimeout> | undefined;
  protected readonly quick = computed(() =>
    quickFilter({
      type: this.type(),
      status: this.status(),
      attention: this.attention(),
      project: this.project(),
    }),
  );
  protected readonly quickLabel = computed(() => {
    const f = this.quick();
    return f
      ? quickFilterLabel(
          f,
          f.project ? this.store.projectsById().get(f.project)?.name : undefined,
        )
      : '';
  });

  protected readonly typeLabels: Readonly<Record<string, string>> =
    ASSET_TYPE_LABELS;
  protected readonly typeIcons: Readonly<Record<string, string>> =
    ASSET_TYPE_ICONS;
  protected readonly statusLabels: Readonly<Record<string, string>> =
    ASSET_STATUS_LABELS;
  protected readonly statusSeverity: Readonly<Record<string, TagSeverity>> =
    ASSET_STATUS_SEVERITY;
  protected readonly severityTag: Readonly<Record<string, TagSeverity>> =
    SEVERITY_TAG;
  protected readonly runtimeLabels: Readonly<Record<string, string>> =
    RUNTIME_LABELS;
  protected readonly runtimeSeverity: Readonly<Record<string, TagSeverity>> =
    RUNTIME_SEVERITY;
  protected readonly runtimeIcons: Readonly<Record<string, string>> =
    RUNTIME_ICONS;
  /** Columnas visibles (la del nombre, siempre). */
  protected readonly columns = computed(() =>
    INVENTORY_COLUMNS.filter(
      (c) => c.key === 'name' || !this.state.hiddenColumns().has(c.key),
    ),
  );
  protected readonly shownColumns = computed(
    () => new Set<string>(this.columns().map((c) => c.key)),
  );
  /** Las que se pueden ocultar, para el selector. */
  protected readonly optionalColumns = INVENTORY_COLUMNS.filter((c) => c.key !== 'name');
  protected readonly visibleOptional = computed(() =>
    this.columns()
      .map((c) => c.key)
      .filter((k) => k !== 'name'),
  );
  protected readonly fixableLabel = fixableLabel;

  /** Selección para las acciones en lote: lo que se marca es lo que entra (sin propagar). */
  protected readonly selectable = computed(() => canBulk(this.auth.user()?.role));
  protected readonly selected = signal<ReadonlySet<string>>(new Set());
  protected readonly bulkTarget = computed(() => ({ assetIds: [...this.selected()] }));
  /** Assets que cumplen el filtro (rápido y de texto): «Seleccionar lo visible». */
  private readonly visibleIds = computed(() => {
    const matches = this.matcher();
    const ids: string[] = [];
    const walk = (nodes: readonly AssetTreeSummaryNode[]) => {
      for (const node of nodes) {
        if (!matches || matches(node)) ids.push(node.id);
        walk(node.children);
      }
    };
    walk(this.shown().nodes);
    return ids;
  });
  protected readonly allVisibleSelected = computed(() => {
    const ids = this.visibleIds();
    const selected = this.selected();
    return ids.length > 0 && ids.every((id) => selected.has(id));
  });
  protected readonly someVisibleSelected = computed(
    () => this.selected().size > 0 && !this.allVisibleSelected(),
  );

  protected readonly exportItems: MenuItem[] = [
    { label: 'CSV', icon: 'bi bi-filetype-csv', command: () => this.export('csv') },
    { label: 'JSON', icon: 'bi bi-filetype-json', command: () => this.export('json') },
  ];

  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  private readonly forest = signal<AssetTreeSummaryNode[]>([]);

  /**
   * Nodos del treeTable. Se reconstruyen al cargar, al filtrar y con «Expandir/Contraer todo»; al
   * abrir una rama el propio treeTable cambia `expanded` del nodo y aquí solo se recuerda en el
   * estado.
   */
  protected readonly nodes = signal<TreeNode<InventoryRow>[]>([]);
  protected readonly total = computed(() => countNodes(this.forest()));
  /**
   * Árbol con el filtro rápido y la búsqueda aplicados (lo que cumple y sus antepasados, con las
   * ramas abiertas), o el entero.
   */
  private readonly shown = computed(() => {
    const matches = this.matcher();
    return matches
      ? filterTree(this.forest(), matches)
      : { nodes: this.forest(), expand: [], matches: null };
  });
  protected readonly matches = computed(() => this.shown().matches);

  constructor() {
    this.expiry.load();
    // La búsqueda de la URL (enlace compartido, búsqueda global, atrás) pasa al buscador; sin
    // `?q=`, la que se conserva de la visita anterior se vuelve a escribir en la URL.
    effect(() => {
      const q = this.q();
      untracked(() => {
        if (q !== undefined && q !== this.state.filter().trim()) this.state.filter.set(q);
        else if (q === undefined && this.state.filter()) this.writeQuery(0);
      });
    });
    // Al cargar o al cambiar el filtro de la URL se rehacen los nodos.
    effect(() => {
      this.shown();
      this.expiry.days();
      untracked(() => this.rebuild());
    });
    // Cambiar el filtro vacía la selección: nunca se actúa sobre algo que ya no se ve.
    effect(() => {
      this.quick();
      this.state.filter();
      this.state.includeRetired();
      untracked(() => this.clearSelection());
    });
    this.store.ensureTags();
    this.store.ensureProjects();
    this.load();
  }

  protected setVisibleColumns(keys: readonly string[]): void {
    this.state.setHiddenColumns(
      this.optionalColumns.map((c) => c.key).filter((k) => !keys.includes(k)),
    );
  }

  protected toggleSelected(id: string, on: boolean): void {
    this.selected.update((current) => {
      const next = new Set(current);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  protected toggleAllVisible(on: boolean): void {
    this.selected.set(on ? new Set(this.visibleIds()) : new Set());
  }

  protected clearSelection(): void {
    if (this.selected().size) this.selected.set(new Set());
  }

  protected onBulkDone(): void {
    this.clearSelection();
    this.load();
  }

  /** Descarga lo que se ve: mismos filtros y columnas visibles. */
  protected export(format: ExportFormat): void {
    const f = this.quick();
    download(
      inventoryExportUrl(this.apiBase, {
        format,
        columns: exportColumns(this.columns().map((c) => c.key)),
        q: this.state.filter().trim() || undefined,
        type: f?.type,
        status: f?.status,
        attention: f?.attention,
        project: f?.project,
        includeRetired: this.state.includeRetired() || undefined,
      }),
    );
  }

  clearQuickFilter(): void {
    void this.router.navigate([], {
      queryParams: { type: null, status: null, attention: null, project: null },
      queryParamsHandling: 'merge',
    });
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api.tree(this.state.includeRetired()).subscribe({
      next: (forest) => {
        this.forest.set(forest);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        this.loading.set(false);
        // El 401 ya lo gestiona el interceptor (vuelta al login).
        if (err instanceof HttpErrorResponse && err.status === 401) return;
        this.error.set('No se pudo cargar el inventario.');
      },
    });
  }

  setView(view: string): void {
    void this.router.navigate([], {
      queryParams: { view: view === 'topology' ? view : null, root: null },
      queryParamsHandling: 'merge',
    });
  }

  setRoot(root: string | null): void {
    void this.router.navigate([], {
      queryParams: { root },
      queryParamsHandling: 'merge',
    });
  }

  setProject(project: string | null): void {
    void this.router.navigate([], {
      queryParams: { project },
      queryParamsHandling: 'merge',
    });
  }

  setIncludeRetired(value: boolean): void {
    this.state.includeRetired.set(value);
    this.load();
  }

  applyFilter(value: string): void {
    this.state.filter.set(value);
    this.writeQuery(300);
  }

  /** `?q=` en la URL (sin apilar historial a cada tecla). */
  private writeQuery(delay: number): void {
    clearTimeout(this.urlTimer);
    this.urlTimer = setTimeout(() => {
      const q = this.state.filter().trim();
      if ((this.q() ?? '') === q) return;
      void this.router.navigate([], {
        queryParams: { q: q || null },
        queryParamsHandling: 'merge',
        replaceUrl: true,
      });
    }, delay);
  }

  expandAll(): void {
    this.state.expanded.set(new Set(branchKeys(this.shown().nodes)));
    this.rebuild();
  }

  collapseAll(): void {
    this.state.expanded.set(new Set());
    this.rebuild();
  }

  private rebuild(): void {
    const { nodes, expand } = this.shown();
    const expanded = new Set([...this.state.expanded(), ...expand]);
    this.nodes.set(toTreeNodes(nodes, expanded, this.expiry.days()));
  }

  onExpand(event: TreeTableNodeExpandEvent<InventoryRow>): void {
    if (event.node?.key) this.state.setExpanded(event.node.key, true);
  }

  onCollapse(event: TreeTableNodeCollapseEvent<InventoryRow>): void {
    if (event.node?.key) this.state.setExpanded(event.node.key, false);
  }
}

function countNodes(nodes: readonly AssetTreeSummaryNode[]): number {
  return nodes.reduce((n, node) => n + 1 + countNodes(node.children), 0);
}
