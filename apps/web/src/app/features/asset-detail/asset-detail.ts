import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { GRAPH_MAX_DEPTH, sshdAuthRisk } from '@infraward/shared-types';
import type {
  Asset,
  AssetRelations,
  AssetSummary,
  AssetTreeSummaryNode,
  DockerHostResources,
  Snapshot,
  SnapshotSummary,
} from '@infraward/shared-types';
import type { MenuItem } from '@openng/optimus-ui/api';
import { BreadcrumbModule } from '@openng/optimus-ui/breadcrumb';
import { ButtonModule } from '@openng/optimus-ui/button';
import { IconFieldModule } from '@openng/optimus-ui/iconfield';
import { InputIconModule } from '@openng/optimus-ui/inputicon';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { TableModule } from '@openng/optimus-ui/table';
import { PanelModule } from '@openng/optimus-ui/panel';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { TabsModule } from '@openng/optimus-ui/tabs';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { TableLazyLoadEvent } from '@openng/optimus-ui/types/table';
import {
  catchError,
  forkJoin,
  map,
  of,
  startWith,
  switchMap,
  type Observable,
} from 'rxjs';
import { MessageService } from '@openng/optimus-ui/api';
import { InventoryApi } from '../../core/api/inventory-api';
import { OrganizationApi } from '../../core/api/organization-api';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';
import { TagEditor } from '../../shared/tag-editor';
import {
  ASSET_STATUS_LABELS,
  ASSET_STATUS_SEVERITY,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  RELATION_INCOMING_LABELS,
  RELATION_LABELS,
  RUNTIME_ICONS,
  RUNTIME_LABELS,
  RUNTIME_SEVERITY,
  type TagSeverity,
} from '../../shared/labels';
import {
  sectionLabel,
  SNAPSHOT_SOURCE_LABELS,
} from '../../shared/maintenance-labels';
import {
  collectionMeta,
  sshdFacts,
  factsPackages,
  factsPorts,
  factsServices,
} from './facts-summary';
import { VaultEntries } from '../vault/vault-entries';
import { TerminalButton } from './terminal-button';
import { AssetActions } from './asset-actions';
import { AssetFindings } from './asset-findings';
import { AssetRuns } from './asset-runs';
import { AssetHierarchy } from './asset-hierarchy';
import { AssetRelationMap } from './asset-relation-map';
import { AssetName } from './asset-name';
import { AssetOverview } from './asset-overview';
import { FactsViewer } from './facts-viewer';
import { SnapshotDiffView, summaryText } from './snapshot-diff';

type Loaded =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | {
      state: 'ready';
      asset: Asset;
      relations: AssetRelations;
      ancestors: AssetSummary[];
      /** Resumen del árbol (dirección, estado de ejecución, findings e hijos); null si falla. */
      node: AssetTreeSummaryNode | null;
      /** Volúmenes, redes e imágenes de un host Docker; null si falla. */
      docker: DockerHostResources | null;
    };

/** Pestaña con la que abre la ficha. */
export const DEFAULT_TAB = 'overview';

export const SNAPSHOT_PAGE = 10;

/** Vistas de la pestaña Relaciones (`?view=`); el mapa, por defecto. */
export const RELATION_VIEWS = [
  { value: 'map', label: 'Mapa', icon: 'bi-bounding-box-circles' },
  { value: 'hierarchy', label: 'Jerarquía', icon: 'bi-diagram-3' },
  { value: 'list', label: 'Lista', icon: 'bi-list-ul' },
] as const;
export type RelationsView = (typeof RELATION_VIEWS)[number]['value'];

@Component({
  selector: 'app-asset-detail',
  imports: [
    DatePipe,
    RouterLink,
    BreadcrumbModule,
    ButtonModule,
    IconFieldModule,
    InputIconModule,
    InputTextModule,
    MessageModule,
    SkeletonModule,
    TableModule,
    TabsModule,
    TagModule,
    TooltipModule,
    PanelModule,
    FactsViewer,
    SnapshotDiffView,
    AssetActions,
    AssetFindings,
    AssetRuns,
    AssetOverview,
    AssetName,
    TagEditor,
    FormsModule,
    SelectButtonModule,
    AssetRelationMap,
    AssetHierarchy,
    VaultEntries,
    TerminalButton,
  ],
  templateUrl: './asset-detail.html',
  styleUrl: './asset-detail.scss',
})
export class AssetDetail {
  private readonly api = inject(InventoryApi);
  private readonly organization = inject(OrganizationApi);
  private readonly store = inject(OrganizationStore);
  private readonly messages = inject(MessageService);
  protected readonly auth = inject(AuthService);
  protected readonly savingTags = signal(false);

  /** Parámetro `:id` de la ruta. */
  readonly id = input.required<string>();
  /** `?tab=`: pestaña abierta, para volver a ella (p. ej. desde la ficha de un CVE). */
  readonly tab = input<string>();
  /** `?view=`: vista de la pestaña Relaciones (mapa, jerarquía o lista). */
  readonly view = input<string>();
  /** `?depth=`: saltos del mapa de relaciones. */
  readonly depth = input<string>();
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly typeLabels: Readonly<Record<string, string>> =
    ASSET_TYPE_LABELS;
  protected readonly typeIcons: Readonly<Record<string, string>> =
    ASSET_TYPE_ICONS;
  protected readonly statusLabels: Readonly<Record<string, string>> =
    ASSET_STATUS_LABELS;
  protected readonly statusSeverity: Readonly<Record<string, TagSeverity>> =
    ASSET_STATUS_SEVERITY;
  protected readonly relationLabels: Readonly<Record<string, string>> =
    RELATION_LABELS;
  protected readonly incomingLabels: Readonly<Record<string, string>> =
    RELATION_INCOMING_LABELS;
  protected readonly runtimeLabels: Readonly<Record<string, string>> =
    RUNTIME_LABELS;
  protected readonly runtimeSeverity: Readonly<Record<string, TagSeverity>> =
    RUNTIME_SEVERITY;
  protected readonly runtimeIcons: Readonly<Record<string, string>> =
    RUNTIME_ICONS;
  protected readonly snapshotSources: Readonly<Record<string, string>> =
    SNAPSHOT_SOURCE_LABELS;
  protected readonly sectionLabel = sectionLabel;
  protected readonly summaryText = summaryText;
  protected readonly snapshotPage = SNAPSHOT_PAGE;
  protected readonly home: MenuItem = {
    label: 'Inventario',
    icon: 'bi bi-diagram-3',
    routerLink: '/inventory',
  };

  /** Pestaña pedida (la de `?tab=` al cambiar de asset; si no, el Resumen). */
  protected readonly requestedTab = signal<string>(DEFAULT_TAB);

  /** Se incrementa para recargar la ficha (tras una acción o un job terminado). */
  private readonly refreshes = signal(0);
  private shownId: string | null = null;

  protected readonly loaded = toSignal(
    toObservable(
      computed(() => ({ id: this.id(), refresh: this.refreshes() })),
    ).pipe(
      switchMap(({ id }) => {
        // Mismo asset: se recarga en el sitio, sin volver al Resumen ni pasar por «cargando».
        const reload = id === this.shownId;
        this.shownId = id;
        return this.load(id, reload);
      }),
    ),
    { initialValue: { state: 'loading' } as Loaded },
  );

  protected readonly asset = computed(() => {
    const l = this.loaded();
    return l.state === 'ready' ? l.asset : null;
  });
  protected readonly relations = computed(() => {
    const l = this.loaded();
    return l.state === 'ready' ? l.relations : null;
  });
  protected readonly ancestors = computed(() => {
    const l = this.loaded();
    return l.state === 'ready' ? l.ancestors : [];
  });
  protected readonly node = computed(() => {
    const l = this.loaded();
    return l.state === 'ready' ? l.node : null;
  });
  protected readonly docker = computed(() => {
    const l = this.loaded();
    return l.state === 'ready' ? l.docker : null;
  });
  /** Migas: la ruta completa por relaciones `contains`, de la raíz al asset. */
  protected readonly crumbs = computed<MenuItem[]>(() => {
    const asset = this.asset();
    return [
      ...this.ancestors().map((a) => ({
        label: a.name,
        routerLink: ['/assets', a.id],
      })),
      ...(asset ? [{ label: asset.name }] : []),
    ];
  });
  protected readonly meta = computed(() =>
    collectionMeta(this.asset()?.facts ?? {}),
  );
  /** sshd admite root o contraseñas (`sshd -T`, sudoers v7): aviso en solo lectura. */
  protected readonly sshdRisk = computed(() => {
    const sshd = sshdFacts(this.asset()?.facts ?? {});
    const risk = sshdAuthRisk(sshd);
    return risk && sshd ? { ...risk, sshd } : null;
  });
  /** Credenciales de la caja fuerte: con `vault.manage` y en lo que tiene consola o panel. */
  protected readonly hasCredentials = computed(() => {
    const type = this.asset()?.type;
    return (
      this.auth.can('vault.manage') &&
      !!type &&
      ['server', 'vm', 'lxc', 'container', 'database', 'domain'].includes(type)
    );
  });
  protected readonly packages = computed(() =>
    factsPackages(this.asset()?.facts ?? {}),
  );
  protected readonly services = computed(() =>
    factsServices(this.asset()?.facts ?? {}),
  );
  protected readonly ports = computed(() =>
    factsPorts(this.asset()?.facts ?? {}),
  );
  protected readonly relationViews = [...RELATION_VIEWS];
  protected readonly relationsView = linkedSignal<RelationsView>(() =>
    RELATION_VIEWS.some((v) => v.value === this.view())
      ? (this.view() as RelationsView)
      : 'map',
  );
  protected readonly mapDepth = linkedSignal(() => {
    const depth = Number(this.depth());
    return depth >= 1 && depth <= GRAPH_MAX_DEPTH ? Math.floor(depth) : 1;
  });

  /** Pestañas que tiene este asset (las del `p-tablist`). */
  private readonly availableTabs = computed(() => [
    DEFAULT_TAB,
    ...(this.hasFindings() ? ['findings'] : []),
    ...(this.packages().length ? ['packages'] : []),
    ...(this.services().length ? ['services'] : []),
    ...(this.ports().length ? ['ports'] : []),
    'relations',
    ...(this.hasCredentials() ? ['credentials'] : []),
    'runs',
    'snapshots',
    'raw',
  ]);
  /** La pestaña pedida si este asset la tiene; si no (un `?tab=` viejo o a mano), el Resumen. */
  protected readonly shownTab = computed(() =>
    this.availableTabs().includes(this.requestedTab()) ? this.requestedTab() : DEFAULT_TAB,
  );
  /** Findings: de imágenes (y de los contenedores, los de su imagen), servidores y CT (su SBOM). */
  protected readonly hasFindings = computed(() => {
    const type = this.asset()?.type;
    return (
      type === 'container' ||
      type === 'image' ||
      type === 'lxc' ||
      type === 'server'
    );
  });
  protected readonly hasFacts = computed(
    () => Object.keys(this.asset()?.facts ?? {}).length > 0,
  );

  // --- Snapshots ---
  protected readonly snapshots = signal<SnapshotSummary[]>([]);
  protected readonly snapshotTotal = signal(0);
  protected readonly snapshotsLoading = signal(false);
  protected readonly selectedSummary = signal<SnapshotSummary | null>(null);
  protected readonly selectedSnapshot = signal<Snapshot | null>(null);
  protected readonly snapshotLoading = signal(false);

  /** Vuelve a pedir el asset (p. ej. con los facts de una recolección recién terminada). */
  private readonly actions = viewChild(AssetActions);

  /** Purga este asset o su duplicado (confirmación escribiendo el nombre, en las acciones). */
  purgeAsset(target: { id: string; name: string }): void {
    this.actions()?.openPurge(target);
  }

  /**
   * «Generar el comando» de los avisos (sudoers o CA SSH desactualizados): como la acción del
   * menú, genera un comando nuevo antes de abrir el stepper (si no, se vería el alta ya «Lista»).
   */
  regenerateCommand(event: Event): void {
    event.preventDefault();
    this.actions()?.run('regenerate');
  }

  refresh(): void {
    this.refreshes.update((n) => n + 1);
  }

  saveTags(asset: Asset, tags: string[]): void {
    this.savingTags.set(true);
    this.organization.updateAsset(asset.id, { tags }).subscribe({
      next: () => {
        this.savingTags.set(false);
        this.store.reloadTags();
        // La política puede cambiar con las etiquetas (reglas por etiqueta).
        this.refresh();
      },
      error: (err: unknown) => {
        this.savingTags.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'No se pudieron guardar los tags',
          detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
        });
      },
    });
  }

  private load(id: string, reload = false): Observable<Loaded> {
    if (!reload) {
      this.resetSnapshots();
      this.requestedTab.set(this.tab() || DEFAULT_TAB);
    }
    return forkJoin({
      asset: this.api.asset(id),
      relations: this.api.relations(id),
      ancestors: this.api.ancestors(id),
      // Sin el resumen del árbol la ficha sigue sirviendo (sin dirección ni hijos).
      node: this.api
        .subtree(id)
        .pipe(catchError(() => of<AssetTreeSummaryNode | null>(null))),
      // Volúmenes, redes e imágenes (vacío si no es un host Docker); opcional como el árbol.
      docker: this.api
        .dockerResources(id)
        .pipe(catchError(() => of<DockerHostResources | null>(null))),
    }).pipe(
      map(({ asset, relations, ancestors, node, docker }): Loaded => ({
        state: 'ready',
        asset,
        relations,
        ancestors,
        node,
        docker,
      })),
      catchError((err: unknown) =>
        of<Loaded>({ state: 'error', message: loadError(err) }),
      ),
      reload ? (source) => source : startWith<Loaded>({ state: 'loading' }),
    );
  }

  selectRelationsView(view: RelationsView): void {
    this.relationsView.set(view);
    this.mergeQuery({ view: view === 'map' ? null : view });
  }

  selectMapDepth(depth: number): void {
    this.mapDepth.set(depth);
    this.mergeQuery({ depth: depth === 1 ? null : depth });
  }

  /** Cambia la URL sin entrada nueva en el historial. */
  private mergeQuery(queryParams: Record<string, string | number | null>): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  selectTab(value: string | number | undefined): void {
    const tab = String(value ?? DEFAULT_TAB);
    this.requestedTab.set(tab);
    // En la URL (sin entrada nueva en el historial): al volver atrás se abre la misma pestaña.
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { tab: tab === DEFAULT_TAB ? null : tab },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  loadSnapshots(event: TableLazyLoadEvent): void {
    const id = this.id();
    this.snapshotsLoading.set(true);
    this.api
      .snapshots(id, {
        offset: event.first ?? 0,
        limit: event.rows ?? SNAPSHOT_PAGE,
      })
      .subscribe({
        next: (page) => {
          if (id !== this.id()) return;
          this.snapshots.set(page.items);
          this.snapshotTotal.set(page.total);
          this.snapshotsLoading.set(false);
        },
        error: () => this.snapshotsLoading.set(false),
      });
  }

  selectSnapshot(summary: SnapshotSummary | null): void {
    this.selectedSummary.set(summary);
    this.selectedSnapshot.set(null);
    if (!summary) return;
    this.snapshotLoading.set(true);
    this.api.snapshot(summary.id).subscribe({
      next: (snapshot) => {
        if (this.selectedSummary()?.id !== snapshot.id) return;
        this.selectedSnapshot.set(snapshot);
        this.snapshotLoading.set(false);
      },
      error: () => this.snapshotLoading.set(false),
    });
  }

  private resetSnapshots(): void {
    this.snapshots.set([]);
    this.snapshotTotal.set(0);
    this.selectedSummary.set(null);
    this.selectedSnapshot.set(null);
  }
}

function loadError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 404) return 'Este asset no existe (o se ha purgado).';
    if (err.status === 400) return 'Identificador de asset no válido.';
  }
  return 'No se pudo cargar el asset.';
}
