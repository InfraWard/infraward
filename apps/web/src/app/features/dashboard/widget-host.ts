import {
  Component,
  computed,
  inject,
  input,
  output,
  signal,
  ViewEncapsulation,
} from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import {
  DASHBOARD_WIDGETS,
  widgetRequestParams,
  widgetTitle,
  type DashboardWidget,
  type RecentActivityData,
  type RunningJobsData,
} from '@infraward/shared-types';
import type { MenuItem } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MenuModule } from '@openng/optimus-ui/menu';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { catchError, map, of, startWith, switchMap } from 'rxjs';
import { DashboardApi } from '../../core/api/dashboard-api';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';
import { ASSET_TYPE_LABELS } from '../../shared/labels';
import { pollWhile } from '../../shared/poll';
import { dashboardLinks } from './dashboard-links';
import {
  AssetCountsWidget,
  AssetSummaryWidget,
  FixableVulnerabilitiesWidget,
  PendingEnrollmentWidget,
  RunningJobsWidget,
  VulnerabilityCountsWidget,
} from './widgets/counter-widgets';
import {
  AttentionWidget,
  ExpirationsWidget,
  NewVulnerabilitiesWidget,
  RecentActivityWidget,
  TopVulnerabilitiesWidget,
} from './widgets/list-widgets';
import { TrendWidget } from './widgets/trend-widget';

/** Con tareas en curso, los widgets de tareas se refrescan con esta cadencia. */
export const WIDGET_POLL_MS = 5000;

/** Acciones del menú de un widget en edición. */
export type WidgetAction =
  | 'configure'
  | 'before'
  | 'after'
  | 'wider'
  | 'narrower'
  | 'taller'
  | 'shorter'
  | 'remove';

type Loaded =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; data: unknown };

/**
 * Un widget del panel (DESIGN §15): pide solo sus datos (`GET /dashboard/widgets/<tipo>`), con su
 * esqueleto, su error con «Reintentar» y su enlace a la sección filtrada. En edición, el asa para
 * arrastrar y el menú (configurar, mover, tamaño y quitar: la alternativa con teclado).
 */
@Component({
  selector: 'app-widget-host',
  encapsulation: ViewEncapsulation.None,
  imports: [
    ButtonModule,
    MenuModule,
    SkeletonModule,
    AssetCountsWidget,
    AssetSummaryWidget,
    AttentionWidget,
    FixableVulnerabilitiesWidget,
    ExpirationsWidget,
    NewVulnerabilitiesWidget,
    PendingEnrollmentWidget,
    RecentActivityWidget,
    RunningJobsWidget,
    TopVulnerabilitiesWidget,
    TrendWidget,
    VulnerabilityCountsWidget,
  ],
  templateUrl: './widget-host.html',
  styleUrl: './widget-host.scss',
})
export class WidgetHost {
  private readonly api = inject(DashboardApi);
  private readonly store = inject(OrganizationStore);

  readonly widget = input.required<DashboardWidget>();
  /** Sustituye al proyecto del widget (selector de la página o panel de un proyecto). */
  readonly project = input<string>();
  /** Panel de un proyecto: no se enseña el proyecto en cada widget. */
  readonly locked = input(false);
  readonly editing = input(false);
  /** Para el menú: si puede moverse antes o después. */
  readonly first = input(false);
  readonly last = input(false);
  readonly action = output<WidgetAction>();

  protected readonly def = computed(
    () => DASHBOARD_WIDGETS[this.widget().type],
  );
  protected readonly title = computed(() => widgetTitle(this.widget()));
  private readonly retry = signal(0);

  /** Lo que se pide: solo cambia con el tipo, los filtros o las opciones (no al moverlo). */
  private readonly request = computed(() => {
    const w = this.widget();
    return JSON.stringify([
      w.type,
      widgetRequestParams(w, this.project()),
      this.retry(),
    ]);
  });

  protected readonly loaded = toSignal(
    toObservable(this.request).pipe(
      switchMap(() => {
        const w = this.widget();
        const load = () => this.api.widget<unknown>(w, this.project());
        const busy = (d: unknown) =>
          w.type === 'running-jobs'
            ? (d as RunningJobsData).count > 0
            : w.type === 'recent-activity'
              ? (d as RecentActivityData).running > 0
              : false;
        return pollWhile(load, busy, WIDGET_POLL_MS).pipe(
          map((data): Loaded => ({ state: 'ready', data })),
          catchError((err: unknown) =>
            of<Loaded>({
              state: 'error',
              message: apiErrorMessage(err, 'No se pudo cargar.'),
            }),
          ),
          startWith<Loaded>({ state: 'loading' }),
        );
      }),
    ),
    { initialValue: { state: 'loading' } as Loaded },
  );

  /** Los datos, del tipo que espere cada componente (el `@switch` del tipo los separa). */
  protected readonly data = computed(() => {
    const l = this.loaded();
    return (l.state === 'ready' ? l.data : null) as never;
  });

  /** Ámbito efectivo: el proyecto que lo sustituye o el suyo, y los tags y tipos que admite. */
  private readonly scope = computed(() => {
    const w = this.widget();
    const allowed = this.def().filters;
    return {
      project:
        this.project() ??
        (allowed.includes('projectId') ? w.filters.projectId : undefined),
      tags: allowed.includes('tags') ? w.filters.tags : undefined,
      types: allowed.includes('types') ? w.filters.types : undefined,
    };
  });
  protected readonly links = computed(() => dashboardLinks(this.scope()));

  /** Filtros a la vista (el proyecto solo si es del widget y no del panel). */
  protected readonly chips = computed(() => {
    const w = this.widget();
    const s = this.scope();
    const chips: { key: string; text: string; icon: string; warn?: boolean }[] =
      [];
    const own = !this.locked() && !this.project() ? s.project : undefined;
    if (own) {
      const p = this.store.projectsById().get(own);
      chips.push(
        p
          ? { key: 'p', text: p.name, icon: 'bi-folder2' }
          : this.store.projectsLoaded()
            ? {
                key: 'p',
                text: 'Proyecto borrado',
                icon: 'bi-folder-x',
                warn: true,
              }
            : { key: 'p', text: '…', icon: 'bi-folder2' },
      );
    }
    for (const t of s.tags ?? [])
      chips.push({ key: `t:${t}`, text: t, icon: 'bi-tag' });
    for (const t of s.types ?? [])
      chips.push({
        key: `y:${t}`,
        text: ASSET_TYPE_LABELS[t],
        icon: 'bi-funnel',
      });
    if (w.filters.site)
      chips.push({
        key: 's',
        text: `${w.filters.site} (sin efecto)`,
        icon: 'bi-geo-alt',
      });
    return chips;
  });

  protected readonly menu = computed<MenuItem[]>(() => {
    const w = this.widget();
    const def = this.def();
    const item = (
      label: string,
      icon: string,
      act: WidgetAction,
      disabled = false,
    ): MenuItem => ({
      label,
      icon: `bi ${icon}`,
      disabled,
      command: () => this.action.emit(act),
    });
    return [
      item('Configurar…', 'bi-sliders', 'configure'),
      { separator: true },
      item('Mover antes', 'bi-arrow-up', 'before', this.first()),
      item('Mover después', 'bi-arrow-down', 'after', this.last()),
      item('Más ancho', 'bi-arrows', 'wider', w.w >= 12),
      item(
        'Más estrecho',
        'bi-arrows-collapse-vertical',
        'narrower',
        w.w <= def.min.w,
      ),
      item('Más alto', 'bi-arrows-vertical', 'taller', w.h >= 12),
      item('Más bajo', 'bi-arrows-collapse', 'shorter', w.h <= def.min.h),
      { separator: true },
      item('Quitar', 'bi-trash', 'remove'),
    ];
  });

  constructor() {
    this.store.ensureProjects();
  }

  protected reload(): void {
    this.retry.update((n) => n + 1);
  }
}
