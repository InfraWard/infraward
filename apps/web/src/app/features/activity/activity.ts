import { DatePipe } from '@angular/common';
import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  signal,
} from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import {
  JOB_NAMES,
  JOB_RUN_ORIGINS,
  JOB_RUN_STATE_FILTERS,
  type JobName,
  type JobRunListQuery,
  type JobRunOrigin,
  type JobRunStateFilter,
  type JobRunSummary,
  type Page,
  type WorkerReplica,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { ChipModule } from '@openng/optimus-ui/chip';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressBarModule } from '@openng/optimus-ui/progressbar';
import { SelectModule } from '@openng/optimus-ui/select';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { TableLazyLoadEvent } from '@openng/optimus-ui/types/table';
import { catchError, map, of, startWith, switchMap, timer } from 'rxjs';
import { JobsApi } from '../../core/api/jobs-api';
import { apiErrorMessage } from '../../shared/api-errors';
import {
  ASSET_TYPE_ICONS,
  bulkSummary,
  formatDuration,
  isRunning,
  JOB_ICONS,
  JOB_LABELS,
  JOB_ORIGIN_HINTS,
  JOB_ORIGIN_ICONS,
  JOB_ORIGIN_LABELS,
  JOB_STATE_LABELS,
  JOB_STATE_SEVERITY,
  parentLabel,
  type TagSeverity,
} from '../../shared/labels';
import { pollWhile } from '../../shared/poll';

export const ACTIVITY_PAGE = 25;
/** Con algo en cola o en curso, la lista se refresca con esta cadencia. */
export const ACTIVITY_POLL_MS = 3000;
/** Cadencia con la que se miran las réplicas del worker conectadas. */
export const WORKERS_POLL_MS = 15_000;

/** «3 workers conectados» y el detalle de cada réplica (para el tooltip). */
export function workersSummary(workers: readonly WorkerReplica[]): {
  label: string;
  detail: string;
} {
  const n = workers.length;
  return {
    label:
      n === 0
        ? 'Ningún worker conectado'
        : `${n} ${n === 1 ? 'worker conectado' : 'workers conectados'}`,
    detail: workers
      .map(
        (w) =>
          `${w.name} en ${w.host}${w.leader ? ' (líder)' : ''}: ${w.queues.join(', ')}`,
      )
      .join('\n'),
  };
}

const UUID = /^[0-9a-f-]{36}$/i;

/**
 * Filtros de la URL (`?state=failed&name=asset.collect&origin=bulk&assetId=…&parentJobId=…`),
 * validados. `parentJobId`: las tareas de una operación en lote (o las que encadenó otra).
 */
export function activityQuery(
  params: {
    state?: string;
    name?: string;
    origin?: string;
    assetId?: string;
    parentJobId?: string;
  },
  page: { offset: number; limit: number },
): JobRunListQuery {
  const state = (JOB_RUN_STATE_FILTERS as readonly string[]).includes(
    params.state ?? '',
  )
    ? (params.state as JobRunStateFilter)
    : undefined;
  const name = (Object.values(JOB_NAMES) as string[]).includes(params.name ?? '')
    ? (params.name as JobName)
    : undefined;
  const assetId = UUID.test(params.assetId ?? '') ? params.assetId : undefined;
  const parentJobId = UUID.test(params.parentJobId ?? '') ? params.parentJobId : undefined;
  const origin = (JOB_RUN_ORIGINS as readonly string[]).includes(params.origin ?? '')
    ? (params.origin as JobRunOrigin)
    : undefined;
  return {
    state,
    name,
    ...(origin ? { origin } : {}),
    assetId,
    parentJobId,
    limit: page.limit,
    offset: page.offset,
  };
}

type Loaded =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; page: Page<JobRunSummary> };

/**
 * Actividad del worker: recolecciones, descubrimientos, escaneos y verificaciones de alta, en
 * curso y recientes (historial de `job_runs`), con de dónde viene cada una (un lote, otra tarea,
 * la comprobación periódica…). Cada fila abre su detalle con el log (`/activity/:id`). Mientras
 * haya algo pendiente se refresca sola.
 */
@Component({
  selector: 'app-activity',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    ChipModule,
    MessageModule,
    ProgressBarModule,
    SelectModule,
    SelectButtonModule,
    TableModule,
    TagModule,
    TooltipModule,
  ],
  templateUrl: './activity.html',
  styleUrl: './activity.scss',
})
export class Activity {
  private readonly api = inject(JobsApi);
  private readonly router = inject(Router);

  /** Query params (enlazados por el router). */
  readonly state = input<string>();
  readonly name = input<string>();
  readonly origin = input<string>();
  readonly assetId = input<string>();
  readonly parentJobId = input<string>();

  protected readonly pageSize = ACTIVITY_PAGE;
  protected readonly jobLabels: Readonly<Record<string, string>> = JOB_LABELS;
  protected readonly jobIcons: Readonly<Record<string, string>> = JOB_ICONS;
  protected readonly stateLabels: Readonly<Record<string, string>> =
    JOB_STATE_LABELS;
  protected readonly stateSeverity: Readonly<Record<string, TagSeverity>> =
    JOB_STATE_SEVERITY;
  protected readonly typeIcons: Readonly<Record<string, string>> =
    ASSET_TYPE_ICONS;
  protected readonly originLabels: Readonly<Record<string, string>> = JOB_ORIGIN_LABELS;
  protected readonly originIcons: Readonly<Record<string, string>> = JOB_ORIGIN_ICONS;
  protected readonly originHints: Readonly<Record<string, string>> = JOB_ORIGIN_HINTS;
  protected readonly duration = formatDuration;
  protected readonly isRunning = isRunning;
  protected readonly parentLabel = parentLabel;
  protected readonly bulkSummary = bulkSummary;

  protected readonly stateOptions = [
    { label: 'Todas', value: null },
    { label: 'En curso', value: 'running' },
    { label: 'Fallidas', value: 'failed' },
    { label: 'Terminadas', value: 'completed' },
  ];
  protected readonly nameOptions = [
    { label: 'Todos los tipos', value: null },
    ...Object.values(JOB_NAMES)
      .filter((n) => n !== JOB_NAMES.ping)
      .map((n) => ({ label: JOB_LABELS[n], value: n })),
  ];
  protected readonly originOptions = [
    { label: 'Cualquier origen', value: null },
    ...JOB_RUN_ORIGINS.map((o) => ({
      label: JOB_ORIGIN_LABELS[o],
      value: o,
      icon: JOB_ORIGIN_ICONS[o],
    })),
  ];

  protected readonly first = signal(0);
  protected readonly query = computed(() =>
    activityQuery(
      {
        state: this.state(),
        name: this.name(),
        origin: this.origin(),
        assetId: this.assetId(),
        parentJobId: this.parentJobId(),
      },
      { offset: this.first(), limit: ACTIVITY_PAGE },
    ),
  );

  protected readonly loaded = toSignal(
    toObservable(this.query).pipe(
      switchMap((query) =>
        pollWhile(
          () => this.api.list(query),
          // Una operación en lote está terminada, pero sus tareas pueden seguir en curso.
          (page) => page.items.some((r) => isRunning(r) || !!r.children?.running),
          ACTIVITY_POLL_MS,
        ).pipe(
          map((page): Loaded => ({ state: 'ready', page })),
          catchError((err: unknown) =>
            of<Loaded>({
              state: 'error',
              message: apiErrorMessage(err, 'No se pudo cargar la actividad.'),
            }),
          ),
          startWith<Loaded>({ state: 'loading' }),
        ),
      ),
    ),
    { initialValue: { state: 'loading' } as Loaded },
  );

  /** Última página recibida (se mantiene mientras se carga la siguiente). */
  protected readonly page = linkedSignal<Loaded, Page<JobRunSummary>>({
    source: this.loaded,
    computation: (l, previous) =>
      l.state === 'ready' ? l.page : (previous?.value ?? { items: [], total: 0 }),
  });
  protected readonly running = computed(
    () => this.page().items.filter(isRunning).length,
  );
  /** Réplicas del worker (null si no se pudo saber: la Actividad funciona igual). */
  protected readonly workers = toSignal(
    timer(0, WORKERS_POLL_MS).pipe(
      switchMap(() =>
        this.api.workers().pipe(
          map(workersSummary),
          catchError(() => of(null)),
        ),
      ),
    ),
    { initialValue: null },
  );
  /**
   * La operación o tarea cuyas tareas se están viendo (`?parentJobId=`), para el chip y su enlace.
   * null mientras carga o si ya no está en el historial.
   */
  protected readonly parentRun = toSignal(
    toObservable(computed(() => this.query().parentJobId)).pipe(
      switchMap((id) =>
        id
          ? this.api.run(id).pipe(catchError(() => of(null)))
          : of(null),
      ),
    ),
    { initialValue: null },
  );
  /** Nombre del asset filtrado (de las filas, para el chip). */
  protected readonly assetName = computed(
    () => this.page().items.find((r) => r.assetId === this.query().assetId)?.assetName ?? 'este asset',
  );

  setFilter(change: {
    state?: string | null;
    name?: string | null;
    origin?: string | null;
    assetId?: null;
    parentJobId?: null;
  }): void {
    this.first.set(0);
    void this.router.navigate([], {
      queryParams: change,
      queryParamsHandling: 'merge',
    });
  }

  /** Un clic en la fila abre su detalle (salvo que sea en un enlace o un botón de la fila). */
  openRun(run: JobRunSummary, event: MouseEvent): void {
    if ((event.target as HTMLElement | null)?.closest('a, button')) return;
    void this.router.navigate(['/activity', run.id], {
      state: { fromActivity: true },
    });
  }

  onLazyLoad(event: TableLazyLoadEvent): void {
    const first = event.first ?? 0;
    if (first !== this.first()) this.first.set(first);
  }
}
