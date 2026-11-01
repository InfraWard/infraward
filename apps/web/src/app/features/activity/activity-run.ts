import { DatePipe, Location } from '@angular/common';
import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  untracked,
} from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import type {
  JobRunLog,
  JobRunSummary,
  Page,
} from '@infraward/shared-types';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressBarModule } from '@openng/optimus-ui/progressbar';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { catchError, map, of, startWith, switchMap } from 'rxjs';
import { JobsApi } from '../../core/api/jobs-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { JobLogView } from '../../shared/job-log';
import {
  ASSET_TYPE_ICONS,
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

/** Con la ejecución o alguna de sus tareas pendiente, el detalle se refresca con esta cadencia. */
export const RUN_POLL_MS = 3000;
/** Tareas que se listan en el detalle (el resto, en la Actividad filtrada). */
export const RUN_CHILDREN_SHOWN = 50;

interface RunDetail {
  run: JobRunSummary;
  /** Las tareas que lanzó (solo si tiene alguna). */
  children: Page<JobRunSummary> | null;
}

type Loaded<T> =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; value: T };

/**
 * Detalle de una ejecución de la Actividad (`/activity/:id`): qué es y sobre qué asset, de dónde
 * viene (el lote o la tarea que la lanzó, enlazados, o si fue programada, manual o del alta), las
 * tareas que lanzó y su log. Mientras algo siga pendiente, se refresca sola.
 */
@Component({
  selector: 'app-activity-run',
  imports: [
    DatePipe,
    RouterLink,
    JobLogView,
    MessageModule,
    ProgressBarModule,
    SkeletonModule,
    TableModule,
    TagModule,
    TooltipModule,
  ],
  templateUrl: './activity-run.html',
  styleUrl: './activity-run.scss',
})
export class ActivityRun {
  private readonly api = inject(JobsApi);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly location = inject(Location);

  /** Parámetro `:id` de la ruta. */
  readonly id = input.required<string>();

  protected readonly jobLabels: Readonly<Record<string, string>> = JOB_LABELS;
  protected readonly jobIcons: Readonly<Record<string, string>> = JOB_ICONS;
  protected readonly stateLabels: Readonly<Record<string, string>> = JOB_STATE_LABELS;
  protected readonly stateSeverity: Readonly<Record<string, TagSeverity>> = JOB_STATE_SEVERITY;
  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly originLabels: Readonly<Record<string, string>> = JOB_ORIGIN_LABELS;
  protected readonly originIcons: Readonly<Record<string, string>> = JOB_ORIGIN_ICONS;
  protected readonly originHints: Readonly<Record<string, string>> = JOB_ORIGIN_HINTS;
  protected readonly duration = formatDuration;
  protected readonly isRunning = isRunning;
  protected readonly parentLabel = parentLabel;
  protected readonly childrenShown = RUN_CHILDREN_SHOWN;

  /** El log pide `assets.operate`, como en la ficha: lleva el stderr de los servidores. */
  protected readonly canReadLog = computed(() => this.auth.can('assets.operate'));

  /**
   * Se llegó desde la Actividad (o desde otro detalle): «←» es un «atrás», que conserva los
   * filtros y la página. Si no (enlace directo, recarga), lleva a la Actividad sin filtros.
   */
  protected readonly inApp = computed(() => {
    this.id();
    return untracked(() => {
      const state =
        this.router.currentNavigation()?.extras.state ??
        (typeof history === 'undefined' ? null : (history.state as unknown));
      return !!(state as { fromActivity?: boolean } | null)?.fromActivity;
    });
  });

  protected readonly loaded = toSignal(
    toObservable(this.id).pipe(
      switchMap((id) =>
        pollWhile(
          () =>
            this.api.run(id).pipe(
              switchMap((run) =>
                run.children
                  ? this.api
                      .list({ parentJobId: id, limit: RUN_CHILDREN_SHOWN })
                      .pipe(map((children): RunDetail => ({ run, children })))
                  : of<RunDetail>({ run, children: null }),
              ),
            ),
          (d) =>
            isRunning(d.run) ||
            !!d.run.children?.running ||
            !!d.children?.items.some(isRunning),
          RUN_POLL_MS,
        ).pipe(
          map((value): Loaded<RunDetail> => ({ state: 'ready', value })),
          catchError((err: unknown) =>
            of<Loaded<RunDetail>>({
              state: 'error',
              message: apiErrorMessage(err, 'No se pudo cargar la ejecución.'),
            }),
          ),
          startWith<Loaded<RunDetail>>({ state: 'loading' }),
        ),
      ),
    ),
    { initialValue: { state: 'loading' } as Loaded<RunDetail> },
  );

  /** Último detalle recibido de esta ejecución (se mantiene mientras se refresca). */
  protected readonly detail = linkedSignal<Loaded<RunDetail>, RunDetail | null>({
    source: this.loaded,
    computation: (l, previous) => {
      if (l.state === 'ready') return l.value;
      return l.state === 'loading' && previous?.value?.run.id === this.id()
        ? previous.value
        : null;
    },
  });

  /**
   * Ejecución cuyo log se pide: no hay sin permiso, ni de una operación en lote (no ejecuta nada:
   * el log está en cada una de sus tareas).
   */
  private readonly logRunId = computed(() => {
    const run = this.detail()?.run;
    if (!run || !this.canReadLog() || run.name === 'assets.bulk') return null;
    return run.id;
  });

  protected readonly log = toSignal(
    toObservable(this.logRunId).pipe(
      switchMap((id) =>
        id
          ? pollWhile(
              () => this.api.jobRunLog(id),
              (log) => isRunning(log.run),
              RUN_POLL_MS,
            ).pipe(
              map((value): Loaded<JobRunLog> => ({ state: 'ready', value })),
              catchError((err: unknown) =>
                of<Loaded<JobRunLog>>({
                  state: 'error',
                  message: apiErrorMessage(err, 'No se pudo cargar el log.'),
                }),
              ),
              startWith<Loaded<JobRunLog>>({ state: 'loading' }),
            )
          : of(null),
      ),
    ),
    { initialValue: null },
  );

  /**
   * El último mensaje, salvo en curso (va con la barra de progreso) o si solo repite el error
   * (`Fallo: …`, que ya se ve arriba).
   */
  protected showMessage(run: JobRunSummary): boolean {
    if (!run.message || run.state === 'active') return false;
    return !(run.state === 'failed' && run.message.startsWith('Fallo'));
  }

  back(event: Event): void {
    if (!this.inApp()) return;
    event.preventDefault();
    this.location.back();
  }
}
