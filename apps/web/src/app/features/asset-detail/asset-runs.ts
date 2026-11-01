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
import { RouterLink } from '@angular/router';
import type { JobRunLog, JobRunSummary, Page } from '@infraward/shared-types';
import { MessageModule } from '@openng/optimus-ui/message';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import type { TableLazyLoadEvent } from '@openng/optimus-ui/types/table';
import { catchError, combineLatest, map, of, startWith, switchMap } from 'rxjs';
import { JobsApi } from '../../core/api/jobs-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { JobLogView } from '../../shared/job-log';
import {
  formatDuration,
  isRunning,
  JOB_ICONS,
  JOB_LABELS,
  JOB_STATE_LABELS,
  JOB_STATE_SEVERITY,
  type TagSeverity,
} from '../../shared/labels';
import { pollWhile } from '../../shared/poll';

export const RUNS_PAGE = 15;
/** Con algo en cola o en curso, la lista y el log abierto se refrescan con esta cadencia. */
export const RUNS_POLL_MS = 3000;

type Loaded<T> =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; value: T };

/**
 * Pestaña «Recolecciones» de la ficha (DESIGN §20, «Log de cada ejecución»): las ejecuciones del
 * asset (recolecciones, descubrimientos, escaneos…) con su estado y duración, y el log de la que
 * se elija en un visor monoespaciado por niveles. Mientras haya algo en curso, se refresca sola.
 */
@Component({
  selector: 'app-asset-runs',
  imports: [
    DatePipe,
    RouterLink,
    JobLogView,
    MessageModule,
    SkeletonModule,
    TableModule,
    TagModule,
  ],
  template: `
    <div class="runs">
      <div>
        @if (list(); as l) {
          @if (l.state === 'error') {
            <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mb">{{ l.message }}</p-message>
          }
        }
        <p-table
          [value]="page().items"
          [lazy]="true"
          [paginator]="page().total > pageSize"
          [rows]="pageSize"
          [first]="first()"
          [totalRecords]="page().total"
          [loading]="list().state === 'loading'"
          selectionMode="single"
          [selection]="selectedRun()"
          (selectionChange)="select($event)"
          dataKey="id"
          size="small"
          (onLazyLoad)="onLazyLoad($event)"
        >
          <ng-template #header>
            <tr>
              <th scope="col">Fecha</th>
              <th scope="col">Tipo</th>
              <th scope="col">Estado</th>
              <th scope="col">Duración</th>
            </tr>
          </ng-template>
          <ng-template #body let-r>
            <tr [pSelectableRow]="r" class="clickable" [class.failed]="r.state === 'failed'" [attr.data-run]="r.id">
              <td class="nowrap">{{ r.createdAt | date: 'short' }}</td>
              <td>
                <i [class]="'bi ' + jobIcons[r.name]" aria-hidden="true"></i> {{ jobLabels[r.name] ?? r.name }}
              </td>
              <td>
                <p-tag [value]="stateLabels[r.state]" [severity]="stateSeverity[r.state]" />
                @if (!r.hasLog && !isRunning(r)) {
                  <i class="bi bi-journal-x muted no-log" title="Sin log" aria-label="Sin log"></i>
                }
              </td>
              <td class="nowrap">{{ duration(r.durationMs) }}</td>
            </tr>
          </ng-template>
          <ng-template #emptymessage>
            <tr><td colspan="4" class="muted">Sin ejecuciones: aún no se ha recogido ni escaneado.</td></tr>
          </ng-template>
        </p-table>
        <p class="muted small">Los logs antiguos se borran automáticamente pasado un tiempo.</p>
      </div>

      <div class="log-panel">
        @if (selectedRun() && !canReadLog()) {
          <p-message severity="info" icon="bi bi-lock" data-log-forbidden>
            Ver el log de una ejecución requiere permiso para operar el inventario (admin, editor u
            operador): lleva errores de los servidores.
          </p-message>
        } @else if (selectedRun(); as run) {
          <div class="log-head">
            <h3>
              <i [class]="'bi ' + jobIcons[run.name]" aria-hidden="true"></i>
              {{ jobLabels[run.name] ?? run.name }} del {{ run.createdAt | date: 'medium' }}
            </h3>
            <a [routerLink]="['/activity', run.id]" class="open-activity" data-open-activity>
              Ver en la Actividad <i class="bi bi-box-arrow-up-right" aria-hidden="true"></i>
            </a>
          </div>
          @if (log(); as l) {
            @if (l.state === 'loading') {
              <p-skeleton height="12rem" />
            } @else if (l.state === 'error') {
              <p-message severity="error" icon="bi bi-exclamation-triangle">{{ l.message }}</p-message>
            } @else {
              <app-job-log [log]="l.value" />
            }
          }
        } @else {
          <p class="muted">
            Cada recolección, descubrimiento o escaneo guarda su log: pasos, comandos con su duración,
            errores y resultado (sin secretos). Selecciona una para verlo.
          </p>
        }
      </div>
    </div>
  `,
  styles: `
    .runs {
      display: grid;
      grid-template-columns: minmax(20rem, 2fr) 3fr;
      gap: 1.5rem;
      align-items: start;
    }
    @media (width < 900px) {
      .runs {
        grid-template-columns: 1fr;
      }
    }
    .clickable {
      cursor: pointer;
    }
    tr.failed td {
      background: color-mix(in srgb, var(--p-red-500, #ef4444) 10%, transparent);
    }
    tr.failed td:first-child {
      box-shadow: inset 3px 0 0 var(--p-red-500, #ef4444);
    }
    .nowrap {
      white-space: nowrap;
    }
    .muted {
      color: var(--p-text-muted-color);
    }
    .small {
      font-size: 0.85rem;
    }
    .no-log {
      margin-left: 0.35rem;
    }
    h3 {
      margin: 0 0 0.75rem;
      font-size: 1.1rem;
    }
    .log-head {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1rem;
      align-items: baseline;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }
    .log-head h3 {
      margin: 0;
    }
    .open-activity {
      font-size: 0.9rem;
      white-space: nowrap;
    }
    :host ::ng-deep .mb {
      margin-bottom: 0.75rem;
    }
  `,
})
export class AssetRuns {
  private readonly api = inject(JobsApi);
  private readonly auth = inject(AuthService);

  readonly assetId = input.required<string>();

  protected readonly pageSize = RUNS_PAGE;
  protected readonly jobLabels: Readonly<Record<string, string>> = JOB_LABELS;
  protected readonly jobIcons: Readonly<Record<string, string>> = JOB_ICONS;
  protected readonly stateLabels: Readonly<Record<string, string>> = JOB_STATE_LABELS;
  protected readonly stateSeverity: Readonly<Record<string, TagSeverity>> = JOB_STATE_SEVERITY;
  protected readonly duration = formatDuration;
  protected readonly isRunning = isRunning;

  protected readonly first = signal(0);
  protected readonly selectedId = signal<string | null>(null);
  /** El log (no la lista) pide `assets.operate`: lleva el stderr de los servidores. */
  protected readonly canReadLog = computed(() => this.auth.can('assets.operate'));

  protected readonly list = toSignal(
    combineLatest([toObservable(this.assetId), toObservable(this.first)]).pipe(
      switchMap(([assetId, offset]) =>
        pollWhile(
          () => this.api.assetRuns(assetId, { limit: RUNS_PAGE, offset }),
          (page) => page.items.some(isRunning),
          RUNS_POLL_MS,
        ).pipe(
          map((value): Loaded<Page<JobRunSummary>> => ({ state: 'ready', value })),
          catchError((err: unknown) =>
            of<Loaded<Page<JobRunSummary>>>({
              state: 'error',
              message: apiErrorMessage(err, 'No se pudieron cargar las ejecuciones.'),
            }),
          ),
          startWith<Loaded<Page<JobRunSummary>>>({ state: 'loading' }),
        ),
      ),
    ),
    { initialValue: { state: 'loading' } as Loaded<Page<JobRunSummary>> },
  );

  /** Última página recibida (se mantiene mientras se carga la siguiente). */
  protected readonly page = linkedSignal<
    Loaded<Page<JobRunSummary>>,
    Page<JobRunSummary>
  >({
    source: this.list,
    computation: (l, previous) =>
      l.state === 'ready' ? l.value : (previous?.value ?? { items: [], total: 0 }),
  });

  protected readonly selectedRun = computed(
    () => this.page().items.find((r) => r.id === this.selectedId()) ?? null,
  );

  protected readonly log = toSignal(
    combineLatest([toObservable(this.assetId), toObservable(this.selectedId)]).pipe(
      switchMap(([assetId, runId]) =>
        runId && this.canReadLog()
          ? pollWhile(
              () => this.api.runLog(assetId, runId),
              (log) => isRunning(log.run),
              RUNS_POLL_MS,
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

  select(run: JobRunSummary | JobRunSummary[] | null | undefined): void {
    const one = Array.isArray(run) ? run[0] : run;
    this.selectedId.set(one?.id ?? null);
  }

  onLazyLoad(event: TableLazyLoadEvent): void {
    const first = event.first ?? 0;
    if (first !== this.first()) this.first.set(first);
  }
}
