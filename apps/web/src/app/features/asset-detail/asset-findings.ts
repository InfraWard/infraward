import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import {
  FINDING_STATUSES,
  SEVERITIES,
  type ContainerImageSummary,
  type SbomSummary,
  type FindingListQuery,
  type FindingStatus,
  type PriorityBand,
  type Severity,
  type VulnerabilityGroup,
  HIDDEN_REASON_LABELS,
  PRIORITY_BAND_LABELS,
  PRIORITY_BANDS,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import type { TableLazyLoadEvent } from '@openng/optimus-ui/types/table';
import { FindingsApi } from '../../core/api/findings-api';
import { SEVERITY_TAG, type TagSeverity } from '../../shared/labels';
import { PriorityReasons, PriorityScore } from '../../shared/priority';
import {
  filterFromParams,
  paramsFromFilter,
} from '../vulnerabilities/vulnerability-filter';
import type { VulnerabilityOrigin } from '../vulnerabilities/vulnerability-view';

export const FINDINGS_PAGE = 25;

/** «Urgente», «Alta o más»…, y «Todas». */
export const PRIORITY_OPTIONS: { label: string; value: PriorityBand | null }[] = [
  { label: 'Todas', value: null },
  ...[...PRIORITY_BANDS]
    .reverse()
    .map((b) => ({
      label: b === 'urgent' ? PRIORITY_BAND_LABELS[b] : `${PRIORITY_BAND_LABELS[b]} o más`,
      value: b,
    })),
];

/**
 * Filtro de las listas de vulnerabilidades (la global y la del asset). Por defecto, la vista
 * principal (DESIGN §9): abiertas con prioridad media o más, por prioridad.
 */
export interface FindingsFilter {
  status: FindingStatus | null;
  minSeverity: Severity | null;
  fixable: boolean;
  minPriority: PriorityBand | null;
  kev: boolean;
  /** EPSS mínimo (0–1). */
  minEpss: number | null;
  /** Expuestas: puerto fuera de loopback, contenedor publicado o nombre público. */
  exposed: boolean;
}

export const DEFAULT_FINDINGS_FILTER: FindingsFilter = {
  status: 'open',
  minSeverity: null,
  fixable: false,
  minPriority: 'medium',
  kev: false,
  minEpss: null,
  exposed: false,
};

/** Sin filtros de prioridad, severidad, parche ni explotación («ver todas»); el estado se conserva. */
export function showAll(filter: FindingsFilter): FindingsFilter {
  return {
    ...filter,
    minSeverity: null,
    fixable: false,
    minPriority: null,
    kev: false,
    minEpss: null,
    exposed: false,
  };
}

/** ¿Deja algo fuera por prioridad, severidad, parche o explotación? */
export function isFiltered(filter: FindingsFilter): boolean {
  return (
    filter.minPriority !== null ||
    filter.minSeverity !== null ||
    filter.fixable ||
    filter.kev ||
    filter.minEpss !== null ||
    filter.exposed
  );
}

export function toQuery(
  filter: FindingsFilter,
  page: { offset: number; limit: number },
): FindingListQuery {
  return {
    ...(filter.status ? { status: filter.status } : {}),
    ...(filter.minSeverity ? { minSeverity: filter.minSeverity } : {}),
    ...(filter.fixable ? { fixable: true } : {}),
    ...(filter.minPriority ? { minPriority: filter.minPriority } : {}),
    ...(filter.kev ? { kev: true } : {}),
    ...(filter.minEpss !== null ? { minEpss: filter.minEpss } : {}),
    ...(filter.exposed ? { exposure: 'any' as const } : {}),
    limit: page.limit,
    offset: page.offset,
  };
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  open: 'Abierto',
  fixed: 'Corregido',
  accepted: 'Aceptado',
};

const SCAN_STATUS_LABELS: Record<ContainerImageSummary['scanStatus'], string> =
  {
    pending: 'Pendiente de escaneo',
    scanned: 'Escaneada',
    skipped: 'No escaneada',
    failed: 'Escaneo fallido',
  };

/** «openssl, libssl3 +2» para la fila del CVE. */
export function packagesLabel(group: VulnerabilityGroup, shown = 2): string {
  const names = [...new Set(group.packages.map((p) => p.packageName))];
  const rest = names.length - shown;
  return names.slice(0, shown).join(', ') + (rest > 0 ? ` +${rest}` : '');
}

/**
 * Vulnerabilidades de un asset (las de su imagen si es un contenedor), una fila por CVE con los
 * paquetes afectados dentro, y con el filtro por defecto.
 */
@Component({
  selector: 'app-asset-findings',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    CheckboxModule,
    MessageModule,
    SelectModule,
    TableModule,
    TagModule,
    PriorityReasons,
    PriorityScore,
  ],
  template: `
    @if (image(); as img) {
      <p class="scan" data-scan>
        <i class="bi bi-layers" aria-hidden="true"></i>
        Imagen <code>{{ img.repoTags[0] ?? img.imageId.slice(0, 19) }}</code
        >:
        <p-tag
          [value]="scanLabels[img.scanStatus]"
          [severity]="img.scanStatus === 'scanned' ? 'success' : 'warn'"
        />
        @if (img.scannedAt) {
          <span class="muted">el {{ img.scannedAt | date: 'short' }}</span>
        }
        @if (img.trivyVersion) {
          <span class="muted">· Trivy {{ img.trivyVersion }}</span>
        }
        @if (img.scanReason) {
          <span class="muted">· {{ img.scanReason }}</span>
        }
      </p>
    }

    @if (scanDisabled()) {
      <p class="scan muted" data-scan-disabled>
        <i class="bi bi-slash-circle" aria-hidden="true"></i>
        Escaneo desactivado por la política de inventario: no se vuelve a escanear y estas
        vulnerabilidades no cuentan en el panel ni en las listas (se conservan aquí).
      </p>
    }
    @if (sbom(); as sb) {
      <p class="scan" data-sbom>
        <i class="bi bi-box-seam" aria-hidden="true"></i>
        SBOM: {{ sb.packageCount }} paquetes
        @if (sb.os) {
          <span class="muted">· {{ sb.os.family }} {{ sb.os.name }}</span>
        }
        @if (sb.evaluatedAt) {
          <span class="muted">· evaluado el {{ sb.evaluatedAt | date: 'short' }}</span>
        }
        @if (sb.dbUpdatedAt) {
          <span class="muted"
            >· BD de Trivy del {{ sb.dbUpdatedAt | date: 'shortDate' }}</span
          >
        }
        @if (sb.evaluationError) {
          <span class="muted"
            >· última re-evaluación fallida: {{ sb.evaluationError }}</span
          >
        }
      </p>
    } @else if (loaded() && !image()) {
      <p class="scan muted" data-sbom>
        <i class="bi bi-box-seam" aria-hidden="true"></i>
        Sin SBOM todavía: se genera al recoger el asset o con «Escanear vulnerabilidades».
      </p>
    }

    <p class="summary muted" data-total>
      {{ total() }} {{ total() === 1 ? 'vulnerabilidad' : 'vulnerabilidades' }}
      {{ filtered() ? 'con este filtro' : 'en total' }} (una fila por CVE).
    </p>

    <div class="filters">
      <span class="field">
        <label for="findingStatus">Estado</label>
        <p-select
          inputId="findingStatus"
          [options]="statusOptions"
          optionLabel="label"
          optionValue="value"
          [ngModel]="filter().status"
          (ngModelChange)="update({ status: $event })"
        />
      </span>
      <span class="field">
        <label for="minPriority">Prioridad mínima</label>
        <p-select
          inputId="minPriority"
          [options]="priorityOptions"
          optionLabel="label"
          optionValue="value"
          [ngModel]="filter().minPriority"
          (ngModelChange)="update({ minPriority: $event })"
          data-filter="prio"
        />
      </span>
      <span class="field">
        <label for="minSeverity">Severidad mínima</label>
        <p-select
          inputId="minSeverity"
          [options]="severityOptions"
          optionLabel="label"
          optionValue="value"
          [ngModel]="filter().minSeverity"
          (ngModelChange)="update({ minSeverity: $event })"
        />
      </span>
      <span class="check">
        <p-checkbox
          inputId="fixable"
          [binary]="true"
          [ngModel]="filter().fixable"
          (ngModelChange)="update({ fixable: $event })"
        />
        <label for="fixable">Solo con parche</label>
      </span>
      @if (filtered()) {
        <p-button
          label="Ver todas"
          icon="bi bi-funnel"
          severity="secondary"
          [text]="true"
          (onClick)="setFilter(showAll(filter()))"
          data-action="show-all"
        />
      } @else {
        <p-button
          label="Solo lo accionable"
          icon="bi bi-funnel-fill"
          severity="secondary"
          [text]="true"
          (onClick)="setFilter(defaults)"
          data-action="defaults"
        />
      }
    </div>

    <p-table
      [value]="items()"
      [lazy]="true"
      [paginator]="true"
      [rows]="pageSize"
      [first]="first()"
      [totalRecords]="total()"
      [loading]="loading()"
      dataKey="vulnerabilityId"
      [expandedRowKeys]="expanded()"
      size="small"
      (onLazyLoad)="onLazyLoad($event)"
      (onRowExpand)="toggle($event.data.vulnerabilityId, true)"
      (onRowCollapse)="toggle($event.data.vulnerabilityId, false)"
    >
      <ng-template #header>
        <tr>
          <th style="width: 3rem"><span class="sr-only">Paquetes</span></th>
          <th style="width: 7.5rem">Prioridad</th>
          <th>Vulnerabilidad</th>
          <th style="width: 7rem">Severidad</th>
          <th>Paquetes afectados</th>
          <th style="width: 8rem">Parche</th>
        </tr>
      </ng-template>
      <ng-template #body let-g let-expandedRow="expanded">
        <tr [attr.data-vulnerability]="g.vulnerabilityId" [class.noise]="!!g.noiseReason">
          <td>
            <p-button
              [pRowToggler]="g"
              [text]="true"
              [rounded]="true"
              severity="secondary"
              size="small"
              [icon]="expandedRow ? 'bi bi-chevron-down' : 'bi bi-chevron-right'"
              [ariaLabel]="(expandedRow ? 'Ocultar' : 'Ver') + ' los paquetes de ' + g.vulnerabilityId"
            />
          </td>
          <td><app-priority-score [priority]="g.priority" /></td>
          <td>
            <a [routerLink]="['/vulnerabilities', g.vulnerabilityId]" [state]="origin()">{{
              g.vulnerabilityId
            }}</a>
            @if (g.kev) {
              <p-tag value="KEV" severity="danger" icon="bi bi-fire" styleClass="kev" />
            }
            @if (g.title) {
              <div class="muted small">{{ g.title }}</div>
            }
            <app-priority-reasons [reasons]="g.priority?.reasons" />
          </td>
          <td>
            <p-tag [value]="g.severity" [severity]="severityTag[g.severity]" />
          </td>
          <td>
            <code>{{ packagesLabel(g) }}</code>
            <span class="muted small" data-package-count>
              · {{ g.packages.length }} {{ g.packages.length === 1 ? 'paquete' : 'paquetes' }}</span
            >
          </td>
          <td>
            @if (g.fixable) {
              <p-tag value="Disponible" severity="success" icon="bi bi-check2" />
            } @else {
              <span class="muted">Sin parche</span>
            }
          </td>
        </tr>
      </ng-template>
      <ng-template #expandedrow let-g>
        <tr class="packages-row">
          <td></td>
          <td colspan="5">
            <table class="packages" [attr.data-packages]="g.vulnerabilityId">
              <thead>
                <tr>
                  <th>Paquete</th>
                  <th>Instalada</th>
                  <th>Corregida en</th>
                  <th>Estado</th>
                  <th>Prioridad</th>
                </tr>
              </thead>
              <tbody>
                @for (p of g.packages; track p.findingId) {
                  <tr>
                    <td>
                      <code>{{ p.packageName }}</code>
                      @if (p.pkgPath) {
                        <div class="muted small">{{ p.pkgPath }}</div>
                      }
                    </td>
                    <td><code>{{ p.installedVersion }}</code></td>
                    <td>
                      @if (p.fixedVersion) {
                        <code>{{ p.fixedVersion }}</code>
                      } @else {
                        <span class="muted">sin parche</span>
                      }
                    </td>
                    <td>{{ statusLabels[p.status] }}</td>
                    <td>
                      {{ p.priority ?? '—' }}
                      @if (p.noiseReason) {
                        <span class="muted small">· {{ hiddenLabels[p.noiseReason] }}</span>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </td>
        </tr>
      </ng-template>
      <ng-template #emptymessage>
        <tr>
          <td colspan="6" class="muted">
            @if (filtered()) {
              Nada que corregir con este filtro.
              <a
                href=""
                (click)="$event.preventDefault(); setFilter(showAll(filter()))"
                >Ver todas</a
              >
            } @else {
              Sin vulnerabilidades.
            }
          </td>
        </tr>
      </ng-template>
    </p-table>
    @if (error(); as message) {
      <p-message severity="error" icon="bi bi-exclamation-triangle">{{
        message
      }}</p-message>
    }
  `,
  styles: `
    .scan {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .filters {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: flex-end;
      margin-bottom: 0.75rem;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    .check {
      display: inline-flex;
      gap: 0.5rem;
      align-items: center;
      padding-bottom: 0.5rem;
    }
    .muted {
      color: var(--p-text-muted-color);
    }
    .small {
      font-size: 0.8rem;
    }
    tr.noise > td {
      opacity: 0.7;
    }
    :host ::ng-deep .kev {
      margin-left: 0.4rem;
      font-size: 0.7rem;
    }
    a {
      color: var(--p-primary-color);
      text-decoration: none;
    }
    .summary {
      margin: 0 0 0.75rem;
    }
    .packages {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
      th,
      td {
        text-align: left;
        padding: 0.3rem 0.5rem;
        border-bottom: 1px solid var(--p-content-border-color);
      }
      th {
        font-weight: 600;
        color: var(--p-text-muted-color);
      }
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }
  `,
})
export class AssetFindings {
  private readonly api = inject(FindingsApi);

  readonly assetId = input.required<string>();
  /** Escaneo desactivado por su política (§10): se avisa y sus findings no cuentan fuera. */
  readonly scanDisabled = input(false);
  /** Nombre del asset, para el «← volver» de la ficha del CVE. */
  readonly assetName = input<string>();
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  /** Estado de la navegación al CVE: volver a esta ficha (con la pestaña, que va en la URL). */
  protected origin(): { from: VulnerabilityOrigin } | undefined {
    const label = this.assetName();
    return label ? { from: { url: this.router.url, label } } : undefined;
  }

  protected readonly pageSize = FINDINGS_PAGE;
  protected readonly defaults = DEFAULT_FINDINGS_FILTER;
  protected readonly showAll = showAll;
  protected readonly severityTag: Readonly<Record<string, TagSeverity>> =
    SEVERITY_TAG;
  protected readonly statusLabels: Readonly<Record<string, string>> =
    STATUS_LABELS;
  protected readonly scanLabels: Readonly<Record<string, string>> =
    SCAN_STATUS_LABELS;
  protected readonly statusOptions = [
    { label: 'Todos', value: null },
    ...FINDING_STATUSES.map((s) => ({ label: STATUS_LABELS[s], value: s })),
  ];
  protected readonly hiddenLabels: Readonly<Record<string, string>> =
    HIDDEN_REASON_LABELS;
  protected readonly priorityOptions = PRIORITY_OPTIONS;
  protected readonly severityOptions = [
    { label: 'Todas', value: null },
    ...[...SEVERITIES]
      .reverse()
      .map((s) => ({ label: `${s} o más`, value: s })),
  ];

  /**
   * Filtro de la pestaña, en la URL de la ficha (`?status=&min=&fixable=`, como la lista): al volver
   * de la ficha de un CVE se ve lo mismo que antes.
   */
  protected readonly filter = signal<FindingsFilter>(
    filterFromParams(this.route.snapshot.queryParams),
  );
  protected readonly filtered = computed(() => isFiltered(this.filter()));
  protected readonly items = signal<VulnerabilityGroup[]>([]);
  protected readonly expanded = signal<Record<string, boolean>>({});
  protected readonly packagesLabel = packagesLabel;
  protected readonly total = signal(0);
  protected readonly first = signal(0);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly image = signal<ContainerImageSummary | null>(null);
  protected readonly sbom = signal<SbomSummary | null>(null);
  /** Ya llegó la primera página (para no avisar de «sin SBOM» mientras carga). */
  protected readonly loaded = signal(false);
  private request = 0;

  update(change: Partial<FindingsFilter>): void {
    this.setFilter({ ...this.filter(), ...change });
  }

  setFilter(filter: FindingsFilter): void {
    this.filter.set(filter);
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: paramsFromFilter(filter),
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
    this.load(0);
  }

  onLazyLoad(event: TableLazyLoadEvent): void {
    this.load(event.first ?? 0);
  }

  toggle(id: string, open: boolean): void {
    this.expanded.update((e) => ({ ...e, [id]: open }));
  }

  private load(offset: number): void {
    const id = ++this.request;
    this.first.set(offset);
    this.loading.set(true);
    this.error.set(null);
    this.api
      .assetVulnerabilities(
        this.assetId(),
        toQuery(this.filter(), { offset, limit: FINDINGS_PAGE }),
      )
      .subscribe({
        next: (page) => {
          if (id !== this.request) return;
          this.items.set(page.items);
          this.expanded.set({});
          this.total.set(page.total);
          this.image.set(page.image);
          this.sbom.set(page.sbom);
          this.loaded.set(true);
          this.loading.set(false);
        },
        error: () => {
          if (id !== this.request) return;
          this.loading.set(false);
          this.error.set('No se pudieron cargar las vulnerabilidades.');
        },
      });
  }
}
