import { DatePipe } from '@angular/common';
import { Component, computed, DestroyRef, inject, signal, type OnInit } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import {
  ASSET_TYPES,
  AUDIT_ACTIONS,
  AUDIT_OUTCOMES,
  type AuditCategory,
  type AuditEvent,
  type AuditOutcome,
  type AuditQuery,
  type UserSummary,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { AuditApi } from '../../core/api/audit-api';
import { UsersApi } from '../../core/api/users-api';
import { apiErrorMessage } from '../../shared/api-errors';
import {
  AUDIT_ACTION_LABELS,
  AUDIT_CATEGORY_LABELS,
  auditDetail,
} from '../../shared/audit-labels';

const PAGE = 50;
const CATEGORIES = [...new Set(AUDIT_ACTIONS.map((a) => a.split('.')[0]))] as AuditCategory[];
const UUID = /^[0-9a-f-]{36}$/i;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
/** Tipos de objetivo que son assets (enlazan a su ficha si siguen existiendo). */
const ASSET_TARGETS = new Set<string>(['asset', ...ASSET_TYPES]);

/** Filtros de la URL (`?category=user,auth&actor=…&outcome=failure&q=…&from=…&to=…`), validados. */
export interface AuditFilters {
  category: AuditCategory[];
  actor: string | null;
  outcome: AuditOutcome | null;
  q: string;
  from: string;
  to: string;
}

export function auditFilters(
  params: Record<string, string | string[] | undefined>,
): AuditFilters {
  const one = (key: string): string => {
    const v = params[key];
    return Array.isArray(v) ? (v[0] ?? '') : (v ?? '');
  };
  // `?category=a,b` (lo que escribe la web) o `?category=a&category=b` (escrito a mano).
  const category = params['category'];
  return {
    category: (Array.isArray(category) ? category.join(',') : (category ?? ''))
      .split(',')
      .filter((c): c is AuditCategory => (CATEGORIES as string[]).includes(c)),
    actor: UUID.test(one('actor')) ? one('actor') : null,
    outcome: (AUDIT_OUTCOMES as readonly string[]).includes(one('outcome'))
      ? (one('outcome') as AuditOutcome)
      : null,
    q: one('q').slice(0, 200),
    from: DAY.test(one('from')) ? one('from') : '',
    to: DAY.test(one('to')) ? one('to') : '',
  };
}

/** Consulta a la API: las fechas, como días completos en la hora local. */
export function auditQuery(f: AuditFilters): AuditQuery {
  return {
    category: f.category.length ? f.category : undefined,
    actorId: f.actor ?? undefined,
    outcome: f.outcome ?? undefined,
    q: f.q.trim() || undefined,
    from: f.from ? new Date(`${f.from}T00:00:00`).toISOString() : undefined,
    to: f.to ? new Date(`${f.to}T23:59:59.999`).toISOString() : undefined,
    limit: PAGE,
  };
}

/** Ajustes > Auditoría (solo admin): quién hizo qué, sobre qué, cuándo y desde dónde. */
@Component({
  selector: 'app-audit-log',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    InputTextModule,
    MessageModule,
    MultiSelectModule,
    SelectModule,
    TableModule,
    TagModule,
  ],
  template: `
    <p-card styleClass="block" data-block="audit">
      <ng-template #title>Registro de auditoría</ng-template>
      <p class="text-muted intro">
        Altas y bajas, purgas, cambios de política, de usuarios y de roles, pasos a CA e inicios de
        sesión (también los fallidos), con su IP. Nunca guarda contraseñas ni secretos.
      </p>
      <div class="filters">
        <p-multiselect [options]="categoryOptions" optionLabel="label" optionValue="value"
          [ngModel]="filters().category" (ngModelChange)="set({ category: $event })"
          placeholder="Todas las acciones" ariaLabel="Tipo de acción" display="chip" [showToggleAll]="false"
          data-filter="category" />
        <p-select [options]="actorOptions()" optionLabel="label" optionValue="value" [filter]="true"
          [ngModel]="filters().actor" (ngModelChange)="set({ actor: $event })"
          ariaLabel="Usuario" data-filter="actor" />
        <p-select [options]="outcomeOptions" optionLabel="label" optionValue="value"
          [ngModel]="filters().outcome" (ngModelChange)="set({ outcome: $event })"
          ariaLabel="Resultado" data-filter="outcome" />
        <input pInputText type="search" placeholder="Objetivo o email…" aria-label="Buscar"
          [ngModel]="filters().q" (change)="set({ q: $any($event.target).value })" data-filter="q" />
        <label class="date">Desde <input pInputText type="date" [ngModel]="filters().from"
          (ngModelChange)="set({ from: $event ?? '' })" data-filter="from" /></label>
        <label class="date">Hasta <input pInputText type="date" [ngModel]="filters().to"
          (ngModelChange)="set({ to: $event ?? '' })" data-filter="to" /></label>
        @if (filtered()) {
          <p-button label="Quitar filtros" icon="bi bi-x-lg" size="small" severity="secondary" [text]="true"
            (onClick)="clear()" data-action="clear-filters" />
        }
      </div>

      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else {
        <div class="table-scroll">
          <p-table [value]="events()" size="small" dataKey="id" [loading]="loading()">
            <ng-template #header>
              <tr>
                <th style="width: 10rem">Cuándo</th>
                <th>Quién</th>
                <th>Acción</th>
                <th>Sobre qué</th>
                <th style="width: 8rem">IP</th>
                <th>Detalle</th>
              </tr>
            </ng-template>
            <ng-template #body let-e>
              <tr [attr.data-event]="e.action">
                <td class="nowrap">{{ e.occurredAt | date: 'short' }}</td>
                <td class="wrap">{{ e.actorEmail ?? 'sistema' }}</td>
                <td>
                  <p-tag [value]="actionLabel(e)" [severity]="e.outcome === 'failure' ? 'danger' : 'secondary'"
                    [icon]="e.outcome === 'failure' ? 'bi bi-x-circle' : ''" />
                </td>
                <td class="wrap">
                  @if (assetLink(e); as link) {
                    <a [routerLink]="link">{{ e.targetLabel ?? e.targetId }}</a>
                  } @else if (e.targetType === 'vulnerability' && e.targetLabel) {
                    <a [routerLink]="['/vulnerabilities', e.targetLabel]">{{ e.targetLabel }}</a>
                  } @else {
                    {{ e.targetLabel ?? '—' }}
                  }
                </td>
                <td class="nowrap"><code>{{ e.ip ?? '—' }}</code></td>
                <td class="text-muted wrap">{{ detail(e) }}</td>
              </tr>
            </ng-template>
            <ng-template #emptymessage>
              <tr><td colspan="6" class="text-muted">{{ loading() ? 'Cargando…' : 'Ningún evento con estos filtros.' }}</td></tr>
            </ng-template>
          </p-table>
        </div>
        @if (nextCursor()) {
          <p-button label="Cargar más" icon="bi bi-chevron-down" size="small" severity="secondary" [text]="true"
            [loading]="loading()" (onClick)="more()" data-action="more" />
        }
      }
    </p-card>
  `,
  styles: `
    .intro {
      margin-top: 0;
    }
    .filters {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-bottom: 0.85rem;
    }
    .filters > * {
      max-width: 100%;
    }
    .filters p-multiselect {
      min-width: min(16rem, 100%);
    }
    .date {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      color: var(--p-text-muted-color);
    }
    /* Los emails no se parten letra a letra: la tabla se desplaza dentro de su caja. */
    .wrap {
      overflow-wrap: break-word;
      min-width: 9rem;
    }
  `,
})
export class AuditLog implements OnInit {
  private readonly api = inject(AuditApi);
  private readonly usersApi = inject(UsersApi);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly categoryOptions = CATEGORIES.map((c) => ({ value: c, label: AUDIT_CATEGORY_LABELS[c] }));
  protected readonly outcomeOptions = [
    { value: null, label: 'Cualquier resultado' },
    { value: 'success', label: 'Correctas' },
    { value: 'failure', label: 'Fallidas' },
  ];

  protected readonly filters = signal<AuditFilters>(auditFilters({}));
  protected readonly events = signal<AuditEvent[]>([]);
  protected readonly nextCursor = signal<string | null>(null);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  private readonly users = signal<UserSummary[]>([]);
  protected readonly actorOptions = computed(() => [
    { value: null, label: 'Cualquier usuario' },
    ...this.users().map((u) => ({ value: u.id, label: `${u.name} (${u.email})` })),
  ]);
  protected readonly filtered = computed(() => {
    const f = this.filters();
    return !!(f.category.length || f.actor || f.outcome || f.q || f.from || f.to);
  });

  ngOnInit(): void {
    this.usersApi.list().subscribe({ next: (u) => this.users.set(u), error: () => undefined });
    this.route.queryParams
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        this.filters.set(auditFilters(params as Record<string, string>));
        this.load(null);
      });
  }

  protected set(change: Partial<AuditFilters>): void {
    const next = { ...this.filters(), ...change };
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: {
        category: next.category.length ? next.category.join(',') : null,
        actor: next.actor,
        outcome: next.outcome,
        q: next.q.trim() || null,
        from: next.from || null,
        to: next.to || null,
      },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  protected clear(): void {
    this.set({ category: [], actor: null, outcome: null, q: '', from: '', to: '' });
  }

  protected more(): void {
    this.load(this.nextCursor());
  }

  private load(cursor: string | null): void {
    this.loading.set(true);
    this.error.set(null);
    this.api.list({ ...auditQuery(this.filters()), cursor: cursor ?? undefined }).subscribe({
      next: (page) => {
        this.events.update((current) => (cursor ? [...current, ...page.items] : page.items));
        this.nextCursor.set(page.nextCursor);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        this.loading.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudo leer el registro de auditoría.'));
      },
    });
  }

  protected actionLabel(e: AuditEvent): string {
    return AUDIT_ACTION_LABELS[e.action] ?? e.action;
  }

  protected detail(e: AuditEvent): string {
    return auditDetail(e);
  }

  protected assetLink(e: AuditEvent): string[] | null {
    if (!e.targetId || !e.targetType || e.action === 'asset.purged') return null;
    return ASSET_TARGETS.has(e.targetType) ? ['/assets', e.targetId] : null;
  }
}
