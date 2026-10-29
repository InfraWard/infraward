import { DatePipe } from '@angular/common';
import {
  Component,
  computed,
  inject,
  input,
  output,
  signal,
  type OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  INVENTORY_POLICY_FIELDS,
  scanDisabledReason,
  type Asset,
  type AssetPolicy,
  type InventoryPolicyField,
  type InventoryPolicyFields,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { MaintenanceApi } from '../../core/api/maintenance-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import {
  POLICY_FIELD_LABELS,
  policySourceLabel,
  policyValueLabel,
} from '../../shared/maintenance-labels';
import { PolicyForm } from '../../shared/policy-form';

/**
 * Bloque «Política de inventario» del resumen (DESIGN §10): valor efectivo de cada campo y de
 * dónde sale (propia, heredada, por etiqueta, global), la reconciliación de su nodo raíz y, para
 * admin, el diálogo para fijar o quitar la regla propia.
 */
@Component({
  selector: 'app-asset-policy',
  imports: [
    DatePipe,
    RouterLink,
    ButtonModule,
    CardModule,
    DialogModule,
    MessageModule,
    TagModule,
    PolicyForm,
  ],
  template: `
    <p-card styleClass="card" data-section="policy">
      <ng-template #title>
        <i class="bi bi-sliders" aria-hidden="true"></i> Política de inventario
      </ng-template>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else if (policy(); as p) {
        <dl>
          @for (row of rows(); track row.field) {
            <dt>{{ row.label }}</dt>
            <dd [attr.data-policy]="row.field">
              <strong>{{ row.value }}</strong>
              <span class="muted small" [class.own]="row.own"> · {{ row.source }}</span>
            </dd>
          }
          <dt>Reconciliación</dt>
          <dd data-policy="root">
            @if (p.reconcileRoot; as root) {
              @if (root.id === asset().id) {
                @if (p.reconciledAt) {
                  Última: {{ p.reconciledAt | date: 'short' }}
                } @else {
                  Aún no se ha reconciliado
                }
                @if (p.nextReconcileAt) {
                  <span class="muted small"> · siguiente hacia las {{ p.nextReconcileAt | date: 'short' }}</span>
                }
              } @else {
                Con su nodo raíz,
                <a [routerLink]="['/assets', root.id]">{{ root.name }}</a>
              }
            } @else {
              <span class="muted">No se reconcilia (sin nodo raíz con conexión)</span>
            }
          </dd>
        </dl>
        @if (!p.effective.values.scanEnabled) {
          <p class="muted small scan-off" data-scan-disabled>
            <i class="bi bi-slash-circle" aria-hidden="true"></i>
            {{ scanReason(p.effective) }}: no se generan SBOM ni se lanza Trivy; sus
            vulnerabilidades se conservan, pero no cuentan en el panel ni en las listas. Sigue en
            el inventario.
          </p>
        }
        @if (auth.can('policy.write')) {
          <div class="actions">
            <p-button
              [label]="p.rule ? 'Cambiar la regla propia' : 'Fijar una regla propia'"
              icon="bi bi-pencil"
              size="small"
              severity="secondary"
              [outlined]="true"
              (onClick)="edit()"
              data-action="edit-policy"
            />
            @if (isRoot()) {
              <p-button
                label="Reconciliar ahora"
                icon="bi bi-arrow-clockwise"
                size="small"
                severity="secondary"
                [text]="true"
                [loading]="busy()"
                (onClick)="reconcile()"
                data-action="reconcile"
              />
            }
          </div>
        }
      } @else {
        <p class="muted">Cargando…</p>
      }
    </p-card>

    <p-dialog
      header="Política de {{ asset().name }}"
      [visible]="editing()"
      (visibleChange)="editing.set($event)"
      [modal]="true"
      [style]="{ width: 'min(34rem, 95vw)' }"
      data-dialog="policy"
    >
      <p class="muted small intro">
        Una regla en este asset se aplica también a todo lo que contiene (CT, contenedores,
        imágenes), salvo que un descendiente tenga la suya. «Heredar» toma el valor de su nodo
        superior, de sus etiquetas o de la política global.
      </p>
      <app-policy-form [(value)]="draft" id="asset-policy" />
      @if (saveError(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      <ng-template #footer>
        @if (policy()?.rule) {
          <p-button
            label="Quitar la regla propia"
            icon="bi bi-x-lg"
            severity="danger"
            [text]="true"
            [disabled]="busy()"
            (onClick)="removeRule()"
            data-action="remove-policy"
          />
        }
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="editing.set(false)" />
        <p-button
          label="Guardar"
          icon="bi bi-check-lg"
          [loading]="busy()"
          (onClick)="save()"
          data-action="save-policy"
        />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    dl {
      display: grid;
      grid-template-columns: max-content minmax(0, 1fr);
      gap: 0.35rem 1rem;
      margin: 0;
    }
    dt {
      color: var(--p-text-muted-color);
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .own {
      color: var(--p-primary-color);
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-top: 0.85rem;
    }
    .scan-off {
      margin: 0.75rem 0 0;
    }
    .intro {
      margin-top: 0;
    }
    :host ::ng-deep .mt {
      margin-top: 0.75rem;
    }
    @media (max-width: 599.98px) {
      dl {
        grid-template-columns: minmax(0, 1fr);
        gap: 0.1rem;
      }
      dt:not(:first-child) {
        margin-top: 0.4rem;
      }
    }
  `,
})
export class AssetPolicyBlock implements OnInit {
  private readonly api = inject(MaintenanceApi);
  private readonly messages = inject(MessageService);
  protected readonly auth = inject(AuthService);

  readonly asset = input.required<Asset>();
  /** La política cambió (la ficha recarga lo que depende de ella). */
  readonly changed = output<void>();

  protected readonly policy = signal<AssetPolicy | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly editing = signal(false);
  protected readonly busy = signal(false);
  protected readonly saveError = signal<string | null>(null);
  protected draft: InventoryPolicyFields = {};
  protected readonly scanReason = scanDisabledReason;

  protected readonly isRoot = computed(
    () => this.policy()?.reconcileRoot?.id === this.asset().id,
  );

  protected readonly rows = computed(() => {
    const p = this.policy();
    if (!p) return [];
    return INVENTORY_POLICY_FIELDS.filter(
      // El intervalo solo actúa en las raíces.
      (f) => f !== 'reconcileIntervalMinutes' || this.isRoot(),
    ).map((field: InventoryPolicyField) => ({
      field,
      label: POLICY_FIELD_LABELS[field],
      value: policyValueLabel(field, p.effective.values[field]),
      source: policySourceLabel(p.effective.sources[field]),
      own: p.effective.sources[field].kind === 'own',
    }));
  });

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.assetPolicy(this.asset().id).subscribe({
      next: (p) => {
        this.policy.set(p);
        this.error.set(null);
      },
      error: (err: unknown) =>
        this.error.set(apiErrorMessage(err, 'No se pudo leer la política del asset.')),
    });
  }

  protected edit(): void {
    const rule = this.policy()?.rule;
    this.draft = {
      reconcileIntervalMinutes: rule?.reconcileIntervalMinutes ?? null,
      scanEnabled: rule?.scanEnabled ?? null,
      scanPeriodic: rule?.scanPeriodic ?? null,
      scanExclusions: rule?.scanExclusions ?? null,
    };
    this.saveError.set(null);
    this.editing.set(true);
  }

  protected save(): void {
    this.apply(this.api.setAssetPolicy(this.asset().id, this.draft), 'Política guardada');
  }

  protected removeRule(): void {
    this.apply(this.api.removeAssetPolicy(this.asset().id), 'Regla propia quitada');
  }

  private apply(
    request: ReturnType<MaintenanceApi['setAssetPolicy']>,
    summary: string,
  ): void {
    this.busy.set(true);
    request.subscribe({
      next: (p) => {
        this.busy.set(false);
        this.policy.set(p);
        this.editing.set(false);
        this.messages.add({ severity: 'success', summary, life: 4000 });
        this.changed.emit();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.saveError.set(apiErrorMessage(err, 'No se pudo guardar la política.'));
      },
    });
  }

  protected reconcile(): void {
    this.busy.set(true);
    this.api.reconcile(this.asset().id).subscribe({
      next: () => {
        this.busy.set(false);
        this.messages.add({
          severity: 'info',
          summary: 'Reconciliación encolada',
          detail: 'Se recoge el nodo y se descubren sus hijos; el progreso, en Actividad.',
          life: 5000,
        });
        this.changed.emit();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'No se pudo reconciliar',
          detail: apiErrorMessage(err, 'Error al encolar la reconciliación.'),
          life: 6000,
        });
      },
    });
  }
}
