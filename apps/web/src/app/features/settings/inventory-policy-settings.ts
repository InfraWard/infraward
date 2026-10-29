import { Component, computed, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  INVENTORY_RULE_FIELDS,
  type InventoryPolicyFields,
  type InventoryPolicyList,
  type InventoryPolicyRule,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { AutoCompleteModule } from '@openng/optimus-ui/autocomplete';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import type { AutoCompleteCompleteEvent } from '@openng/optimus-ui/types/autocomplete';
import type { Observable } from 'rxjs';
import { MaintenanceApi } from '../../core/api/maintenance-api';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { TagChip } from '../../shared/tag-chip';
import { apiErrorMessage } from '../../shared/api-errors';
import { policyValueLabel } from '../../shared/maintenance-labels';
import { PolicyForm } from '../../shared/policy-form';

/** Etiquetas y roles: sin espacios, empiezan por letra o número (como en la API). */
const LABEL = /^[\p{L}\p{N}][\p{L}\p{N}._:/-]*$/u;

/**
 * Política de inventario en Ajustes (DESIGN §10): la global, las reglas por etiqueta y por
 * proyecto (crear, cambiar, borrar) y las de los assets (se cambian en su ficha), y «Reconciliar
 * ahora».
 */
@Component({
  selector: 'app-inventory-policy-settings',
  imports: [
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    TableModule,
    TagModule,
    AutoCompleteModule,
    SelectModule,
    TagChip,
    PolicyForm,
  ],
  template: `
    <p-card styleClass="block" data-block="policy">
      <ng-template #title>Política de inventario</ng-template>
      <p class="text-muted intro">
        Cada cuánto se reconcilian los nodos raíz (recolección y descubrimiento de lo que
        contienen) y si se escanean sus vulnerabilidades. Una regla de un asset vale para todo lo
        que contiene; prioridad: la del propio asset, la del nodo superior más cercano, la de sus
        etiquetas (la más restrictiva), la de sus proyectos (la más restrictiva) y la global.
      </p>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else if (list(); as l) {
        <h3>Global</h3>
        @if (auth.can('policy.write')) {
          <app-policy-form [(value)]="globalDraft" [allowInherit]="false" id="global" />
          <div class="actions">
            <p-button
              label="Guardar la global"
              icon="bi bi-check-lg"
              size="small"
              [loading]="busy()"
              (onClick)="saveGlobal()"
              data-action="save-global"
            />
            <p-button
              label="Reconciliar ahora"
              icon="bi bi-arrow-clockwise"
              size="small"
              severity="secondary"
              [outlined]="true"
              [loading]="busy()"
              (onClick)="reconcile()"
              data-action="reconcile-all"
            />
          </div>
        } @else {
          <dl data-global>
            @for (f of fields; track f.field) {
              <dt>{{ f.label }}</dt>
              <dd>{{ value(f.field, l.global) }}</dd>
            }
          </dl>
        }

        <h3>Reglas por etiqueta</h3>
        <div class="table-scroll">
          <p-table [value]="tagRules()" size="small" dataKey="id">
            <ng-template #header>
              <tr>
                <th>Etiqueta</th>
                @for (f of fields; track f.field) {
                  <th>{{ f.label }}</th>
                }
                @if (auth.can('policy.write')) {
                  <th style="width: 6rem"></th>
                }
              </tr>
            </ng-template>
            <ng-template #body let-rule>
              <tr [attr.data-rule]="rule.tag">
                <td><app-tag-chip [tag]="rule.tag" [color]="store.tagColors().get(rule.tag)" /></td>
                @for (f of fields; track f.field) {
                  <td [class.text-muted]="rule[f.field] === null">{{ value(f.field, rule) }}</td>
                }
                @if (auth.can('policy.write')) {
                  <td class="row-actions">
                    <p-button icon="bi bi-pencil" size="small" severity="secondary" [text]="true"
                      ariaLabel="Cambiar la regla" (onClick)="editRule(rule)" />
                    <p-button icon="bi bi-trash" size="small" severity="danger" [text]="true"
                      ariaLabel="Borrar la regla" (onClick)="removeRule(rule)" />
                  </td>
                }
              </tr>
            </ng-template>
            <ng-template #emptymessage>
              <tr><td [attr.colspan]="auth.can('policy.write') ? 5 : 4" class="text-muted">Sin reglas por etiqueta.</td></tr>
            </ng-template>
          </p-table>
        </div>
        @if (auth.can('policy.write')) {
          <p-button
            label="Añadir una regla por etiqueta"
            icon="bi bi-plus-lg"
            size="small"
            severity="secondary"
            [text]="true"
            (onClick)="newRule('tag')"
            data-action="new-tag-rule"
          />
        }

        <h3>Reglas por proyecto</h3>
        <div class="table-scroll">
          <p-table [value]="projectRules()" size="small" dataKey="id">
            <ng-template #header>
              <tr>
                <th>Proyecto</th>
                @for (f of fields; track f.field) {
                  <th>{{ f.label }}</th>
                }
                @if (auth.can('policy.write')) {
                  <th style="width: 6rem"></th>
                }
              </tr>
            </ng-template>
            <ng-template #body let-rule>
              <tr [attr.data-project-rule]="rule.projectName">
                <td>
                  <span class="project">
                    <span class="dot" [style.background]="store.projectsById().get(rule.projectId)?.color ?? 'var(--p-text-muted-color)'"></span>
                    <a [routerLink]="['/projects', rule.projectId]">{{ rule.projectName ?? rule.projectId }}</a>
                  </span>
                </td>
                @for (f of fields; track f.field) {
                  <td [class.text-muted]="rule[f.field] === null">{{ value(f.field, rule) }}</td>
                }
                @if (auth.can('policy.write')) {
                  <td class="row-actions">
                    <p-button icon="bi bi-pencil" size="small" severity="secondary" [text]="true"
                      ariaLabel="Cambiar la regla" (onClick)="editRule(rule)" />
                    <p-button icon="bi bi-trash" size="small" severity="danger" [text]="true"
                      ariaLabel="Borrar la regla" (onClick)="removeRule(rule)" />
                  </td>
                }
              </tr>
            </ng-template>
            <ng-template #emptymessage>
              <tr><td [attr.colspan]="auth.can('policy.write') ? 5 : 4" class="text-muted">Sin reglas por proyecto.</td></tr>
            </ng-template>
          </p-table>
        </div>
        @if (auth.can('policy.write') && freeProjects().length) {
          <p-button
            label="Añadir una regla por proyecto"
            icon="bi bi-plus-lg"
            size="small"
            severity="secondary"
            [text]="true"
            (onClick)="newRule('project')"
            data-action="new-project-rule"
          />
        }

        <h3>Reglas de assets</h3>
        <div class="table-scroll">
          <p-table [value]="assetRules()" size="small" dataKey="id">
            <ng-template #header>
              <tr>
                <th>Asset</th>
                @for (f of fields; track f.field) {
                  <th>{{ f.label }}</th>
                }
              </tr>
            </ng-template>
            <ng-template #body let-rule>
              <tr [attr.data-asset-rule]="rule.assetId">
                <td><a [routerLink]="['/assets', rule.assetId]">{{ rule.assetName ?? rule.assetId }}</a></td>
                @for (f of fields; track f.field) {
                  <td [class.text-muted]="rule[f.field] === null">{{ value(f.field, rule) }}</td>
                }
              </tr>
            </ng-template>
            <ng-template #emptymessage>
              <tr><td colspan="4" class="text-muted">Ningún asset tiene regla propia (se fijan en su ficha).</td></tr>
            </ng-template>
          </p-table>
        </div>
      } @else {
        <p class="text-muted">Cargando…</p>
      }
    </p-card>

    <p-dialog
      [header]="dialogTitle()"
      [visible]="dialogOpen()"
      (visibleChange)="dialogOpen.set($event)"
      [modal]="true"
      [style]="{ width: 'min(34rem, 95vw)' }"
      [attr.data-dialog]="kind() === 'tag' ? 'tag-rule' : 'project-rule'"
    >
      @if (!editing()) {
        @if (kind() === 'tag') {
          <label for="ruleTag" class="tag-label">Etiqueta</label>
          <p-autocomplete
            inputId="ruleTag"
            styleClass="tag-input"
            [fluid]="true"
            [ngModel]="tag()"
            (ngModelChange)="tag.set($event ?? '')"
            [suggestions]="tagSuggestions()"
            (completeMethod)="completeTag($event)"
            [completeOnFocus]="true"
            [minLength]="0"
            [delay]="0"
            placeholder="p. ej. prod, lab, env:dev"
            appendTo="body"
          />
        } @else {
          <label for="ruleProject" class="tag-label">Proyecto</label>
          <p-select
            inputId="ruleProject"
            styleClass="tag-input"
            [options]="freeProjects()"
            optionLabel="name"
            optionValue="id"
            [ngModel]="projectId()"
            (ngModelChange)="projectId.set($event)"
            placeholder="Elige un proyecto"
            appendTo="body"
          />
        }
      }
      <app-policy-form [(value)]="ruleDraft" id="tag-rule" />
      @if (dialogError(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="dialog-error">{{ message }}</p-message>
      }
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="dialogOpen.set(false)" />
        <p-button label="Guardar" icon="bi bi-check-lg" [loading]="busy()" (onClick)="saveRule()" data-action="save-tag-rule" />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    h3 {
      font-size: 1rem;
      margin: 1.25rem 0 0.6rem;
    }
    .intro {
      margin-top: 0;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-top: 0.85rem;
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.4rem 1rem;
      margin: 0;
    }
    dt {
      color: var(--p-text-muted-color);
    }
    dd {
      margin: 0;
    }
    .row-actions {
      white-space: nowrap;
      text-align: right;
    }
    .tag-label {
      display: block;
      font-weight: 600;
      margin-bottom: 0.3rem;
    }
    .tag-input {
      width: 100%;
      margin-bottom: 1rem;
    }
    :host ::ng-deep .dialog-error {
      margin-top: 0.75rem;
    }
    :host ::ng-deep .tag-input {
      width: 100%;
      margin-bottom: 1rem;
    }
    .project {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }
    .dot {
      width: 0.6rem;
      height: 0.6rem;
      border-radius: 50%;
      flex: none;
    }
  `,
})
export class InventoryPolicySettings implements OnInit {
  private readonly api = inject(MaintenanceApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);
  protected readonly auth = inject(AuthService);
  protected readonly store = inject(OrganizationStore);

  protected readonly fields = INVENTORY_RULE_FIELDS.map((field) => ({
    field,
    label: {
      reconcileIntervalMinutes: 'Reconciliación',
      scanEnabled: 'Escaneo',
      scanPeriodic: 'Escaneo automático',
      scanExclusions: 'Excluido',
    }[field],
  }));

  protected readonly list = signal<InventoryPolicyList | null>(null);
  protected readonly tagRules = signal<InventoryPolicyRule[]>([]);
  protected readonly assetRules = signal<InventoryPolicyRule[]>([]);
  protected readonly projectRules = signal<InventoryPolicyRule[]>([]);
  /** Proyectos sin regla todavía (una por proyecto). */
  protected readonly freeProjects = computed(() => {
    const taken = new Set(this.projectRules().map((r) => r.projectId));
    return this.store.projects().filter((p) => !taken.has(p.id));
  });
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected globalDraft: InventoryPolicyFields = {};

  protected readonly dialogOpen = signal(false);
  protected readonly editing = signal<InventoryPolicyRule | null>(null);
  protected readonly kind = signal<'tag' | 'project'>('tag');
  protected readonly tag = signal('');
  protected readonly projectId = signal<string | null>(null);
  protected readonly tagSuggestions = signal<string[]>([]);
  protected readonly dialogTitle = computed(() => {
    const rule = this.editing();
    if (rule?.scope === 'project') return `Regla del proyecto ${rule.projectName ?? ''}`;
    if (rule) return `Regla de la etiqueta ${rule.tag}`;
    return this.kind() === 'tag' ? 'Nueva regla por etiqueta' : 'Nueva regla por proyecto';
  });
  protected readonly dialogError = signal<string | null>(null);
  protected ruleDraft: InventoryPolicyFields = {};

  ngOnInit(): void {
    this.store.ensureTags();
    this.store.ensureProjects();
    this.load();
  }

  protected completeTag(event: AutoCompleteCompleteEvent): void {
    const q = (event.query ?? '').trim().toLowerCase();
    const taken = new Set(this.tagRules().map((r) => r.tag));
    this.tagSuggestions.set(
      this.store
        .tags()
        .map((t) => t.tag)
        .filter((t) => !taken.has(t) && t.toLowerCase().includes(q))
        .slice(0, 20),
    );
  }

  private load(): void {
    this.api.policies().subscribe({
      next: (l) => {
        this.list.set(l);
        this.tagRules.set(l.rules.filter((r) => r.scope === 'tag'));
        this.assetRules.set(l.rules.filter((r) => r.scope === 'asset'));
        this.projectRules.set(l.rules.filter((r) => r.scope === 'project'));
        this.globalDraft = {
          reconcileIntervalMinutes: l.global.reconcileIntervalMinutes,
          scanEnabled: l.global.scanEnabled,
          scanPeriodic: l.global.scanPeriodic,
          scanExclusions: l.global.scanExclusions,
        };
      },
      error: (err: unknown) =>
        this.error.set(apiErrorMessage(err, 'No se pudo leer la política de inventario.')),
    });
  }

  protected value(
    field: (typeof INVENTORY_RULE_FIELDS)[number],
    rule: InventoryPolicyRule,
  ): string {
    return policyValueLabel(field, rule[field]);
  }

  protected saveGlobal(): void {
    const d = this.globalDraft;
    this.run(
      this.api.updateGlobal({
        reconcileIntervalMinutes: d.reconcileIntervalMinutes ?? undefined,
        scanEnabled: d.scanEnabled ?? undefined,
        scanPeriodic: d.scanPeriodic ?? undefined,
        scanExclusions: d.scanExclusions ?? null,
      }),
      'Política global guardada',
    );
  }

  protected newRule(kind: 'tag' | 'project'): void {
    this.kind.set(kind);
    this.editing.set(null);
    this.tag.set('');
    this.projectId.set(null);
    this.ruleDraft = {
      reconcileIntervalMinutes: null,
      scanEnabled: null,
      scanPeriodic: null,
      scanExclusions: null,
    };
    this.dialogError.set(null);
    this.dialogOpen.set(true);
  }

  protected editRule(rule: InventoryPolicyRule): void {
    this.kind.set(rule.scope === 'project' ? 'project' : 'tag');
    this.editing.set(rule);
    this.ruleDraft = {
      reconcileIntervalMinutes: rule.reconcileIntervalMinutes,
      scanEnabled: rule.scanEnabled,
      scanPeriodic: rule.scanPeriodic,
      scanExclusions: rule.scanExclusions,
    };
    this.dialogError.set(null);
    this.dialogOpen.set(true);
  }

  protected saveRule(): void {
    const rule = this.editing();
    const fields = this.ruleDraft;
    if (INVENTORY_RULE_FIELDS.every((f) => fields[f] === null || fields[f] === undefined)) {
      this.dialogError.set('Fija al menos un campo (el resto se hereda).');
      return;
    }
    const tag = this.tag().trim();
    const projectId = this.projectId();
    if (!rule && this.kind() === 'tag' && !LABEL.test(tag)) {
      this.dialogError.set('Etiqueta no válida: sin espacios, empieza por letra o número.');
      return;
    }
    if (!rule && this.kind() === 'project' && !projectId) {
      this.dialogError.set('Elige un proyecto.');
      return;
    }
    this.run(
      rule
        ? this.api.updateRule(rule.id, fields)
        : this.kind() === 'tag'
          ? this.api.createRule({ scope: 'tag', tag, ...fields })
          : this.api.createRule({ scope: 'project', projectId: projectId!, ...fields }),
      'Regla guardada',
      (message) => this.dialogError.set(message),
      () => this.dialogOpen.set(false),
    );
  }

  protected removeRule(rule: InventoryPolicyRule): void {
    this.confirm.confirm({
      header: 'Borrar la regla',
      message:
        rule.scope === 'project'
          ? `Los assets del proyecto «${rule.projectName}» volverán a heredar la política. ¿Seguir?`
          : `Los assets con la etiqueta «${rule.tag}» volverán a heredar la política. ¿Seguir?`,
      acceptLabel: 'Borrar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () => this.run(this.api.removeRule(rule.id), 'Regla borrada'),
    });
  }

  protected reconcile(): void {
    this.busy.set(true);
    this.api.reconcile().subscribe({
      next: () => {
        this.busy.set(false);
        this.messages.add({
          severity: 'info',
          summary: 'Reconciliación encolada',
          detail: 'Se reconcilian los nodos raíz con el intervalo vencido; el progreso, en Actividad.',
          life: 5000,
        });
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

  private run(
    request: Observable<unknown>,
    summary: string,
    onError?: (message: string) => void,
    onDone?: () => void,
  ): void {
    this.busy.set(true);
    request.subscribe({
      next: () => {
        this.busy.set(false);
        onDone?.();
        this.messages.add({ severity: 'success', summary, life: 4000 });
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        const message = apiErrorMessage(err, 'No se pudo guardar.');
        if (onError) onError(message);
        else this.messages.add({ severity: 'error', summary: 'Error', detail: message, life: 6000 });
      },
    });
  }
}
