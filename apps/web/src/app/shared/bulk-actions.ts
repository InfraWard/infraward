import { Component, computed, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  BULK_ACTION_LABELS,
  BULK_ASSET_ACTIONS,
  hasPermission,
  type BulkAssetAction,
  type BulkAssetTarget,
  type BulkOperationResult,
  type BulkProjectMode,
  type InventoryPolicyFields,
  type Permission,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { Observable } from 'rxjs';
import { BulkApi } from '../core/api/bulk-api';
import { AuthService } from '../core/auth/auth.service';
import { OrganizationStore } from '../core/organization-store';
import { apiErrorMessage } from './api-errors';
import { PolicyForm } from './policy-form';
import { TagEditor } from './tag-editor';

/** Permiso de cada acción en lote: el mismo que la de un asset. */
export const BULK_ACTION_PERMISSION: Record<BulkAssetAction, Permission> = {
  tags: 'assets.write',
  project: 'projects.write',
  collect: 'assets.operate',
  scan: 'assets.operate',
  policy: 'policy.write',
  retire: 'assets.write',
};

const BULK_ACTION_ICONS: Record<BulkAssetAction, string> = {
  tags: 'bi-tags',
  project: 'bi-folder-symlink',
  collect: 'bi-cloud-download',
  scan: 'bi-shield-check',
  policy: 'bi-sliders',
  retire: 'bi-archive',
};

/** «web1, web2, web3 y 4 más». */
export function namesSummary(names: readonly string[], max = 8): string {
  if (names.length <= max) return names.join(', ');
  return `${names.slice(0, max).join(', ')} y ${names.length - max} más`;
}

/** Quién puede hacer alguna acción en lote (para enseñar las casillas). */
export function canBulk(
  role: Parameters<typeof hasPermission>[0],
  actions: readonly BulkAssetAction[] = BULK_ASSET_ACTIONS,
): boolean {
  return actions.some((a) => hasPermission(role, BULK_ACTION_PERMISSION[a]));
}

/**
 * Barra de acciones en lote (QoL-6) para una selección del árbol (`assetIds`) o de la lista de
 * vulnerabilidades (`vulnerabilityIds`: actúa sobre sus afectados). Solo enseña las acciones que
 * permite el rol. Dar de baja confirma con la lista completa (y los descendientes que arrastra).
 */
@Component({
  selector: 'app-bulk-actions',
  imports: [
    FormsModule,
    RouterLink,
    ButtonModule,
    DialogModule,
    MessageModule,
    SelectModule,
    SelectButtonModule,
    TooltipModule,
    PolicyForm,
    TagEditor,
  ],
  template: `
    <div class="dock">
    @if (count() > 0) {
      <div class="bulk-bar" role="region" aria-label="Acciones en lote" data-bulk-bar>
        <span class="count" aria-live="polite">
          <i class="bi bi-check2-square" aria-hidden="true"></i>
          <strong>{{ count() }}</strong> {{ noun() }}
        </span>
        <span class="actions">
          @for (action of allowed(); track action) {
            <p-button
              [label]="labels[action]"
              [icon]="'bi ' + icons[action]"
              [severity]="action === 'retire' ? 'danger' : 'secondary'"
              [outlined]="true"
              size="small"
              [loading]="busy() === action"
              [disabled]="!!busy()"
              (onClick)="start(action)"
              [attr.data-bulk]="action"
            />
          }
          <!-- Acciones propias de la vista (p. ej. aceptar el riesgo de los CVE). -->
          <ng-content />
        </span>
        <p-button
          label="Quitar la selección"
          icon="bi bi-x-lg"
          severity="secondary"
          [text]="true"
          size="small"
          (onClick)="cleared.emit()"
          data-bulk-clear
        />
      </div>
    }

    @if (result(); as r) {
      <p-message
        [severity]="r.skipped.length ? 'warn' : 'success'"
        icon="bi {{ r.skipped.length ? 'bi-exclamation-triangle' : 'bi-check-circle' }}"
        styleClass="bulk-result"
        data-bulk-result
      >
        <div class="result">
          <span>
            <strong>{{ labels[r.action] }}</strong>: {{ r.applied.length }}
            {{ r.applied.length === 1 ? 'asset' : 'assets' }}
            @if (r.jobs.length) {
              · {{ r.jobs.length }} {{ r.jobs.length === 1 ? 'tarea' : 'tareas' }}
            }
            @if (r.skipped.length) {
              · {{ r.skipped.length }} {{ r.skipped.length === 1 ? 'omitido' : 'omitidos' }}
            }
          </span>
          <a [routerLink]="['/activity', r.operationId]" data-bulk-activity>
            Ver en Actividad
          </a>
          <p-button
            icon="bi bi-x-lg"
            severity="secondary"
            [text]="true"
            size="small"
            ariaLabel="Cerrar"
            (onClick)="result.set(null)"
          />
        </div>
        @if (r.skipped.length) {
          <ul class="skipped" data-bulk-skipped>
            @for (s of r.skipped.slice(0, 20); track s.id) {
              <li><strong>{{ s.name }}</strong>: {{ s.reason }}</li>
            }
            @if (r.skipped.length > 20) {
              <li>y {{ r.skipped.length - 20 }} más</li>
            }
          </ul>
        }
        @if (r.revocations?.length) {
          <p class="revocations">
            Quita el acceso de los servidores dados de baja con estos comandos (como root):
          </p>
          @for (rev of r.revocations; track rev.assetId) {
            @if (rev.command) {
              <pre class="command"><code>{{ rev.command }}</code></pre>
            }
          }
        }
      </p-message>
    }
    </div>

    <p-dialog
      [header]="dialogHeader()"
      [visible]="dialog() !== null"
      (visibleChange)="!$event && closeDialog()"
      [modal]="true"
      [style]="{ width: 'min(34rem, 95vw)' }"
      data-dialog="bulk"
    >
      <p class="muted small scope" data-bulk-scope>{{ scopeText() }}</p>
      @switch (dialog()) {
        @case ('tags') {
          <div class="field">
            <span class="label" id="bulk-add-label">Añadir</span>
            <app-tag-editor
              [tags]="addTags()"
              [editable]="true"
              (tagsChange)="addTags.set($event)"
              aria-labelledby="bulk-add-label"
              data-bulk-add
            />
          </div>
          <div class="field">
            <span class="label" id="bulk-remove-label">Quitar</span>
            <app-tag-editor
              [tags]="removeTags()"
              [editable]="true"
              (tagsChange)="removeTags.set($event)"
              aria-labelledby="bulk-remove-label"
              data-bulk-remove
            />
          </div>
          <p class="muted small">Los demás tags de cada asset no cambian.</p>
        }
        @case ('project') {
          <div class="field">
            <label class="label" for="bulk-project">Proyecto</label>
            <p-select
              inputId="bulk-project"
              [options]="store.projects()"
              optionLabel="name"
              optionValue="id"
              placeholder="Elige un proyecto"
              [ngModel]="projectId()"
              (ngModelChange)="projectId.set($event)"
              appendTo="body"
              data-bulk-project
            />
          </div>
          <div class="field">
            <span class="label">Cómo</span>
            <p-selectbutton
              [options]="projectModes"
              optionLabel="label"
              optionValue="value"
              [ngModel]="projectMode()"
              (ngModelChange)="projectMode.set($event)"
              [allowEmpty]="false"
              aria-label="Cómo entran en el proyecto"
            />
          </div>
          <p class="muted small">{{ projectModeHelp() }}</p>
        }
        @case ('policy') {
          <p class="muted small">
            Se fija como regla propia de cada asset (y de lo que contiene). «Heredar» deja de fijar ese
            campo.
          </p>
          <app-policy-form [(value)]="policyDraft" id="bulk-policy" />
        }
      }
      @if (dialogError(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      <ng-template #footer>
        @if (dialog() === 'policy') {
          <p-button
            label="Quitar la regla propia"
            icon="bi bi-x-lg"
            severity="danger"
            [text]="true"
            [disabled]="!!busy()"
            (onClick)="applyPolicy(true)"
            data-bulk-policy-clear
          />
        }
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="closeDialog()" />
        <p-button
          label="Aplicar"
          icon="bi bi-check-lg"
          [loading]="!!busy()"
          [disabled]="!canApply()"
          (onClick)="apply()"
          data-bulk-apply
        />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    /* Barra y resultado fijos abajo: se ven aunque la tabla sea larga. */
    .dock {
      position: sticky;
      bottom: 0.75rem;
      z-index: 2;
      display: grid;
      gap: 0.5rem;
      margin: 0.75rem 0;
    }
    .dock:empty {
      display: none;
    }
    .bulk-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem 0.75rem;
      padding: 0.6rem 0.85rem;
      border: 1px solid var(--p-primary-color);
      border-radius: var(--p-content-border-radius, 6px);
      background: var(--p-content-background);
      box-shadow: 0 4px 16px rgb(0 0 0 / 0.12);
    }
    .count {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      white-space: nowrap;
    }
    .count i {
      color: var(--p-primary-color);
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      flex: 1 1 auto;
    }
    :host ::ng-deep .bulk-result {
      margin: 0;
      box-shadow: 0 4px 16px rgb(0 0 0 / 0.12);
    }
    :host ::ng-deep .bulk-result .p-message-text {
      max-height: 40vh;
      overflow-y: auto;
    }
    .result {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.25rem 0.85rem;
    }
    .skipped {
      margin: 0.4rem 0 0;
      padding-left: 1.2rem;
      font-size: 0.875rem;
    }
    .revocations {
      margin: 0.5rem 0 0.25rem;
    }
    .command {
      margin: 0.25rem 0;
      padding: 0.4rem 0.6rem;
      overflow-x: auto;
      background: var(--p-app-code-background);
      border-radius: 4px;
      font-size: 0.8rem;
    }
    .scope {
      margin-top: 0;
    }
    .field {
      display: grid;
      gap: 0.35rem;
      margin-bottom: 0.85rem;
    }
    .label {
      font-weight: 600;
    }
    :host ::ng-deep .field .p-select {
      width: 100%;
    }
    :host ::ng-deep .mt {
      margin-top: 0.75rem;
    }
    @media (max-width: 599.98px) {
      .dock {
        bottom: 0.5rem;
      }
      .actions {
        flex-basis: 100%;
      }
    }
  `,
})
export class BulkActions {
  private readonly api = inject(BulkApi);
  private readonly auth = inject(AuthService);
  private readonly confirmation = inject(ConfirmationService);
  private readonly messages = inject(MessageService);
  protected readonly store = inject(OrganizationStore);

  /** A qué assets se aplica (ids del árbol o los afectados de unos CVE). */
  readonly target = input.required<BulkAssetTarget>();
  /** Cuántos hay seleccionados (assets o CVE). */
  readonly count = input.required<number>();
  /** «assets seleccionados», «CVE seleccionados»… */
  readonly noun = input('seleccionados');
  /** Acciones que tienen sentido aquí (se filtran además por el rol). */
  readonly actions = input<readonly BulkAssetAction[]>(BULK_ASSET_ACTIONS);
  /** Terminó una operación: quien la usa recarga y vacía la selección. */
  readonly done = output<BulkOperationResult>();
  readonly cleared = output<void>();

  protected readonly labels = BULK_ACTION_LABELS;
  protected readonly icons = BULK_ACTION_ICONS;
  protected readonly allowed = computed(() =>
    this.actions().filter((a) => this.auth.can(BULK_ACTION_PERMISSION[a])),
  );
  protected readonly busy = signal<BulkAssetAction | null>(null);
  protected readonly result = signal<BulkOperationResult | null>(null);

  protected readonly dialog = signal<'tags' | 'project' | 'policy' | null>(null);
  protected readonly dialogError = signal<string | null>(null);
  /** Assets a los que llega la acción (con CVE, sus afectados; lo dice el diálogo). */
  private readonly previewNames = signal<string[] | null>(null);
  protected readonly addTags = signal<string[]>([]);
  protected readonly removeTags = signal<string[]>([]);
  protected readonly projectId = signal<string | null>(null);
  protected readonly projectMode = signal<BulkProjectMode>('include');
  protected policyDraft: InventoryPolicyFields = {};

  protected readonly projectModes = [
    { label: 'Incluir', value: 'include' },
    { label: 'Excluir', value: 'exclude' },
    { label: 'Heredar', value: 'inherit' },
  ];

  protected readonly dialogHeader = computed(() => {
    const d = this.dialog();
    return d ? `${BULK_ACTION_LABELS[d]}` : '';
  });

  protected readonly scopeText = computed(() => {
    const names = this.previewNames();
    if (!names) return 'Calculando a qué assets afecta…';
    return `${names.length} ${names.length === 1 ? 'asset' : 'assets'}: ${namesSummary(names)}`;
  });

  protected readonly projectModeHelp = computed(() => {
    switch (this.projectMode()) {
      case 'include':
        return 'Entran en el proyecto con todo lo que contienen.';
      case 'exclude':
        return 'Excepción: quedan fuera aunque su nodo superior esté dentro.';
      default:
        return 'Se quita su fila propia: vuelven a heredar lo que diga su nodo superior.';
    }
  });

  protected readonly canApply = computed(() => {
    switch (this.dialog()) {
      case 'tags':
        return this.addTags().length + this.removeTags().length > 0;
      case 'project':
        return !!this.projectId();
      default:
        return true;
    }
  });

  protected start(action: BulkAssetAction): void {
    this.result.set(null);
    switch (action) {
      case 'tags':
      case 'project':
      case 'policy':
        return this.openDialog(action);
      case 'retire':
        return this.confirmRetire();
      case 'collect':
        return this.run(action, this.api.collect(this.target()));
      case 'scan':
        return this.run(action, this.api.scan(this.target()));
    }
  }

  private openDialog(action: 'tags' | 'project' | 'policy'): void {
    this.addTags.set([]);
    this.removeTags.set([]);
    this.projectId.set(null);
    this.projectMode.set('include');
    this.policyDraft = {
      reconcileIntervalMinutes: null,
      scanEnabled: null,
      scanPeriodic: null,
      scanExclusions: null,
    };
    this.dialogError.set(null);
    this.previewNames.set(null);
    if (action === 'tags') this.store.ensureTags();
    if (action === 'project') this.store.ensureProjects();
    this.dialog.set(action);
    this.api.preview(this.target()).subscribe({
      next: (p) => this.previewNames.set(p.assets.map((a) => a.name)),
      error: (err: unknown) =>
        this.dialogError.set(apiErrorMessage(err, 'No se pudo calcular a qué assets afecta.')),
    });
  }

  protected closeDialog(): void {
    if (!this.busy()) this.dialog.set(null);
  }

  /**
   * Tags, proyecto, política y baja cambian el propio asset: solo por id (un CVE no tiene tags,
   * proyecto ni política; la API rechaza `vulnerabilityIds` en esas acciones).
   */
  private assetIds(): { assetIds: string[] } {
    return { assetIds: this.target().assetIds ?? [] };
  }

  protected apply(): void {
    const target = this.assetIds();
    switch (this.dialog()) {
      case 'tags':
        return this.run(
          'tags',
          this.api.tags({ ...target, add: this.addTags(), remove: this.removeTags() }),
        );
      case 'project':
        return this.run(
          'project',
          this.api.project({ ...target, project: this.projectId()!, mode: this.projectMode() }),
        );
      case 'policy':
        return this.applyPolicy(false);
    }
  }

  protected applyPolicy(clear: boolean): void {
    this.run(
      'policy',
      this.api.policy(
        clear ? { ...this.assetIds(), clear: true } : { ...this.assetIds(), fields: this.policyDraft },
      ),
    );
  }

  private confirmRetire(): void {
    this.busy.set('retire');
    this.api.preview(this.target()).subscribe({
      next: (p) => {
        this.busy.set(null);
        const descendants = p.retire.descendants;
        const more = descendants.length
          ? ` Con ellos se dan de baja ${descendants.length} que contienen: ${namesSummary(descendants.map((d) => d.name), 6)}.`
          : '';
        this.confirmation.confirm({
          header: `¿Dar de baja ${p.retire.total} ${p.retire.total === 1 ? 'asset' : 'assets'}?`,
          message: `${namesSummary(p.assets.map((a) => a.name), 12)}.${more} Se puede deshacer (no es una purga), pero se borran sus claves y hay que quitarles el acceso.`,
          icon: 'bi bi-archive',
          acceptLabel: `Dar de baja ${p.retire.total}`,
          rejectLabel: 'Cancelar',
          acceptButtonProps: { severity: 'danger' },
          rejectButtonProps: { severity: 'secondary', text: true },
          accept: () => this.run('retire', this.api.retire(this.assetIds())),
        });
      },
      error: (err: unknown) => {
        this.busy.set(null);
        this.messages.add({
          severity: 'error',
          summary: apiErrorMessage(err, 'No se pudo preparar la baja.'),
          life: 6000,
        });
      },
    });
  }

  private run(action: BulkAssetAction, request: Observable<BulkOperationResult>): void {
    this.busy.set(action);
    this.dialogError.set(null);
    request.subscribe({
      next: (r) => {
        this.busy.set(null);
        this.dialog.set(null);
        this.result.set(r);
        if (action === 'tags') this.store.reloadTags();
        this.done.emit(r);
      },
      error: (err: unknown) => {
        this.busy.set(null);
        const message = apiErrorMessage(err, `No se pudo ${BULK_ACTION_LABELS[action].toLowerCase()}.`);
        if (this.dialog()) this.dialogError.set(message);
        else this.messages.add({ severity: 'error', summary: message, life: 6000 });
      },
    });
  }
}
