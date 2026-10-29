import { HttpErrorResponse } from '@angular/common/http';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  inject,
  Injector,
  input,
  signal,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import type {
  AssetSummary,
  InventoryPolicyFields,
  InventoryPolicyRule,
  ProjectDetail as ProjectDetailContract,
  ProjectMember,
} from '@infraward/shared-types';
import { INVENTORY_RULE_FIELDS } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { AutoCompleteModule } from '@openng/optimus-ui/autocomplete';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import type { AutoCompleteCompleteEvent } from '@openng/optimus-ui/types/autocomplete';
import { type Observable } from 'rxjs';
import { MaintenanceApi } from '../../core/api/maintenance-api';
import { OrganizationApi } from '../../core/api/organization-api';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';
import { ASSET_TYPE_ICONS, ASSET_TYPE_LABELS } from '../../shared/labels';
import {
  POLICY_FIELD_LABELS,
  policyValueLabel,
} from '../../shared/maintenance-labels';
import { PolicyForm } from '../../shared/policy-form';
import { DashboardBoard } from '../dashboard/dashboard-board';
import { ProjectDialog } from './project-dialog';

/**
 * Página de un proyecto: su panel (QoL-8; el resumen de assets y vulnerabilidades son widgets),
 * filas directas (incluidos y excepciones), añadir assets, la regla de política del proyecto y
 * editar o borrar.
 */
@Component({
  selector: 'app-project-detail',
  imports: [
    FormsModule,
    RouterLink,
    AutoCompleteModule,
    ButtonModule,
    CardModule,
    DialogModule,
    MessageModule,
    SkeletonModule,
    TableModule,
    TagModule,
    PolicyForm,
    ProjectDialog,
    DashboardBoard,
  ],
  templateUrl: './project-detail.html',
  styleUrl: './project-detail.scss',
})
export class ProjectDetail {
  private readonly api = inject(OrganizationApi);
  private readonly maintenance = inject(MaintenanceApi);
  private readonly store = inject(OrganizationStore);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);
  private readonly router = inject(Router);
  protected readonly auth = inject(AuthService);

  /** Parámetro `:id` de la ruta. */
  readonly id = input.required<string>();

  protected readonly project = signal<ProjectDetailContract | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly editing = signal(false);
  protected readonly typeIcons: Readonly<Record<string, string>> =
    ASSET_TYPE_ICONS;
  protected readonly typeLabels: Readonly<Record<string, string>> =
    ASSET_TYPE_LABELS;
  protected readonly fields = INVENTORY_RULE_FIELDS;
  protected readonly fieldLabels = POLICY_FIELD_LABELS;
  protected readonly valueLabel = policyValueLabel;

  // --- Añadir assets ---
  protected readonly search = signal<AssetSummary | string | null>(null);
  protected readonly suggestions = signal<AssetSummary[]>([]);

  // --- Política del proyecto ---
  protected readonly rule = signal<InventoryPolicyRule | null>(null);
  protected readonly ruleDialog = signal(false);
  protected draft: InventoryPolicyFields = {};

  protected readonly included = computed(() =>
    (this.project()?.members ?? []).filter((m) => m.mode === 'include'),
  );
  protected readonly excluded = computed(() =>
    (this.project()?.members ?? []).filter((m) => m.mode === 'exclude'),
  );

  /** `#panel` (desde el botón «Panel» de la lista): baja al panel del proyecto. */
  private readonly fragment = toSignal(inject(ActivatedRoute).fragment);
  private readonly injector = inject(Injector);

  constructor() {
    effect(() => this.load(this.id()));
    effect(() => {
      if (this.project() && this.fragment() === 'panel')
        afterNextRender(() => this.scrollToPanel(), {
          injector: this.injector,
        });
    });
  }

  protected scrollToPanel(): void {
    document
      .getElementById('panel')
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  load(id: string): void {
    this.api.project(id).subscribe({
      next: (p) => {
        this.project.set(p);
        this.error.set(null);
      },
      error: (err: unknown) => {
        if (err instanceof HttpErrorResponse && err.status === 401) return;
        this.error.set(
          err instanceof HttpErrorResponse && err.status === 404
            ? 'Ese proyecto no existe (¿lo borraron?).'
            : 'No se pudo cargar el proyecto.',
        );
      },
    });
    this.maintenance.policies().subscribe({
      next: (list) =>
        this.rule.set(
          list.rules.find((r) => r.scope === 'project' && r.projectId === id) ??
            null,
        ),
    });
  }

  complete(event: AutoCompleteCompleteEvent): void {
    const q = (event.query ?? '').trim();
    this.api.searchAssets(q).subscribe({
      next: (page) => {
        const taken = new Set(
          (this.project()?.members ?? []).map((m) => m.asset.id),
        );
        this.suggestions.set(
          page.items.filter((a) => !taken.has(a.id) && a.status !== 'retired'),
        );
      },
    });
  }

  add(asset: AssetSummary): void {
    this.search.set(null);
    this.run(
      this.api.setMember(this.id(), asset.id, 'include'),
      `${asset.name} añadido con lo que contiene`,
    );
  }

  remove(member: ProjectMember): void {
    this.run(
      this.api.removeMember(this.id(), member.asset.id),
      member.mode === 'exclude'
        ? 'Excepción quitada'
        : `${member.asset.name} quitado`,
    );
  }

  edited(): void {
    this.load(this.id());
  }

  confirmDelete(): void {
    const p = this.project();
    if (!p) return;
    this.confirm.confirm({
      header: 'Borrar el proyecto',
      message: `Se borra «${p.name}» con sus filas y su regla de política; los assets no se tocan. ¿Seguir?`,
      acceptLabel: 'Borrar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.api.deleteProject(p.id).subscribe({
          next: () => {
            this.store.reloadProjects();
            this.messages.add({
              severity: 'success',
              summary: 'Proyecto borrado',
              life: 2500,
            });
            void this.router.navigate(['/projects']);
          },
          error: (err: unknown) => this.fail(err),
        }),
    });
  }

  openRule(): void {
    const r = this.rule();
    this.draft = {
      reconcileIntervalMinutes: r?.reconcileIntervalMinutes ?? null,
      scanEnabled: r?.scanEnabled ?? null,
      scanPeriodic: r?.scanPeriodic ?? null,
      scanExclusions: r?.scanExclusions ?? null,
    };
    this.ruleDialog.set(true);
  }

  saveRule(): void {
    const r = this.rule();
    const empty = INVENTORY_RULE_FIELDS.every(
      (f) => this.draft[f] === null || this.draft[f] === undefined,
    );
    if (empty) {
      if (r) this.removeRule();
      else this.ruleDialog.set(false);
      return;
    }
    const request = r
      ? this.maintenance.updateRule(r.id, this.draft)
      : this.maintenance.createRule({
          scope: 'project',
          projectId: this.id(),
          ...this.draft,
        });
    this.run(request, 'Regla del proyecto guardada', () =>
      this.ruleDialog.set(false),
    );
  }

  removeRule(): void {
    const r = this.rule();
    if (!r) return;
    this.run(
      this.maintenance.removeRule(r.id),
      'Regla del proyecto quitada',
      () => this.ruleDialog.set(false),
    );
  }

  private run(
    request: Observable<unknown>,
    done: string,
    after?: () => void,
  ): void {
    this.busy.set(true);
    request.subscribe({
      next: () => {
        this.busy.set(false);
        this.messages.add({ severity: 'success', summary: done, life: 2500 });
        this.store.reloadProjects();
        after?.();
        this.load(this.id());
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.fail(err);
      },
    });
  }

  private fail(err: unknown): void {
    this.messages.add({
      severity: 'error',
      summary: 'No se pudo hacer',
      detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
    });
  }
}
