import { Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type {
  Asset,
  AssetProjects,
  Project,
  ProjectMembershipMode,
  ProjectMembershipSource,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { SelectModule } from '@openng/optimus-ui/select';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { Observable } from 'rxjs';
import { OrganizationApi } from '../../core/api/organization-api';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';

/** «directo», «heredado de pve», «por quienes la usan». */
export function membershipLabel(source: ProjectMembershipSource): string {
  switch (source.kind) {
    case 'direct':
      return 'directo';
    case 'inherited':
      return `heredado de ${source.from.name}`;
    case 'holders':
      return 'por los hosts y contenedores que la usan';
  }
}

/**
 * Tarjeta «Proyectos» del Resumen (DESIGN §5): a qué proyectos pertenece y por qué, y las
 * excepciones. Con `projects.write`: añadir a un proyecto (con lo que contiene), excluir de uno
 * heredado y quitar filas propias.
 */
@Component({
  selector: 'app-asset-projects',
  imports: [FormsModule, RouterLink, ButtonModule, CardModule, SelectModule, TooltipModule],
  template: `
    <p-card styleClass="card" data-section="projects">
      <ng-template #title>
        <i class="bi bi-collection" aria-hidden="true"></i> Proyectos
      </ng-template>
      @if (data(); as d) {
        @if (d.projects.length) {
          <ul class="list">
            @for (p of d.projects; track p.id) {
              <li [attr.data-project]="p.name">
                <span class="dot" [style.background]="p.color ?? 'var(--p-text-muted-color)'"></span>
                <a [routerLink]="['/projects', p.id]">{{ p.name }}</a>
                <span class="muted">· {{ label(p.source) }}</span>
                @if (canWrite()) {
                  <span class="spacer"></span>
                  @if (p.source.kind === 'direct') {
                    <p-button
                      label="Quitar"
                      severity="secondary"
                      [text]="true"
                      size="small"
                      [disabled]="busy()"
                      [pTooltip]="'Quitar ' + asset().name + ' (y lo que contiene) de ' + p.name"
                      (onClick)="remove(p)"
                      data-action="remove-membership"
                    />
                  } @else {
                    <p-button
                      label="Excluir"
                      severity="secondary"
                      [text]="true"
                      size="small"
                      [disabled]="busy()"
                      [pTooltip]="'Excepción: sacar ' + asset().name + ' y lo que contiene de ' + p.name"
                      (onClick)="set(p, 'exclude')"
                      data-action="exclude"
                    />
                  }
                }
              </li>
            }
          </ul>
        } @else {
          <p class="muted">No pertenece a ningún proyecto.</p>
        }
        @if (d.excluded.length) {
          <p class="muted small">Excluido (con lo que contiene) de:</p>
          <ul class="list">
            @for (p of d.excluded; track p.id) {
              <li [attr.data-excluded]="p.name">
                <span class="dot" [style.background]="p.color ?? 'var(--p-text-muted-color)'"></span>
                <a [routerLink]="['/projects', p.id]">{{ p.name }}</a>
                @if (canWrite()) {
                  <span class="spacer"></span>
                  <p-button
                    label="Quitar la excepción"
                    severity="secondary"
                    [text]="true"
                    size="small"
                    [disabled]="busy()"
                    (onClick)="remove(p)"
                    data-action="remove-exclusion"
                  />
                }
              </li>
            }
          </ul>
        }
        @if (canWrite() && available().length) {
          <div class="add">
            <p-select
              [options]="available()"
              optionLabel="name"
              optionValue="id"
              [ngModel]="choice()"
              (ngModelChange)="choice.set($event)"
              placeholder="Añadir a un proyecto…"
              ariaLabel="Proyecto"
              appendTo="body"
              styleClass="pick"
              data-project-pick
            />
            <p-button
              label="Añadir"
              icon="bi bi-plus-lg"
              size="small"
              [disabled]="!choice() || busy()"
              (onClick)="add()"
              data-action="add-to-project"
            />
          </div>
          <small class="muted">Entra con todo lo que contiene (CT, contenedores, imágenes…).</small>
        }
      } @else if (error()) {
        <p class="muted">No se pudieron cargar sus proyectos.</p>
      }
    </p-card>
  `,
  styles: `
    .list {
      list-style: none;
      margin: 0 0 0.5rem;
      padding: 0;
      display: grid;
      gap: 0.25rem;
    }
    li {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      flex-wrap: wrap;
    }
    .dot {
      width: 0.6rem;
      height: 0.6rem;
      border-radius: 50%;
      flex: none;
    }
    .spacer {
      flex: 1;
    }
    .muted {
      color: var(--p-text-muted-color);
      margin: 0;
    }
    .small {
      font-size: 0.85rem;
      margin: 0.25rem 0;
    }
    .add {
      display: flex;
      gap: 0.5rem;
      align-items: center;
      flex-wrap: wrap;
      margin: 0.5rem 0 0.25rem;
    }
    :host ::ng-deep .pick {
      flex: 1 1 12rem;
      min-width: 0;
    }
  `,
})
export class AssetProjectsCard {
  private readonly api = inject(OrganizationApi);
  private readonly messages = inject(MessageService);
  private readonly store = inject(OrganizationStore);
  protected readonly auth = inject(AuthService);

  readonly asset = input.required<Asset>();
  /** Cambió la pertenencia: la política puede cambiar (reglas por proyecto). */
  readonly changed = output<void>();

  protected readonly data = signal<AssetProjects | null>(null);
  protected readonly error = signal(false);
  protected readonly busy = signal(false);
  protected readonly choice = signal<string | null>(null);
  protected readonly canWrite = computed(
    () => this.auth.can('projects.write') && this.asset().status !== 'retired',
  );
  protected readonly label = membershipLabel;
  /** Proyectos en los que aún no está (ni excluido). */
  protected readonly available = computed(() => {
    const d = this.data();
    const taken = new Set([
      ...(d?.projects ?? []).map((p) => p.id),
      ...(d?.excluded ?? []).map((p) => p.id),
    ]);
    return this.store.projects().filter((p) => !taken.has(p.id));
  });

  constructor() {
    this.store.ensureProjects();
    effect(() => this.load(this.asset().id));
  }

  add(): void {
    const id = this.choice();
    if (!id) return;
    this.run(this.api.setMember(id, this.asset().id, 'include'), 'Añadido al proyecto');
  }

  set(project: Project, mode: ProjectMembershipMode): void {
    this.run(
      this.api.setMember(project.id, this.asset().id, mode),
      mode === 'exclude' ? `Excluido de ${project.name}` : 'Añadido al proyecto',
    );
  }

  remove(project: Project): void {
    this.run(this.api.removeMember(project.id, this.asset().id), 'Hecho');
  }

  private load(id: string): void {
    this.api.assetProjects(id).subscribe({
      next: (d) => {
        this.data.set(d);
        this.error.set(false);
      },
      error: () => this.error.set(true),
    });
  }

  private run(request: Observable<unknown>, done: string): void {
    this.busy.set(true);
    request.subscribe({
      next: () => {
        this.busy.set(false);
        this.choice.set(null);
        this.messages.add({ severity: 'success', summary: done, life: 2500 });
        this.store.reloadProjects();
        this.load(this.asset().id);
        this.changed.emit();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'No se pudo cambiar',
          detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
        });
      },
    });
  }
}
