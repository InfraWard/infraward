import { Component, effect, inject, input, model, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  PROJECT_DESCRIPTION_MAX,
  PROJECT_NAME_MAX,
  type Project,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { OrganizationApi } from '../../core/api/organization-api';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';
import { ColorSwatches } from '../../shared/color-swatches';

/** Alta o edición de un proyecto: nombre, descripción y color. */
@Component({
  selector: 'app-project-dialog',
  imports: [
    FormsModule,
    ButtonModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    TextareaModule,
    ColorSwatches,
  ],
  template: `
    <p-dialog
      [header]="project() ? 'Editar el proyecto' : 'Nuevo proyecto'"
      [visible]="visible()"
      (visibleChange)="visible.set($event)"
      [modal]="true"
      [style]="{ width: 'min(32rem, 95vw)' }"
      data-dialog="project"
    >
      <form class="form" (ngSubmit)="save()" id="project-form">
        <label for="project-name">Nombre</label>
        <input
          pInputText
          id="project-name"
          name="name"
          [attr.maxlength]="nameMax"
          [ngModel]="name()"
          (ngModelChange)="name.set($event)"
          autocomplete="off"
        />
        <label for="project-description">Descripción <span class="muted">(opcional)</span></label>
        <textarea
          pTextarea
          id="project-description"
          name="description"
          rows="3"
          [attr.maxlength]="descriptionMax"
          [ngModel]="description()"
          (ngModelChange)="description.set($event)"
        ></textarea>
        <span class="label">Color</span>
        <app-color-swatches [(value)]="color" label="Color del proyecto" />
        @if (error(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
        }
      </form>
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="visible.set(false)" />
        <p-button
          [label]="project() ? 'Guardar' : 'Crear'"
          (onClick)="save()"
          icon="bi bi-check-lg"
          [loading]="saving()"
          data-action="save-project"
        />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    .form {
      display: grid;
      gap: 0.4rem;
    }
    label,
    .label {
      font-weight: 600;
      margin-top: 0.4rem;
    }
    .muted {
      color: var(--p-text-muted-color);
      font-weight: normal;
    }
    textarea {
      resize: vertical;
    }
  `,
})
export class ProjectDialog {
  private readonly api = inject(OrganizationApi);
  private readonly store = inject(OrganizationStore);
  private readonly messages = inject(MessageService);
  protected readonly nameMax = PROJECT_NAME_MAX;
  protected readonly descriptionMax = PROJECT_DESCRIPTION_MAX;

  readonly visible = model(false);
  /** null = proyecto nuevo. */
  readonly project = input<Project | null>(null);
  readonly saved = output<Project>();

  protected readonly name = signal('');
  protected readonly description = signal('');
  protected readonly color = signal<string | null>(null);
  protected readonly saving = signal(false);
  protected readonly error = signal<string | null>(null);

  constructor() {
    // Al abrir: los datos del proyecto (o vacío).
    effect(() => {
      if (!this.visible()) return;
      const p = this.project();
      this.name.set(p?.name ?? '');
      this.description.set(p?.description ?? '');
      this.color.set(p?.color ?? null);
      this.error.set(null);
    });
  }

  save(): void {
    const name = this.name().trim();
    if (!name) {
      this.error.set('Ponle un nombre.');
      return;
    }
    const body = {
      name,
      description: this.description().trim() || null,
      color: this.color(),
    };
    const p = this.project();
    this.saving.set(true);
    (p ? this.api.updateProject(p.id, body) : this.api.createProject(body)).subscribe({
      next: (project) => {
        this.saving.set(false);
        this.visible.set(false);
        this.store.reloadProjects();
        this.messages.add({
          severity: 'success',
          summary: p ? 'Proyecto guardado' : `Proyecto «${project.name}» creado`,
          life: 2500,
        });
        this.saved.emit(project);
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudo guardar el proyecto.'));
      },
    });
  }
}
