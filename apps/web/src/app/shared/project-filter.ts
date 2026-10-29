import { Component, computed, inject, input, output } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { SelectModule } from '@openng/optimus-ui/select';
import { OrganizationStore } from '../core/organization-store';

/**
 * Selector de proyecto de los filtros (inventario, vulnerabilidades y panel): emite el id elegido
 * o null («Todos los proyectos»). Sin proyectos creados no se muestra.
 */
@Component({
  selector: 'app-project-filter',
  imports: [FormsModule, SelectModule],
  template: `
    @if (options().length) {
      <p-select
        [options]="options()"
        optionLabel="name"
        optionValue="id"
        [ngModel]="value() ?? null"
        (ngModelChange)="changed.emit($event ?? null)"
        [showClear]="true"
        placeholder="Todos los proyectos"
        ariaLabel="Filtrar por proyecto"
        appendTo="body"
        styleClass="project-filter"
        data-project-filter
      >
        <ng-template #selectedItem let-p>
          <span class="opt"><span class="dot" [style.background]="p.color ?? 'var(--p-text-muted-color)'"></span>{{ p.name }}</span>
        </ng-template>
        <ng-template #item let-p>
          <span class="opt" [attr.data-option]="p.name"><span class="dot" [style.background]="p.color ?? 'var(--p-text-muted-color)'"></span>{{ p.name }}</span>
        </ng-template>
      </p-select>
    }
  `,
  styles: `
    .opt {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
    }
    .dot {
      width: 0.6rem;
      height: 0.6rem;
      border-radius: 50%;
      flex: none;
    }
    :host ::ng-deep .project-filter {
      min-width: 12rem;
      max-width: 100%;
    }
  `,
})
export class ProjectFilter {
  private readonly store = inject(OrganizationStore);
  readonly value = input<string | null | undefined>(null);
  readonly changed = output<string | null>();
  protected readonly options = computed(() => this.store.projects());

  constructor() {
    this.store.ensureProjects();
  }
}
