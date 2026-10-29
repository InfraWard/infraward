import { Component, computed, inject, input } from '@angular/core';
import { Router } from '@angular/router';
import { ProjectFilter } from '../../shared/project-filter';
import { DashboardBoard } from './dashboard-board';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Panel de inicio (DESIGN §15): el tuyo, hecho con widgets (el por defecto si no lo has
 * personalizado). El selector de proyecto (`?project=`) limita todos los widgets a ese proyecto.
 */
@Component({
  selector: 'app-dashboard',
  imports: [DashboardBoard, ProjectFilter],
  template: `
    <header class="page-head">
      <div>
        <h1><i class="bi bi-speedometer2" aria-hidden="true"></i> Panel</h1>
        <p>Lo que hay, lo que hay que corregir y lo que pide atención.</p>
      </div>
      <app-project-filter
        [value]="projectId()"
        (changed)="setProject($event)"
      />
    </header>
    <app-dashboard-board [scopeProject]="projectId()" [canEdit]="true" />
  `,
})
export class Dashboard {
  private readonly router = inject(Router);

  /** `?project=<id>`: solo lo de ese proyecto. */
  readonly project = input<string>();
  protected readonly projectId = computed(() =>
    UUID.test(this.project() ?? '') ? this.project()! : undefined,
  );

  setProject(project: string | null): void {
    void this.router.navigate([], {
      queryParams: { project },
      queryParamsHandling: 'merge',
    });
  }
}
