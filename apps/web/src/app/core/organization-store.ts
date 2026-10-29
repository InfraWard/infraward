import { computed, inject, Injectable, signal } from '@angular/core';
import type { ProjectWithStats, TagInfo } from '@infraward/shared-types';
import { OrganizationApi } from './api/organization-api';

/**
 * Tags (con su color) y proyectos compartidos por el árbol, la ficha, los filtros y los ajustes.
 * Se piden la primera vez que alguien los necesita y se vuelven a pedir tras cada cambio.
 */
@Injectable({ providedIn: 'root' })
export class OrganizationStore {
  private readonly api = inject(OrganizationApi);

  readonly tags = signal<TagInfo[]>([]);
  readonly projects = signal<ProjectWithStats[]>([]);
  readonly projectsLoaded = signal(false);
  private tagsRequested = false;
  private projectsRequested = false;

  readonly tagColors = computed(
    () =>
      new Map(
        this.tags().flatMap((t) => (t.color ? [[t.tag, t.color] as const] : [])),
      ),
  );
  readonly projectsById = computed(
    () => new Map(this.projects().map((p) => [p.id, p])),
  );

  ensureTags(): void {
    if (this.tagsRequested) return;
    this.tagsRequested = true;
    this.reloadTags();
  }

  ensureProjects(): void {
    if (this.projectsRequested) return;
    this.projectsRequested = true;
    this.reloadProjects();
  }

  reloadTags(): void {
    this.api.tags().subscribe({
      next: (tags) => this.tags.set(tags),
      error: () => (this.tagsRequested = false),
    });
  }

  reloadProjects(): void {
    this.api.projects().subscribe({
      next: (projects) => {
        this.projects.set(projects);
        this.projectsLoaded.set(true);
      },
      error: () => (this.projectsRequested = false),
    });
  }
}
