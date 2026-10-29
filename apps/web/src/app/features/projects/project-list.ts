import { DecimalPipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import type { Project } from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { ProjectDialog } from './project-dialog';
import { fixableLabel } from './project-stats';
import { AssetTypeChips, SeverityBar, SeverityRing } from './project-visuals';

/** Cómo se ven los proyectos (se recuerda en el navegador). */
export type ProjectView = 'grid' | 'list';
const VIEW_KEY = 'infraward:projects:view';

function savedView(): ProjectView {
  try {
    return localStorage.getItem(VIEW_KEY) === 'list' ? 'list' : 'grid';
  } catch {
    return 'grid';
  }
}

/**
 * Página de proyectos (DESIGN §15), en cuadrícula (tarjetas visuales: anillo de severidad, cifras
 * clave y tipos de asset por icono) o en lista (una fila por proyecto). Cada uno enlaza a su
 * página y a las vistas filtradas.
 */
@Component({
  selector: 'app-project-list',
  imports: [
    DecimalPipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    MessageModule,
    SelectButtonModule,
    SkeletonModule,
    TooltipModule,
    ProjectDialog,
    SeverityBar,
    SeverityRing,
    AssetTypeChips,
  ],
  template: `
    <header class="page-head">
      <div>
        <h1><i class="bi bi-collection" aria-hidden="true"></i> Proyectos</h1>
        <p class="muted">
          Grupos de assets: cada uno entra con todo lo que contiene, salvo excepciones.
        </p>
      </div>
      <div class="head-actions">
        <p-selectbutton
          [options]="views"
          optionValue="value"
          [ngModel]="view()"
          (ngModelChange)="setView($event)"
          [allowEmpty]="false"
          ariaLabel="Vista"
          data-project-view
        >
          <ng-template #item let-o>
            <i class="bi {{ o.icon }}" [pTooltip]="o.label" tooltipPosition="bottom" aria-hidden="true"></i>
            <span class="sr-only">{{ o.label }}</span>
          </ng-template>
        </p-selectbutton>
        @if (auth.can('projects.write')) {
          <p-button label="Nuevo proyecto" icon="bi bi-plus-lg" (onClick)="creating.set(true)" data-action="new-project" />
        }
      </div>
    </header>

    @if (!store.projectsLoaded()) {
      <div class="grid">
        <p-skeleton height="13rem" />
        <p-skeleton height="13rem" />
      </div>
    } @else if (!store.projects().length) {
      <p-message severity="info" icon="bi bi-info-circle">
        Aún no hay proyectos.
        @if (auth.can('projects.write')) {
          Crea uno y añade un nodo: entrará con todo lo que contiene.
        }
      </p-message>
    } @else if (view() === 'grid') {
      <div class="grid" data-project-grid>
        @for (p of store.projects(); track p.id) {
          <article class="card" [style.--project-color]="p.color ?? null" [attr.data-project]="p.name">
            <a class="cover" [routerLink]="['/projects', p.id]" [attr.aria-label]="'Abrir ' + p.name"></a>
            <header class="card-head">
              <span class="badge" aria-hidden="true">{{ initial(p.name) }}</span>
              <div class="title">
                <h2>{{ p.name }}</h2>
                @if (p.description) {
                  <p class="description" [title]="p.description">{{ p.description }}</p>
                }
              </div>
            </header>
            <div class="body">
              <app-severity-ring [stats]="p.stats" />
              <dl class="figures">
                <div data-kpi="assets"><dt>Assets</dt><dd>{{ p.stats.assets | number }}</dd></div>
                <div data-kpi="cves"><dt>CVE abiertos</dt><dd>{{ p.stats.openVulnerabilities | number }}</dd></div>
                <div data-kpi="critical">
                  <dt>Críticas</dt>
                  <dd [class.danger]="p.stats.openFindings.CRITICAL > 0">{{ p.stats.openFindings.CRITICAL | number }}</dd>
                </div>
              </dl>
            </div>
            <footer class="card-foot">
              <app-asset-type-chips class="one-line" [stats]="p.stats" [compact]="true" [max]="4" />
              <nav class="links" [attr.aria-label]="'Ver ' + p.name + ' en'">
                <a [routerLink]="['/inventory']" [queryParams]="{ project: p.id }" pTooltip="Inventario" tooltipPosition="top" aria-label="Inventario"><i class="bi bi-diagram-3"></i></a>
                <a [routerLink]="['/vulnerabilities']" [queryParams]="{ project: p.id }" pTooltip="Vulnerabilidades" tooltipPosition="top" aria-label="Vulnerabilidades"><i class="bi bi-shield-exclamation"></i></a>
                <a [routerLink]="['/projects', p.id]" fragment="panel" pTooltip="Panel" tooltipPosition="top" aria-label="Panel"><i class="bi bi-speedometer2"></i></a>
              </nav>
            </footer>
          </article>
        }
      </div>
    } @else {
      <div class="list" role="table" aria-label="Proyectos" data-project-list>
        <div class="list-head" role="row">
          <span role="columnheader">Proyecto</span>
          <span role="columnheader" class="num">Assets</span>
          <span role="columnheader" class="num">CVE</span>
          <span role="columnheader">Severidad</span>
          <span role="columnheader" class="num">Con parche</span>
          <span role="columnheader" class="sr-only">Ver en</span>
        </div>
        @for (p of store.projects(); track p.id) {
          <div class="list-row" role="row" [style.--project-color]="p.color ?? null" [attr.data-project]="p.name">
            <span role="cell" class="name">
              <span class="dot" aria-hidden="true"></span>
              <a [routerLink]="['/projects', p.id]">{{ p.name }}</a>
              @if (p.description) {
                <small class="muted ellipsis" [title]="p.description">{{ p.description }}</small>
              }
            </span>
            <span role="cell" class="num" data-kpi="assets" data-label="Assets ">{{ p.stats.assets | number }}</span>
            <span role="cell" class="num" data-kpi="cves" data-label="CVE ">{{ p.stats.openVulnerabilities | number }}</span>
            <span role="cell" class="bar">
              @if (p.stats.openVulnerabilities) {
                <app-severity-bar [stats]="p.stats" [compact]="true" />
              } @else {
                <small class="muted">—</small>
              }
            </span>
            <span role="cell" class="num" data-kpi="fixable" data-label="Con parche ">
              @if (fixable(p.stats); as f) {
                <span class="danger" [pTooltip]="f + ' con parche'">{{ p.stats.fixableFindings.CRITICAL + p.stats.fixableFindings.HIGH | number }}</span>
              } @else {
                <i class="bi bi-shield-check ok" aria-label="Ninguno"></i>
              }
            </span>
            <span role="cell" class="links">
              <a [routerLink]="['/inventory']" [queryParams]="{ project: p.id }" pTooltip="Inventario" aria-label="Inventario"><i class="bi bi-diagram-3"></i></a>
              <a [routerLink]="['/vulnerabilities']" [queryParams]="{ project: p.id }" pTooltip="Vulnerabilidades" aria-label="Vulnerabilidades"><i class="bi bi-shield-exclamation"></i></a>
              <a [routerLink]="['/projects', p.id]" fragment="panel" pTooltip="Panel" aria-label="Panel"><i class="bi bi-speedometer2"></i></a>
            </span>
          </div>
        }
      </div>
    }

    <app-project-dialog [(visible)]="creating" (saved)="onCreated($event)" />
  `,
  styles: `
    .page-head {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: flex-end;
      justify-content: space-between;
      margin-bottom: 1.25rem;
    }
    .head-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    h1 {
      margin: 0.5rem 0 0.25rem;
      font-size: 1.5rem;
    }
    .muted {
      color: var(--p-text-muted-color);
      margin: 0;
    }
    .danger {
      color: var(--p-app-danger-color);
    }
    .ok {
      color: var(--p-app-success-color);
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }

    /* --- Cuadrícula --- */
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(min(100%, 19rem), 1fr));
      gap: 1rem;
    }
    .card {
      --project-color: var(--p-primary-color);
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 1rem;
      padding: 1.1rem 1.15rem 0.9rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: 14px;
      background:
        linear-gradient(160deg, color-mix(in srgb, var(--project-color) 14%, transparent), transparent 45%),
        var(--p-content-background);
      transition: box-shadow 0.15s, transform 0.15s, border-color 0.15s;
    }
    .card:hover {
      border-color: color-mix(in srgb, var(--project-color) 55%, var(--p-content-border-color));
      box-shadow: 0 6px 20px -8px color-mix(in srgb, var(--project-color) 45%, transparent);
      transform: translateY(-2px);
    }
    /* Toda la tarjeta lleva a su página; los enlaces del pie quedan por encima. */
    .cover {
      position: absolute;
      inset: 0;
      border-radius: inherit;
    }
    .cover:focus-visible {
      outline: 2px solid var(--p-primary-color);
      outline-offset: 2px;
    }
    .card-head {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      min-width: 0;
    }
    .badge {
      flex: none;
      width: 2.6rem;
      height: 2.6rem;
      border-radius: 10px;
      display: grid;
      place-items: center;
      font-weight: 700;
      font-size: 1.15rem;
      color: #fff;
      background: var(--project-color);
    }
    .title {
      min-width: 0;
    }
    h2 {
      margin: 0;
      font-size: 1.05rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .description,
    .ellipsis {
      margin: 0.1rem 0 0;
      font-size: 0.85rem;
      color: var(--p-text-muted-color);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .body {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }
    .figures {
      flex: 1;
      display: grid;
      gap: 0.45rem;
      margin: 0;
    }
    .figures div {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 0.5rem;
      border-bottom: 1px dashed var(--p-content-border-color);
      padding-bottom: 0.3rem;
    }
    .figures div:last-child {
      border-bottom: 0;
    }
    dt {
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
    dd {
      margin: 0;
      font-size: 1.1rem;
      font-weight: 600;
    }
    .card-foot {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      margin-top: auto;
    }
    .card-foot app-asset-type-chips {
      min-width: 0;
    }
    .links {
      position: relative;
      z-index: 1;
      display: flex;
      gap: 0.15rem;
      flex: none;
    }
    .links a {
      display: grid;
      place-items: center;
      width: 2rem;
      height: 2rem;
      border-radius: 8px;
      color: var(--p-text-muted-color);
    }
    .links a:hover {
      color: var(--p-primary-color);
      background: var(--p-app-background);
    }

    /* --- Lista --- */
    .list {
      border: 1px solid var(--p-content-border-color);
      border-radius: 12px;
      background: var(--p-content-background);
      overflow: hidden;
    }
    .list-head,
    .list-row {
      display: grid;
      grid-template-columns: minmax(12rem, 2.2fr) 5rem 5rem minmax(8rem, 1.4fr) 6rem 6.5rem;
      align-items: center;
      gap: 1rem;
      padding: 0.7rem 1rem;
    }
    .list-head {
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
      background: var(--p-app-background);
    }
    .list-head {
      border-left: 3px solid transparent;
    }
    .list-row {
      --project-color: var(--p-primary-color);
      border-top: 1px solid var(--p-content-border-color);
      border-left: 3px solid var(--project-color);
    }
    .list-row .links {
      justify-content: flex-end;
    }
    .list-row:hover {
      background: color-mix(in srgb, var(--project-color) 6%, transparent);
    }
    .name {
      display: grid;
      grid-template-columns: auto 1fr;
      column-gap: 0.5rem;
      align-items: center;
      min-width: 0;
    }
    .name a {
      font-weight: 600;
      color: inherit;
      text-decoration: none;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .name a:hover {
      text-decoration: underline;
    }
    .name small {
      grid-column: 2;
    }
    .dot {
      width: 0.65rem;
      height: 0.65rem;
      border-radius: 50%;
      background: var(--project-color);
    }
    .num {
      text-align: right;
      font-variant-numeric: tabular-nums;
    }
    .list-row .num {
      font-weight: 600;
    }
    @media (max-width: 800px) {
      .list-head {
        display: none;
      }
      .list-row {
        grid-template-columns: 1fr auto;
        gap: 0.4rem 1rem;
      }
      .list-row .name {
        grid-column: 1 / -1;
      }
      .list-row .bar {
        grid-column: 1 / -1;
      }
      .list-row .num {
        text-align: left;
      }
      .list-row [data-label]::before {
        content: attr(data-label);
        font-weight: 400;
        color: var(--p-text-muted-color);
      }
    }
  `,
})
export class ProjectList {
  protected readonly store = inject(OrganizationStore);
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly creating = signal(false);
  protected readonly fixable = fixableLabel;
  protected readonly view = signal<ProjectView>(savedView());
  protected readonly views = [
    { value: 'grid', label: 'Cuadrícula', icon: 'bi-grid-3x2-gap' },
    { value: 'list', label: 'Lista', icon: 'bi-list-ul' },
  ];

  protected setView(view: ProjectView): void {
    this.view.set(view);
    try {
      localStorage.setItem(VIEW_KEY, view);
    } catch {
      // Sin almacenamiento (ventana privada): solo para esta visita.
    }
  }

  /** Inicial del proyecto para la insignia. */
  protected initial(name: string): string {
    return [...name.trim()][0]?.toUpperCase() ?? '?';
  }

  constructor() {
    // Siempre al día al entrar (el resumen cambia con el inventario).
    this.store.reloadProjects();
  }

  /** Recién creado: a su página, para añadirle assets. */
  protected onCreated(project: Project): void {
    void this.router.navigate(['/projects', project.id]);
  }
}
