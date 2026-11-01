import {
  Component,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  ASSET_TYPES,
  DASHBOARD_TAGS_MAX,
  DASHBOARD_TITLE_MAX,
  DASHBOARD_WIDGETS,
  WIDGET_TYPES,
  widgetOptions,
  type AssetType,
  type DashboardWidget,
  type WidgetOptionSpec,
  type WidgetType,
  byCodeUnit,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { SelectModule } from '@openng/optimus-ui/select';
import { OrganizationStore } from '../../core/organization-store';
import { ASSET_TYPE_LABELS } from '../../shared/labels';

/** Catálogo de widgets: elegir el tipo que se añade. */
@Component({
  selector: 'app-widget-catalog',
  imports: [DialogModule],
  template: `
    <p-dialog
      header="Añadir un widget"
      [visible]="visible()"
      (visibleChange)="!$event && closed.emit()"
      [modal]="true"
      [style]="{ width: 'min(46rem, 96vw)' }"
      [dismissableMask]="true"
      appendTo="body"
    >
      <ul class="catalog" data-widget-catalog>
        @for (t of types; track t) {
          <li>
            <button
              type="button"
              (click)="picked.emit(t)"
              [attr.data-add-widget]="t"
            >
              <i class="bi {{ defs[t].icon }}" aria-hidden="true"></i>
              <strong>{{ defs[t].label }}</strong>
              <span>{{ defs[t].description }}</span>
            </button>
          </li>
        }
      </ul>
    </p-dialog>
  `,
  styles: `
    .catalog {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(13rem, 1fr));
      gap: 0.6rem;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    button {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.15rem 0.5rem;
      width: 100%;
      height: 100%;
      padding: 0.7rem;
      text-align: left;
      font: inherit;
      color: inherit;
      cursor: pointer;
      border-radius: 6px;
      border: 1px solid var(--p-content-border-color);
      background: var(--p-content-background);
      &:hover,
      &:focus-visible {
        border-color: var(--p-primary-color);
      }
    }
    i {
      grid-row: span 2;
      color: var(--p-primary-color);
      font-size: 1.2rem;
    }
    span {
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
  `,
})
export class WidgetCatalog {
  readonly visible = input(false);
  readonly picked = output<WidgetType>();
  readonly closed = output<void>();
  protected readonly types = WIDGET_TYPES;
  protected readonly defs = DASHBOARD_WIDGETS;
}

interface OptionField {
  key: string;
  spec: WidgetOptionSpec;
}

/**
 * Configuración de un widget: título, filtros (proyecto, tags, tipo y sitio, el que el tipo
 * admita) y sus opciones, del catálogo. En el panel de un proyecto, el proyecto está fijado.
 */
@Component({
  selector: 'app-widget-config',
  imports: [
    FormsModule,
    ButtonModule,
    DialogModule,
    InputNumberModule,
    InputTextModule,
    MultiSelectModule,
    SelectModule,
  ],
  template: `
    @if (widget(); as w) {
      <p-dialog
        [header]="(adding() ? 'Añadir: ' : 'Configurar: ') + defs[w.type].label"
        [visible]="true"
        (visibleChange)="!$event && closed.emit()"
        [modal]="true"
        [style]="{ width: 'min(34rem, 96vw)' }"
        appendTo="body"
      >
        <form class="form" (ngSubmit)="submit()" data-widget-config>
          <div class="field">
            <label for="cfg-title">Título</label>
            <input
              pInputText
              id="cfg-title"
              name="title"
              [ngModel]="title()"
              (ngModelChange)="title.set($event)"
              [maxlength]="titleMax"
              [placeholder]="defs[w.type].label"
            />
          </div>
          @if (allows('projectId')) {
            <div class="field">
              <label for="cfg-project">Proyecto</label>
              @if (lockedProject()) {
                <input
                  pInputText
                  id="cfg-project"
                  name="project"
                  [value]="lockedName()"
                  disabled
                />
                <small
                  >El panel de un proyecto solo enseña lo de ese
                  proyecto.</small
                >
              } @else {
                <p-select
                  inputId="cfg-project"
                  name="project"
                  [options]="store.projects()"
                  optionLabel="name"
                  optionValue="id"
                  [showClear]="true"
                  placeholder="Todos los proyectos"
                  [ngModel]="projectId()"
                  (ngModelChange)="projectId.set($event ?? undefined)"
                  appendTo="body"
                  data-config="project"
                />
                <small
                  >El selector de proyecto de la página, si se usa, lo
                  sustituye.</small
                >
              }
            </div>
          }
          @if (allows('tags')) {
            <div class="field">
              <label for="cfg-tags">Tags (alguno de ellos)</label>
              <p-multiselect
                inputId="cfg-tags"
                name="tags"
                [options]="tagOptions()"
                [ngModel]="tags()"
                (ngModelChange)="tags.set($event ?? [])"
                [filter]="true"
                display="chip"
                [selectionLimit]="tagsMax"
                placeholder="Cualquiera"
                appendTo="body"
                data-config="tags"
              />
            </div>
          }
          @if (allows('types')) {
            <div class="field">
              <label for="cfg-types">Tipo de asset (alguno de ellos)</label>
              <p-multiselect
                inputId="cfg-types"
                name="types"
                [options]="typeOptions"
                optionLabel="label"
                optionValue="value"
                [ngModel]="types()"
                (ngModelChange)="types.set($event ?? [])"
                display="chip"
                placeholder="Cualquiera"
                appendTo="body"
                data-config="types"
              />
            </div>
          }
          <div class="field">
            <label for="cfg-site">Sitio</label>
            <input
              pInputText
              id="cfg-site"
              name="site"
              [value]="w.filters.site ?? ''"
              disabled
              placeholder="Aún no hay sitios"
            />
            <small>Llegará con los workers remotos: hoy no tiene efecto.</small>
          </div>
          @for (f of fields(); track f.key) {
            <div class="field">
              <label [for]="'cfg-' + f.key">{{ f.spec.label }}</label>
              @switch (f.spec.kind) {
                @case ('select') {
                  <p-select
                    [inputId]="'cfg-' + f.key"
                    [name]="f.key"
                    [options]="$any(f.spec).choices"
                    optionLabel="label"
                    optionValue="value"
                    [ngModel]="options()[f.key]"
                    (ngModelChange)="setOption(f.key, $event)"
                    appendTo="body"
                    [attr.data-config]="f.key"
                  />
                }
                @case ('multi') {
                  <p-multiselect
                    [inputId]="'cfg-' + f.key"
                    [name]="f.key"
                    [options]="$any(f.spec).choices"
                    optionLabel="label"
                    optionValue="value"
                    [ngModel]="options()[f.key]"
                    (ngModelChange)="setOption(f.key, $event)"
                    display="chip"
                    appendTo="body"
                    [attr.data-config]="f.key"
                  />
                }
                @case ('number') {
                  <p-inputnumber
                    [inputId]="'cfg-' + f.key"
                    [name]="f.key"
                    [ngModel]="options()[f.key]"
                    (ngModelChange)="setOption(f.key, $event ?? null)"
                    [min]="$any(f.spec).min"
                    [max]="$any(f.spec).max"
                    [useGrouping]="false"
                    [showClear]="true"
                    [attr.data-config]="f.key"
                  />
                  @if ($any(f.spec).hint) {
                    <small>{{ $any(f.spec).hint }}</small>
                  }
                }
              }
            </div>
          }
          @if (error(); as e) {
            <p class="error">{{ e }}</p>
          }
          <div class="actions">
            <p-button
              label="Cancelar"
              severity="secondary"
              [text]="true"
              (onClick)="closed.emit()"
            />
            <p-button
              type="submit"
              [label]="adding() ? 'Añadir' : 'Aplicar'"
              icon="bi bi-check-lg"
              data-config-submit
            />
          </div>
        </form>
      </p-dialog>
    }
  `,
  styles: `
    .form {
      display: grid;
      gap: 0.9rem;
    }
    .field {
      display: grid;
      gap: 0.3rem;
    }
    label {
      font-weight: 600;
      font-size: 0.9rem;
    }
    small {
      font-weight: 400;
      color: var(--p-text-muted-color);
    }
    .actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.5rem;
    }
    .error {
      margin: 0;
      color: var(--p-app-danger-color);
    }
    :host ::ng-deep .p-select,
    :host ::ng-deep .p-multiselect,
    :host ::ng-deep .p-inputnumber {
      width: 100%;
    }
  `,
})
export class WidgetConfig {
  protected readonly store = inject(OrganizationStore);
  /** El widget que se edita (null = cerrado). */
  readonly widget = input<DashboardWidget | null>(null);
  readonly adding = input(false);
  readonly lockedProject = input<string>();
  readonly saved = output<DashboardWidget>();
  readonly closed = output<void>();

  protected readonly defs = DASHBOARD_WIDGETS;
  protected readonly titleMax = DASHBOARD_TITLE_MAX;
  protected readonly tagsMax = DASHBOARD_TAGS_MAX;
  protected readonly typeOptions = ASSET_TYPES.map((t) => ({
    value: t,
    label: ASSET_TYPE_LABELS[t],
  }));

  protected readonly title = signal('');
  protected readonly projectId = signal<string | undefined>(undefined);
  protected readonly tags = signal<string[]>([]);
  protected readonly types = signal<AssetType[]>([]);
  protected readonly options = signal<Record<string, unknown>>({});
  protected readonly error = signal<string | null>(null);

  protected readonly tagOptions = computed(() => {
    const known = this.store.tags().map((t) => t.tag);
    return [...new Set([...known, ...this.tags()])].sort(byCodeUnit);
  });
  protected readonly lockedName = computed(
    () =>
      this.store.projectsById().get(this.lockedProject() ?? '')?.name ??
      'Este proyecto',
  );
  protected readonly fields = computed<OptionField[]>(() => {
    const w = this.widget();
    return w
      ? Object.entries(DASHBOARD_WIDGETS[w.type].options).map(
          ([key, spec]) => ({ key, spec }),
        )
      : [];
  });

  constructor() {
    // Al abrir con otro widget, el formulario parte de sus valores (tags y proyectos, al abrirse).
    effect(() => {
      const w = this.widget();
      if (!w) return;
      this.store.ensureTags();
      this.store.ensureProjects();
      this.title.set(w.title ?? '');
      this.projectId.set(w.filters.projectId);
      this.tags.set([...(w.filters.tags ?? [])]);
      this.types.set([...(w.filters.types ?? [])]);
      this.options.set(widgetOptions(w.type, w.options));
      this.error.set(null);
    });
  }

  protected allows(filter: 'projectId' | 'tags' | 'types'): boolean {
    const w = this.widget();
    return !!w && DASHBOARD_WIDGETS[w.type].filters.includes(filter);
  }

  protected setOption(key: string, value: unknown): void {
    this.options.update((o) => ({ ...o, [key]: value }));
  }

  protected submit(): void {
    const w = this.widget();
    if (!w) return;
    const options = this.options();
    for (const { key, spec } of this.fields())
      if (
        spec.kind === 'multi' &&
        !(options[key] as unknown[] | undefined)?.length
      ) {
        this.error.set(`${spec.label}: elige al menos uno.`);
        return;
      }
    const title = this.title().trim();
    this.saved.emit({
      ...w,
      ...(title ? { title } : { title: undefined }),
      filters: {
        ...(this.lockedProject()
          ? { projectId: this.lockedProject() }
          : this.projectId()
            ? { projectId: this.projectId() }
            : {}),
        ...(this.tags().length ? { tags: this.tags() } : {}),
        ...(this.types().length ? { types: this.types() } : {}),
        ...(w.filters.site ? { site: w.filters.site } : {}),
      },
      options: widgetOptions(w.type, options),
    });
  }
}
