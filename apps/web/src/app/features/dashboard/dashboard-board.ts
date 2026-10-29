import { HttpErrorResponse } from '@angular/common/http';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import {
  DASHBOARD_COLUMNS,
  DASHBOARD_MAX_HEIGHT,
  DASHBOARD_MAX_WIDGETS,
  DASHBOARD_SCHEMA,
  DASHBOARD_WIDGETS,
  newWidget,
  packWidgets,
  sortWidgets,
  validateDashboardLayout,
  type DashboardDocument,
  type DashboardWidget,
  type WidgetType,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { SkeletonModule } from '@openng/optimus-ui/skeleton';
import { TagModule } from '@openng/optimus-ui/tag';
import type { GridStack, GridStackNode } from 'gridstack';
import { DashboardApi } from '../../core/api/dashboard-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { UnsavedChanges } from '../../shared/unsaved-changes';
import { WidgetCatalog, WidgetConfig } from './widget-dialogs';
import { WidgetHost, type WidgetAction } from './widget-host';

/** Alto de una fila de la rejilla y margen de cada widget (iguales en lectura y en edición). */
export const ROW_PX = 80;
export const MARGIN_PX = 6;
/** Por debajo, una columna y sin arrastrar (el menú de cada widget mueve y redimensiona). */
const WIDE = '(min-width: 768px)';

/**
 * Un panel de widgets (DESIGN §15): el tuyo o, con `project`, el de un proyecto (fijado a él).
 * En lectura es una rejilla CSS (sin gridstack); al personalizar se carga gridstack bajo demanda
 * para arrastrar y redimensionar. Guarda con la versión que se editó (409 si alguien guardó antes).
 */
@Component({
  selector: 'app-dashboard-board',
  imports: [
    ButtonModule,
    MessageModule,
    SkeletonModule,
    TagModule,
    WidgetCatalog,
    WidgetConfig,
    WidgetHost,
  ],
  templateUrl: './dashboard-board.html',
  styleUrl: './dashboard-board.scss',
})
export class DashboardBoard {
  private readonly api = inject(DashboardApi);
  private readonly confirm = inject(ConfirmationService);
  private readonly messages = inject(MessageService);
  private readonly unsaved = inject(UnsavedChanges);
  private readonly injector = inject(Injector);

  /** Panel del proyecto (si no, el del usuario). */
  readonly project = input<string>();
  /** Selector de proyecto de la página: sustituye al de cada widget (solo en el personal). */
  readonly scopeProject = input<string>();
  readonly canEdit = input(false);

  private readonly boardEl = viewChild<ElementRef<HTMLElement>>('board');

  protected readonly doc = signal<DashboardDocument | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly editing = signal(false);
  protected readonly draft = signal<DashboardWidget[]>([]);
  protected readonly dirty = signal(false);
  protected readonly saving = signal(false);
  protected readonly saveError = signal<string | null>(null);
  protected readonly catalogOpen = signal(false);
  protected readonly configuring = signal<{
    widget: DashboardWidget;
    adding: boolean;
  } | null>(null);
  /** Al salir de la edición, los widgets se vuelven a crear (gridstack deja estilos en línea). */
  protected readonly epoch = signal(0);
  private readonly media = globalThis.matchMedia?.(WIDE);
  protected readonly wide = signal(this.media?.matches ?? true);

  protected readonly widgets = computed(() =>
    sortWidgets(
      this.editing() ? this.draft() : (this.doc()?.layout.widgets ?? []),
    ),
  );
  /** Proyecto que se manda en cada petición: el del panel del proyecto o el de la página. */
  protected readonly override = computed(
    () => this.project() ?? this.scopeProject(),
  );
  protected readonly rows = computed(() =>
    this.widgets().reduce((max, w) => Math.max(max, w.y + w.h), 0),
  );
  protected readonly full = computed(
    () => this.draft().length >= DASHBOARD_MAX_WIDGETS,
  );
  protected readonly rowPx = ROW_PX;
  protected readonly marginPx = MARGIN_PX;
  protected readonly maxHeight = DASHBOARD_MAX_HEIGHT;
  /** Tamaño mínimo del tipo (también al redimensionar con gridstack). */
  protected minSize(w: DashboardWidget) {
    return DASHBOARD_WIDGETS[w.type].min;
  }

  private grid: GridStack | null = null;

  constructor() {
    const query = this.media;
    const onChange = () => this.wide.set(query?.matches ?? true);
    query?.addEventListener('change', onChange);
    const destroyRef = inject(DestroyRef);
    destroyRef.onDestroy(() => {
      query?.removeEventListener('change', onChange);
      this.destroyGrid();
      this.unsaved.set(false);
    });
    effect(() => {
      const project = this.project();
      untracked(() => this.load(project));
    });
    // Con gridstack activo, cambiar a pantalla estrecha lo quita (y al revés lo pone).
    effect(() => {
      const wide = this.wide();
      if (!untracked(this.editing)) return;
      if (wide) untracked(() => this.initGrid());
      else untracked(() => this.destroyGrid(true));
    });
    effect(() => this.unsaved.set(this.editing() && this.dirty()));
  }

  private load(project: string | undefined): void {
    this.doc.set(null);
    this.loadError.set(null);
    this.api.get(project).subscribe({
      next: (doc) => this.doc.set(doc),
      error: (err: unknown) =>
        this.loadError.set(apiErrorMessage(err, 'No se pudo cargar el panel.')),
    });
  }

  protected startEdit(): void {
    const doc = this.doc();
    if (!doc) return;
    this.draft.set(doc.layout.widgets.map((w) => structuredClone(w)));
    this.dirty.set(false);
    this.saveError.set(null);
    this.editing.set(true);
    if (this.wide()) this.initGrid();
  }

  protected cancel(): void {
    if (!this.dirty()) return this.stopEdit();
    this.confirm.confirm({
      header: 'Descartar los cambios',
      message: 'El panel tiene cambios sin guardar. ¿Descartarlos?',
      acceptLabel: 'Descartar',
      rejectLabel: 'Seguir editando',
      acceptButtonProps: { severity: 'danger' },
      accept: () => this.stopEdit(),
    });
  }

  private stopEdit(): void {
    this.destroyGrid();
    this.editing.set(false);
    this.dirty.set(false);
    this.configuring.set(null);
    this.epoch.update((n) => n + 1);
  }

  protected save(): void {
    const doc = this.doc();
    if (!doc) return;
    this.pullFromGrid();
    const layout = { schema: DASHBOARD_SCHEMA, widgets: this.draft() };
    const checked = validateDashboardLayout(layout, this.project());
    if (!checked.ok) {
      this.saveError.set(checked.error);
      return;
    }
    this.saving.set(true);
    this.saveError.set(null);
    this.api.save(checked.layout, doc.version, this.project()).subscribe({
      next: (saved) => {
        this.saving.set(false);
        this.doc.set(saved);
        this.stopEdit();
        this.messages.add({ severity: 'success', summary: 'Panel guardado' });
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.saveError.set(
          err instanceof HttpErrorResponse && err.status === 409
            ? apiErrorMessage(err, 'Alguien guardó el panel antes.')
            : apiErrorMessage(err, 'No se pudo guardar el panel.'),
        );
      },
    });
  }

  protected reset(): void {
    this.confirm.confirm({
      header: this.project()
        ? 'Volver a la plantilla del proyecto'
        : 'Volver al panel por defecto',
      message: this.project()
        ? 'Se borra el panel de este proyecto para todos y vuelve la plantilla. ¿Seguro?'
        : 'Se borra tu panel personalizado y vuelve el de por defecto. ¿Seguro?',
      acceptLabel: 'Restablecer',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      accept: () =>
        this.api.reset(this.project()).subscribe({
          next: (doc) => {
            this.doc.set(doc);
            this.stopEdit();
            this.messages.add({
              severity: 'success',
              summary: 'Panel restablecido',
            });
          },
          error: (err: unknown) =>
            this.saveError.set(
              apiErrorMessage(err, 'No se pudo restablecer el panel.'),
            ),
        }),
    });
  }

  /** Recargar tras un 409 (se pierden los cambios sin guardar). */
  protected reload(): void {
    this.stopEdit();
    this.load(this.project());
  }

  protected add(type: WidgetType): void {
    this.catalogOpen.set(false);
    const id = `w-${crypto.randomUUID().slice(0, 8)}`;
    const widget = newWidget(type, this.draft(), id);
    if (this.project()) widget.filters = { projectId: this.project() };
    this.configuring.set({ widget, adding: true });
  }

  protected applyConfig(widget: DashboardWidget): void {
    const adding = this.configuring()?.adding ?? false;
    this.configuring.set(null);
    this.dirty.set(true);
    if (adding) {
      this.draft.update((list) => [...list, widget]);
      this.afterRender(() => {
        const el = this.itemEl(widget.id);
        if (this.grid && el) this.grid.makeWidget(el);
        el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      });
    } else
      this.draft.update((list) =>
        list.map((w) => (w.id === widget.id ? widget : w)),
      );
  }

  protected onAction(widget: DashboardWidget, action: WidgetAction): void {
    if (action === 'configure') {
      this.configuring.set({ widget, adding: false });
      return;
    }
    if (action === 'remove') {
      const el = this.itemEl(widget.id);
      if (this.grid && el) this.grid.removeWidget(el, false, false);
      this.draft.update((list) => list.filter((w) => w.id !== widget.id));
      this.dirty.set(true);
      return;
    }
    const def = DASHBOARD_WIDGETS[widget.type];
    const order = sortWidgets(this.draft());
    const i = order.findIndex((w) => w.id === widget.id);
    const resized = (w: DashboardWidget): DashboardWidget => {
      switch (action) {
        case 'wider':
          return { ...w, w: Math.min(DASHBOARD_COLUMNS, w.w + 1) };
        case 'narrower':
          return { ...w, w: Math.max(def.min.w, w.w - 1) };
        case 'taller':
          return { ...w, h: Math.min(DASHBOARD_MAX_HEIGHT, w.h + 1) };
        case 'shorter':
          return { ...w, h: Math.max(def.min.h, w.h - 1) };
        default:
          return w;
      }
    };
    const next = order.map((w, k) => (k === i ? resized(w) : w));
    if (action === 'before' && i > 0)
      [next[i - 1], next[i]] = [next[i]!, next[i - 1]!];
    if (action === 'after' && i < next.length - 1)
      [next[i + 1], next[i]] = [next[i]!, next[i + 1]!];
    this.draft.set(packWidgets(next));
    this.dirty.set(true);
    this.syncGrid();
  }

  // --- gridstack (solo en edición y en pantallas anchas) ---

  private initGrid(): void {
    if (this.grid) return;
    this.afterRender(async () => {
      const el = this.boardEl()?.nativeElement;
      if (!el || !this.editing() || this.grid) return;
      const { GridStack } = await import('gridstack');
      if (!this.editing() || this.grid) return;
      const grid = GridStack.init(
        {
          column: DASHBOARD_COLUMNS,
          cellHeight: ROW_PX,
          margin: MARGIN_PX,
          handle: '.dw-handle',
          animate: true,
          // Gravedad arriba (sin huecos), como la rejilla de lectura.
          mode: 'top',
        },
        el,
      );
      if (!grid) return;
      this.grid = grid;
      // Cualquier cambio en la rejilla: el borrador copia las posiciones de todos los widgets
      // (gridstack no avisa de todo lo que recoloca al resolver colisiones).
      grid.on('change added removed dragstop resizestop', () => {
        this.pullFromGrid();
        this.dirty.set(true);
      });
    });
  }

  /** Lleva a gridstack las posiciones del borrador (tras mover o cambiar el tamaño con el menú). */
  private syncGrid(): void {
    const grid = this.grid;
    if (!grid) return;
    this.afterRender(() => {
      grid.batchUpdate();
      for (const w of this.draft()) {
        const el = this.itemEl(w.id);
        if (el) grid.update(el, { x: w.x, y: w.y, w: w.w, h: w.h });
      }
      grid.batchUpdate(false);
      this.pullFromGrid();
    });
  }

  /**
   * Mientras gridstack está activo, él manda: el borrador toma la posición y el tamaño de todos
   * sus widgets (nunca se solapan entre sí).
   */
  private pullFromGrid(): void {
    const nodes: GridStackNode[] = this.grid?.engine.nodes ?? [];
    if (!nodes.length) return;
    const byId = new Map(nodes.map((n) => [String(n.id), n]));
    this.draft.update((list) =>
      list.map((w) => {
        const n = byId.get(w.id);
        return n
          ? { ...w, x: n.x ?? w.x, y: n.y ?? w.y, w: n.w ?? w.w, h: n.h ?? w.h }
          : w;
      }),
    );
  }

  private destroyGrid(rerender = false): void {
    if (!this.grid) return;
    this.grid.destroy(false);
    this.grid = null;
    if (rerender) this.epoch.update((n) => n + 1);
  }

  private itemEl(id: string): HTMLElement | null {
    return (
      this.boardEl()?.nativeElement.querySelector<HTMLElement>(
        `[gs-id="${CSS.escape(id)}"]`,
      ) ?? null
    );
  }

  private afterRender(fn: () => void | Promise<void>): void {
    afterNextRender(() => void fn(), { injector: this.injector });
  }
}
