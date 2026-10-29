import {
  afterNextRender,
  Component,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  InjectionToken,
  input,
  output,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import type { Core, ElementDefinition, LayoutOptions } from 'cytoscape';
import { ButtonModule } from '@openng/optimus-ui/button';
import { graphStylesheet, readPalette } from './graph-model';

/** Crea el motor de grafos; carga Cytoscape (y fcose) solo cuando se abre un mapa. */
export type GraphEngineFactory = () => Promise<typeof import('cytoscape')>;

export const GRAPH_ENGINE = new InjectionToken<GraphEngineFactory>(
  'GRAPH_ENGINE',
  {
    providedIn: 'root',
    factory: () => async () => {
      const [{ default: cytoscape }, { default: fcose }] = await Promise.all([
        import('cytoscape'),
        import('cytoscape-fcose'),
      ]);
      cytoscape.use(fcose);
      return cytoscape;
    },
  },
);

export type GraphLayout = 'concentric' | 'fcose';

/**
 * Lienzo de Cytoscape: pinta los elementos con el estilo del tema (y lo rehace al cambiar entre
 * claro y oscuro), con zoom, «Encuadrar todo», pantalla completa y los eventos de selección y
 * apertura de un nodo. Lo que se proyecta dentro (p. ej. la tarjeta del nodo) flota sobre el lienzo
 * y también se ve a pantalla completa.
 */
@Component({
  selector: 'app-graph-canvas',
  imports: [ButtonModule],
  template: `
    <div class="canvas" #canvas role="img" [attr.aria-label]="label()"></div>
    @if (!ready()) {
      <p class="loading"><i class="bi bi-hourglass-split" aria-hidden="true"></i> Cargando el mapa…</p>
    }
    <ng-content />
    <div class="zoom" role="toolbar" aria-label="Vista del mapa">
      <p-button icon="bi bi-plus-lg" [text]="true" severity="secondary" size="small" ariaLabel="Acercar" title="Acercar" (onClick)="zoom(1.25)" />
      <p-button icon="bi bi-dash-lg" [text]="true" severity="secondary" size="small" ariaLabel="Alejar" title="Alejar" (onClick)="zoom(0.8)" />
      <p-button icon="bi bi-bullseye" [text]="true" severity="secondary" size="small" ariaLabel="Encuadrar todo" title="Encuadrar todo" (onClick)="fit()" data-fit />
      <p-button
        [icon]="fullscreen() ? 'bi bi-fullscreen-exit' : 'bi bi-fullscreen'"
        [text]="true"
        severity="secondary"
        size="small"
        [ariaLabel]="fullscreen() ? 'Salir de pantalla completa' : 'Pantalla completa'"
        [title]="fullscreen() ? 'Salir de pantalla completa (Esc)' : 'Pantalla completa'"
        (onClick)="toggleFullscreen()"
        data-fullscreen
      />
    </div>
  `,
  styles: `
    :host {
      position: relative;
      display: block;
      height: var(--graph-height, clamp(22rem, 62dvh, 44rem));
      border: 1px solid var(--p-content-border-color);
      border-radius: var(--p-content-border-radius, 6px);
      background: var(--p-content-background);
      overflow: hidden;
    }
    :host(:fullscreen),
    :host(.pseudo-fullscreen) {
      height: 100dvh;
      border: none;
      border-radius: 0;
    }
    /* Sin la API de pantalla completa (Safari en iPhone): ocupa la ventana. */
    :host(.pseudo-fullscreen) {
      position: fixed;
      inset: 0;
      z-index: 1100;
    }
    .canvas {
      position: absolute;
      inset: 0;
    }
    .loading {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      margin: 0;
      color: var(--p-text-muted-color);
    }
    .zoom {
      position: absolute;
      top: 0.25rem;
      right: 0.25rem;
      display: flex;
      flex-direction: column;
      background: var(--p-content-background);
      border: 1px solid var(--p-content-border-color);
      border-radius: 6px;
      z-index: 2;
    }
  `,
  host: { '[class.pseudo-fullscreen]': 'pseudoFullscreen()' },
})
export class GraphCanvas {
  readonly elements = input.required<ElementDefinition[]>();
  readonly layout = input<GraphLayout>('concentric');
  /** Nodo que se mantiene seleccionado (p. ej. el que muestra el panel). */
  readonly selectedId = input<string | null>(null);
  /** Resumen para lectores de pantalla (la alternativa textual es la vista de lista). */
  readonly label = input('Mapa de relaciones');

  readonly nodeSelected = output<string | null>();
  readonly nodeActivated = output<string>();

  protected readonly ready = signal(false);
  /** A pantalla completa (la del navegador o, sin ella, ocupando la ventana). */
  protected readonly fullscreen = signal(false);
  protected readonly pseudoFullscreen = signal(false);
  private readonly el = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly host = viewChild.required<ElementRef<HTMLElement>>('canvas');
  private readonly engine = inject(GRAPH_ENGINE);
  private cy: Core | null = null;
  private dark = globalThis.matchMedia?.('(prefers-color-scheme: dark)');

  constructor() {
    const destroyRef = inject(DestroyRef);
    afterNextRender(() => {
      void this.engine().then((cytoscape) => {
        if (this.destroyed) return;
        this.cy = cytoscape({
          container: this.host().nativeElement,
          style: this.stylesheet(),
          minZoom: 0.15,
          maxZoom: 3,
          wheelSensitivity: 0.3,
          boxSelectionEnabled: false,
          selectionType: 'single',
        });
        // Tocar el fondo deselecciona; tocar un nodo lo selecciona.
        this.cy.on('tap', (event) => {
          if (event.target === event.cy) this.nodeSelected.emit(null);
        });
        this.cy.on('tap', 'node', (event) =>
          this.nodeSelected.emit((event.target as { id: () => string }).id()),
        );
        this.cy.on('dbltap', 'node', (event) =>
          this.nodeActivated.emit((event.target as { id: () => string }).id()),
        );
        this.render(this.elements());
        this.ready.set(true);
      });
    });
    // Solo los elementos repintan: `render` lee otras señales (la selección) que no deben volver a
    // lanzar el layout, o cada clic en un nodo reencuadraría el mapa.
    effect(() => {
      const elements = this.elements();
      untracked(() => {
        if (this.cy) this.render(elements);
      });
    });
    effect(() => {
      const id = this.selectedId();
      if (!this.cy) return;
      this.cy.nodes(':selected').unselect();
      if (id) this.cy.getElementById(id).select();
    });

    const onScheme = () => this.cy?.style(this.stylesheet());
    this.dark?.addEventListener?.('change', onScheme);
    const onFullscreen = () => {
      this.fullscreen.set(document.fullscreenElement === this.el.nativeElement);
      this.refit();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && this.pseudoFullscreen()) this.toggleFullscreen();
    };
    document.addEventListener('fullscreenchange', onFullscreen);
    document.addEventListener('keydown', onKey);
    const resize = new ResizeObserver(() => this.cy?.resize());
    afterNextRender(() => resize.observe(this.host().nativeElement));
    destroyRef.onDestroy(() => {
      this.destroyed = true;
      this.dark?.removeEventListener?.('change', onScheme);
      document.removeEventListener('fullscreenchange', onFullscreen);
      document.removeEventListener('keydown', onKey);
      if (document.fullscreenElement === this.el.nativeElement)
        void document.exitFullscreen();
      resize.disconnect();
      this.cy?.destroy();
      this.cy = null;
    });
  }

  private destroyed = false;

  zoom(factor: number): void {
    const cy = this.cy;
    if (!cy) return;
    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
  }

  fit(): void {
    this.cy?.fit(undefined, 40);
  }

  toggleFullscreen(): void {
    const host = this.el.nativeElement;
    if (this.pseudoFullscreen()) {
      this.pseudoFullscreen.set(false);
      this.fullscreen.set(false);
      this.refit();
    } else if (document.fullscreenElement === host) {
      void document.exitFullscreen();
    } else if (host.requestFullscreen && document.fullscreenEnabled) {
      void host.requestFullscreen().catch(() => this.enterPseudoFullscreen());
    } else {
      this.enterPseudoFullscreen();
    }
  }

  private enterPseudoFullscreen(): void {
    this.pseudoFullscreen.set(true);
    this.fullscreen.set(true);
    this.refit();
  }

  /** Tras cambiar de tamaño (pantalla completa), vuelve a medir y encuadra. */
  private refit(): void {
    requestAnimationFrame(() => {
      this.cy?.resize();
      this.fit();
    });
  }

  private stylesheet() {
    return graphStylesheet(
      readPalette(this.dark?.matches ?? false, document.documentElement),
    );
  }

  /**
   * Cambia los elementos conservando la posición de los que ya estaban; los nuevos salen junto a
   * su grupo o a un vecino ya colocado, y el layout los recoloca sin barajar el resto.
   */
  private render(elements: ElementDefinition[]): void {
    const cy = this.cy!;
    const before = new Map(
      cy.nodes().map((n) => [n.id(), { ...n.position() }] as const),
    );
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
    });
    const incremental = before.size > 0 && this.layout() === 'fcose';
    if (incremental)
      cy.nodes().forEach((n) => {
        const known = before.get(n.id());
        const anchor =
          known ??
          before.get(n.data('parent') as string) ??
          n
            .neighborhood('node')
            .map((m) => before.get(m.id()))
            .find(Boolean);
        if (anchor)
          n.position({
            x: anchor.x + (known ? 0 : Math.random() * 40 - 20),
            y: anchor.y + (known ? 0 : Math.random() * 40 - 20),
          });
      });
    const layout = cy.layout(this.layoutOptions(incremental));
    // Con pocos nodos, «ajustar» los ampliaría de más: como mucho a tamaño real.
    layout.one('layoutstop', () => {
      if (cy.zoom() > 1.2) {
        cy.zoom(1.2);
        cy.center();
      }
    });
    layout.run();
    const id = this.selectedId();
    if (id) cy.getElementById(id).select();
  }

  private layoutOptions(incremental: boolean): LayoutOptions {
    if (this.layout() === 'fcose')
      return {
        name: 'fcose',
        quality: 'default',
        randomize: !incremental,
        animate: incremental,
        animationDuration: 350,
        fit: true,
        padding: 40,
        nodeDimensionsIncludeLabels: true,
        packComponents: true,
        nodeRepulsion: 9000,
        idealEdgeLength: 90,
        nestingFactor: 0.6,
        tile: true,
      } as LayoutOptions;
    // Concéntrico: el centro en medio y un anillo por cada salto (`depth` en los datos).
    return {
      name: 'concentric',
      concentric: (n: { data: (k: string) => unknown }) =>
        10 - Number(n.data('depth') ?? 0),
      levelWidth: () => 1,
      minNodeSpacing: 34,
      nodeDimensionsIncludeLabels: true,
      fit: true,
      padding: 40,
      animate: false,
    } as LayoutOptions;
  }
}
