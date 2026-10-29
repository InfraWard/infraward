import { Component, computed, input, linkedSignal, signal } from '@angular/core';

type Kind = 'object' | 'array' | 'primitive';

/** Elementos que se pintan de una vez al abrir un objeto o lista grande. */
export const FACTS_PAGE = 100;

/**
 * Vista JSON plegable de los facts. Solo crea los hijos de lo que está abierto (una lista de
 * cientos de paquetes no cuesta nada mientras está cerrada) y todo se pinta como texto con
 * interpolación: nada pasa por `innerHTML`.
 */
@Component({
  selector: 'app-facts-viewer',
  imports: [FactsViewer],
  template: `
    @if (kind() === 'primitive') {
      <span class="entry">
        @if (name() !== null) {
          <span class="key">{{ name() }}:</span>
        }
        <span class="value {{ valueClass() }}">{{ display() }}</span>
      </span>
    } @else {
      <button
        type="button"
        class="toggle"
        [attr.aria-expanded]="open()"
        (click)="open.set(!open())"
      >
        <i class="bi" [class.bi-caret-down-fill]="open()" [class.bi-caret-right-fill]="!open()" aria-hidden="true"></i>
        @if (name() !== null) {
          <span class="key">{{ name() }}</span>
        }
        <span class="meta">{{ meta() }}</span>
      </button>
      @if (open()) {
        <ul>
          @for (entry of visible(); track entry[0]) {
            <li>
              <app-facts-viewer [name]="entry[0]" [value]="entry[1]" [depth]="depth() + 1" />
            </li>
          }
          @if (hidden() > 0) {
            <li>
              <button type="button" class="more" (click)="limit.set(limit() + pageSize)">
                Mostrar {{ hidden() > pageSize ? pageSize : hidden() }} más (quedan {{ hidden() }})
              </button>
            </li>
          }
        </ul>
      }
    }
  `,
  styles: `
    :host {
      display: block;
      font-family: var(--p-font-family-mono, ui-monospace, monospace);
      font-size: 0.85rem;
      line-height: 1.6;
    }
    ul {
      list-style: none;
      margin: 0;
      padding-left: 1.25rem;
      border-left: 1px dashed var(--p-content-border-color);
    }
    .toggle,
    .more {
      background: none;
      border: 0;
      padding: 0;
      font: inherit;
      color: inherit;
      cursor: pointer;
      display: inline-flex;
      gap: 0.35rem;
      align-items: center;
    }
    .more {
      color: var(--p-primary-color);
    }
    .key {
      font-weight: 600;
    }
    .entry .key {
      margin-right: 0.35rem;
    }
    .meta {
      color: var(--p-text-muted-color);
    }
    .string {
      color: var(--p-app-success-color);
    }
    .number,
    .boolean {
      color: var(--p-app-info-color);
    }
    .null {
      color: var(--p-text-muted-color);
      font-style: italic;
    }
  `,
})
export class FactsViewer {
  readonly value = input.required<unknown>();
  readonly name = input<string | null>(null);
  readonly depth = input(0);
  /** Niveles abiertos al empezar. */
  readonly openDepth = input(1);

  protected readonly pageSize = FACTS_PAGE;
  protected readonly limit = signal(FACTS_PAGE);
  /** El nivel raíz (y los que indique openDepth) empiezan abiertos. */
  protected readonly open = linkedSignal(() => this.depth() < this.openDepth());

  protected readonly kind = computed<Kind>(() => {
    const v = this.value();
    if (Array.isArray(v)) return 'array';
    return typeof v === 'object' && v !== null ? 'object' : 'primitive';
  });

  private readonly entries = computed<[string, unknown][]>(() => {
    const v = this.value();
    if (Array.isArray(v)) return v.map((item, i) => [String(i), item]);
    if (typeof v === 'object' && v !== null) return Object.entries(v);
    return [];
  });

  protected readonly visible = computed(() =>
    this.entries().slice(0, this.limit()),
  );
  protected readonly hidden = computed(() =>
    Math.max(0, this.entries().length - this.limit()),
  );

  protected readonly meta = computed(() => {
    const n = this.entries().length;
    return this.kind() === 'array'
      ? `[${n} ${n === 1 ? 'elemento' : 'elementos'}]`
      : `{${n} ${n === 1 ? 'clave' : 'claves'}}`;
  });

  protected readonly valueClass = computed(() => {
    const v = this.value();
    return v === null || v === undefined ? 'null' : typeof v;
  });

  protected readonly display = computed(() => {
    const v = this.value();
    if (v === null || v === undefined) return 'null';
    return typeof v === 'string' ? `"${v}"` : String(v);
  });
}
