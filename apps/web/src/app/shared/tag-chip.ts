import { Component, input, output } from '@angular/core';

/**
 * Un tag con su color (si tiene): punto de color y fondo suave del mismo tono, legible en claro
 * y en oscuro. Con `removable`, una «x» para quitarlo.
 */
@Component({
  selector: 'app-tag-chip',
  template: `
    <span
      class="tag-chip"
      [class.colored]="!!color()"
      [style.--tag-color]="color()"
      [attr.data-tag]="tag()"
    >
      <span class="dot" aria-hidden="true"></span>
      <span class="text">{{ tag() }}</span>
      @if (removable()) {
        <button
          type="button"
          class="remove"
          [attr.aria-label]="'Quitar el tag ' + tag()"
          (click)="remove.emit(); $event.stopPropagation()"
        >
          <i class="bi bi-x" aria-hidden="true"></i>
        </button>
      }
    </span>
  `,
  styles: `
    :host {
      display: inline-flex;
      max-width: 100%;
    }
    .tag-chip {
      --tag-color: var(--p-text-muted-color);
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      max-width: 100%;
      /* Compacto por defecto (árbol); quien lo coloca puede igualarlo a un p-tag. */
      font-size: var(--tag-font-size, 0.75rem);
      line-height: 1.4;
      padding: var(--tag-padding, 0 0.45rem);
      border-radius: 999px;
      border: 1px solid color-mix(in srgb, var(--tag-color) 45%, transparent);
      background: color-mix(in srgb, var(--tag-color) 12%, transparent);
      color: var(--p-text-color);
    }
    .dot {
      flex: none;
      width: 0.5rem;
      height: 0.5rem;
      border-radius: 50%;
      background: var(--tag-color);
    }
    .text {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .remove {
      display: inline-flex;
      border: 0;
      padding: 0;
      margin-right: -0.2rem;
      background: none;
      color: var(--p-text-muted-color);
      cursor: pointer;
      border-radius: 50%;
    }
    .remove:hover,
    .remove:focus-visible {
      color: var(--p-text-color);
    }
  `,
})
export class TagChip {
  readonly tag = input.required<string>();
  readonly color = input<string | null | undefined>(null);
  readonly removable = input(false);
  readonly remove = output<void>();
}
