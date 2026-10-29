import { Component, input, model } from '@angular/core';
import { ORGANIZATION_COLORS } from '@infraward/shared-types';

/** Paleta fija de colores (proyectos y tags) con «Sin color»; legible en claro y en oscuro. */
@Component({
  selector: 'app-color-swatches',
  template: `
    <div class="swatches" role="radiogroup" [attr.aria-label]="label()">
      <button
        type="button"
        class="swatch none"
        role="radio"
        [attr.aria-checked]="!value()"
        [class.selected]="!value()"
        aria-label="Sin color"
        title="Sin color"
        (click)="value.set(null)"
      >
        <i class="bi bi-slash-lg" aria-hidden="true"></i>
      </button>
      @for (c of colors; track c) {
        <button
          type="button"
          class="swatch"
          role="radio"
          [attr.aria-checked]="value() === c"
          [class.selected]="value() === c"
          [style.background]="c"
          [attr.aria-label]="'Color ' + c"
          [title]="c"
          [attr.data-color]="c"
          (click)="value.set(c)"
        ></button>
      }
    </div>
  `,
  styles: `
    .swatches {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }
    .swatch {
      width: 1.6rem;
      height: 1.6rem;
      border-radius: 50%;
      border: 2px solid transparent;
      padding: 0;
      cursor: pointer;
      outline-offset: 2px;
    }
    .swatch.selected {
      border-color: var(--p-text-color);
      box-shadow: 0 0 0 2px var(--p-content-background) inset;
    }
    .none {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: transparent;
      border: 1px dashed var(--p-content-border-color);
      color: var(--p-text-muted-color);
    }
    .none.selected {
      border: 2px solid var(--p-text-color);
    }
  `,
})
export class ColorSwatches {
  readonly value = model<string | null>(null);
  readonly label = input('Color');
  protected readonly colors = ORGANIZATION_COLORS;
}
