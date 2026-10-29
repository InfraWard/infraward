import { Component, input } from '@angular/core';

/**
 * Marca de InfraWard (escudo con el árbol). Decorativa: el texto «InfraWard»
 * va al lado y da el nombre accesible.
 */
@Component({
  selector: 'app-brand-mark',
  template: `
    <img
      src="logo.svg"
      width="32"
      height="32"
      alt=""
      class="mark"
      [style.width.px]="size()"
      [style.height.px]="size()"
    />
  `,
  styles: `
    :host {
      display: inline-flex;
      flex: none;
      line-height: 0;
    }
    .mark {
      display: block;
      width: 32px;
      height: 32px;
    }
  `,
})
export class BrandMark {
  /** Lado en píxeles. */
  readonly size = input(32);
}
