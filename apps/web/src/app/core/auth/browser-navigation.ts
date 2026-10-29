import { InjectionToken } from '@angular/core';

/** Navegación completa del navegador (salir de la app hacia el proveedor OIDC); en tests, un doble. */
export interface BrowserNavigation {
  assign(url: string): void;
}

export const BROWSER_NAVIGATION = new InjectionToken<BrowserNavigation>(
  'BROWSER_NAVIGATION',
  { factory: () => ({ assign: (url: string) => window.location.assign(url) }) },
);
