import { inject, Injectable, signal } from '@angular/core';
import { DEFAULT_EXPIRY_WARNING_DAYS } from '@infraward/shared-types';
import { DomainsApi } from './api/domains-api';

/**
 * Umbrales de aviso de caducidad (Ajustes > Inventario), pedidos una vez y compartidos por el
 * árbol, la ficha y el panel. Hasta tenerlos (o si fallan), los de por defecto.
 */
@Injectable({ providedIn: 'root' })
export class ExpiryThresholds {
  private readonly api = inject(DomainsApi);
  private loaded = false;
  readonly days = signal<readonly number[]>(DEFAULT_EXPIRY_WARNING_DAYS);

  /** Pide los umbrales si aún no se pidieron (o de nuevo con `force`). */
  load(force = false): void {
    if (this.loaded && !force) return;
    this.loaded = true;
    this.api.expiryWarnings().subscribe({
      next: (s) => this.days.set(s.days),
      error: () => (this.loaded = false),
    });
  }

  set(days: readonly number[]): void {
    this.loaded = true;
    this.days.set(days);
  }
}
