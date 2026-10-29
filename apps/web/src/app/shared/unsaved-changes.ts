import { inject, Injectable, signal } from '@angular/core';
import type { CanDeactivateFn } from '@angular/router';

/**
 * Cambios del panel sin guardar (QoL-8): el navegador avisa al cerrar o recargar la pestaña y la
 * navegación pide confirmación (`unsavedChangesGuard`).
 */
@Injectable({ providedIn: 'root' })
export class UnsavedChanges {
  readonly dirty = signal(false);
  private readonly beforeUnload = (event: BeforeUnloadEvent) => event.preventDefault();

  set(dirty: boolean): void {
    if (dirty === this.dirty()) return;
    this.dirty.set(dirty);
    if (dirty) addEventListener('beforeunload', this.beforeUnload);
    else removeEventListener('beforeunload', this.beforeUnload);
  }
}

export const DISCARD_QUESTION = 'El panel tiene cambios sin guardar. ¿Salir y descartarlos?';

/** Al salir de una página con un panel en edición y cambios, pregunta antes. */
export const unsavedChangesGuard: CanDeactivateFn<unknown> = () => {
  const unsaved = inject(UnsavedChanges);
  if (!unsaved.dirty()) return true;
  if (!confirm(DISCARD_QUESTION)) return false;
  unsaved.set(false);
  return true;
};

