import { Injectable, signal } from '@angular/core';

const HIDDEN_COLUMNS_KEY = 'infraward.inventory.hiddenColumns';

/**
 * Estado del árbol que se conserva al ir a la ficha y volver (en memoria, por pestaña). Las
 * columnas ocultas se recuerdan en el navegador (comodidad: sin almacenamiento, todas visibles).
 */
@Injectable({ providedIn: 'root' })
export class InventoryState {
  readonly expanded = signal<ReadonlySet<string>>(new Set());
  readonly filter = signal('');
  readonly includeRetired = signal(false);
  readonly hiddenColumns = signal<ReadonlySet<string>>(readHiddenColumns());

  setHiddenColumns(keys: readonly string[]): void {
    this.hiddenColumns.set(new Set(keys));
    try {
      localStorage.setItem(HIDDEN_COLUMNS_KEY, JSON.stringify(keys));
    } catch {
      // Sin almacenamiento (privado, bloqueado): solo dura esta visita.
    }
  }

  setExpanded(key: string, open: boolean): void {
    this.expanded.update((current) => {
      const next = new Set(current);
      if (open) next.add(key);
      else next.delete(key);
      return next;
    });
  }
}

function readHiddenColumns(): ReadonlySet<string> {
  try {
    const raw = JSON.parse(localStorage.getItem(HIDDEN_COLUMNS_KEY) ?? '[]') as unknown;
    return new Set(Array.isArray(raw) ? raw.filter((k) => typeof k === 'string') : []);
  } catch {
    return new Set();
  }
}
