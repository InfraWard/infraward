/**
 * Caché corta en memoria (por proceso de la API) que guarda la **promesa**: dos peticiones iguales
 * a la vez hacen una sola consulta. Una promesa rechazada no se queda (el siguiente lo reintenta).
 * Al llenarse, sale la entrada más antigua.
 */
export class TtlCache<T> {
  private readonly entries = new Map<
    string,
    { at: number; ttlMs: number; value: Promise<T> }
  >();

  constructor(
    private readonly maxEntries: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** El valor de `key` si sigue vivo; si no, el de `load` (y lo guarda `ttlMs`). */
  get(key: string, ttlMs: number, load: () => Promise<T>): Promise<T> {
    const now = this.now();
    const hit = this.entries.get(key);
    if (hit && now - hit.at < hit.ttlMs) return hit.value;
    if (hit) this.entries.delete(key);
    if (ttlMs <= 0) return load();
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
    const value = load();
    const entry = { at: now, ttlMs, value };
    this.entries.set(key, entry);
    value.catch(() => {
      if (this.entries.get(key) === entry) this.entries.delete(key);
    });
    return value;
  }

  get size(): number {
    return this.entries.size;
  }

  clear(): void {
    this.entries.clear();
  }
}
