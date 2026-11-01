/**
 * Comparador por unidades de código UTF-16: el mismo orden que `Array#sort()` sin argumentos,
 * determinista y sin depender del idioma (para ids, claves y listas canónicas que se comparan o
 * se guardan). Para ordenar textos que se muestran, mejor `localeCompare`.
 */
export function byCodeUnit(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
