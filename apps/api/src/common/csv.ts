/** Marca de orden de bytes UTF-8: sin ella, Excel lee mal las tildes. */
const BOM = String.fromCharCode(0xfeff);

/** Valor de una celda: las listas van unidas con `; ` en la misma celda. */
export type CsvValue =
  string | number | boolean | null | undefined | readonly string[];

/**
 * Una celda que empieza por `= + - @`, tabulador o retorno de carro la tomaría una hoja de cálculo
 * por una fórmula (inyección CSV/DDE): se le antepone un apóstrofo. Los números no se tocan.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

function cell(value: CsvValue): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'boolean')
    return String(value);
  let text = Array.isArray(value) ? value.join('; ') : (value as string);
  if (FORMULA_START.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) || text !== text.trim()
    ? `"${text.replaceAll('"', '""')}"`
    : text;
}

/**
 * CSV (RFC 4180, separador `,` y fin de línea CRLF) con BOM UTF-8 para que Excel lea bien las
 * tildes. `columns` da el orden y la cabecera.
 */
export function toCsv<T extends Record<string, CsvValue>>(
  columns: readonly (keyof T & string)[],
  rows: readonly T[],
): string {
  const lines = [columns.map((c) => cell(c)).join(',')];
  for (const row of rows)
    lines.push(columns.map((c) => cell(row[c])).join(','));
  return `${BOM}${lines.join('\r\n')}\r\n`;
}

/** `infraward-<qué>-2026-10-18.csv` (sin caracteres raros: va en Content-Disposition). */
export function exportFilename(
  what: string,
  format: 'csv' | 'json',
  now = new Date(),
): string {
  // Fecha local del servidor (la de quien exporta, normalmente), no la UTC.
  const pad = (n: number) => String(n).padStart(2, '0');
  const day = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  return `infraward-${what.replace(/[^a-z0-9-]/gi, '')}-${day}.${format}`;
}
