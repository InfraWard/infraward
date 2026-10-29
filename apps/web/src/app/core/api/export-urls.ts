import type {
  ExportFormat,
  FindingListQuery,
  InventoryExportColumn,
  InventoryExportQuery,
  VulnerabilityExportGroup,
} from '@infraward/shared-types';
import { toParams } from './query-params';

/**
 * URLs de descarga de las exportaciones (QoL-6). Se abren con un enlace normal (`<a download>`):
 * la cookie de sesión va sola y un GET no necesita el token CSRF.
 */
export function inventoryExportUrl(
  api: string,
  query: Omit<InventoryExportQuery, 'columns'> & { columns: readonly InventoryExportColumn[] },
): string {
  const { columns, ...rest } = query;
  const params = toParams({ ...rest, columns: columns.join(',') });
  return `${api}/assets/export?${params.toString()}`;
}

export function vulnerabilityExportUrl(
  api: string,
  query: Omit<FindingListQuery, 'limit' | 'offset'>,
  groupBy: VulnerabilityExportGroup,
  format: ExportFormat,
): string {
  const params = toParams({ ...query, groupBy, format });
  return `${api}/vulnerabilities/export?${params.toString()}`;
}

/** Descarga un enlace sin salir de la página. */
export function download(url: string): void {
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}
