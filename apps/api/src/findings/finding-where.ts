import {
  NOT_UNUSED_IMAGE,
  PUBLIC_EXPOSED_OWNER,
  SCAN_ENABLED_OWNER,
} from '@infraward/domain';
import { findingSearchWhere } from './finding-search.js';
import {
  PRIORITY_BAND_MIN,
  severitiesAtLeast,
  type FindingListQuery,
} from '@infraward/shared-types';

/** Condiciones SQL (sobre `findings f`) con sus parámetros posicionales. */
export interface SqlWhere {
  where: string[];
  params: unknown[];
}

export { NOT_UNUSED_IMAGE, SCAN_ENABLED_OWNER };

export { likeLiteral } from './finding-search.js';

/**
 * Expuesto de cualquier forma: los motivos de su prioridad llevan un puerto expuesto (proceso o
 * contenedor publicado) o un nombre público.
 */
export const EXPOSED_FINDING = `(f.priority_reasons @> '[{"code":"port"}]'::jsonb
  OR f.priority_reasons @> '[{"code":"public"}]'::jsonb)`;

/** En KEV (la tabla por CVE). */
const IN_KEV = `EXISTS (SELECT 1 FROM vulnerability_intel ki
  WHERE ki.vulnerability_id = f.vulnerability_id AND ki.in_kev)`;

/**
 * Filtros de una lista de findings (los de cada finding, antes de agrupar), comunes a la lista de
 * un asset, la agrupada por CVE y la búsqueda global. `params` puede traer ya parámetros: los
 * nuevos se numeran a continuación.
 */
const NO_WHERE: SqlWhere = { where: [], params: [] };

export function findingWhere(
  query: Omit<FindingListQuery, 'limit' | 'offset'>,
  base: SqlWhere = NO_WHERE,
): SqlWhere {
  const where = [...base.where];
  const params = [...base.params];
  const add = (sql: string, value: unknown) => {
    params.push(value);
    where.push(sql.replaceAll('?', `$${params.length}`));
  };
  if (query.status) add('f.status = ?', query.status);
  if (query.severity) add('f.severity = ?', query.severity);
  if (query.minSeverity)
    add(
      'f.severity::text = ANY(?::text[])',
      severitiesAtLeast(query.minSeverity),
    );
  if (query.vulnerabilityId)
    add('upper(f.vulnerability_id) = upper(?)', query.vulnerabilityId);
  // Sintaxis de filtros (DESIGN §15); el texto libre, CVE por prefijo o paquete por subcadena.
  if (query.q?.trim())
    where.push(
      ...findingSearchWhere(query.q, (value) => {
        params.push(value);
        return `$${params.length}`;
      }),
    );
  if (query.openedSince)
    add(`f.status = 'open' AND f.opened_at > ?::timestamptz`, query.openedSince);
  if (query.fixable === true) where.push('f.fixed_version IS NOT NULL');
  if (query.fixable === false) where.push('f.fixed_version IS NULL');
  if (query.exposure === 'public') where.push(PUBLIC_EXPOSED_OWNER);
  if (query.exposure === 'any') where.push(EXPOSED_FINDING);
  if (query.kev === true) where.push(IN_KEV);
  if (query.minEpss !== undefined)
    add(
      `EXISTS (SELECT 1 FROM vulnerability_intel ei
                WHERE ei.vulnerability_id = f.vulnerability_id AND ei.epss >= ?)`,
      query.minEpss,
    );
  // Lo que la vista principal oculta, por motivo (DESIGN §9): con `hidden`, solo eso.
  switch (query.hidden) {
    case 'scan_disabled':
      where.push(`NOT ${SCAN_ENABLED_OWNER}`);
      break;
    case 'unused_image':
      where.push(`NOT ${NOT_UNUSED_IMAGE}`, SCAN_ENABLED_OWNER);
      break;
    case 'kernel_not_running':
    case 'no_fix_planned':
      add('f.noise_reason = ?', query.hidden);
      where.push(SCAN_ENABLED_OWNER);
      break;
    case 'low_priority':
      where.push(
        `f.priority < ${PRIORITY_BAND_MIN.medium}`,
        'f.noise_reason IS NULL',
        SCAN_ENABLED_OWNER,
      );
      break;
    default:
      if (query.inUse === true) where.push(NOT_UNUSED_IMAGE);
      if (query.includeNoise !== true) where.push('f.noise_reason IS NULL');
      if (query.minPriority)
        where.push(`f.priority >= ${PRIORITY_BAND_MIN[query.minPriority]}`);
      if (query.includeScanDisabled !== true) where.push(SCAN_ENABLED_OWNER);
  }
  // Proyectos efectivos guardados (§5): las imágenes ya están en los de quienes las usan.
  if (query.projectId)
    add(
      `EXISTS (SELECT 1 FROM assets po
                WHERE po.id = f.asset_id AND po.effective_projects @> ARRAY[?]::uuid[])`,
      query.projectId,
    );
  return { where, params };
}
