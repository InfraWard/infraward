import { formatSearchTerm, type AssetType } from '@infraward/shared-types';

/** Filtros de un widget en la API (DESIGN §15): proyecto, tags (O) y tipos (O); entre ellos, Y. */
export interface WidgetScope {
  projectId?: string;
  tags?: string[];
  types?: AssetType[];
}

/** Parámetros posicionales de una consulta: `push` devuelve el `$n` del valor. */
export class SqlParams {
  readonly values: unknown[] = [];
  readonly push = (value: unknown): string => {
    this.values.push(value);
    return `$${this.values.length}`;
  };
}

/**
 * Condiciones sobre un asset (`alias`) del ámbito del widget: sus proyectos efectivos, alguno de
 * los tags (índice GIN `IDX_assets_tags`) y alguno de los tipos.
 */
export function assetScopeSql(
  alias: string,
  scope: WidgetScope,
  push: (value: unknown) => string,
): string[] {
  const where: string[] = [];
  if (scope.projectId)
    where.push(
      `${alias}.effective_projects @> ARRAY[${push(scope.projectId)}::uuid]`,
    );
  if (scope.tags?.length)
    where.push(`${alias}.tags && ${push(scope.tags)}::text[]`);
  if (scope.types?.length)
    where.push(`${alias}.type::text = ANY(${push(scope.types)}::text[])`);
  return where;
}

/**
 * Los tags y tipos como búsqueda de vulnerabilidades (`tag:a tag:b tipo:server`): así se aplican
 * al **asset afectado**, igual que en la lista de Vulnerabilidades y en su enlace.
 */
export function scopeSearchQuery(scope: WidgetScope): string | undefined {
  const terms = [
    ...(scope.tags ?? []).map((t) => formatSearchTerm('tag', t)),
    ...(scope.types ?? []).map((t) => formatSearchTerm('tipo', t)),
  ];
  return terms.length ? terms.join(' ') : undefined;
}

/** Clave estable del ámbito para la caché. */
export function scopeKey(scope: WidgetScope): string {
  return JSON.stringify([
    scope.projectId ?? null,
    [...(scope.tags ?? [])].sort(),
    [...(scope.types ?? [])].sort(),
  ]);
}
