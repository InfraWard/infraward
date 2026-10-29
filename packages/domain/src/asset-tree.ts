import type { AssetStatus, AssetType } from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';

/** Profundidad máxima que recorren las consultas recursivas (protección ante datos corruptos). */
export const MAX_TREE_DEPTH = 32;

/**
 * Clave de `pg_advisory_xact_lock` que serializa las altas y cambios de relaciones `contains`
 * (API y descubridores del worker): sin ella, dos altas A→B y B→A a la vez crean un ciclo.
 */
export const CONTAINS_LOCK = 0x1f_a55e7;

/** Fila de un recorrido del árbol `contains`: el asset, su padre dentro del recorrido y su nivel. */
export interface AssetTreeRow {
  id: string;
  /** null en las raíces del recorrido. */
  parentId: string | null;
  depth: number;
}

export interface SubtreeOptions {
  /**
   * Estados que se excluyen junto con todo lo que cuelga de ellos. Las raíces pedidas por id
   * se devuelven siempre; con `'roots'` también se filtran.
   */
  excludeStatuses?: AssetStatus[];
  /**
   * Tipos que no se recorren (ni ellos ni lo que cuelgue de ellos), p. ej. los volúmenes y redes
   * de Docker en el árbol del inventario. Las raíces pedidas por id se devuelven siempre.
   */
  excludeTypes?: readonly AssetType[];
  maxDepth?: number;
}

/**
 * Recorre el árbol `contains` hacia abajo desde `roots` (ids concretos o, con `'roots'`, todos
 * los assets sin padre salvo las imágenes, que no forman parte del árbol: se llega a ellas desde
 * sus contenedores con `instance_of`). La ruta acumulada corta cualquier ciclo aunque la BD
 * llegara a tenerlo.
 */
export async function findSubtreeRows(
  manager: EntityManager,
  roots: string[] | 'roots',
  options: SubtreeOptions = {},
): Promise<AssetTreeRow[]> {
  const anchor =
    roots === 'roots'
      ? `NOT EXISTS (SELECT 1 FROM asset_relations r
                      WHERE r.child_id = a.id AND r.type = 'contains')
         AND a.type <> 'image'
         AND a.type::text <> ALL($3::text[])
         AND a.status::text <> ALL($1::text[])`
      : `a.id = ANY($4::uuid[])`;
  const rows: { id: string; parent_id: string | null; depth: number }[] =
    await manager.query(
      `WITH RECURSIVE tree AS (
         SELECT a.id, NULL::uuid AS parent_id, 0 AS depth, ARRAY[a.id] AS path
           FROM assets a
          WHERE ${anchor}
         UNION ALL
         SELECT r.child_id, r.parent_id, t.depth + 1, t.path || r.child_id
           FROM tree t
           JOIN asset_relations r ON r.parent_id = t.id AND r.type = 'contains'
           JOIN assets c ON c.id = r.child_id
          WHERE NOT r.child_id = ANY(t.path)
            AND t.depth < $2
            AND c.status::text <> ALL($1::text[])
            AND c.type::text <> ALL($3::text[])
       )
       SELECT id, parent_id, depth FROM tree`,
      [
        options.excludeStatuses ?? [],
        options.maxDepth ?? MAX_TREE_DEPTH,
        options.excludeTypes ?? [],
        ...(roots === 'roots' ? [] : [roots]),
      ],
    );
  return rows.map((r) => ({ id: r.id, parentId: r.parent_id, depth: r.depth }));
}

/** El asset y todos sus descendientes `contains` (sin filtrar por estado). */
export async function findSubtreeIds(
  manager: EntityManager,
  id: string,
): Promise<string[]> {
  return (await findSubtreeRows(manager, [id])).map((r) => r.id);
}

/** ¿Es `ancestorId` el propio `id` o uno de sus antepasados por relaciones `contains`? */
export async function isSelfOrAncestor(
  manager: EntityManager,
  ancestorId: string,
  id: string,
): Promise<boolean> {
  const rows: unknown[] = await manager.query(
    `WITH RECURSIVE up AS (
       SELECT $1::uuid AS id, ARRAY[$1::uuid] AS path
       UNION ALL
       SELECT r.parent_id, up.path || r.parent_id
         FROM up
         JOIN asset_relations r ON r.child_id = up.id AND r.type = 'contains'
        WHERE NOT r.parent_id = ANY(up.path)
          AND cardinality(up.path) <= $3
     )
     SELECT 1 FROM up WHERE id = $2::uuid LIMIT 1`,
    [id, ancestorId, MAX_TREE_DEPTH],
  );
  return rows.length > 0;
}

/**
 * Antepasados `contains` del asset (sin él), con `depth` 1 para el padre, 2 para el abuelo…
 * La ruta acumulada corta cualquier ciclo aunque la BD llegara a tenerlo.
 */
export async function findAncestorRows(
  manager: EntityManager,
  id: string,
  maxDepth = MAX_TREE_DEPTH,
): Promise<{ id: string; depth: number }[]> {
  const rows: { id: string; depth: number }[] = await manager.query(
    `WITH RECURSIVE up AS (
       SELECT $1::uuid AS id, 0 AS depth, ARRAY[$1::uuid] AS path
       UNION ALL
       SELECT r.parent_id, up.depth + 1, up.path || r.parent_id
         FROM up
         JOIN asset_relations r ON r.child_id = up.id AND r.type = 'contains'
        WHERE NOT r.parent_id = ANY(up.path)
          AND up.depth < $2
     )
     SELECT id, depth FROM up WHERE depth > 0 ORDER BY depth`,
    [id, maxDepth],
  );
  return rows;
}

export type TreeNode<T> = T & { children: TreeNode<T>[] };

/**
 * Monta el árbol a partir de los nodos y su padre. Un nodo cuyo padre no está en la lista
 * se trata como raíz. Hermanos ordenados por nombre.
 */
export function buildTree<T extends { id: string; name: string }>(
  rows: { node: T; parentId: string | null }[],
): TreeNode<T>[] {
  const nodes = new Map<string, TreeNode<T>>();
  for (const { node } of rows) nodes.set(node.id, { ...node, children: [] });

  const roots: TreeNode<T>[] = [];
  for (const { node, parentId } of rows) {
    const current = nodes.get(node.id)!;
    const parent = parentId ? nodes.get(parentId) : undefined;
    (parent ? parent.children : roots).push(current);
  }

  const sort = (list: TreeNode<T>[]) => {
    list.sort(
      (a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id),
    );
    for (const node of list) sort(node.children);
  };
  sort(roots);
  return roots;
}
