import { diffSnapshots, findSubtreeIds, Snapshot } from '@infraward/domain';
import type {
  AssetFacts,
  NotificationItem,
  SnapshotSource,
} from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';

// Mantenimiento del inventario (DESIGN §10): estados missing/retired con su contador de
// ejecuciones y snapshots solo con cambios. Todo dentro de la transacción de quien llama.

type Row = { id: string; name: string; type: NotificationItem['type'] };

/**
 * Pasa a `missing` los `active` de `ids` (y sus descendientes `contains` activos: un CT destruido
 * se lleva sus contenedores). Cuenta la primera ejecución sin verlos; `scopeId` es quien seguirá
 * contando (su padre). Devuelve los de `ids` que cambiaron (para la notificación).
 */
export async function markMissing(
  m: EntityManager,
  ids: readonly string[],
  scopeId: string,
): Promise<Row[]> {
  if (ids.length === 0) return [];
  const [changed]: [Row[], number] = await m.query(
    `UPDATE assets SET status = 'missing', missing_runs = 1, missing_since = now(),
            missing_scope_id = $2, updated_at = now()
      WHERE id = ANY($1::uuid[]) AND status = 'active'
     RETURNING id, name, type`,
    [ids, scopeId],
  );
  const descendants = new Set<string>();
  for (const row of changed)
    for (const id of await findSubtreeIds(m, row.id))
      if (id !== row.id) descendants.add(id);
  if (descendants.size)
    await m.query(
      `UPDATE assets a SET status = 'missing', missing_runs = 1, missing_since = now(),
              missing_scope_id = r.parent_id, updated_at = now()
         FROM asset_relations r
        WHERE r.child_id = a.id AND r.type = 'contains'
          AND a.id = ANY($1::uuid[]) AND a.status = 'active'`,
      [[...descendants]],
    );
  return changed;
}

/**
 * Otra ejecución completa sin ver estos `missing`: suma uno y retira (con su subárbol) los que
 * llegan a `retireAfter`. Devuelve los retirados de `ids`.
 */
export async function bumpMissing(
  m: EntityManager,
  ids: readonly string[],
  retireAfter: number,
): Promise<Row[]> {
  if (ids.length === 0) return [];
  const [due]: [Row[], number] = await m.query(
    `UPDATE assets SET missing_runs = missing_runs + 1, updated_at = now()
      WHERE id = ANY($1::uuid[]) AND status = 'missing'
     RETURNING id, name, type, missing_runs`,
    [ids],
  );
  const retire = (due as (Row & { missing_runs: number })[]).filter(
    (r) => r.missing_runs >= retireAfter,
  );
  await retireSubtrees(
    m,
    retire.map((r) => r.id),
  );
  return retire.map(({ id, name, type }) => ({ id, name, type }));
}

/**
 * Retirada automática (nunca se borra): los assets y todo su subárbol `contains` pasan a
 * `retired` con `retired_auto`, se quitan los `stores` de los hosts retirados y las imágenes que
 * se quedan sin ningún host se retiran también.
 */
export async function retireSubtrees(
  m: EntityManager,
  ids: readonly string[],
): Promise<void> {
  if (ids.length === 0) return;
  const all = new Set<string>();
  for (const id of ids)
    for (const sub of await findSubtreeIds(m, id)) all.add(sub);
  const list = [...all];
  await m.query(
    `UPDATE assets SET status = 'retired', retired_auto = true, updated_at = now()
      WHERE id = ANY($1::uuid[]) AND status <> 'retired'`,
    [list],
  );
  const [orphans]: [{ child_id: string }[], number] = await m.query(
    `DELETE FROM asset_relations WHERE type = 'stores' AND parent_id = ANY($1::uuid[])
     RETURNING child_id`,
    [list],
  );
  if (orphans.length)
    await m.query(
      `UPDATE assets a SET status = 'retired', retired_auto = true, updated_at = now()
        WHERE a.id = ANY($1::uuid[]) AND a.type = 'image' AND a.status <> 'retired'
          AND NOT EXISTS (SELECT 1 FROM asset_relations s
                           WHERE s.child_id = a.id AND s.type = 'stores')`,
      [orphans.map((o) => o.child_id)],
    );
}

/** Contadores de ausencia a cero (visto de nuevo). */
export const SEEN = {
  missingRuns: 0,
  missingSince: null,
  missingScopeId: null,
  retiredAuto: false,
} as const;

/**
 * Guarda un snapshot si hay cambios reales respecto al último (o si es el primero), con el diff
 * calculado (DESIGN §10). Devuelve su id, o null si no había cambios.
 */
export async function saveSnapshotIfChanged(
  m: EntityManager,
  assetId: string,
  facts: AssetFacts,
  roles: readonly string[],
  source: SnapshotSource,
  jobId: string | null,
): Promise<string | null> {
  const last = await m.findOne(Snapshot, {
    where: { assetId },
    order: { collectedAt: 'DESC', id: 'DESC' },
    select: { id: true, facts: true, roles: true },
  });
  const next = { facts, roles };
  const diff = last ? diffSnapshots(last, next) : null;
  if (diff?.summary.length === 0) return null;
  const snapshot = await m.save(
    m.create(Snapshot, {
      assetId,
      facts,
      roles: [...roles],
      jobId,
      source,
      previousId: last?.id ?? null,
      diff,
    }),
  );
  return snapshot.id;
}
