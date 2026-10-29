import type { AssetStatus, AssetType } from '@infraward/shared-types';
import {
  seenKey,
  type AssetRef,
  type DiscoveredAsset,
  type DiscoveryListing,
} from './discoverer.js';

/** Asset ya inventariado que puede corresponder a un hijo descubierto. */
export interface ExistingChild {
  id: string;
  type: AssetType;
  naturalKey: string | null;
  status: AssetStatus;
  /** Padre `contains` actual (null si no tiene). */
  parentId: string | null;
  /**
   * Está en el ámbito de este descubrimiento: cuelga del padre descubierto, directamente o a
   * través de otros hijos de los tipos del descubridor (suscripción → dominio → base de datos).
   * Por defecto, solo los hijos directos.
   */
  inScope?: boolean;
  /** Retirado por la reconciliación (no a mano): si reaparece, vuelve a `active`. */
  retiredAuto?: boolean;
}

export interface ReconcileUpdate {
  id: string;
  discovered: DiscoveredAsset;
  /** Nueva clave natural si se encontró por un alias; null si no cambia. */
  rename: string | null;
  /** true si hay que colgarlo de su padre (no tenía padre o estaba en otro). */
  attach: boolean;
  /** Padre dentro del listado (null = el asset descubierto). */
  parent: AssetRef | null;
  /** Padre del que se descuelga (null si no tenía). */
  previousParentId: string | null;
  /** `missing` (o retirado automáticamente) → `active`. */
  reactivate: boolean;
}

export interface ReconcilePlan {
  create: DiscoveredAsset[];
  update: ReconcileUpdate[];
  /** Hijos de este padre que ya no existen: pasan a `missing`. */
  missing: string[];
  /**
   * Hijos ya `missing` que siguen sin verse con un listado completo: suman una ejecución (a
   * `RECONCILE_RETIRE_AFTER`, `retired`; DESIGN §10).
   */
  stillMissing: string[];
  warnings: string[];
}

export interface ReconcileInput {
  parentId: string;
  childTypes: readonly AssetType[];
  listing: DiscoveryListing;
  /**
   * Assets con la clave (o un alias) de algún hijo descubierto y todos los hijos `contains`
   * actuales del padre de los tipos del descubridor.
   */
  existing: ExistingChild[];
}

/**
 * Decide qué crear, actualizar, renombrar, mover y marcar como desaparecido (DESIGN §8, §10).
 * Pura: el worker la aplica en una transacción.
 * - Nunca borra: lo que desaparece pasa a `missing`, y solo si el listado está completo
 *   (un fallo de red no puede marcar todo un nodo como desaparecido).
 * - Lo que sigue existiendo en otro padre (otro nodo del clúster) no ha desaparecido: lo
 *   recoge el descubrimiento de ese padre.
 * - Los tipos de `partialTypes` nunca desaparecen (su listado es parcial).
 * - Hijos anidados (`parent`): cuelgan de otro hijo del listado; el ámbito es el subárbol de
 *   los tipos del descubridor (`inScope`).
 * - Los `retired` a mano no se tocan: solo un aviso. Los retirados por la reconciliación
 *   (`retiredAuto`) vuelven a `active` si reaparecen.
 * - Los que ya estaban `missing` y siguen sin verse van a `stillMissing` (§10: a `retired` tras
 *   varias ejecuciones).
 */
export function planReconcile(input: ReconcileInput): ReconcilePlan {
  const { parentId, listing, existing } = input;
  const plan: ReconcilePlan = {
    create: [],
    update: [],
    missing: [],
    stillMissing: [],
    warnings: [],
  };
  const byKey = new Map<string, ExistingChild>();
  for (const e of existing)
    if (e.naturalKey) byKey.set(seenKey(e.type, e.naturalKey), e);

  const handled = new Set<string>();
  for (const d of listing.children) {
    let target = byKey.get(seenKey(d.type, d.naturalKey));
    let rename: string | null = null;
    const aliased = d.aliases
      .map((a) => byKey.get(seenKey(d.type, a)))
      .find((e) => e !== undefined);
    if (!target && aliased) {
      target = aliased;
      rename = d.naturalKey;
    } else if (target && aliased) {
      plan.warnings.push(
        `${d.name}: existe con la clave ${d.naturalKey} y con una antigua (${aliased.naturalKey}); se usa la nueva`,
      );
    }
    if (!target) {
      plan.create.push(d);
      continue;
    }
    handled.add(target.id);
    if (target.status === 'retired' && !target.retiredAuto) {
      plan.warnings.push(
        `${d.name} (${d.naturalKey}) está dado de baja: no se actualiza`,
      );
      continue;
    }
    // Padre esperado: el asset descubierto, o un hijo del listado (null si aún no existe).
    const expected = d.parent
      ? (byKey.get(seenKey(d.parent.type, d.parent.naturalKey))?.id ?? null)
      : parentId;
    plan.update.push({
      id: target.id,
      discovered: d,
      rename,
      attach: expected === null || target.parentId !== expected,
      parent: d.parent ?? null,
      previousParentId: target.parentId,
      reactivate:
        target.status === 'missing' || target.status === 'retired',
    });
  }

  if (listing.complete) {
    const partial = new Set(listing.partialTypes ?? []);
    for (const e of existing) {
      if (
        handled.has(e.id) ||
        !(e.inScope ?? e.parentId === parentId) ||
        !input.childTypes.includes(e.type) ||
        partial.has(e.type) ||
        (e.status !== 'active' && e.status !== 'missing') ||
        // Sin clave natural: lo añadió alguien a mano, no es del descubridor.
        !e.naturalKey ||
        listing.seen.has(seenKey(e.type, e.naturalKey))
      )
        continue;
      if (e.status === 'missing') plan.stillMissing.push(e.id);
      else plan.missing.push(e.id);
    }
  }
  return plan;
}
