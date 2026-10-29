import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  DiscoveryError,
  planReconcile,
  seenKey,
  type AssetRef,
  type DiscoveryListing,
  type ExistingChild,
} from '@infraward/connectors';
import {
  Asset,
  AssetRelation,
  CONTAINS_LOCK,
  isSelfOrAncestor,
  MAX_TREE_DEPTH,
  notifyAssets,
  recomputePolicies,
} from '@infraward/domain';
import type {
  AssetDiscoverJobResult,
  AssetRelationType,
  AssetStatus,
  AssetType,
  NotificationItem,
} from '@infraward/shared-types';
import { DataSource, type EntityManager } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import {
  bumpMissing,
  markMissing,
  saveSnapshotIfChanged,
  SEEN,
} from './maintenance.js';
import { assertFence } from '../jobs/fence.js';

/** Qué gestiona un listado bajo su padre: los tipos de sus hijos y de sus enlaces. */
export interface ListingScope {
  readonly childTypes: readonly AssetType[];
  readonly linkTypes?: readonly AssetRelationType[];
  /** Los enlaces pueden apuntar a assets fuera del listado (por su clave natural). */
  readonly externalTargets?: boolean;
  /** Dentro de la misma transacción, tras aplicar el listado (p. ej. enlazar registros DNS). */
  readonly afterApply?: (
    m: EntityManager,
    ids: ReadonlyMap<string, string>,
  ) => Promise<void>;
}

export interface ListingApplied {
  counts: Pick<
    AssetDiscoverJobResult,
    'created' | 'updated' | 'reparented' | 'renamed' | 'missing' | 'reactivated'
  > & { retired: number };
  /** Hijos que hay que recoger. */
  collect: string[];
  warnings: string[];
  /** `<tipo>|<clave natural>` → id de todo lo del listado. */
  ids: ReadonlyMap<string, string>;
}

/**
 * Aplica un listado de descubrimiento (DESIGN §8, §10): lo usan el descubrimiento por SSH
 * (`asset.discover`) y la sincronización de los conectores de dominios (`domains.sync`).
 */
@Injectable()
export class ListingReconciler {
  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
  ) {}

  /**
   * Aplica `planReconcile` en una transacción, serializada con las demás altas de relaciones
   * `contains` (mismo candado que la API) y con el padre bloqueado: si se retiró mientras
   * tanto, no se escribe nada. Mantenimiento (§10): snapshot de lo nuevo y de lo que cambia,
   * contador de ausencias (`missing` → `retired` tras `RECONCILE_RETIRE_AFTER`), notificaciones
   * agrupadas y la política efectiva recalculada.
   */
  apply(
    parentRef: { id: string; name: string },
    scope: ListingScope,
    listing: DiscoveryListing,
    jobId: string | null,
  ): Promise<ListingApplied> {
    const parentId = parentRef.id;
    return this.db.transaction(async (m) => {
      // Fencing (DESIGN §20): una réplica sustituida no aplica su listado.
      await assertFence(m);
      await m.query('SELECT pg_advisory_xact_lock($1)', [CONTAINS_LOCK]);
      const parent = await m.findOne(Asset, {
        where: { id: parentId },
        lock: { mode: 'pessimistic_write' },
      });
      if (!parent || parent.status !== 'active')
        throw new DiscoveryError(
          'El asset se retiró o cambió de estado durante el descubrimiento',
        );

      const keys = listing.children.flatMap((c) => [
        c.naturalKey,
        ...c.aliases,
      ]);
      // Existentes: los de las claves del listado y el ámbito del descubridor = el subárbol del
      // padre recorriendo solo hijos de sus tipos (suscripción → dominio → base de datos; el
      // descubridor de Docker de un nodo no ve los contenedores de sus CT).
      const rows: {
        id: string;
        type: AssetType;
        natural_key: string | null;
        status: AssetStatus;
        retired_auto: boolean;
        parent_id: string | null;
        in_scope: boolean;
      }[] = await m.query(
        `WITH RECURSIVE scope(id, depth) AS (
             SELECT r.child_id, 1
               FROM asset_relations r JOIN assets a ON a.id = r.child_id
              WHERE r.type = 'contains' AND r.parent_id = $3 AND a.type::text = ANY($1::text[])
           UNION
             SELECT r.child_id, s.depth + 1
               FROM scope s
               JOIN asset_relations r ON r.parent_id = s.id AND r.type = 'contains'
               JOIN assets a ON a.id = r.child_id
              WHERE a.type::text = ANY($1::text[]) AND s.depth < $4)
         SELECT a.id, a.type, a.natural_key, a.status, a.retired_auto, r.parent_id,
                a.id IN (SELECT id FROM scope) AS in_scope
           FROM assets a
           LEFT JOIN asset_relations r ON r.child_id = a.id AND r.type = 'contains'
          WHERE a.type::text = ANY($1::text[])
            AND (a.natural_key = ANY($2::text[]) OR a.id IN (SELECT id FROM scope))`,
        [scope.childTypes, keys, parentId, MAX_TREE_DEPTH],
      );
      const existing: ExistingChild[] = rows.map((r) => ({
        id: r.id,
        type: r.type,
        naturalKey: r.natural_key,
        status: r.status,
        retiredAuto: r.retired_auto,
        parentId: r.parent_id,
        inScope: r.in_scope,
      }));
      const plan = planReconcile({
        parentId,
        childTypes: scope.childTypes,
        listing,
        existing,
      });

      const counts = {
        created: 0,
        updated: 0,
        reparented: 0,
        renamed: 0,
        missing: 0,
        reactivated: 0,
        retired: 0,
      };
      const collect: string[] = [];
      const warnings = [...plan.warnings];
      const created: NotificationItem[] = [];
      const reactivated: NotificationItem[] = [];
      // Clave → id de lo que hay en el listado (para padres anidados y enlaces).
      const ids = new Map<string, string>();
      for (const u of plan.update)
        ids.set(seenKey(u.discovered.type, u.discovered.naturalKey), u.id);
      const parentOf = (ref: AssetRef | null | undefined): string => {
        if (!ref) return parentId;
        const id = ids.get(seenKey(ref.type, ref.naturalKey));
        if (id) return id;
        warnings.push(
          `${ref.naturalKey}: no está en el inventario; se cuelga del asset descubierto`,
        );
        return parentId;
      };

      // En el orden del listado: los padres van antes que sus hijos.
      for (const d of plan.create) {
        const child = await m.save(
          m.create(Asset, {
            type: d.type,
            discoveredName: d.name,
            status: 'active',
            naturalKey: d.naturalKey,
            facts: d.facts,
          }),
        );
        ids.set(seenKey(d.type, d.naturalKey), child.id);
        await m.save(
          m.create(AssetRelation, {
            parentId: parentOf(d.parent),
            childId: child.id,
            type: 'contains',
          }),
        );
        await saveSnapshotIfChanged(
          m,
          child.id,
          child.facts,
          child.roles,
          'discover',
          jobId,
        );
        created.push({ id: child.id, name: d.name, type: child.type });
        counts.created++;
        if (d.collect) collect.push(child.id);
      }

      for (const u of plan.update) {
        const child = await m.findOneByOrFail(Asset, { id: u.id });
        // Solo el nombre descubierto: el visible (`name`) respeta el puesto a mano (§5).
        child.discoveredName = u.discovered.name;
        // Solo se sustituyen las claves del descubridor; los facts recogidos se conservan.
        child.facts = { ...child.facts, ...u.discovered.facts };
        if (u.rename) {
          child.naturalKey = u.rename;
          counts.renamed++;
        }
        if (u.reactivate) {
          child.status = 'active';
          Object.assign(child, SEEN);
          reactivated.push({
            id: child.id,
            name: child.name,
            type: child.type,
          });
          counts.reactivated++;
        }
        await m.save(child);
        await saveSnapshotIfChanged(
          m,
          child.id,
          child.facts,
          child.roles,
          'discover',
          jobId,
        );
        counts.updated++;
        if (u.attach) {
          const target = parentOf(u.parent);
          if (await isSelfOrAncestor(m, u.id, target)) {
            warnings.push(
              `${u.discovered.name}: colgarlo de este nodo crearía un ciclo; no se mueve`,
            );
          } else {
            await m.delete(AssetRelation, {
              childId: u.id,
              type: 'contains',
            });
            await m.save(
              m.create(AssetRelation, {
                parentId: target,
                childId: u.id,
                type: 'contains',
              }),
            );
            if (u.previousParentId) counts.reparented++;
          }
        }
        if (u.discovered.collect) collect.push(u.id);
      }

      await replaceLinks(m, scope, listing, ids, [
        ...plan.create.map((d) => ids.get(seenKey(d.type, d.naturalKey))!),
        ...plan.update.map((u) => u.id),
      ]);

      // Primero los que ya faltaban (suman una ejecución), luego los que faltan desde ahora.
      const retired = await bumpMissing(
        m,
        plan.stillMissing,
        this.config.get('RECONCILE_RETIRE_AFTER', { infer: true }),
      );
      counts.retired = retired.length;
      const missing = await markMissing(m, plan.missing, parentId);
      counts.missing = missing.length;

      await notifyAssets(m, 'asset_created', parentRef, created);
      await notifyAssets(m, 'asset_reactivated', parentRef, reactivated);
      await notifyAssets(m, 'asset_missing', parentRef, missing);
      await notifyAssets(m, 'asset_retired', parentRef, retired);
      await scope.afterApply?.(m, ids);
      // Lo nuevo hereda la política de su padre antes de encolar nada (§10).
      await recomputePolicies(m);
      return { counts, collect, warnings, ids };
    });
  }
}

/**
 * Relaciones no jerárquicas del descubridor (`linkTypes`: contenedor → volumen/red, dominio →
 * certificado): para cada asset del listado (creado o actualizado; nunca un retirado) se
 * sustituyen las suyas de esos tipos por las del listado. Un enlace a algo que no está en el
 * listado no se crea, salvo con `externalTargets` (un registro DNS → el certificado de Plesk
 * con la misma huella): entonces se busca por su clave natural entre los no retirados.
 */
async function replaceLinks(
  m: EntityManager,
  scope: ListingScope,
  listing: DiscoveryListing,
  ids: ReadonlyMap<string, string>,
  sources: string[],
): Promise<void> {
  const types = scope.linkTypes ?? [];
  if (types.length === 0 || sources.length === 0) return;
  await m.query(
    `DELETE FROM asset_relations
      WHERE parent_id = ANY($1::uuid[]) AND type::text = ANY($2::text[])`,
    [sources, types],
  );
  const allowed = new Set(sources);
  if (scope.externalTargets) {
    const wanted = (listing.links ?? []).filter(
      (l) =>
        types.includes(l.type) && !ids.has(seenKey(l.to.type, l.to.naturalKey)),
    );
    if (wanted.length > 0) {
      const found: { id: string; type: AssetType; natural_key: string }[] =
        await m.query(
          `SELECT id, type, natural_key FROM assets
            WHERE natural_key = ANY($1::text[]) AND status <> 'retired'`,
          [wanted.map((l) => l.to.naturalKey)],
        );
      const resolved = new Map(ids);
      for (const f of found)
        resolved.set(seenKey(f.type, f.natural_key), f.id);
      ids = resolved;
    }
  }
  const rows = (listing.links ?? [])
    .filter((l) => types.includes(l.type))
    .map((l) => ({
      type: l.type,
      from: ids.get(seenKey(l.from.type, l.from.naturalKey)),
      to: ids.get(seenKey(l.to.type, l.to.naturalKey)),
    }))
    .filter(
      (l): l is { type: AssetRelationType; from: string; to: string } =>
        !!l.from && !!l.to && l.from !== l.to && allowed.has(l.from),
    );
  if (rows.length === 0) return;
  await m.query(
    `INSERT INTO asset_relations (parent_id, child_id, type)
     SELECT f, t, ty::asset_relation_type
       FROM unnest($1::uuid[], $2::uuid[], $3::text[]) AS x(f, t, ty)
     ON CONFLICT DO NOTHING`,
    [rows.map((r) => r.from), rows.map((r) => r.to), rows.map((r) => r.type)],
  );
}
