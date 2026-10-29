import {
  DEFAULT_INVENTORY_POLICY,
  INVENTORY_POLICY_FIELDS,
  type AssetStatus,
  type AssetType,
  type EffectiveInventoryPolicy,
  type InventoryPolicyField,
  type InventoryPolicySource,
  type InventoryPolicyValues,
  type ScanExclusionMatch,
  type ScanExclusionOrigin,
  type ScanExclusions,
  normalizeScanExclusions,
  scanExclusionMatch,
} from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';
import { CONTAINS_LOCK, MAX_TREE_DEPTH } from './asset-tree.js';
import { resolveProjects } from './project-membership.js';

/** Regla tal como la necesita el resolvedor (null = no fija ese campo). */
export interface PolicyRuleInput {
  scope: 'global' | 'asset' | 'tag' | 'project';
  assetId: string | null;
  tag: string | null;
  projectId?: string | null;
  reconcileIntervalMinutes: number | null;
  scanEnabled: boolean | null;
  scanPeriodic: boolean | null;
  /** Lo que excluye del escaneo (QoL-6b); null = nada. */
  scanExclusions?: ScanExclusions | null;
}

export interface PolicyAssetInput {
  id: string;
  type: AssetType;
  status: AssetStatus;
  /** Para los patrones de las exclusiones: el nombre visible y el descubierto. */
  name?: string;
  discoveredName?: string | null;
  tags: readonly string[];
  /** Proyectos efectivos (heredados incluidos). */
  projects?: readonly string[];
  /** Padre `contains` (null = raíz). */
  parentId: string | null;
}

export interface PolicyInput {
  assets: readonly PolicyAssetInput[];
  rules: readonly PolicyRuleInput[];
  /**
   * Imagen → assets que la usan (hosts con `stores` y contenedores con `instance_of`). Las
   * imágenes no están en el árbol: sin regla propia, heredan de quienes la usan.
   */
  imageHolders: ReadonlyMap<string, readonly string[]>;
}

type FieldValue<F extends InventoryPolicyField> = InventoryPolicyValues[F];

/**
 * Lo más restrictivo de varias etiquetas: `false` gana; en el intervalo, 0 (nunca) gana y si no,
 * el más largo.
 */
function moreRestrictive<F extends InventoryPolicyField>(
  field: F,
  a: FieldValue<F>,
  b: FieldValue<F>,
): boolean {
  if (field === 'reconcileIntervalMinutes') {
    const x = a as number;
    const y = b as number;
    if (y === 0) return false;
    return x === 0 || x > y;
  }
  return a === false && b === true;
}

/**
 * Política efectiva de cada asset (DESIGN §10), campo a campo:
 * regla propia > antepasado `contains` más cercano que lo fija > etiquetas del asset (la más
 * restrictiva) > proyectos del asset (el más restrictivo) > global. La etiqueta va antes que el
 * proyecto porque se pone en el propio asset y el proyecto suele llegar heredado. Las imágenes
 * sin regla propia ni de etiqueta escanean si alguno de los hosts o contenedores no retirados que
 * la usan lo permite (una imagen compartida sirve también al host que sí escanea; los proyectos
 * les llegan así, a través de quienes la usan); sin ninguno, la global.
 */
export function resolvePolicies(
  input: PolicyInput,
): Map<string, EffectiveInventoryPolicy> {
  const global = input.rules.find((r) => r.scope === 'global');
  const globalValues: InventoryPolicyValues = {
    reconcileIntervalMinutes:
      global?.reconcileIntervalMinutes ??
      DEFAULT_INVENTORY_POLICY.reconcileIntervalMinutes,
    scanEnabled: global?.scanEnabled ?? DEFAULT_INVENTORY_POLICY.scanEnabled,
    scanPeriodic: global?.scanPeriodic ?? DEFAULT_INVENTORY_POLICY.scanPeriodic,
  };
  const byAsset = new Map<string, PolicyRuleInput>();
  const byTag = new Map<string, PolicyRuleInput>();
  const byProject = new Map<string, PolicyRuleInput>();
  for (const r of input.rules) {
    if (r.scope === 'asset' && r.assetId) byAsset.set(r.assetId, r);
    if (r.scope === 'tag' && r.tag) byTag.set(r.tag, r);
    if (r.scope === 'project' && r.projectId) byProject.set(r.projectId, r);
  }
  const assets = new Map(input.assets.map((a) => [a.id, a]));
  const result = new Map<string, EffectiveInventoryPolicy>();

  const resolveField = <F extends InventoryPolicyField>(
    asset: PolicyAssetInput,
    field: F,
    viaTree: boolean,
  ): { value: FieldValue<F>; source: InventoryPolicySource } | null => {
    const own = byAsset.get(asset.id)?.[field];
    if (own !== null && own !== undefined)
      return { value: own as FieldValue<F>, source: { kind: 'own' } };
    if (viaTree) {
      let parentId = asset.parentId;
      const seen = new Set([asset.id]);
      for (let depth = 0; parentId && depth < MAX_TREE_DEPTH; depth++) {
        if (seen.has(parentId)) break;
        seen.add(parentId);
        const value = byAsset.get(parentId)?.[field];
        if (value !== null && value !== undefined)
          return {
            value: value as FieldValue<F>,
            source: { kind: 'inherited', assetId: parentId },
          };
        parentId = assets.get(parentId)?.parentId ?? null;
      }
    }
    let best: { value: FieldValue<F>; tag: string } | null = null;
    for (const tag of [...asset.tags].sort()) {
      const value = byTag.get(tag)?.[field];
      if (value === null || value === undefined) continue;
      if (!best || moreRestrictive(field, value as FieldValue<F>, best.value))
        best = { value: value as FieldValue<F>, tag };
    }
    if (best)
      return { value: best.value, source: { kind: 'tag', tag: best.tag } };
    if (!viaTree) return null;
    let bestProject: { value: FieldValue<F>; projectId: string } | null = null;
    for (const projectId of [...(asset.projects ?? [])].sort()) {
      const value = byProject.get(projectId)?.[field];
      if (value === null || value === undefined) continue;
      if (
        !bestProject ||
        moreRestrictive(field, value as FieldValue<F>, bestProject.value)
      )
        bestProject = { value: value as FieldValue<F>, projectId };
    }
    if (bestProject)
      return {
        value: bestProject.value,
        source: { kind: 'project', projectId: bestProject.projectId },
      };
    return null;
  };

  const build = (
    asset: PolicyAssetInput,
    fallback: (field: InventoryPolicyField) => {
      value: InventoryPolicyValues[InventoryPolicyField];
      source: InventoryPolicySource;
    },
    viaTree: boolean,
  ): EffectiveInventoryPolicy => {
    const values = {} as Record<InventoryPolicyField, unknown>;
    const sources = {} as Record<InventoryPolicyField, InventoryPolicySource>;
    for (const field of INVENTORY_POLICY_FIELDS) {
      const r = resolveField(asset, field, viaTree) ?? fallback(field);
      values[field] = r.value;
      sources[field] = r.source;
    }
    return { values: values as unknown as InventoryPolicyValues, sources };
  };
  const fromGlobal = (field: InventoryPolicyField) => ({
    value: globalValues[field],
    source: { kind: 'global' } as InventoryPolicySource,
  });

  /**
   * Exclusiones que alcanzan al asset (se suman todas, como lo más restrictivo): la propia, las de
   * sus antepasados, sus etiquetas y sus proyectos (estas dos, solo `viaTree`) y la global.
   */
  const exclusionRules = (
    asset: PolicyAssetInput,
    viaTree: boolean,
  ): { by: ScanExclusionOrigin; ex: ScanExclusions }[] => {
    const list: { by: ScanExclusionOrigin; ex: ScanExclusions }[] = [];
    const push = (
      by: ScanExclusionOrigin,
      rule: PolicyRuleInput | undefined,
    ) => {
      const ex = normalizeScanExclusions(rule?.scanExclusions);
      if (ex) list.push({ by, ex });
    };
    push({ kind: 'own' }, byAsset.get(asset.id));
    if (viaTree) {
      let parentId = asset.parentId;
      const seen = new Set([asset.id]);
      for (let depth = 0; parentId && depth < MAX_TREE_DEPTH; depth++) {
        if (seen.has(parentId)) break;
        seen.add(parentId);
        push({ kind: 'inherited', assetId: parentId }, byAsset.get(parentId));
        parentId = assets.get(parentId)?.parentId ?? null;
      }
    }
    for (const tag of [...asset.tags].sort())
      push({ kind: 'tag', tag }, byTag.get(tag));
    if (viaTree)
      for (const projectId of [...(asset.projects ?? [])].sort())
        push({ kind: 'project', projectId }, byProject.get(projectId));
    push({ kind: 'global' }, global);
    return list;
  };
  const firstExclusion = (
    rules: readonly { by: ScanExclusionOrigin; ex: ScanExclusions }[],
    target: PolicyAssetInput,
  ): { by: ScanExclusionOrigin; match: ScanExclusionMatch } | null => {
    const subject = {
      id: target.id,
      type: target.type,
      name: target.name ?? '',
      discoveredName: target.discoveredName ?? null,
    };
    for (const r of rules) {
      const match = scanExclusionMatch(subject, r.ex);
      if (match) return { by: r.by, match };
    }
    return null;
  };
  const exclude = (
    policy: EffectiveInventoryPolicy,
    source: InventoryPolicySource,
  ) => {
    policy.values.scanEnabled = false;
    policy.sources.scanEnabled = source;
  };

  const applicable = new Map<
    string,
    { by: ScanExclusionOrigin; ex: ScanExclusions }[]
  >();
  for (const asset of input.assets) {
    if (asset.type === 'image') continue;
    const policy = build(asset, fromGlobal, true);
    const rules = exclusionRules(asset, true);
    applicable.set(asset.id, rules);
    const excluded = firstExclusion(rules, asset);
    if (excluded) exclude(policy, { kind: 'excluded', ...excluded });
    result.set(asset.id, policy);
  }

  for (const asset of input.assets) {
    if (asset.type !== 'image') continue;
    const holders = (input.imageHolders.get(asset.id) ?? [])
      .filter((id) => assets.get(id)?.status !== 'retired')
      .flatMap((id) => {
        const policy = result.get(id);
        if (!policy) return [];
        // Un holder que la excluye (tipo, patrón o asset) no la deja escanear.
        const excluded = firstExclusion(applicable.get(id) ?? [], asset);
        return [{ id, policy, excluded }];
      });
    const allowing = holders.filter((h) => !h.excluded);
    const policy = build(
      asset,
      (field) =>
        holders.length === 0 || field === 'reconcileIntervalMinutes'
          ? fromGlobal(field)
          : {
              value: allowing.some((h) => h.policy.values[field] === true),
              source: { kind: 'holders' },
            },
      false,
    );
    // Su regla, sus etiquetas o la global la excluyen; o nadie la deja y alguien la excluye.
    const direct = firstExclusion(exclusionRules(asset, false), asset);
    if (direct) exclude(policy, { kind: 'excluded', ...direct });
    else if (
      policy.sources.scanEnabled.kind === 'holders' &&
      !policy.values.scanEnabled
    ) {
      const by = holders.find((h) => h.excluded && h.policy.values.scanEnabled);
      if (by?.excluded)
        exclude(policy, { kind: 'excluded', ...by.excluded, holderId: by.id });
    }
    result.set(asset.id, policy);
  }
  return result;
}

/** Política efectiva guardada (`assets.effective_policy`); `{}` aún sin calcular ⇒ por defecto. */
export function policyValues(
  stored: Partial<EffectiveInventoryPolicy> | null | undefined,
): InventoryPolicyValues {
  return { ...DEFAULT_INVENTORY_POLICY, ...(stored?.values ?? {}) };
}

/**
 * Recalcula y guarda los proyectos efectivos y la política efectiva de todo el inventario (solo
 * escribe los assets que cambian). Toma el mismo candado que las relaciones `contains`: llamar
 * dentro de una transacción.
 */
export async function recomputePolicies(m: EntityManager): Promise<number> {
  await m.query('SELECT pg_advisory_xact_lock($1)', [CONTAINS_LOCK]);
  const rows: {
    id: string;
    type: AssetType;
    status: AssetStatus;
    tags: string[];
    name: string;
    discovered_name: string;
    parent_id: string | null;
    effective_policy: unknown;
    effective_projects: string[];
  }[] = await m.query(
    `SELECT a.id, a.type, a.status, a.tags, a.name, a.discovered_name, r.parent_id,
            a.effective_policy, a.effective_projects
       FROM assets a
       LEFT JOIN asset_relations r ON r.child_id = a.id AND r.type = 'contains'`,
  );
  const links: { image_id: string; holder_id: string }[] = await m.query(
    `SELECT r.child_id AS image_id, r.parent_id AS holder_id
       FROM asset_relations r JOIN assets i ON i.id = r.child_id
      WHERE i.type = 'image' AND r.type IN ('stores', 'instance_of')`,
  );
  const memberships: {
    project_id: string;
    asset_id: string;
    mode: 'include' | 'exclude';
  }[] = await m.query(
    `SELECT project_id, asset_id, mode FROM project_memberships`,
  );
  const rules: {
    scope: 'global' | 'asset' | 'tag' | 'project';
    asset_id: string | null;
    tag: string | null;
    project_id: string | null;
    reconcile_interval_minutes: number | null;
    scan_enabled: boolean | null;
    scan_periodic: boolean | null;
    scan_exclusions: ScanExclusions | null;
  }[] = await m.query(
    `SELECT scope, asset_id, tag, project_id, reconcile_interval_minutes, scan_enabled,
            scan_periodic, scan_exclusions
       FROM inventory_policies`,
  );
  const imageHolders = new Map<string, string[]>();
  for (const l of links)
    imageHolders.set(l.image_id, [
      ...(imageHolders.get(l.image_id) ?? []),
      l.holder_id,
    ]);
  const projects = resolveProjects({
    assets: rows.map((r) => ({
      id: r.id,
      type: r.type,
      status: r.status,
      parentId: r.parent_id,
    })),
    memberships: memberships.map((r) => ({
      projectId: r.project_id,
      assetId: r.asset_id,
      mode: r.mode,
    })),
    imageHolders,
  });
  const resolved = resolvePolicies({
    assets: rows.map((r) => ({
      id: r.id,
      type: r.type,
      status: r.status,
      tags: r.tags,
      name: r.name,
      discoveredName: r.discovered_name,
      projects: projects.get(r.id) ?? [],
      parentId: r.parent_id,
    })),
    rules: rules.map((r) => ({
      scope: r.scope,
      assetId: r.asset_id,
      tag: r.tag,
      projectId: r.project_id,
      reconcileIntervalMinutes: r.reconcile_interval_minutes,
      scanEnabled: r.scan_enabled,
      scanPeriodic: r.scan_periodic,
      scanExclusions: r.scan_exclusions,
    })),
    imageHolders,
  });
  const ids: string[] = [];
  const policies: string[] = [];
  const projectLists: string[] = [];
  for (const r of rows) {
    const policy = resolved.get(r.id);
    const json = JSON.stringify(policy);
    const own = projects.get(r.id) ?? [];
    const projectsChanged =
      own.join(',') !== [...(r.effective_projects ?? [])].sort().join(',');
    if (
      policy &&
      (projectsChanged || stableJson(policy) !== stableJson(r.effective_policy))
    ) {
      ids.push(r.id);
      policies.push(json);
      // Literal de array de PostgreSQL: unnest no admite arrays de arrays de distinta longitud.
      projectLists.push(`{${own.join(',')}}`);
    }
  }
  if (ids.length)
    await m.query(
      `UPDATE assets a SET effective_policy = x.p, effective_projects = x.pr::uuid[]
         FROM unnest($1::uuid[], $2::jsonb[], $3::text[]) AS x(id, p, pr)
        WHERE a.id = x.id`,
      [ids, policies, projectLists],
    );
  return ids.length;
}

/** JSON con las claves ordenadas, para comparar con lo guardado (JSONB las reordena). */
function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : v,
  );
}

/**
 * Condición SQL «el asset `alias` escanea» según su política guardada (sin calcular = sí), para
 * filtrar en consultas: `WHERE ${scanEnabledSql('a')}`.
 */
export function scanEnabledSql(alias: string): string {
  return `COALESCE((${alias}.effective_policy->'values'->>'scanEnabled')::boolean, true)`;
}

/** Condición SQL «el asset `alias` escanea solo» (escaneo activado y periódico). */
export function scanAutomaticSql(alias: string): string {
  return `(${scanEnabledSql(alias)} AND COALESCE((${alias}.effective_policy->'values'->>'scanPeriodic')::boolean, true))`;
}

/** ¿Se puede escanear automáticamente (tras recoger o descubrir, relleno)? */
export function scansAutomatically(
  stored: Partial<EffectiveInventoryPolicy> | null | undefined,
): boolean {
  const v = policyValues(stored);
  return v.scanEnabled && v.scanPeriodic;
}
