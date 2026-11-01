import {
  byCodeUnit,
  type AssetStatus,
  type AssetType,
  type ProjectMembershipMode,
} from '@infraward/shared-types';
import { MAX_TREE_DEPTH } from './asset-tree.js';

/** Fila directa de un asset en un proyecto. */
export interface MembershipInput {
  projectId: string;
  assetId: string;
  mode: ProjectMembershipMode;
}

export interface ProjectAssetInput {
  id: string;
  type: AssetType;
  status: AssetStatus;
  /** Padre `contains` (null = raíz). */
  parentId: string | null;
}

export interface ProjectsInput {
  assets: readonly ProjectAssetInput[];
  memberships: readonly MembershipInput[];
  /** Imagen → hosts (`stores`) y contenedores (`instance_of`) que la usan. */
  imageHolders: ReadonlyMap<string, readonly string[]>;
}

/**
 * Qué decide cada proyecto para un asset recorriendo su camino `contains` (él primero, después
 * sus antepasados): la fila más cercana de cada proyecto. Devuelve proyecto → asset cuya fila
 * decide y su modo.
 */
export function decideAlongPath(
  path: readonly string[],
  rowsByAsset: ReadonlyMap<string, readonly MembershipInput[]>,
): Map<string, { assetId: string; mode: ProjectMembershipMode }> {
  const decided = new Map<
    string,
    { assetId: string; mode: ProjectMembershipMode }
  >();
  for (const id of path)
    for (const row of rowsByAsset.get(id) ?? [])
      if (!decided.has(row.projectId))
        decided.set(row.projectId, { assetId: id, mode: row.mode });
  return decided;
}

/**
 * Proyectos efectivos de cada asset (DESIGN §5). Un asset puede estar en varios proyectos y cada
 * proyecto se resuelve por separado: lo decide la fila más cercana de su camino `contains`
 * (`include` ⇒ dentro, `exclude` ⇒ fuera; sin ninguna, fuera). Las imágenes, fuera del árbol,
 * están en los proyectos de los hosts y contenedores no retirados que las usan, más sus propias
 * filas (`include` añade, `exclude` quita). Devuelve los ids ordenados.
 */
export function resolveProjects(input: ProjectsInput): Map<string, string[]> {
  const assets = new Map(input.assets.map((a) => [a.id, a]));
  const rowsByAsset = new Map<string, MembershipInput[]>();
  for (const row of input.memberships)
    rowsByAsset.set(row.assetId, [...(rowsByAsset.get(row.assetId) ?? []), row]);
  const result = new Map<string, string[]>();

  const pathOf = (asset: ProjectAssetInput): string[] => {
    const path = [asset.id];
    let parentId = asset.parentId;
    for (let depth = 0; parentId && depth < MAX_TREE_DEPTH; depth++) {
      if (path.includes(parentId)) break;
      path.push(parentId);
      parentId = assets.get(parentId)?.parentId ?? null;
    }
    return path;
  };

  for (const asset of input.assets) {
    if (asset.type === 'image') continue;
    const decided = decideAlongPath(pathOf(asset), rowsByAsset);
    result.set(
      asset.id,
      [...decided]
        .filter(([, d]) => d.mode === 'include')
        .map(([projectId]) => projectId)
        .sort(byCodeUnit),
    );
  }

  for (const asset of input.assets) {
    if (asset.type !== 'image') continue;
    const projects = new Set<string>();
    for (const holderId of input.imageHolders.get(asset.id) ?? []) {
      if (assets.get(holderId)?.status === 'retired') continue;
      for (const p of result.get(holderId) ?? []) projects.add(p);
    }
    for (const row of rowsByAsset.get(asset.id) ?? [])
      if (row.mode === 'include') projects.add(row.projectId);
      else projects.delete(row.projectId);
    result.set(asset.id, [...projects].sort(byCodeUnit));
  }
  return result;
}
