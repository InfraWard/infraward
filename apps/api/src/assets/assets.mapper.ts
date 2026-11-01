import type {
  Asset as AssetContract,
  AssetRelation as AssetRelationContract,
  AssetRelationWithPeer,
  AssetSummary,
  AssetTreeSummaryNode,
  EffectiveInventoryPolicy,
  Snapshot as SnapshotContract,
  SnapshotDiff,
  SnapshotSummary,
} from '@infraward/shared-types';
import {
  policyValues,
  type Asset,
  type AssetRelation,
  type Snapshot,
} from '@infraward/domain';
import { emptyFindingCounts, type OpenFindingCounts } from './open-findings.js';
import type { TreeExtras } from './tree-extras.js';

// Entidad → contrato de la API (fechas en ISO 8601).

export function toAsset(
  asset: Asset,
  links?: { duplicateOf: AssetSummary | null; duplicates: AssetSummary[] },
  options: { notes?: boolean } = {},
): AssetContract {
  return {
    id: asset.id,
    type: asset.type,
    name: asset.name,
    discoveredName: asset.discoveredName,
    displayName: asset.displayName,
    ...(options.notes ? { notes: asset.notes } : {}),
    projects: asset.effectiveProjects ?? [],
    status: asset.status,
    naturalKey: asset.naturalKey,
    roles: asset.roles,
    tags: asset.tags,
    facts: asset.facts,
    connection: asset.connection,
    // Solo referencias: los valores nunca están en la BD.
    credentials: asset.credentials,
    sshAuth: asset.sshAuth,
    hostKeyFingerprint: asset.hostKeyFingerprint,
    adminAccess: asset.adminAccess ?? null,
    duplicateOfId: asset.duplicateOfId,
    ...links,
    effectivePolicy: effectivePolicyOf(asset),
    missingRuns: asset.missingRuns,
    missingSince: asset.missingSince?.toISOString() ?? null,
    retiredAuto: asset.retiredAuto,
    createdAt: asset.createdAt.toISOString(),
    updatedAt: asset.updatedAt.toISOString(),
  };
}

export function toRelation(relation: AssetRelation): AssetRelationContract {
  return {
    id: relation.id,
    parentId: relation.parentId,
    childId: relation.childId,
    type: relation.type,
    createdAt: relation.createdAt.toISOString(),
  };
}

export function toAssetSummary(
  asset: Pick<Asset, 'id' | 'name' | 'type' | 'status'>,
): AssetSummary {
  return {
    id: asset.id,
    name: asset.name,
    type: asset.type,
    status: asset.status,
  };
}

/** Nodo del árbol sin hijos (los añade `buildTree`): nunca facts, conexión ni credenciales. */
export function toTreeSummary(
  asset: Pick<
    Asset,
    | 'id'
    | 'name'
    | 'type'
    | 'status'
    | 'roles'
    | 'tags'
    | 'displayName'
    | 'discoveredName'
    | 'effectiveProjects'
  >,
  extras: TreeExtras,
  findings: OpenFindingCounts = emptyFindingCounts(),
): Omit<AssetTreeSummaryNode, 'children'> {
  return {
    ...toAssetSummary(asset),
    discoveredName: asset.displayName ? asset.discoveredName : null,
    roles: asset.roles,
    tags: asset.tags,
    projects: asset.effectiveProjects ?? [],
    address: extras.address,
    ips: extras.ips,
    runtimeState: extras.runtimeState,
    runtimeDetail: extras.runtimeDetail,
    openFindings: findings.open,
    fixableFindings: findings.fixable,
    kernelNotRunningFindings: findings.kernelNotRunning,
    sudoersOutdated: extras.sudoersOutdated,
    collectionWarnings: extras.collectionWarnings,
    duplicateOf: extras.duplicateOf,
    machineIdClone: extras.machineIdClone,
    expiresAt: extras.expiresAt,
    dnsWarning: extras.dnsWarning,
    sshCaOutdated: extras.sshCaOutdated,
    sshdRisk: extras.sshdRisk,
    scanDisabled: extras.scanDisabled,
  };
}

export function toRelationWithPeer(
  relation: AssetRelation,
  peer: Pick<Asset, 'id' | 'name' | 'type' | 'status'>,
): AssetRelationWithPeer {
  return { ...toRelation(relation), peer: toAssetSummary(peer) };
}

export function toSnapshotSummary(
  snapshot: Omit<Snapshot, 'facts' | 'diff'> & {
    diff?: Pick<SnapshotDiff, 'summary'> | null;
  },
): SnapshotSummary {
  return {
    id: snapshot.id,
    assetId: snapshot.assetId,
    collectedAt: snapshot.collectedAt.toISOString(),
    roles: snapshot.roles,
    jobId: snapshot.jobId,
    source: snapshot.source,
    previousId: snapshot.previousId,
    changeSummary: snapshot.diff?.summary ?? null,
  };
}

export function toSnapshot(snapshot: Snapshot): SnapshotContract {
  return {
    ...toSnapshotSummary(snapshot),
    facts: snapshot.facts,
    diff: snapshot.diff,
  };
}

/** Política efectiva guardada; aún sin calcular (`{}`), la de por defecto con origen global. */
export function effectivePolicyOf(
  asset: Pick<Asset, 'effectivePolicy'>,
): EffectiveInventoryPolicy {
  const stored = asset.effectivePolicy as Partial<EffectiveInventoryPolicy>;
  if (stored.values && stored.sources)
    return stored as EffectiveInventoryPolicy;
  const global = { kind: 'global' } as const;
  return {
    values: policyValues(stored),
    sources: {
      reconcileIntervalMinutes: global,
      scanEnabled: global,
      scanPeriodic: global,
    },
  };
}
