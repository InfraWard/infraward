import { Asset, Project } from '@infraward/domain';
import type {
  EffectiveInventoryPolicy,
  InventoryPolicySource,
} from '@infraward/shared-types';
import { In, type EntityManager } from 'typeorm';

/**
 * Orígenes de la política efectiva con los nombres de los antepasados, proyectos y, en una
 * exclusión (QoL-6b), del host o contenedor por el que una imagen queda fuera.
 */
export async function namedPolicySources(
  m: EntityManager,
  effective: EffectiveInventoryPolicy,
): Promise<EffectiveInventoryPolicy['sources']> {
  const origins = Object.values(effective.sources).flatMap((s) =>
    s.kind === 'excluded' ? [s.by] : [s],
  );
  const inherited = [
    ...origins.flatMap((s) => (s.kind === 'inherited' ? [s.assetId] : [])),
    ...Object.values(effective.sources).flatMap((s) =>
      s.kind === 'excluded' && s.holderId ? [s.holderId] : [],
    ),
  ];
  const projectIds = origins.flatMap((s) =>
    s.kind === 'project' ? [s.projectId] : [],
  );
  const names = new Map(
    (inherited.length
      ? await m.find(Asset, {
          where: { id: In(inherited) },
          select: { id: true, name: true },
        })
      : []
    ).map((a) => [a.id, a.name]),
  );
  const projectNames = new Map(
    (projectIds.length
      ? await m.find(Project, {
          where: { id: In(projectIds) },
          select: { id: true, name: true },
        })
      : []
    ).map((p) => [p.id, p.name]),
  );
  const named = <S extends InventoryPolicySource>(s: S): S =>
    s.kind === 'inherited'
      ? { ...s, assetName: names.get(s.assetId) }
      : s.kind === 'project'
        ? { ...s, projectName: projectNames.get(s.projectId) }
        : s;
  return Object.fromEntries(
    Object.entries(effective.sources).map(([field, s]) => [
      field,
      s.kind === 'excluded'
        ? {
            ...s,
            by: named(s.by),
            ...(s.holderId ? { holderName: names.get(s.holderId) } : {}),
          }
        : named(s),
    ]),
  ) as Record<keyof EffectiveInventoryPolicy['values'], InventoryPolicySource>;
}
