import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  buildTopology,
  expandGraph,
  findSubtreeRows,
  type GraphRelationRow,
  type TopologyAsset,
  type TopologyRelation,
} from '@infraward/domain';
import {
  GRAPH_MAX_DEPTH,
  SEVERITIES,
  type AssetGraph,
  type AssetStatus,
  type AssetType,
  type GraphEdge,
  type GraphNode,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import type { AssetGraphQueryDto, TopologyQueryDto } from './graph.dto.js';
import { openFindingsBySeverity } from './open-findings.js';
import {
  TREE_EXTRAS_SELECT,
  treeExtras,
  type TreeExtrasRow,
} from './tree-extras.js';

type SummaryRow = TreeExtrasRow & {
  id: string;
  name: string;
  status: AssetStatus;
};

/** Lo que el grafo dice de cada nodo además de su resumen. */
interface NodePlacement {
  parentId: string | null;
  depth: number;
  hidden: Partial<Record<AssetType, number>>;
  hiddenCritical: number;
}

/**
 * Grafos de relaciones (QoL-4): el mapa de un asset (`GET /assets/:id/graph`) y la topología por
 * niveles (`GET /assets/topology`). Nodos resumidos como en el árbol: nunca facts completos,
 * conexión ni credenciales.
 */
@Injectable()
export class AssetGraphService {
  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async graph(id: string, query: AssetGraphQueryDto): Promise<AssetGraph> {
    const type = await this.ensureAsset(id);
    const includeRetired = query.includeRetired ?? false;
    const expanded = await expandGraph(
      id,
      (ids) => this.relationsTouching(ids, id, includeRetired),
      { depth: query.depth ?? 1 },
    );
    // Un registro DNS: su camino hasta el servicio entero, aunque quede lejos del centro.
    const servicePath =
      type === 'dns_record' ? await this.servicePath(id, expanded) : undefined;
    // Padre `contains` de cada nodo si también está en el mapa.
    const parents = new Map(
      expanded.edges
        .filter((e) => e.type === 'contains')
        .map((e) => [e.target, e.source]),
    );
    const placements = new Map(
      [...expanded.depths].map(([nodeId, depth]) => [
        nodeId,
        {
          parentId: parents.get(nodeId) ?? null,
          depth,
          hidden: expanded.hidden.get(nodeId) ?? {},
          hiddenCritical: 0,
        },
      ]),
    );
    return {
      centerId: id,
      nodes: await this.summaries(placements),
      edges: expanded.edges,
      truncated: expanded.truncated,
      ...(servicePath && { servicePath }),
    };
  }

  /**
   * Añade al mapa los assets del camino del registro (con su distancia en saltos) y las
   * relaciones entre los nodos que ya están (`contains`, `routes_to`, `served_by`, `resolves_to`).
   */
  private async servicePath(
    recordId: string,
    expanded: Awaited<ReturnType<typeof expandGraph>>,
  ): Promise<string[]> {
    const [row]: { hops: { assetId: string | null }[]; pinned: string | null }[] =
      await this.db.query(
        `SELECT p.hops, p.pinned_asset_id AS pinned FROM dns_service_paths p
          WHERE p.record_id = $1`,
        [recordId],
      );
    if (!row) return [recordId];
    const ids = [
      ...new Set(
        [...row.hops.map((h) => h.assetId), row.pinned].filter(
          (x): x is string => !!x && x !== recordId,
        ),
      ),
    ];
    const alive: { id: string }[] = ids.length
      ? await this.db.query(
          `SELECT id FROM assets WHERE id = ANY($1::uuid[]) AND status <> 'retired'`,
          [ids],
        )
      : [];
    const kept = ids.filter((x) => alive.some((a) => a.id === x));
    kept.forEach((x, i) => {
      if (!expanded.depths.has(x))
        expanded.depths.set(x, Math.min(i + 1, GRAPH_MAX_DEPTH));
    });
    const all = [...expanded.depths.keys()];
    const known = new Set(expanded.edges.map((e) => e.id));
    const extra: { id: string; source: string; target: string; type: GraphEdge['type'] }[] =
      await this.db.query(
        `SELECT id, parent_id AS source, child_id AS target, type FROM asset_relations
          WHERE type IN ('contains', 'routes_to', 'served_by', 'resolves_to')
            AND parent_id = ANY($1::uuid[]) AND child_id = ANY($1::uuid[])`,
        [all],
      );
    for (const e of extra)
      if (!known.has(e.id)) expanded.edges.push({ ...e, count: 1 });
    return [recordId, ...kept];
  }

  async topology(query: TopologyQueryDto): Promise<AssetGraph> {
    if (query.rootId) await this.ensureAsset(query.rootId);
    const excludeStatuses: AssetStatus[] = query.includeRetired
      ? []
      : ['retired'];
    const tree = await findSubtreeRows(
      this.db.manager,
      query.rootId ? [query.rootId] : 'roots',
      { excludeStatuses },
    );
    const treeIds = tree.map((r) => r.id);
    // Las imágenes no están en el árbol: se llega a ellas desde sus hosts y contenedores.
    const images: { id: string }[] = treeIds.length
      ? await this.db.query(
          `SELECT DISTINCT r.child_id AS id
             FROM asset_relations r
             JOIN assets i ON i.id = r.child_id AND i.type = 'image'
            WHERE r.type IN ('stores', 'instance_of')
              AND r.parent_id = ANY($1::uuid[])
              AND i.status::text <> ALL($2::text[])`,
          [treeIds, excludeStatuses],
        )
      : [];
    const allIds = [...treeIds, ...images.map((i) => i.id)];
    const meta: { id: string; type: AssetType; projects: string[] | null }[] =
      allIds.length
        ? await this.db.query(
            `SELECT id, type, effective_projects AS projects
               FROM assets WHERE id = ANY($1::uuid[])`,
            [allIds],
          )
        : [];
    const metaById = new Map(meta.map((m) => [m.id, m]));
    const inProject = (assetId: string) =>
      !query.projectId ||
      (metaById.get(assetId)?.projects ?? []).includes(query.projectId);

    // Con proyecto, cada asset cuelga de su antepasado más cercano que también esté en él.
    const treeParent = new Map(tree.map((r) => [r.id, r.parentId]));
    const keptParent = (assetId: string): string | null => {
      let parent = treeParent.get(assetId) ?? null;
      for (let n = 0; parent && !inProject(parent) && n < 64; n++)
        parent = treeParent.get(parent) ?? null;
      return parent;
    };
    const assets: TopologyAsset[] = allIds
      .filter((assetId) => metaById.has(assetId) && inProject(assetId))
      .map((assetId) => ({
        id: assetId,
        type: metaById.get(assetId)!.type,
        parentId: treeParent.has(assetId) ? keptParent(assetId) : null,
      }));
    const keptIds = assets.map((a) => a.id);
    const relations: TopologyRelation[] = keptIds.length
      ? await this.db.query(
          `SELECT id, parent_id AS "parentId", child_id AS "childId", type
             FROM asset_relations
            WHERE type <> 'contains'
              AND parent_id = ANY($1::uuid[]) AND child_id = ANY($1::uuid[])`,
          [keptIds],
        )
      : [];
    const findings = await openFindingsBySeverity(this.db.manager, keptIds);
    const critical = new Map(
      [...findings].map(([assetId, f]) => [assetId, f.open.CRITICAL]),
    );
    const topology = buildTopology({
      assets,
      relations,
      critical,
      expand: new Set(query.expand ?? []),
    });
    const placements = new Map(
      topology.nodes.map((n) => [
        n.id,
        {
          parentId: n.parentId,
          depth: 0,
          hidden: n.hidden,
          hiddenCritical: n.hiddenCritical,
        },
      ]),
    );
    return {
      centerId: null,
      nodes: await this.summaries(placements),
      edges: topology.edges,
      truncated: topology.truncated,
    };
  }

  /**
   * Relaciones que tocan a `ids`, con el tipo de sus extremos. Sin `includeRetired`, deja fuera
   * las que llevan a un retirado (salvo el propio centro, que se muestra aunque lo esté).
   */
  private relationsTouching(
    ids: string[],
    centerId: string,
    includeRetired: boolean,
  ): Promise<GraphRelationRow[]> {
    return this.db.query(
      `SELECT r.id, r.parent_id AS "parentId", r.child_id AS "childId", r.type,
              p.type AS "parentType", c.type AS "childType"
         FROM asset_relations r
         JOIN assets p ON p.id = r.parent_id
         JOIN assets c ON c.id = r.child_id
        WHERE (r.parent_id = ANY($1::uuid[]) OR r.child_id = ANY($1::uuid[]))
          AND ($3 OR ((p.id = $2 OR p.status <> 'retired')
                      AND (c.id = $2 OR c.status <> 'retired')))
        ORDER BY r.created_at, r.id`,
      [ids, centerId, includeRetired],
    );
  }

  /** Resumen de los nodos, con las rutas de JSONB del árbol y sus findings abiertos. */
  private async summaries(
    placements: Map<string, NodePlacement>,
  ): Promise<GraphNode[]> {
    const ids = [...placements.keys()];
    if (ids.length === 0) return [];
    const [rows, findings] = await Promise.all([
      this.db.query<SummaryRow[]>(
        `SELECT a.id, a.name, a.type, a.status, ${TREE_EXTRAS_SELECT}
           FROM assets a
          WHERE a.id = ANY($1::uuid[])`,
        [ids],
      ),
      openFindingsBySeverity(this.db.manager, ids),
    ]);
    const byId = new Map(rows.map((r) => [r.id, r]));
    // En el orden de `placements` (el del recorrido); puede faltar alguno borrado entre consultas.
    return ids.flatMap((nodeId) => {
      const row = byId.get(nodeId);
      if (!row) return [];
      const extras = treeExtras(row);
      const open = findings.get(nodeId)?.open;
      const placement = placements.get(nodeId)!;
      return [
        {
          id: row.id,
          name: row.name,
          type: row.type,
          status: row.status,
          address: extras.address,
          runtimeState: extras.runtimeState,
          critical: open?.CRITICAL ?? 0,
          maxSeverity: open
            ? (SEVERITIES.findLast((s) => open[s] > 0) ?? null)
            : null,
          ...placement,
          parentId:
            placement.parentId && byId.has(placement.parentId)
              ? placement.parentId
              : null,
        },
      ];
    });
  }

  private async ensureAsset(id: string): Promise<AssetType> {
    const rows: { type: AssetType }[] = await this.db.query(
      'SELECT type FROM assets WHERE id = $1',
      [id],
    );
    if (rows.length === 0) throw new NotFoundException('Asset no encontrado');
    return rows[0].type;
  }
}
