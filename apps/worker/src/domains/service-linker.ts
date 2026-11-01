import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  assetIps,
  resolveServicePaths,
  type ResolvedServicePath,
  type ServiceAsset,
  type ServiceRecord,
} from '@infraward/connectors';
import type {
  AssetType,
  CloudflareTunnel,
  CollectedPort,
  DockerContainerFacts,
  ProxyFacts,
  ServicesLinkJobResult,
} from '@infraward/shared-types';
import { DataSource, type EntityManager } from 'typeorm';

/** Candado de transacción de los caminos (sincronizaciones, tick y job no se pisan). */
export const SERVICE_LINK_LOCK = 0x1d_45_00_02;

const HOST_TYPES = ['server', 'vm', 'lxc'];

/**
 * Caminos de los registros DNS hasta el asset que los sirve (QoL-5b, DESIGN §13): carga solo las
 * rutas de JSONB que hacen falta, resuelve con `resolveServicePaths` (pura) y guarda cada camino
 * con sus eslabones (`dns_service_paths`) y las relaciones `served_by` (registro → asset final) y
 * `routes_to` (eslabón → siguiente). Solo se tocan las relaciones que cambian. Un destino fijado a
 * mano gana al calculado (que se sigue guardando: hasta dónde llegó).
 */
@Injectable()
export class ServiceLinker {
  private readonly logger = new Logger(ServiceLinker.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  link(): Promise<ServicesLinkJobResult> {
    return this.db.transaction(async (m) => {
      await m.query('SELECT pg_advisory_xact_lock($1)', [SERVICE_LINK_LOCK]);
      return this.apply(m);
    });
  }

  private async apply(m: EntityManager): Promise<ServicesLinkJobResult> {
    const records = await this.records(m);
    const assets = [...(await this.hosts(m)), ...(await this.containers(m))];
    const natForwards: {
      publicIp: string;
      publicPort: number;
      proto: 'tcp' | 'udp';
      targetAssetId: string;
      targetPort: number;
    }[] = await m.query(
      `SELECT host(public_ip) AS "publicIp", public_port AS "publicPort", proto,
              target_asset_id AS "targetAssetId", target_port AS "targetPort"
         FROM nat_forwards n JOIN assets a ON a.id = n.target_asset_id
        WHERE a.status <> 'retired'`,
    );
    const tunnelRows: { items: CloudflareTunnel[] | null }[] = await m.query(
      `SELECT facts->'connector'->'tunnels'->'items' AS items FROM assets
        WHERE type = 'dns_provider' AND status = 'active'`,
    );
    const tunnels = tunnelRows.flatMap((t) =>
      Array.isArray(t.items) ? t.items : [],
    );

    const paths = resolveServicePaths({
      records,
      assets,
      natForwards,
      tunnels,
    });
    await this.savePaths(m, paths);
    const { servedBy, routesTo } = await this.saveRelations(m, paths);
    const complete = paths.filter((p) => p.status === 'complete').length;
    const partial = paths.filter((p) => p.status === 'partial').length;
    return { paths: paths.length, complete, partial, servedBy, routesTo };
  }

  /** Registros A/AAAA/CNAME activos con sus destinos `resolves_to` activos. */
  private async records(m: EntityManager): Promise<ServiceRecord[]> {
    const rows: {
      id: string;
      name: string | null;
      type: string | null;
      content: string | null;
      proxied: boolean | null;
      targets: string[] | null;
    }[] = await m.query(
      `SELECT a.id, a.facts->'dns'->>'name' AS name, a.facts->'dns'->>'type' AS type,
              a.facts->'dns'->>'content' AS content,
              (a.facts->'dns'->>'proxied')::boolean AS proxied,
              array_remove(array_agg(t.id), NULL) AS targets
         FROM assets a
         LEFT JOIN asset_relations r ON r.parent_id = a.id AND r.type = 'resolves_to'
         LEFT JOIN assets t ON t.id = r.child_id AND t.status = 'active'
        WHERE a.type = 'dns_record' AND a.status = 'active'
          AND a.facts->'dns'->>'type' IN ('A', 'AAAA', 'CNAME')
        GROUP BY a.id`,
    );
    return rows
      .filter((r) => r.name && r.type && r.content)
      .map((r) => ({
        id: r.id,
        name: r.name!,
        type: r.type as ServiceRecord['type'],
        content: r.content!,
        proxied: r.proxied === true,
        targets: r.targets ?? [],
      }));
  }

  /** Servidores, VMs y CT activos: IPs, puertos (`ss`) y nginx del sistema. */
  private async hosts(m: EntityManager): Promise<ServiceAsset[]> {
    const rows: {
      id: string;
      name: string;
      type: AssetType;
      parent_id: string | null;
      network: unknown;
      proxmox_interfaces: unknown;
      proxmox_config: unknown;
      connection: unknown;
      ports: CollectedPort[] | null;
      proxy: ProxyFacts | null;
      has_proxy: boolean;
    }[] = await m.query(
      `SELECT a.id, a.name, a.type, p.parent_id, a.facts->'network' AS network,
              a.facts->'proxmox'->'interfaces' AS proxmox_interfaces,
              a.facts->'proxmox'->'config' AS proxmox_config, a.connection,
              a.facts->'ports' AS ports, a.facts->'proxy' AS proxy,
              a.facts ? 'proxy' AS has_proxy
         FROM assets a
         LEFT JOIN asset_relations p ON p.child_id = a.id AND p.type = 'contains'
        WHERE a.type::text = ANY($1::text[]) AND a.status = 'active'`,
      [HOST_TYPES],
    );
    return rows.map((h) => ({
      id: h.id,
      name: h.name,
      type: h.type,
      parentId: h.parent_id,
      ips: assetIps(
        {
          network: h.network,
          proxmox: { interfaces: h.proxmox_interfaces, config: h.proxmox_config },
        },
        h.connection,
      ),
      ports: Array.isArray(h.ports) ? h.ports : null,
      ...(h.has_proxy && { proxy: h.proxy }),
    }));
  }

  /** Contenedores activos con lo que necesitan los resolutores (nunca el resto de los facts). */
  private async containers(m: EntityManager): Promise<ServiceAsset[]> {
    const rows: {
      id: string;
      name: string;
      parent_id: string | null;
      image: string | null;
      state: string | null;
      ports: DockerContainerFacts['ports'] | null;
      networks: DockerContainerFacts['networks'] | null;
      compose_service: string | null;
      proxy_routes: DockerContainerFacts['proxyRoutes'] | null;
      proxy: ProxyFacts | null;
      has_proxy: boolean;
    }[] = await m.query(
      `SELECT a.id, a.name, p.parent_id, a.facts->'docker'->>'image' AS image,
              a.facts->'docker'->>'state' AS state, a.facts->'docker'->'ports' AS ports,
              a.facts->'docker'->'networks' AS networks,
              a.facts->'docker'->>'composeService' AS compose_service,
              a.facts->'docker'->'proxyRoutes' AS proxy_routes,
              a.facts->'docker'->'proxy' AS proxy,
              a.facts->'docker' ? 'proxy' AS has_proxy
         FROM assets a
         LEFT JOIN asset_relations p ON p.child_id = a.id AND p.type = 'contains'
        WHERE a.type = 'container' AND a.status = 'active'`,
    );
    return rows.map((c) => {
      const networks = Array.isArray(c.networks) ? c.networks : [];
      return {
        id: c.id,
        name: c.name,
        type: 'container' as const,
        parentId: c.parent_id,
        ips: networks.flatMap((n) => [n.ipv4, n.ipv6].filter((ip): ip is string => !!ip)),
        ports: null,
        ...(c.has_proxy && { proxy: c.proxy }),
        docker: {
          image: c.image ?? '',
          state: c.state ?? 'unknown',
          ports: Array.isArray(c.ports) ? c.ports : [],
          networks,
          composeService: c.compose_service,
          proxyRoutes: Array.isArray(c.proxy_routes) ? c.proxy_routes : [],
        },
      };
    });
  }

  private async savePaths(
    m: EntityManager,
    paths: ResolvedServicePath[],
  ): Promise<void> {
    if (paths.length)
      await m.query(
        `INSERT INTO dns_service_paths
           (record_id, status, final_asset_id, hops, confidence, cut_reason, via_asset_ids, public, computed_at)
         SELECT x.r, x.s, x.f, x.h::jsonb, x.c, x.k, x.v::uuid[], x.p, now()
           FROM unnest($1::uuid[], $2::text[], $3::uuid[], $4::text[], $5::text[], $6::text[], $7::text[], $8::boolean[])
             AS x(r, s, f, h, c, k, v, p)
         ON CONFLICT (record_id) DO UPDATE SET
           -- Un destino fijado a mano gana: se guarda el camino calculado, pero no el estado.
           status = CASE WHEN dns_service_paths.pinned_asset_id IS NULL THEN EXCLUDED.status ELSE 'manual' END,
           final_asset_id = COALESCE(dns_service_paths.pinned_asset_id, EXCLUDED.final_asset_id),
           hops = EXCLUDED.hops, confidence = EXCLUDED.confidence, cut_reason = EXCLUDED.cut_reason,
           public = EXCLUDED.public,
           via_asset_ids = COALESCE((SELECT array_agg(DISTINCT u) FROM unnest(
             EXCLUDED.via_asset_ids || ARRAY[dns_service_paths.pinned_asset_id]) u
             WHERE u IS NOT NULL), '{}'),
           computed_at = EXCLUDED.computed_at`,
        [
          paths.map((p) => p.recordId),
          paths.map((p) => p.status),
          paths.map((p) => p.finalAssetId),
          paths.map((p) => JSON.stringify(p.hops)),
          paths.map((p) => p.confidence),
          paths.map((p) => p.cutReason),
          paths.map(
            (p) =>
              `{${[...new Set(p.hops.map((h) => h.assetId).filter(Boolean))].join(',')}}`,
          ),
          paths.map((p) => p.public),
        ],
      );
    // Registros que ya no son A/AAAA/CNAME o no están activos (salvo los fijados a mano).
    await m.query(
      `DELETE FROM dns_service_paths
        WHERE pinned_asset_id IS NULL AND NOT (record_id = ANY($1::uuid[]))`,
      [paths.map((p) => p.recordId)],
    );
  }

  /** `served_by` y `routes_to`: solo se tocan las que cambian. */
  private async saveRelations(
    m: EntityManager,
    paths: ResolvedServicePath[],
  ): Promise<{ servedBy: number; routesTo: number }> {
    const finals: { record_id: string; final_asset_id: string }[] = await m.query(
      `SELECT record_id, final_asset_id FROM dns_service_paths
        WHERE final_asset_id IS NOT NULL AND final_asset_id <> record_id`,
    );
    const want = new Map<string, 'served_by' | 'routes_to'>();
    for (const f of finals)
      want.set(`${f.record_id}|${f.final_asset_id}|served_by`, 'served_by');
    for (const p of paths) {
      const chain = p.hops
        .map((h) => h.assetId)
        .filter((id): id is string => !!id);
      for (let i = 1; i < chain.length; i++)
        if (chain[i] !== chain[i - 1])
          want.set(`${chain[i - 1]}|${chain[i]}|routes_to`, 'routes_to');
    }
    const have: { id: string; parent_id: string; child_id: string; type: string }[] =
      await m.query(
        `SELECT id, parent_id, child_id, type::text AS type FROM asset_relations
          WHERE type IN ('served_by', 'routes_to')`,
      );
    const haveKeys = new Set(
      have.map((h) => `${h.parent_id}|${h.child_id}|${h.type}`),
    );
    const drop = have
      .filter((h) => !want.has(`${h.parent_id}|${h.child_id}|${h.type}`))
      .map((h) => h.id);
    if (drop.length)
      await m.query(`DELETE FROM asset_relations WHERE id = ANY($1::uuid[])`, [
        drop,
      ]);
    const add = [...want.keys()]
      .filter((k) => !haveKeys.has(k))
      .map((k) => k.split('|'));
    if (add.length)
      await m.query(
        `INSERT INTO asset_relations (parent_id, child_id, type)
         SELECT f, t, ty::asset_relation_type FROM unnest($1::uuid[], $2::uuid[], $3::text[]) AS x(f, t, ty)
         ON CONFLICT DO NOTHING`,
        [add.map((a) => a[0]), add.map((a) => a[1]), add.map((a) => a[2])],
      );
    if (drop.length || add.length)
      this.logger.log(
        `Caminos de los dominios: ${add.length} relaciones nuevas, ${drop.length} quitadas`,
      );
    const count = (t: string) => [...want.values()].filter((v) => v === t).length;
    return { servedBy: count('served_by'), routesTo: count('routes_to') };
  }
}
