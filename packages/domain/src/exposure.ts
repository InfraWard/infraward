/**
 * Assets expuestos con un nombre público (QoL-5b, §9): los finales e intermedios de los caminos de
 * registros DNS públicos (IP pública, proxy de Cloudflare o túnel) y, por `instance_of`, la imagen
 * de un contenedor del camino (sus findings son los de la imagen). Una fila por asset con cuántos
 * registros llegan y los tres primeros nombres.
 */
export const EXPOSED_ASSETS_SQL = `
  SELECT x.asset_id, count(DISTINCT x.record_id)::int AS n,
         (array_agg(DISTINCT x.record_name ORDER BY x.record_name))[1:3] AS names
    FROM (
      SELECT u AS asset_id, p.record_id, COALESCE(r.facts->'dns'->>'name', r.name) AS record_name
        FROM dns_service_paths p
        JOIN assets r ON r.id = p.record_id AND r.status = 'active'
        CROSS JOIN LATERAL unnest(p.via_asset_ids || p.final_asset_id) u
       WHERE p.public AND u IS NOT NULL
      UNION ALL
      SELECT ir.child_id, p.record_id, COALESCE(r.facts->'dns'->>'name', r.name)
        FROM dns_service_paths p
        JOIN assets r ON r.id = p.record_id AND r.status = 'active'
        JOIN asset_relations ir ON ir.type = 'instance_of'
         AND (ir.parent_id = ANY(p.via_asset_ids) OR ir.parent_id = p.final_asset_id)
       WHERE p.public
    ) x
   GROUP BY x.asset_id`;

/** Filtro sobre `findings f`: su dueño está expuesto con un nombre público. */
export const PUBLIC_EXPOSED_OWNER = `EXISTS (
  SELECT 1 FROM (${EXPOSED_ASSETS_SQL}) pe WHERE pe.asset_id = f.asset_id)`;
