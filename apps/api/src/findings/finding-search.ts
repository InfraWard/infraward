import {
  foldText,
  ipMatcher,
  PRIORITY_BAND_MIN,
  parseSearchQuery,
  searchGroups,
  type SearchGroup,
  type SearchKey,
} from '@infraward/shared-types';

/** Banda de prioridad de `f.priority` (los mismos límites que `priorityBand`). */
export const PRIORITY_BAND_SQL = `CASE
  WHEN f.priority >= ${PRIORITY_BAND_MIN.urgent} THEN 'urgent'
  WHEN f.priority >= ${PRIORITY_BAND_MIN.high} THEN 'high'
  WHEN f.priority >= ${PRIORITY_BAND_MIN.medium} THEN 'medium'
  WHEN f.priority IS NOT NULL THEN 'low' END`;

/**
 * `foldText` en SQL: minúsculas y sin marcas diacríticas (descompuesto en NFD, fuera las
 * combinantes). Los valores de la búsqueda ya llegan así: hay que plegar también la columna, o un
 * tag `producción` nunca coincidiría con `tag:producción` (que se busca como `produccion`).
 */
export function foldSql(expr: string): string {
  return `regexp_replace(normalize(lower(${expr}), NFD), '[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]', '', 'g')`;
}

/** Escapa los comodines de LIKE para buscar el texto tal cual. */
export function likeLiteral(text: string): string {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * La búsqueda de vulnerabilidades con la sintaxis de filtros (`search-query.ts`, DESIGN §15) en
 * SQL sobre `findings f`. Las claves de asset (`tag`, `nombre`, `tipo`, `estado`, `rol`,
 * `proyecto`, `ip`) se aplican al **asset afectado**: el dueño del finding o, si es una imagen,
 * alguno de los contenedores y hosts no retirados que la usan (el CVE hereda su contexto).
 * Todo va parametrizado; lo que el parser no entiende ya se quedó fuera.
 */
export function findingSearchWhere(
  q: string,
  push: (value: unknown) => string,
): string[] {
  const parsed = parseSearchQuery(q, 'vulnerabilities');
  return searchGroups(parsed).flatMap((group) => {
    const sql = groupSql(group, push);
    if (!sql) return [];
    return [group.negated ? `NOT (${sql})` : `(${sql})`];
  });
}

function groupSql(
  group: SearchGroup,
  push: (value: unknown) => string,
): string | null {
  const { key, values } = group;
  switch (key) {
    case null:
      // Texto libre: CVE por prefijo o paquete por subcadena (como antes de la sintaxis).
      return values
        .map((v) => {
          const p = push(likeLiteral(v));
          return `(upper(f.vulnerability_id) LIKE upper(${p}) || '%' OR f.package_name ILIKE '%' || ${p} || '%')`;
        })
        .join(' OR ');
    case 'cve':
      return values
        .map(
          (v) =>
            `upper(f.vulnerability_id) LIKE upper(${push(likeLiteral(v))}) || '%'`,
        )
        .join(' OR ');
    case 'package':
      return values
        .map(
          (v) => `f.package_name ILIKE '%' || ${push(likeLiteral(v))} || '%'`,
        )
        .join(' OR ');
    case 'severity':
      return `f.severity::text = ANY(${push(values)}::text[])`;
    case 'priority':
      return `${PRIORITY_BAND_SQL} = ANY(${push(values)}::text[])`;
    default: {
      const cond = assetCondition(key, values, push);
      return cond ? affected(cond) : null;
    }
  }
}

/** El dueño del finding o, en una imagen, uno de quienes la usan cumple `cond(alias)`. */
function affected(cond: (alias: string) => string): string {
  return `EXISTS (
    SELECT 1 FROM assets qa
     WHERE qa.id = f.asset_id
       AND ((${cond('qa')})
            OR (qa.type = 'image' AND EXISTS (
                  SELECT 1 FROM asset_relations qr
                    JOIN assets qh ON qh.id = qr.parent_id AND qh.status <> 'retired'
                   WHERE qr.child_id = qa.id AND qr.type IN ('instance_of', 'stores')
                     AND (${cond('qh')})))))`;
}

/** Estado de ejecución como `runtimeState` de `tree-extras.ts`. */
function runtimeStateSql(a: string): string {
  return `CASE lower(COALESCE(${a}.facts->'docker'->>'state', ${a}.facts->'proxmox'->>'status'))
            WHEN 'running' THEN 'running'
            WHEN 'paused' THEN 'paused' WHEN 'suspended' THEN 'paused'
            WHEN 'stopped' THEN 'stopped' WHEN 'exited' THEN 'stopped'
            WHEN 'created' THEN 'stopped' WHEN 'dead' THEN 'stopped'
            ELSE 'other' END`;
}

/** Las IPs del asset como `treeIps` (host de conexión, IPv4 por defecto, interfaces y `net0`). */
function ipsSql(a: string): string {
  return `SELECT v FROM (
      SELECT ${a}.connection->>'host' AS v
      UNION ALL SELECT ${a}.facts->'network'->>'defaultIpv4'
      UNION ALL SELECT split_part(e, '/', 1)
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(${a}.facts->'proxmox'->'interfaces') = 'array'
                                       THEN ${a}.facts->'proxmox'->'interfaces' ELSE '[]'::jsonb END) i,
             jsonb_array_elements_text(CASE WHEN jsonb_typeof(i->'ipv4') = 'array'
                                            THEN i->'ipv4' ELSE '[]'::jsonb END) e
      UNION ALL SELECT substring(${a}.facts->'proxmox'->'config'->>'net0' FROM 'ip=([0-9.]+)')
    ) ips WHERE v IS NOT NULL`;
}

const IPV4_SQL = String.raw`'^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'`;

function assetCondition(
  key: SearchKey,
  values: string[],
  push: (value: unknown) => string,
): ((alias: string) => string) | null {
  const lower = values.map((v) => foldText(v));
  switch (key) {
    case 'tag': {
      const p = push(lower);
      return (a) =>
        `EXISTS (SELECT 1 FROM unnest(${a}.tags) t WHERE ${foldSql('t')} = ANY(${p}::text[]))`;
    }
    case 'role': {
      const p = push(lower);
      return (a) =>
        `EXISTS (SELECT 1 FROM unnest(${a}.roles) r WHERE ${foldSql('r')} = ANY(${p}::text[]))`;
    }
    case 'name': {
      const ps = lower.map((v) => push(likeLiteral(v)));
      return (a) =>
        ps
          .map(
            (p) =>
              `${foldSql(`${a}.name`)} LIKE '%' || ${p} || '%' OR ${foldSql(`${a}.discovered_name`)} LIKE '%' || ${p} || '%'`,
          )
          .join(' OR ');
    }
    case 'type': {
      const p = push(values);
      return (a) => `${a}.type::text = ANY(${p}::text[])`;
    }
    case 'status': {
      const p = push(values);
      return (a) =>
        `(${a}.status::text = ANY(${p}::text[]) OR ${runtimeStateSql(a)} = ANY(${p}::text[]))`;
    }
    case 'project': {
      // Por nombre (sin mayúsculas ni tildes) o id; los proyectos efectivos ya incluyen los heredados.
      const p = push(lower);
      return (a) =>
        `${a}.effective_projects && ARRAY(SELECT pr.id FROM projects pr
                                            WHERE ${foldSql('pr.name')} = ANY(${p}::text[]) OR pr.id::text = ANY(${p}::text[]))`;
    }
    case 'ip': {
      const conds = values.flatMap((v) => {
        const m = ipMatcher(v);
        if (!m) return [];
        if (m.kind === 'exact') return [`lower(v) = ${push(m.value)}`];
        if (m.kind === 'prefix')
          return [`lower(v) LIKE ${push(likeLiteral(m.value))} || '%'`];
        return [
          `CASE WHEN v ~ ${IPV4_SQL} THEN v::inet <<= ${push(m.value)}::inet ELSE false END`,
        ];
      });
      if (!conds.length) return null;
      return (a) =>
        `EXISTS (SELECT 1 FROM (${ipsSql(a)}) x WHERE ${conds.join(' OR ')})`;
    }
    default:
      return null;
  }
}
