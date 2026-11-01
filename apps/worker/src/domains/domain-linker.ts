import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  assetIps,
  IP_TARGET_TYPES,
  linkDnsRecords,
  type CnameLookup,
  type LinkRecord,
  type LinkTarget,
} from '@infraward/connectors';
import { dnsWarningSql, Notification } from '@infraward/domain';
import {
  NOTIFICATION_MAX_ITEMS,
  type AssetStatus,
  type AssetType,
  type DnsCheckReason,
  type DnsRecordFacts,
} from '@infraward/shared-types';
import { createHash } from 'node:crypto';
import { DataSource, type EntityManager } from 'typeorm';

/** Candado de transacción del enlazado (sincronizaciones y tick no se pisan). */
export const DNS_LINK_LOCK = 0x1d_45_00_01;

const LINKABLE = new Set(['A', 'AAAA', 'CNAME']);

export interface LinkSummary {
  /** Relaciones `resolves_to` tras enlazar. */
  links: number;
  /** Registros con aviso alto sin marcar como esperados. */
  dangling: number;
  /** Avisos altos nuevos notificados en esta pasada. */
  notified: number;
}

/** Hash del valor de un registro: «esperado» vale mientras no cambie. */
export function dnsValueHash(type: string, content: string): string {
  return createHash('sha256').update(`${type}|${content}`).digest('hex');
}

/**
 * Enlaza los registros DNS del inventario con los assets a los que apuntan y decide cuáles son
 * colgantes (DESIGN §13). Se ejecuta tras cada sincronización de un conector (con los CNAME
 * externos recién resueltos) y en cada tick de la reconciliación (sin DNS: con el último
 * resultado de cada CNAME), así un servidor que cambia de IP o se retira se refleja sin esperar
 * a la siguiente sincronización.
 */
@Injectable()
export class DomainLinker {
  private readonly logger = new Logger(DomainLinker.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  /** `cnames`: resultados nuevos de los destinos externos (los demás, los de la vez anterior). */
  link(cnames: ReadonlyMap<string, CnameLookup> = new Map()): Promise<LinkSummary> {
    return this.db.transaction(async (m) => {
      await m.query('SELECT pg_advisory_xact_lock($1)', [DNS_LINK_LOCK]);
      return this.apply(m, cnames);
    });
  }

  private async apply(
    m: EntityManager,
    fresh: ReadonlyMap<string, CnameLookup>,
  ): Promise<LinkSummary> {
    const recordRows: { id: string; status: AssetStatus; dns: DnsRecordFacts | null }[] =
      await m.query(
        `SELECT id, status, facts->'dns' AS dns FROM assets
          WHERE type = 'dns_record' AND status <> 'retired'`,
      );
    const names = new Map<string, string[]>();
    const records: LinkRecord[] = [];
    for (const r of recordRows) {
      if (!r.dns || typeof r.dns.name !== 'string') continue;
      if (r.status === 'active') {
        const list = names.get(r.dns.name) ?? [];
        list.push(r.id);
        names.set(r.dns.name, list);
      }
      if (LINKABLE.has(r.dns.type) && typeof r.dns.content === 'string')
        records.push({
          id: r.id,
          type: r.dns.type as LinkRecord['type'],
          name: r.dns.name,
          content: r.dns.content,
        });
    }

    const zoneRows: { id: string; name: string | null }[] = await m.query(
      `SELECT id, facts->'zone'->>'name' AS name FROM assets
        WHERE type = 'domain' AND status <> 'retired' AND facts ? 'zone'`,
    );
    const zones = new Map(
      zoneRows.filter((z) => z.name).map((z) => [z.name!, z.id]),
    );

    // Solo las rutas que hacen falta (los facts de un servidor llevan miles de paquetes).
    const hostRows: {
      id: string;
      type: AssetType;
      status: AssetStatus;
      network: unknown;
      proxmox_interfaces: unknown;
      proxmox_config: unknown;
      connection: unknown;
    }[] = await m.query(
      `SELECT id, type, status, facts->'network' AS network,
              facts->'proxmox'->'interfaces' AS proxmox_interfaces,
              facts->'proxmox'->'config' AS proxmox_config, connection
         FROM assets WHERE type::text = ANY($1::text[])`,
      [IP_TARGET_TYPES],
    );
    const ips = new Map<string, LinkTarget[]>();
    for (const h of hostRows) {
      const facts = {
        network: h.network,
        proxmox: { interfaces: h.proxmox_interfaces, config: h.proxmox_config },
      };
      for (const ip of assetIps(facts, h.connection)) {
        const list = ips.get(ip) ?? [];
        list.push({ id: h.id, type: h.type, status: h.status });
        ips.set(ip, list);
      }
    }

    // CNAME externos: lo recién resuelto y, si no, lo de la última vez.
    const previous: { target: string; reason: DnsCheckReason }[] = await m.query(
      `SELECT target, reason FROM dns_record_checks
        WHERE reason IN ('cname_nxdomain', 'cname_external')`,
    );
    const cnames = new Map<string, CnameLookup>(
      previous.map((p) => [p.target, p.reason === 'cname_nxdomain' ? 'nxdomain' : 'exists']),
    );
    for (const [k, v] of fresh) cnames.set(k, v);

    const results = linkDnsRecords({ records, ips, zones, names, cnames });

    // Relaciones: solo se tocan las que cambian.
    const want = new Set(
      results.flatMap((r) => r.targets.map((t) => `${r.recordId}|${t}`)),
    );
    const have: { id: string; parent_id: string; child_id: string }[] = await m.query(
      `SELECT r.id, r.parent_id, r.child_id FROM asset_relations r
         JOIN assets a ON a.id = r.parent_id
        WHERE r.type = 'resolves_to' AND a.type = 'dns_record' AND a.status <> 'retired'`,
    );
    const haveKeys = new Set(have.map((h) => `${h.parent_id}|${h.child_id}`));
    const drop = have.filter((h) => !want.has(`${h.parent_id}|${h.child_id}`)).map((h) => h.id);
    if (drop.length)
      await m.query(`DELETE FROM asset_relations WHERE id = ANY($1::uuid[])`, [drop]);
    const add = [...want].filter((k) => !haveKeys.has(k)).map((k) => k.split('|'));
    if (add.length)
      await m.query(
        `INSERT INTO asset_relations (parent_id, child_id, type)
         SELECT f, t, 'resolves_to' FROM unnest($1::uuid[], $2::uuid[]) AS x(f, t)
         ON CONFLICT DO NOTHING`,
        [add.map((a) => a[0]), add.map((a) => a[1])],
      );

    // Comprobaciones.
    const byId = new Map(records.map((r) => [r.id, r]));
    if (results.length)
      await m.query(
        `INSERT INTO dns_record_checks
           (asset_id, level, reason, target, ambiguous, takeover_service, value_hash, checked_at)
         SELECT * , now() FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[],
                                     $5::boolean[], $6::text[], $7::text[])
         ON CONFLICT (asset_id) DO UPDATE SET
           level = EXCLUDED.level, reason = EXCLUDED.reason, target = EXCLUDED.target,
           ambiguous = EXCLUDED.ambiguous, takeover_service = EXCLUDED.takeover_service,
           value_hash = EXCLUDED.value_hash, checked_at = EXCLUDED.checked_at`,
        [
          results.map((r) => r.recordId),
          results.map((r) => r.level),
          results.map((r) => r.reason),
          results.map((r) => r.target),
          results.map((r) => r.ambiguous),
          results.map((r) => r.takeoverService),
          results.map((r) => {
            const rec = byId.get(r.recordId)!;
            return dnsValueHash(rec.type, rec.content);
          }),
        ],
      );
    // Registros que ya no son A/AAAA/CNAME (los retirados conservan la última).
    await m.query(
      `DELETE FROM dns_record_checks c USING assets a
        WHERE a.id = c.asset_id AND a.status <> 'retired' AND NOT (c.asset_id = ANY($1::uuid[]))`,
      [results.map((r) => r.recordId)],
    );

    // Avisos altos nuevos (sin aceptar ni notificar para este valor), de registros activos.
    const fresh_: { id: string; name: string; type: AssetType }[] = await m.query(
      `UPDATE dns_record_checks c SET notified_value_hash = c.value_hash
         FROM assets a
        WHERE a.id = c.asset_id AND a.status = 'active' AND c.level = 'high'
          AND ${dnsWarningSql('c')}
          AND c.notified_value_hash IS DISTINCT FROM c.value_hash
       RETURNING a.id, a.name, a.type`,
    ).then((r: [unknown[], number] | unknown[]) =>
      (Array.isArray(r[0]) ? r[0] : r) as { id: string; name: string; type: AssetType }[],
    );
    if (fresh_.length) {
      const names5 = fresh_.slice(0, 5).map((i) => i.name).join(', ');
      const more = fresh_.length > 5 ? ` y ${fresh_.length - 5} más` : '';
      await m.insert(Notification, {
        kind: 'dns_dangling',
        assetId: null,
        assetName: null,
        message: `${fresh_.length} ${fresh_.length === 1 ? 'registro DNS colgante' : 'registros DNS colgantes'} (posible subdomain takeover o destino retirado) — ${names5}${more}`,
        items: fresh_.slice(0, NOTIFICATION_MAX_ITEMS),
        total: fresh_.length,
      });
    }

    const [{ dangling }]: { dangling: number }[] = await m.query(
      `SELECT count(*)::int AS dangling FROM dns_record_checks c
         JOIN assets a ON a.id = c.asset_id
        WHERE a.status <> 'retired' AND c.level = 'high' AND ${dnsWarningSql('c')}`,
    );
    if (drop.length || add.length || fresh_.length)
      this.logger.log(
        `Registros DNS: ${add.length} enlaces nuevos, ${drop.length} quitados, ${fresh_.length} colgantes nuevos`,
      );
    return { links: want.size, dangling, notified: fresh_.length };
  }
}
