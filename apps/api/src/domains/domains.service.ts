import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  AppSetting,
  Asset,
  EXPIRY_WARNING_DAYS_KEY,
  expiryWarningDays,
  normalizeExpiryDays,
  recomputePolicies,
} from '@infraward/domain';
import {
  formatSecretRef,
  parseSecretRef,
  SecretsService,
} from '@infraward/secrets';
import {
  CONNECTOR_TOKEN_FIELD,
  domainsSyncDeduplicationId,
  JOB_NAMES,
  type AcceptDnsTargetResponse,
  type AssetDomainRecord,
  type AssetDomains,
  type Connector,
  type ConnectorFacts,
  type ConnectorTestResponse,
  type CreateConnectorRequest,
  type DeleteAssetResponse,
  type DnsCheckLevel,
  type DnsCheckReason,
  type DnsRecordCheck,
  type DnsRecordFacts,
  type EnqueueJobResponse,
  type ExpiryWarningSettings,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { toAssetSummary } from '../assets/assets.mapper.js';
import { AssetsService } from '../assets/assets.service.js';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { writableSecretsProvider } from '../secrets/writable-provider.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { JobsService } from '../jobs/jobs.service.js';

/** Lo que se espera la prueba del token en el worker antes de responder. */
const TEST_TIMEOUT_MS = 20_000;
/** Saltos de CNAME que se siguen hacia atrás en «dominios que le apuntan». */
const MAX_CNAME_HOPS = 5;

interface CheckRow {
  same_target?: number;
  level: DnsCheckLevel | null;
  reason: DnsCheckReason;
  target: string;
  ambiguous: boolean;
  takeover_service: string | null;
  checked_at: Date;
  value_hash: string;
  accepted_value_hash: string | null;
  accepted_by: string | null;
  accepted_at: Date | null;
}

/**
 * Conectores de dominios, dominios de un asset, comprobaciones de registros y umbrales de
 * caducidad (DESIGN §13). La API nunca habla con el proveedor: guarda el token en el proveedor
 * de secretos y encola el trabajo al worker (la prueba la espera, con `runQuick`).
 */
@Injectable()
export class DomainsService {
  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly jobs: JobsService,
    private readonly audit: AuditService,
    private readonly assets: AssetsService,
  ) {}

  // --- Conectores ---

  async list(): Promise<Connector[]> {
    const rows: (Asset & {
      domains: number;
      records: number;
    })[] = await this.db.query(
      `SELECT a.id, a.name, a.status, a.facts, a.credentials, a.created_at AS "createdAt",
              (SELECT count(*)::int FROM asset_relations r JOIN assets d ON d.id = r.child_id
                WHERE r.parent_id = a.id AND r.type = 'contains' AND d.type = 'domain'
                  AND d.status <> 'retired') AS domains,
              (SELECT count(*)::int FROM asset_relations r JOIN assets d ON d.id = r.child_id
                 JOIN asset_relations r2 ON r2.parent_id = d.id AND r2.type = 'contains'
                 JOIN assets x ON x.id = r2.child_id
                WHERE r.parent_id = a.id AND r.type = 'contains' AND d.type = 'domain'
                  AND x.type = 'dns_record' AND x.status <> 'retired') AS records
         FROM assets a
        WHERE a.type = 'dns_provider' AND a.status <> 'retired'
        ORDER BY a.name`,
    );
    return rows.map((r) => toConnector(r, r.domains, r.records));
  }

  async create(
    body: CreateConnectorRequest,
    actor: AuditActor,
  ): Promise<Connector> {
    const id = randomUUID();
    const base = await this.secrets.store(
      formatSecretRef({
        provider: this.writableProvider(),
        path: `connectors/${id}/${body.kind}`,
      }),
      { [CONNECTOR_TOKEN_FIELD]: body.apiToken },
    );
    try {
      await this.db.transaction(async (m) => {
        const facts: ConnectorFacts = {
          kind: body.kind,
          verify: null,
          lastSync: null,
        };
        await m.save(
          m.create(Asset, {
            id,
            type: 'dns_provider',
            discoveredName: body.name,
            status: 'active',
            naturalKey: null,
            facts: { connector: facts },
            credentials: { apiToken: `${base}#${CONNECTOR_TOKEN_FIELD}` },
          }),
        );
        await recomputePolicies(m);
        await this.audit.record(actor, 'connector.created', {
          target: { type: 'dns_provider', id, label: body.name },
          details: { kind: body.kind, storedIn: parseSecretRef(base).provider },
          manager: m,
        });
      });
    } catch (error) {
      await this.secrets.remove(base).catch(() => undefined);
      throw error;
    }
    // Se prueba al momento; si vale, se sincroniza.
    const { verify } = await this.test(id, actor);
    if (verify?.ok) await this.sync(id, actor);
    return this.get(id);
  }

  async get(id: string): Promise<Connector> {
    const found = (await this.list()).find((c) => c.id === id);
    if (!found) throw new NotFoundException('Conector no encontrado');
    return found;
  }

  async replaceToken(
    id: string,
    apiToken: string,
    actor: AuditActor,
  ): Promise<Connector> {
    const asset = await this.connector(id);
    const current = asset.credentials.apiToken;
    const kind = connectorKind(asset);
    let base: string;
    // Misma ruta si su proveedor admite escritura; si no, una nueva en el que sí.
    const sameProvider = current ? parseSecretRef(current).provider : null;
    if (current && sameProvider && this.secrets.provider(sameProvider).set) {
      const { provider, path } = parseSecretRef(current);
      base = await this.secrets.store(formatSecretRef({ provider, path }), {
        [CONNECTOR_TOKEN_FIELD]: apiToken,
      });
    } else {
      base = await this.secrets.store(
        formatSecretRef({
          provider: this.writableProvider(),
          path: `connectors/${id}/${kind}`,
        }),
        { [CONNECTOR_TOKEN_FIELD]: apiToken },
      );
    }
    await this.db.transaction(async (m) => {
      await m.update(
        Asset,
        { id },
        { credentials: { apiToken: `${base}#${CONNECTOR_TOKEN_FIELD}` } },
      );
      await this.audit.record(actor, 'connector.token_replaced', {
        target: { type: 'dns_provider', id, label: asset.name },
        details: { replaced: true },
        manager: m,
      });
    });
    await this.test(id, actor);
    return this.get(id);
  }

  async test(id: string, actor: AuditActor): Promise<ConnectorTestResponse> {
    const asset = await this.connector(id);
    const verify = await this.jobs.runQuick(
      JOB_NAMES.domainsTest,
      { assetId: id },
      { idPrefix: 'domains-test-', timeoutMs: TEST_TIMEOUT_MS },
    );
    await this.audit.tryRecord(actor, 'connector.tested', {
      target: { type: 'dns_provider', id, label: asset.name },
      outcome: verify?.ok ? 'success' : 'failure',
      details: {
        zones: verify?.zones ?? 0,
        error: verify ? verify.error : 'el worker no respondió a tiempo',
      },
    });
    return { verify };
  }

  async sync(id: string, actor: AuditActor): Promise<EnqueueJobResponse> {
    const asset = await this.connector(id);
    if (!asset.credentials.apiToken)
      throw new ConflictException('El conector no tiene token');
    const job = await this.jobs.enqueue(
      JOB_NAMES.domainsSync,
      { assetId: id, trigger: 'manual' },
      { deduplicationId: domainsSyncDeduplicationId(id) },
    );
    await this.audit.tryRecord(actor, 'connector.sync_requested', {
      target: { type: 'dns_provider', id, label: asset.name },
    });
    return job;
  }

  /** Baja del conector y de lo que cuelga de él; el token se borra del proveedor de secretos. */
  async remove(id: string, actor: AuditActor): Promise<DeleteAssetResponse> {
    const asset = await this.connector(id);
    const response = await this.assets.remove(id, false, actor);
    await this.audit.tryRecord(actor, 'connector.deleted', {
      target: { type: 'dns_provider', id, label: asset.name },
      details: {
        affected: response.affectedIds.length,
        revoked: response.revocations?.every((r) => r.secretRemoved) ?? true,
      },
    });
    return response;
  }

  // --- Dominios de un asset ---

  /** Registros que llegan al asset: directos (A/AAAA) y por cadenas de CNAME. */
  async domainsOf(id: string): Promise<AssetDomains> {
    await this.exists(id);
    const rows: {
      record_id: string;
      hops: number;
      via: string[];
    }[] = await this.db.query(
      `WITH RECURSIVE chain(record_id, hops, via) AS (
           SELECT r.parent_id, 1, ARRAY[]::uuid[]
             FROM asset_relations r WHERE r.type = 'resolves_to' AND r.child_id = $1
         UNION ALL
           SELECT r.parent_id, c.hops + 1, c.via || c.record_id
             FROM chain c
             JOIN asset_relations r ON r.type = 'resolves_to' AND r.child_id = c.record_id
            WHERE c.hops < $2 AND r.parent_id <> ALL(c.via || c.record_id))
       SELECT DISTINCT ON (record_id) record_id, hops, via
         FROM chain ORDER BY record_id, hops`,
      [id, MAX_CNAME_HOPS],
    );
    if (rows.length === 0) return { records: [] };
    const ids = [...new Set(rows.flatMap((r) => [r.record_id, ...r.via]))];
    const assets: (Pick<Asset, 'id' | 'name' | 'type' | 'status'> & {
      dns: DnsRecordFacts | null;
      domain_id: string | null;
      domain_name: string | null;
      domain_status: Asset['status'] | null;
      cert_id: string | null;
      cert_name: string | null;
      cert_not_after: string | null;
    })[] = await this.db.query(
      `SELECT a.id, a.name, a.type, a.status, a.facts->'dns' AS dns,
              d.id AS domain_id, d.name AS domain_name, d.status AS domain_status,
              c.id AS cert_id, c.name AS cert_name,
              c.facts->'certificate'->>'notAfter' AS cert_not_after
         FROM assets a
         LEFT JOIN asset_relations p ON p.child_id = a.id AND p.type = 'contains'
         LEFT JOIN assets d ON d.id = p.parent_id AND d.type = 'domain'
         LEFT JOIN LATERAL (
           SELECT x.id, x.name, x.facts FROM asset_relations s JOIN assets x ON x.id = s.child_id
            WHERE s.parent_id = a.id AND s.type = 'secured_by' AND x.status <> 'retired'
            LIMIT 1) c ON true
        WHERE a.id = ANY($1::uuid[])`,
      [ids],
    );
    const byId = new Map(assets.map((a) => [a.id, a]));
    const records: AssetDomainRecord[] = [];
    for (const r of rows) {
      const a = byId.get(r.record_id);
      if (!a || a.type !== 'dns_record' || a.status === 'retired' || !a.dns) continue;
      records.push({
        record: toAssetSummary(a),
        domain: a.domain_id
          ? toAssetSummary({
              id: a.domain_id,
              name: a.domain_name ?? '',
              type: 'domain',
              status: a.domain_status ?? 'active',
            })
          : null,
        dns: {
          name: a.dns.name,
          type: a.dns.type,
          content: a.dns.content,
          proxied: a.dns.proxied === true,
        },
        hops: r.hops,
        via: [...r.via]
          .reverse()
          .map((v) => byId.get(v))
          .filter((v): v is NonNullable<typeof v> => !!v)
          .map(toAssetSummary),
        certificate: a.cert_id
          ? { id: a.cert_id, name: a.cert_name ?? '', notAfter: a.cert_not_after }
          : null,
      });
    }
    records.sort(
      (x, y) => x.hops - y.hops || x.dns.name.localeCompare(y.dns.name),
    );
    return { records };
  }

  // --- Comprobaciones de registros ---

  async check(id: string): Promise<DnsRecordCheck | null> {
    await this.exists(id);
    const [row]: CheckRow[] = await this.db.query(
      `SELECT c.*, ${SAME_TARGET_SQL} AS same_target
         FROM dns_record_checks c WHERE c.asset_id = $1`,
      [id],
    );
    return row ? toCheck(row) : null;
  }

  /**
   * Marca como esperados todos los avisos **informativos** con ese destino (p. ej. la IP pública
   * de casa, a la que apuntan muchos registros). Los de prioridad alta, nunca en bloque.
   */
  async acceptTarget(
    target: string,
    actor: AuditActor,
  ): Promise<AcceptDnsTargetResponse> {
    return this.db.transaction(async (m) => {
      const [rows]: [{ asset_id: string }[], number] = await m.query(
        `UPDATE dns_record_checks c SET accepted_value_hash = c.value_hash,
                accepted_by = $2, accepted_at = now()
           FROM assets a
          WHERE a.id = c.asset_id AND a.status <> 'retired' AND c.level = 'info'
            AND c.target = $1 AND c.accepted_value_hash IS DISTINCT FROM c.value_hash
         RETURNING c.asset_id`,
        [target, actor.actorEmail],
      );
      if (rows.length === 0)
        throw new ConflictException('No hay avisos informativos con ese destino');
      await this.audit.record(actor, 'dns.check_accepted', {
        target: { type: 'dns_target', label: target },
        details: { level: 'info', bulk: true, count: rows.length },
        manager: m,
      });
      return { accepted: rows.length };
    });
  }

  /** «Marcar como esperado»: silencia el aviso mientras el registro no cambie de valor. */
  async accept(id: string, actor: AuditActor): Promise<DnsRecordCheck> {
    return this.setAcceptance(id, actor, true);
  }

  async reopen(id: string, actor: AuditActor): Promise<DnsRecordCheck> {
    return this.setAcceptance(id, actor, false);
  }

  private async setAcceptance(
    id: string,
    actor: AuditActor,
    accept: boolean,
  ): Promise<DnsRecordCheck> {
    return this.db.transaction(async (m) => {
      const asset = await m.findOne(Asset, {
        where: { id },
        select: { id: true, name: true, type: true },
      });
      if (!asset) throw new NotFoundException('Asset no encontrado');
      const [[row]]: [CheckRow[], number] = await m.query(
        accept
          ? `UPDATE dns_record_checks SET accepted_value_hash = value_hash,
                    accepted_by = $2, accepted_at = now()
              WHERE asset_id = $1 AND level IS NOT NULL
             RETURNING *, (SELECT 0) AS same_target`
          : `UPDATE dns_record_checks SET accepted_value_hash = NULL,
                    accepted_by = NULL, accepted_at = NULL
              WHERE asset_id = $1 RETURNING *, (SELECT 0) AS same_target`,
        accept ? [id, actor.actorEmail] : [id],
      );
      if (!row)
        throw new ConflictException(
          accept ? 'El registro no tiene ningún aviso' : 'El registro no tiene comprobación',
        );
      await this.audit.record(
        actor,
        accept ? 'dns.check_accepted' : 'dns.check_reopened',
        {
          target: { type: asset.type, id, label: asset.name },
          details: { level: row.level, reason: row.reason, target: row.target },
          manager: m,
        },
      );
      // Con el número de avisos del mismo destino ya al día.
      const [fresh]: CheckRow[] = await m.query(
        `SELECT c.*, ${SAME_TARGET_SQL} AS same_target
           FROM dns_record_checks c WHERE c.asset_id = $1`,
        [id],
      );
      return toCheck(fresh ?? row);
    });
  }

  // --- Umbrales de caducidad ---

  async expiryWarnings(): Promise<ExpiryWarningSettings> {
    return { days: await expiryWarningDays(this.db.manager) };
  }

  async setExpiryWarnings(
    days: number[],
    actor: AuditActor,
  ): Promise<ExpiryWarningSettings> {
    if (new Set(days).size !== days.length)
      throw new BadRequestException('Los umbrales no se pueden repetir');
    const next = normalizeExpiryDays(days);
    return this.db.transaction(async (m) => {
      const before = await expiryWarningDays(m);
      await m.upsert(
        AppSetting,
        { key: EXPIRY_WARNING_DAYS_KEY, value: next },
        ['key'],
      );
      await this.audit.record(actor, 'settings.expiry_changed', {
        target: { type: 'settings', label: 'Avisos de caducidad' },
        details: { from: before.map(String), to: next.map(String) },
        manager: m,
      });
      return { days: next };
    });
  }

  // --- Ayudantes ---

  private async connector(id: string): Promise<Asset> {
    const asset = await this.db.getRepository(Asset).findOneBy({ id });
    if (!asset || asset.type !== 'dns_provider')
      throw new NotFoundException('Conector no encontrado');
    if (asset.status === 'retired')
      throw new ConflictException('El conector está dado de baja');
    return asset;
  }

  private async exists(id: string): Promise<void> {
    const found = await this.db.getRepository(Asset).exists({ where: { id } });
    if (!found) throw new NotFoundException('Asset no encontrado');
  }

  private writableProvider(): string {
    return writableSecretsProvider(this.secrets, this.config);
  }
}

function connectorKind(asset: Asset): ConnectorFacts['kind'] {
  return (asset.facts?.connector as ConnectorFacts | undefined)?.kind ?? 'cloudflare';
}

function toConnector(
  a: Pick<Asset, 'id' | 'name' | 'status' | 'facts' | 'credentials' | 'createdAt'>,
  domains: number,
  records: number,
): Connector {
  const facts = (a.facts?.connector ?? {}) as Partial<ConnectorFacts>;
  const ref = a.credentials?.apiToken;
  let secretProvider: string | null;
  try {
    secretProvider = ref ? parseSecretRef(ref).provider : null;
  } catch {
    secretProvider = null;
  }
  return {
    id: a.id,
    name: a.name,
    kind: facts.kind ?? 'cloudflare',
    status: a.status,
    secretProvider,
    hasToken: !!ref,
    verify: facts.verify ?? null,
    lastSync: facts.lastSync ?? null,
    domains,
    records,
    createdAt: new Date(a.createdAt).toISOString(),
  };
}

/** Avisos informativos sin aceptar, de registros no retirados, con el destino de `c`. */
const SAME_TARGET_SQL = `(SELECT count(*)::int FROM dns_record_checks o
    JOIN assets oa ON oa.id = o.asset_id
   WHERE o.target = c.target AND o.level = 'info' AND oa.status <> 'retired'
     AND o.accepted_value_hash IS DISTINCT FROM o.value_hash)`;

function toCheck(row: CheckRow): DnsRecordCheck {
  const accepted =
    row.accepted_value_hash !== null && row.accepted_value_hash === row.value_hash;
  return {
    level: row.level,
    reason: row.reason,
    target: row.target,
    ambiguous: row.ambiguous,
    takeoverService: row.takeover_service,
    sameTarget: row.same_target ?? 0,
    checkedAt: new Date(row.checked_at).toISOString(),
    accepted: accepted
      ? {
          at: new Date(row.accepted_at!).toISOString(),
          by: row.accepted_by,
        }
      : null,
  };
}
