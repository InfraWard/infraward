import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, NatForward as NatForwardEntity } from '@infraward/domain';
import {
  SERVICE_PIN_TARGET_TYPES,
  type AssetSummary,
  type DomainServicePaths,
  type HopConfidence,
  type NatForward,
  type NatForwardInput,
  type ServedDomains,
  type ServiceCutReason,
  type ServiceHop,
  type ServicePathStatus,
  type ServicePathView,
} from '@infraward/shared-types';
import { DataSource, In, QueryFailedError, type EntityManager } from 'typeorm';
import { toAssetSummary } from '../assets/assets.mapper.js';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { JobsService } from '../jobs/jobs.service.js';

/** Lo que se espera al recálculo de los caminos tras un cambio hecho a mano. */
const RELINK_TIMEOUT_MS = 10_000;
const PIN_TARGETS = new Set<string>(SERVICE_PIN_TARGET_TYPES);
const NAT_TARGETS = new Set(['server', 'vm', 'lxc', 'container']);

interface PathRow {
  record_id: string;
  record_name: string;
  status: ServicePathStatus;
  final_asset_id: string | null;
  hops: ServiceHop[];
  confidence: HopConfidence | null;
  cut_reason: ServiceCutReason | null;
  pinned_asset_id: string | null;
  pinned_by: string | null;
  pinned_at: Date | null;
  computed_at: Date | null;
}

/**
 * Qué servicio sirve cada dominio (QoL-5b, DESIGN §13): caminos que calcula el worker, destino
 * fijado a mano y reenvíos NAT. La API no resuelve nada: lee lo guardado y, tras un cambio a
 * mano, pide al worker que recalcule (`services.link`) y espera un poco a que termine.
 */
@Injectable()
export class ServicePathsService {
  private readonly logger = new Logger(ServicePathsService.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
    private readonly jobs: JobsService,
  ) {}

  /** Camino de un registro DNS (sin calcular: estado `none`). */
  async pathOf(recordId: string): Promise<ServicePathView> {
    const record = await this.asset(recordId);
    if (record.type !== 'dns_record')
      throw new BadRequestException('Solo los registros DNS tienen camino');
    const [view] = await this.views([recordId]);
    return view;
  }

  /** Caminos de los registros de un dominio. */
  async pathsOfDomain(domainId: string): Promise<DomainServicePaths> {
    const domain = await this.asset(domainId);
    if (domain.type !== 'domain')
      throw new BadRequestException('No es un dominio');
    const rows: { id: string }[] = await this.db.query(
      `SELECT a.id FROM asset_relations r JOIN assets a ON a.id = r.child_id
        WHERE r.parent_id = $1 AND r.type = 'contains' AND a.type = 'dns_record'
          AND a.status <> 'retired' AND a.facts->'dns'->>'type' IN ('A', 'AAAA', 'CNAME')
        ORDER BY a.name`,
      [domainId],
    );
    return { paths: await this.views(rows.map((r) => r.id)) };
  }

  /** Registros que sirve un asset (destino final) o cuyo camino pasa por él. */
  async servedBy(assetId: string): Promise<ServedDomains> {
    await this.asset(assetId);
    const rows: {
      record_id: string;
      record_name: string;
      record_type: AssetSummary['type'];
      record_status: AssetSummary['status'];
      status: ServicePathStatus;
      confidence: HopConfidence | null;
      final_id: string | null;
      final_name: string | null;
      final_type: AssetSummary['type'] | null;
      final_status: AssetSummary['status'] | null;
    }[] = await this.db.query(
      `SELECT p.record_id, r.name AS record_name, r.type AS record_type, r.status AS record_status,
              p.status, p.confidence, f.id AS final_id, f.name AS final_name,
              f.type AS final_type, f.status AS final_status
         FROM dns_service_paths p
         JOIN assets r ON r.id = p.record_id
         LEFT JOIN assets f ON f.id = p.final_asset_id
        WHERE r.status <> 'retired'
          AND (p.final_asset_id = $1 OR $1 = ANY(p.via_asset_ids))
        ORDER BY (p.final_asset_id = $1) DESC, r.name
        LIMIT 500`,
      [assetId],
    );
    return {
      records: rows.map((r) => ({
        record: {
          id: r.record_id,
          name: r.record_name,
          type: r.record_type,
          status: r.record_status,
        },
        role: r.final_id === assetId ? 'final' : 'via',
        status: r.status,
        confidence: r.confidence,
        final: r.final_id
          ? {
              id: r.final_id,
              name: r.final_name!,
              type: r.final_type!,
              status: r.final_status!,
            }
          : null,
      })),
    };
  }

  /** Fija a mano el destino de un registro (gana al calculado). */
  async pin(
    recordId: string,
    targetId: string,
    actor: AuditActor,
  ): Promise<ServicePathView> {
    await this.db.transaction(async (m) => {
      const record = await this.asset(recordId, m);
      if (record.type !== 'dns_record')
        throw new BadRequestException('Solo los registros DNS tienen camino');
      const target = await m.findOne(Asset, {
        where: { id: targetId },
        select: { id: true, name: true, type: true, status: true },
      });
      if (!target) throw new NotFoundException('El destino no existe');
      if (!PIN_TARGETS.has(target.type) || target.status === 'retired')
        throw new BadRequestException(
          'El destino tiene que ser un servidor, VM, CT, contenedor o base de datos no retirado',
        );
      await m.query(
        `INSERT INTO dns_service_paths
           (record_id, status, final_asset_id, via_asset_ids, pinned_asset_id, pinned_by, pinned_at)
         VALUES ($1, 'manual', $2, ARRAY[$2]::uuid[], $2, $3, now())
         ON CONFLICT (record_id) DO UPDATE SET
           status = 'manual', final_asset_id = $2, pinned_asset_id = $2, pinned_by = $3,
           pinned_at = now(),
           via_asset_ids = (SELECT array_agg(DISTINCT u) FROM unnest(dns_service_paths.via_asset_ids || ARRAY[$2]::uuid[]) u)`,
        [recordId, targetId, actor.actorEmail],
      );
      await this.audit.record(actor, 'service.path_pinned', {
        target: { type: record.type, id: record.id, label: record.name },
        details: { asset: target.name, assetId: target.id },
        manager: m,
      });
    });
    await this.relink('pin');
    return this.pathOf(recordId);
  }

  async unpin(recordId: string, actor: AuditActor): Promise<ServicePathView> {
    await this.db.transaction(async (m) => {
      const record = await this.asset(recordId, m);
      // El estado y el destino los rehace el recálculo (con el camino calculado).
      const [[row]]: [{ record_id: string }[], number] = await m.query(
        `UPDATE dns_service_paths SET pinned_asset_id = NULL, pinned_by = NULL,
                pinned_at = NULL, status = 'partial', final_asset_id = NULL
          WHERE record_id = $1 AND pinned_asset_id IS NOT NULL
         RETURNING record_id`,
        [recordId],
      );
      if (!row) throw new ConflictException('El registro no tiene destino fijado');
      await this.audit.record(actor, 'service.path_unpinned', {
        target: { type: record.type, id: record.id, label: record.name },
        manager: m,
      });
    });
    await this.relink('unpin');
    return this.pathOf(recordId);
  }

  // --- Reenvíos NAT ---

  async natForwards(): Promise<NatForward[]> {
    const rows = await this.db.getRepository(NatForwardEntity).find({
      relations: { targetAsset: true },
      order: { publicIp: 'ASC', publicPort: 'ASC' },
    });
    return rows.map(toNatForward);
  }

  async createNat(input: NatForwardInput, actor: AuditActor): Promise<NatForward> {
    const id = await this.db.transaction(async (m) => {
      const target = await this.natTarget(input.targetAssetId, m);
      const saved = await this.saveNat(m, () =>
        m.save(NatForwardEntity, {
          publicIp: input.publicIp,
          publicPort: input.publicPort,
          proto: input.proto ?? 'tcp',
          targetAssetId: target.id,
          targetPort: input.targetPort,
          description: input.description?.trim() || null,
          createdBy: actor.actorEmail,
        }),
      );
      await this.audit.record(actor, 'settings.nat_created', {
        target: { type: 'settings', label: 'Reenvíos NAT' },
        details: natDetails(input, target.name),
        manager: m,
      });
      return saved.id;
    });
    await this.relink('nat');
    return this.nat(id);
  }

  async updateNat(
    id: string,
    input: NatForwardInput,
    actor: AuditActor,
  ): Promise<NatForward> {
    await this.db.transaction(async (m) => {
      const existing = await m.findOne(NatForwardEntity, { where: { id } });
      if (!existing) throw new NotFoundException('Reenvío no encontrado');
      const target = await this.natTarget(input.targetAssetId, m);
      await this.saveNat(m, () =>
        m.update(NatForwardEntity, id, {
          publicIp: input.publicIp,
          publicPort: input.publicPort,
          proto: input.proto ?? 'tcp',
          targetAssetId: target.id,
          targetPort: input.targetPort,
          description: input.description?.trim() || null,
        }),
      );
      await this.audit.record(actor, 'settings.nat_updated', {
        target: { type: 'settings', label: 'Reenvíos NAT' },
        details: natDetails(input, target.name),
        manager: m,
      });
    });
    await this.relink('nat');
    return this.nat(id);
  }

  async deleteNat(id: string, actor: AuditActor): Promise<void> {
    await this.db.transaction(async (m) => {
      const existing = await m.findOne(NatForwardEntity, {
        where: { id },
        relations: { targetAsset: true },
      });
      if (!existing) throw new NotFoundException('Reenvío no encontrado');
      await m.delete(NatForwardEntity, id);
      await this.audit.record(actor, 'settings.nat_deleted', {
        target: { type: 'settings', label: 'Reenvíos NAT' },
        details: natDetails(existing, existing.targetAsset?.name ?? existing.targetAssetId),
        manager: m,
      });
    });
    await this.relink('nat');
  }

  // --- Interno ---

  private async nat(id: string): Promise<NatForward> {
    const row = await this.db.getRepository(NatForwardEntity).findOne({
      where: { id },
      relations: { targetAsset: true },
    });
    if (!row) throw new NotFoundException('Reenvío no encontrado');
    return toNatForward(row);
  }

  private async natTarget(id: string, m: EntityManager): Promise<Asset> {
    const target = await m.findOne(Asset, {
      where: { id },
      select: { id: true, name: true, type: true, status: true },
    });
    if (!target) throw new NotFoundException('El destino no existe');
    if (!NAT_TARGETS.has(target.type) || target.status === 'retired')
      throw new BadRequestException(
        'El destino tiene que ser un servidor, VM, CT o contenedor no retirado',
      );
    return target;
  }

  /** Guarda un reenvío; si ya hay uno con esa IP, puerto y protocolo, 409. */
  private async saveNat<T>(_m: EntityManager, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      if (
        error instanceof QueryFailedError &&
        (error as QueryFailedError & { code?: string }).code === '23505'
      )
        throw new ConflictException('Ya hay un reenvío para esa IP, puerto y protocolo');
      throw error;
    }
  }

  private async asset(
    id: string,
    m: EntityManager = this.db.manager,
  ): Promise<Asset> {
    const asset = await m.findOne(Asset, {
      where: { id },
      select: { id: true, name: true, type: true, status: true },
    });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }

  /** Recalcula los caminos en el worker y espera un poco (si tarda, se verá en la siguiente). */
  private async relink(reason: string): Promise<void> {
    const done = await this.jobs
      .runQuick('services.link', { reason }, {
        idPrefix: 'services-link-',
        timeoutMs: RELINK_TIMEOUT_MS,
      })
      .catch(() => null);
    if (!done)
      this.logger.warn(`El recálculo de los caminos (${reason}) no terminó a tiempo`);
  }

  private async views(recordIds: string[]): Promise<ServicePathView[]> {
    if (!recordIds.length) return [];
    const rows: PathRow[] = await this.db.query(
      `SELECT a.id AS record_id, COALESCE(a.facts->'dns'->>'name', a.name) AS record_name,
              COALESCE(p.status, 'none') AS status, p.final_asset_id,
              COALESCE(p.hops, '[]'::jsonb) AS hops, p.confidence, p.cut_reason,
              p.pinned_asset_id, p.pinned_by, p.pinned_at, p.computed_at
         FROM assets a LEFT JOIN dns_service_paths p ON p.record_id = a.id
        WHERE a.id = ANY($1::uuid[])`,
      [recordIds],
    );
    const ids = new Set<string>();
    for (const r of rows) {
      if (r.final_asset_id) ids.add(r.final_asset_id);
      if (r.pinned_asset_id) ids.add(r.pinned_asset_id);
      for (const h of r.hops) if (h.assetId) ids.add(h.assetId);
    }
    const assets = new Map(
      ids.size
        ? (
            await this.db.getRepository(Asset).find({
              where: { id: In([...ids]) },
              select: { id: true, name: true, type: true, status: true },
            })
          ).map((a) => [a.id, toAssetSummary(a)])
        : [],
    );
    const byId = new Map(rows.map((r) => [r.record_id, r]));
    return recordIds
      .map((id) => byId.get(id))
      .filter((r): r is PathRow => !!r)
      .map((r) => ({
        recordId: r.record_id,
        record: r.record_name,
        status: r.status,
        confidence: r.confidence,
        cutReason: r.status === 'manual' ? null : r.cut_reason,
        final: r.final_asset_id ? (assets.get(r.final_asset_id) ?? null) : null,
        hops: r.hops.map((h) => ({
          ...h,
          asset: h.assetId ? (assets.get(h.assetId) ?? null) : null,
        })),
        pinned:
          r.pinned_asset_id && assets.get(r.pinned_asset_id)
            ? {
                asset: assets.get(r.pinned_asset_id)!,
                by: r.pinned_by,
                at: (r.pinned_at ?? new Date()).toISOString(),
              }
            : null,
        computedAt: r.computed_at?.toISOString() ?? null,
      }));
  }
}

function toNatForward(n: NatForwardEntity): NatForward {
  return {
    id: n.id,
    publicIp: n.publicIp,
    publicPort: n.publicPort,
    proto: n.proto,
    target: n.targetAsset
      ? toAssetSummary(n.targetAsset)
      : { id: n.targetAssetId, name: n.targetAssetId, type: 'server', status: 'active' },
    targetPort: n.targetPort,
    description: n.description,
    createdAt: n.createdAt.toISOString(),
    updatedAt: n.updatedAt.toISOString(),
  };
}

function natDetails(
  n: Pick<NatForwardInput, 'publicIp' | 'publicPort' | 'targetPort'> & { proto?: string },
  target: string,
): Record<string, string> {
  return {
    public: `${n.publicIp}:${n.publicPort}/${n.proto ?? 'tcp'}`,
    target: `${target}:${n.targetPort}`,
  };
}
