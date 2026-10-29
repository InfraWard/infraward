import type { AuditAction } from '@infraward/shared-types';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  Asset,
  AssetRelation,
  findAncestorRows,
  InventoryPolicy,
  Project,
  recomputePolicies,
} from '@infraward/domain';
import {
  INVENTORY_POLICY_FIELDS,
  INVENTORY_RULE_FIELDS,
  normalizeScanExclusions,
  JOB_NAMES,
  type AssetPolicy,
  type EnqueueJobResponse,
  type InventoryPolicyFields,
  type InventoryPolicyList,
  type InventoryPolicyRule,
} from '@infraward/shared-types';
import { DataSource, type EntityManager } from 'typeorm';
import { effectivePolicyOf } from '../assets/assets.mapper.js';
import { pgErrorCode, PG_UNIQUE_VIOLATION } from '../database/pg-errors.js';
import { JobsService } from '../jobs/jobs.service.js';
import type {
  CreateInventoryPolicyDto,
  InventoryPolicyFieldsDto,
  UpdateGlobalPolicyDto,
} from './inventory.dto.js';
import { namedPolicySources } from './policy-sources.js';

/**
 * Política de inventario (DESIGN §10): reglas global, por asset (se heredan hacia abajo), por
 * etiqueta y por proyecto, y la reconciliación manual. Cada cambio recalcula la política efectiva guardada en
 * los assets (`recomputePolicies`), que es lo que leen el worker y las consultas.
 */
@Injectable()
export class InventoryService implements OnApplicationBootstrap {
  private readonly logger = new Logger(InventoryService.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly jobs: JobsService,
    private readonly audit: AuditService,
  ) {}

  /** Tras las migraciones: la política efectiva al día (assets nuevos, versiones anteriores). */
  async onApplicationBootstrap(): Promise<void> {
    try {
      const changed = await this.db.transaction((m) => recomputePolicies(m));
      if (changed)
        this.logger.log(`Política efectiva recalculada en ${changed} assets`);
    } catch (error) {
      this.logger.warn(
        `No se pudo recalcular la política efectiva: ${(error as Error).name}`,
      );
    }
  }

  async list(): Promise<InventoryPolicyList> {
    const rules = await this.db.getRepository(InventoryPolicy).find({
      relations: { asset: true, project: true },
      order: { scope: 'ASC', tag: 'ASC', createdAt: 'ASC' },
    });
    const global = rules.find((r) => r.scope === 'global');
    if (!global) throw new NotFoundException('Falta la política global');
    return {
      global: toRule(global),
      rules: rules.filter((r) => r.scope !== 'global').map(toRule),
    };
  }

  async updateGlobal(
    dto: UpdateGlobalPolicyDto,
    actor?: AuditActor,
  ): Promise<InventoryPolicyRule> {
    return this.mutate(async (m) => {
      const global = await m.findOneBy(InventoryPolicy, { scope: 'global' });
      if (!global) throw new NotFoundException('Falta la política global');
      const before = fieldsOf(global);
      for (const field of INVENTORY_POLICY_FIELDS)
        if (dto[field] !== undefined)
          (global as unknown as Record<string, unknown>)[field] = dto[field];
      if (dto.scanExclusions !== undefined)
        global.scanExclusions = normalizeScanExclusions(dto.scanExclusions);
      const saved = await m.save(global);
      await this.auditPolicy(m, actor, 'policy.global_updated', saved, before);
      return toRule(saved);
    });
  }

  async create(
    dto: CreateInventoryPolicyDto,
    actor?: AuditActor,
  ): Promise<InventoryPolicyRule> {
    const fields = pickFields(dto);
    requireSomeField(fields);
    return this.mutate(async (m) => {
      if (dto.scope === 'asset') await this.findAsset(m, dto.assetId!);
      if (dto.scope === 'project') await this.findProject(m, dto.projectId!);
      const rule = await m.save(
        m.create(InventoryPolicy, {
          scope: dto.scope,
          assetId: dto.scope === 'asset' ? dto.assetId! : null,
          tag: dto.scope === 'tag' ? dto.tag! : null,
          projectId: dto.scope === 'project' ? dto.projectId! : null,
          reconcileIntervalMinutes: null,
          scanEnabled: null,
          scanPeriodic: null,
          scanExclusions: null,
          ...fields,
        }),
      );
      const created = await this.ruleById(m, rule.id);
      await this.auditPolicy(m, actor, 'policy.rule_created', rule, null, created);
      return created;
    });
  }

  async update(
    id: string,
    dto: InventoryPolicyFieldsDto,
    actor?: AuditActor,
  ): Promise<InventoryPolicyRule> {
    return this.mutate(async (m) => {
      const rule = await this.findRule(m, id);
      if (rule.scope === 'global')
        throw new BadRequestException(
          'La política global se cambia con PUT /inventory-policies/global',
        );
      const before = fieldsOf(rule);
      Object.assign(rule, pickFields(dto));
      requireSomeField(rule);
      await m.save(rule);
      const updated = await this.ruleById(m, id);
      await this.auditPolicy(m, actor, 'policy.rule_updated', rule, before, updated);
      return updated;
    });
  }

  async remove(id: string, actor?: AuditActor): Promise<void> {
    await this.mutate(async (m) => {
      const rule = await this.findRule(m, id);
      if (rule.scope === 'global')
        throw new ConflictException('La política global no se puede borrar');
      const removed = await this.ruleById(m, id);
      await m.delete(InventoryPolicy, { id });
      await this.auditPolicy(m, actor, 'policy.rule_deleted', rule, fieldsOf(rule), removed, true);
    });
  }

  /** Política efectiva de un asset con el origen de cada campo, su regla y su reconciliación. */
  async assetPolicy(assetId: string): Promise<AssetPolicy> {
    const m = this.db.manager;
    const asset = await this.findAsset(m, assetId);
    const rule = await m.findOne(InventoryPolicy, {
      where: { assetId },
      relations: { asset: true },
    });
    const effective = effectivePolicyOf(asset);
    const sources = await namedPolicySources(m, effective);

    const ancestors = await findAncestorRows(m, assetId);
    const rootId = ancestors.at(-1)?.id ?? asset.id;
    const root =
      rootId === asset.id ? asset : await m.findOneBy(Asset, { id: rootId });
    const reconcilable = !!root && !!root.connection && root.type !== 'image';
    const isRoot = reconcilable && root.id === asset.id;
    const minutes = effective.values.reconcileIntervalMinutes;
    return {
      effective: { values: effective.values, sources },
      rule: rule ? toRule(rule) : null,
      reconcileRoot: reconcilable ? { id: root.id, name: root.name } : null,
      reconciledAt: isRoot ? (asset.reconciledAt?.toISOString() ?? null) : null,
      nextReconcileAt:
        isRoot && minutes > 0 && asset.status === 'active'
          ? new Date(
              Math.max(
                Date.now(),
                (asset.reconciledAt?.getTime() ?? 0) + minutes * 60_000,
              ),
            ).toISOString()
          : null,
    };
  }

  /** Crea o cambia la regla propia de un asset (null en un campo = deja de fijarlo). */
  async setAssetPolicy(
    assetId: string,
    dto: InventoryPolicyFieldsDto,
    actor?: AuditActor,
  ): Promise<AssetPolicy> {
    await this.mutate(async (m) => {
      const asset = await this.findAsset(m, assetId);
      const change = await this.applyAssetPolicyIn(m, assetId, dto);
      if (actor && change)
        await this.audit.record(
          actor,
          change.cleared ? 'policy.asset_cleared' : 'policy.asset_set',
          {
            target: { type: asset.type, id: asset.id, label: asset.name },
            details: change.details,
            manager: m,
          },
        );
    });
    return this.assetPolicy(assetId);
  }

  /**
   * Fija en la regla propia del asset los campos que vienen (null = heredar; los que no vienen se
   * quedan) dentro de la transacción `m`, sin recalcular ni auditar (lo hace quien llama; también
   * las operaciones en lote, QoL-6). Con `clear`, la quita. null si no cambió nada.
   */
  async applyAssetPolicyIn(
    m: EntityManager,
    assetId: string,
    fields: InventoryPolicyFieldsDto,
    options: { clear?: boolean } = {},
  ): Promise<{ cleared: boolean; details: Record<string, unknown> } | null> {
    const existing = await m.findOneBy(InventoryPolicy, { assetId });
    const rule =
      existing ??
      m.create(InventoryPolicy, {
        scope: 'asset',
        assetId,
        tag: null,
        projectId: null,
        reconcileIntervalMinutes: null,
        scanEnabled: null,
        scanPeriodic: null,
        scanExclusions: null,
      });
    const before = rule.id ? fieldsOf(rule) : null;
    if (options.clear)
      for (const f of INVENTORY_RULE_FIELDS) Object.assign(rule, { [f]: null });
    else Object.assign(rule, pickFields(fields));
    const empty = INVENTORY_RULE_FIELDS.every((f) => rule[f] === null);
    const after = empty ? null : fieldsOf(rule);
    if (JSON.stringify(before) === JSON.stringify(after)) return null;
    // Sin ningún campo fijado, la regla sobra.
    if (empty) {
      if (rule.id) await m.delete(InventoryPolicy, { id: rule.id });
    } else await m.save(rule);
    return { cleared: empty, details: policyChanges(before, after) };
  }

  async removeAssetPolicy(
    assetId: string,
    actor?: AuditActor,
  ): Promise<AssetPolicy> {
    await this.mutate(async (m) => {
      const asset = await this.findAsset(m, assetId);
      const rule = await m.findOneBy(InventoryPolicy, { assetId });
      if (!rule) return;
      await m.delete(InventoryPolicy, { assetId });
      if (actor)
        await this.audit.record(actor, 'policy.asset_cleared', {
          target: { type: asset.type, id: asset.id, label: asset.name },
          details: policyChanges(fieldsOf(rule), null),
          manager: m,
        });
    });
    return this.assetPolicy(assetId);
  }

  /**
   * Encola `inventory.reconcile`: todas las raíces con el intervalo vencido o, con `assetId`, ese
   * nodo raíz ahora (activo, con conexión y sin padre).
   */
  async reconcile(
    assetId?: string,
    actor?: AuditActor,
  ): Promise<EnqueueJobResponse> {
    let target: Asset | undefined;
    if (assetId) {
      const asset = await this.findAsset(this.db.manager, assetId);
      target = asset;
      const parent = await this.db
        .getRepository(AssetRelation)
        .findOneBy({ childId: assetId, type: 'contains' });
      if (parent || !asset.connection || asset.type === 'image')
        throw new ConflictException(
          'Solo se reconcilian nodos raíz con conexión (los demás se reconcilian con su raíz)',
        );
      if (asset.status !== 'active' || asset.duplicateOfId)
        throw new ConflictException(
          'Solo se reconcilian nodos raíz activos y no duplicados',
        );
    }
    const res = await this.jobs.enqueue(
      JOB_NAMES.inventoryReconcile,
      assetId ? { assetId } : {},
      { deduplicationId: `reconcile:${assetId ?? 'all'}` },
    );
    if (actor)
      await this.audit.tryRecord(actor, 'inventory.reconcile_requested', {
        target: target
          ? { type: target.type, id: target.id, label: target.name }
          : undefined,
        details: { scope: target ? 'asset' : 'all', jobId: res.id },
      });
    return res;
  }

  /** Evento de auditoría de una regla: su ámbito y los campos que cambian (antes → después). */
  private async auditPolicy(
    m: EntityManager,
    actor: AuditActor | undefined,
    action: AuditAction,
    rule: InventoryPolicy,
    before: InventoryPolicyFields | null,
    view?: InventoryPolicyRule,
    deleted = false,
  ): Promise<void> {
    if (!actor) return;
    const label =
      rule.scope === 'global'
        ? 'Política global'
        : rule.scope === 'tag'
          ? `Etiqueta «${rule.tag}»`
          : rule.scope === 'project'
            ? `Proyecto «${view?.projectName ?? rule.projectId}»`
            : (view?.assetName ?? rule.assetId);
    await this.audit.record(actor, action, {
      target: {
        type:
          rule.scope === 'asset'
            ? 'asset'
            : rule.scope === 'project'
              ? 'project'
              : 'policy',
        id:
          rule.scope === 'asset'
            ? rule.assetId
            : rule.scope === 'project'
              ? rule.projectId
              : rule.id,
        label,
      },
      details: {
        scope: rule.scope,
        ...(rule.tag ? { tag: rule.tag } : {}),
        ...policyChanges(before, deleted ? null : fieldsOf(rule)),
      },
      manager: m,
    });
  }

  /** Cambio + recálculo de la política efectiva en la misma transacción. */
  private async mutate<T>(fn: (m: EntityManager) => Promise<T>): Promise<T> {
    try {
      return await this.db.transaction(async (m) => {
        const result = await fn(m);
        await recomputePolicies(m);
        return result;
      });
    } catch (error) {
      if (pgErrorCode(error) === PG_UNIQUE_VIOLATION)
        throw new ConflictException(
          'Ya hay una regla para ese asset, esa etiqueta o ese proyecto',
        );
      throw error;
    }
  }

  private async findAsset(m: EntityManager, id: string): Promise<Asset> {
    const asset = await m.findOneBy(Asset, { id });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }

  private async findProject(m: EntityManager, id: string): Promise<Project> {
    const project = await m.findOneBy(Project, { id });
    if (!project) throw new NotFoundException('Proyecto no encontrado');
    return project;
  }

  private async findRule(
    m: EntityManager,
    id: string,
  ): Promise<InventoryPolicy> {
    const rule = await m.findOneBy(InventoryPolicy, { id });
    if (!rule) throw new NotFoundException('Regla no encontrada');
    return rule;
  }

  private async ruleById(
    m: EntityManager,
    id: string,
  ): Promise<InventoryPolicyRule> {
    return toRule(
      await m.findOneOrFail(InventoryPolicy, {
        where: { id },
        relations: { asset: true, project: true },
      }),
    );
  }
}

function fieldsOf(rule: InventoryPolicy): InventoryPolicyFields {
  return {
    reconcileIntervalMinutes: rule.reconcileIntervalMinutes,
    scanEnabled: rule.scanEnabled,
    scanPeriodic: rule.scanPeriodic,
    scanExclusions: normalizeScanExclusions(rule.scanExclusions),
  };
}

/** `{campo}From`/`{campo}To` de los campos que cambian (null = sin fijar o sin regla). */
export function policyChanges(
  before: InventoryPolicyFields | null,
  after: InventoryPolicyFields | null,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of INVENTORY_RULE_FIELDS) {
    const from = before?.[field] ?? null;
    const to = after?.[field] ?? null;
    if (JSON.stringify(from) === JSON.stringify(to)) continue;
    out[`${field}From`] = from;
    out[`${field}To`] = to;
  }
  return out;
}

/** Solo los campos presentes (null = deja de fijarlo; unas exclusiones vacías, también). */
function pickFields(dto: InventoryPolicyFields): InventoryPolicyFields {
  return Object.fromEntries(
    INVENTORY_RULE_FIELDS.filter((f) => dto[f] !== undefined).map((f) => [
      f,
      f === 'scanExclusions' ? normalizeScanExclusions(dto[f]) : dto[f],
    ]),
  );
}

function requireSomeField(fields: InventoryPolicyFields): void {
  if (
    INVENTORY_RULE_FIELDS.every(
      (f) => fields[f] === null || fields[f] === undefined,
    )
  )
    throw new BadRequestException(
      'La regla tiene que fijar al menos un campo (intervalo, escaneo, escaneo periódico o exclusiones)',
    );
}

function toRule(rule: InventoryPolicy): InventoryPolicyRule {
  return {
    id: rule.id,
    scope: rule.scope,
    assetId: rule.assetId,
    ...(rule.scope === 'asset' ? { assetName: rule.asset?.name ?? null } : {}),
    tag: rule.tag,
    projectId: rule.projectId,
    ...(rule.scope === 'project'
      ? { projectName: rule.project?.name ?? null }
      : {}),
    reconcileIntervalMinutes: rule.reconcileIntervalMinutes,
    scanEnabled: rule.scanEnabled,
    scanPeriodic: rule.scanPeriodic,
    scanExclusions: normalizeScanExclusions(rule.scanExclusions),
    createdAt: rule.createdAt.toISOString(),
    updatedAt: rule.updatedAt.toISOString(),
  };
}
