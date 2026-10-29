import {
  BadRequestException,
  HttpException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  Asset,
  findSubtreeIds,
  Project,
  recomputePolicies,
  scanEnabledSql,
} from '@infraward/domain';
import {
  BULK_ACTION_LABELS,
  BULK_ASSETS_MAX,
  JOB_NAMES,
  QUEUE_NAMES,
  type AuditAction,
  type BulkAssetAction,
  type BulkAssetRef,
  type BulkAssetIds,
  type BulkAssetTarget,
  type BulkOperationResult,
  type BulkPreviewResponse,
  type BulkSkipped,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { DataSource, In, type EntityManager } from 'typeorm';
import { AssetsService } from '../assets/assets.service.js';
import { LABELS_MAX } from '../assets/labels.js';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { CollectionService } from '../collection/collection.service.js';
import { FindingsService } from '../findings/findings.service.js';
import { InventoryService } from '../inventory/inventory.service.js';
import { ProjectsService } from '../projects/projects.service.js';
import type { BulkPolicyDto, BulkProjectDto, BulkTagsDto } from './bulk.dto.js';

/** Nombres que caben en el detalle de la auditoría (el saneador corta las listas en 50). */
const AUDIT_NAMES_MAX = 50;
/** Descendientes que se enseñan en la confirmación de una baja. */
const PREVIEW_DESCENDANTS_MAX = 200;

type BulkAsset = Pick<Asset, 'id' | 'name' | 'type' | 'status' | 'tags'>;

const ref = (a: BulkAsset): BulkAssetRef => ({
  id: a.id,
  name: a.name,
  type: a.type,
});

/** Lo que hizo una operación, para la Actividad, la auditoría y la respuesta. */
interface Outcome {
  applied: BulkAsset[];
  skipped: BulkSkipped[];
  jobs: string[];
  /** Detalle propio de la acción para la auditoría (añadidos, proyecto…). */
  details: Record<string, unknown>;
}

/**
 * Operaciones en lote sobre varios assets (QoL-6, DESIGN §15). Cada una es **una** fila
 * `assets.bulk` en la Actividad (los jobs que lanza cuelgan de ella) y **un** evento de auditoría
 * con su detalle. Las que cambian datos van en una transacción con un solo recálculo de la
 * política; las que encolan reutilizan las reglas de cada asset (lo que no se puede, a `skipped`
 * con el motivo del 409).
 */
@Injectable()
export class BulkService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
    private readonly assets: AssetsService,
    private readonly collection: CollectionService,
    private readonly findings: FindingsService,
    private readonly inventory: InventoryService,
    private readonly projects: ProjectsService,
  ) {}

  async preview(target: BulkAssetTarget): Promise<BulkPreviewResponse> {
    const { assets } = await this.resolve(this.db.manager, target);
    const roots = assets.filter((a) => a.status !== 'retired');
    const selected = new Set(roots.map((a) => a.id));
    const all = new Set<string>();
    for (const a of roots)
      for (const id of await findSubtreeIds(this.db.manager, a.id)) all.add(id);
    const descendants = all.size
      ? (
          await this.db.manager.find(Asset, {
            select: { id: true, name: true, type: true, status: true },
            where: { id: In([...all].filter((id) => !selected.has(id))) },
            order: { name: 'ASC' },
          })
        ).filter((a) => a.status !== 'retired')
      : [];
    return {
      assets: assets.map(ref),
      retire: {
        total: roots.length + descendants.length,
        descendants: descendants
          .slice(0, PREVIEW_DESCENDANTS_MAX)
          .map((a) => ({ id: a.id, name: a.name, type: a.type })),
      },
    };
  }

  /** Añade y quita tags (sin tocar los demás). */
  tags(dto: BulkTagsDto, actor: AuditActor): Promise<BulkOperationResult> {
    const add = [...new Set(dto.add)];
    const remove = new Set(dto.remove);
    if (!add.length && !remove.size)
      throw new BadRequestException('Indica algún tag que añadir o quitar');
    if (add.some((t) => remove.has(t)))
      throw new BadRequestException(
        'Un tag no puede añadirse y quitarse a la vez',
      );
    return this.mutate('tags', dto, actor, async (m, assets, skipped) => {
      const applied: BulkAsset[] = [];
      for (const asset of assets) {
        const next = [
          ...asset.tags.filter((t) => !remove.has(t)),
          ...add.filter((t) => !asset.tags.includes(t)),
        ];
        if (next.length > LABELS_MAX) {
          skipped.push({
            ...ref(asset),
            reason: `Pasaría de ${LABELS_MAX} tags`,
          });
          continue;
        }
        if (JSON.stringify(next) === JSON.stringify(asset.tags)) {
          skipped.push({ ...ref(asset), reason: 'Ya estaba así' });
          continue;
        }
        await m.update(Asset, { id: asset.id }, { tags: next });
        applied.push(asset);
      }
      return { applied, details: { added: add, removed: [...remove] } };
    });
  }

  /** Mete o saca los assets de un proyecto (o los deja heredar). */
  project(
    dto: BulkProjectDto,
    actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.mutate('project', dto, actor, async (m, assets, skipped) => {
      const project = await m.findOneBy(Project, { id: dto.project });
      if (!project) throw new NotFoundException('Proyecto no encontrado');
      const applied: BulkAsset[] = [];
      for (const asset of assets) {
        const before = await this.projects.applyMemberIn(
          m,
          project.id,
          asset.id,
          dto.mode,
        );
        if (before === undefined)
          skipped.push({ ...ref(asset), reason: 'Ya estaba así' });
        else applied.push(asset);
      }
      return {
        applied,
        details: {
          projectId: project.id,
          project: project.name,
          mode: dto.mode,
        },
      };
    });
  }

  /** Fija (o quita) la regla de política propia de cada asset. */
  policy(dto: BulkPolicyDto, actor: AuditActor): Promise<BulkOperationResult> {
    const fields = dto.fields ?? {};
    const set = Object.entries(fields).filter(([, v]) => v !== undefined);
    if (!dto.clear && !set.length)
      throw new BadRequestException(
        'Indica algún campo de la política o «clear»',
      );
    return this.mutate('policy', dto, actor, async (m, assets, skipped) => {
      const applied: BulkAsset[] = [];
      for (const asset of assets) {
        const change = await this.inventory.applyAssetPolicyIn(
          m,
          asset.id,
          fields,
          {
            clear: dto.clear,
          },
        );
        if (!change) skipped.push({ ...ref(asset), reason: 'Ya estaba así' });
        else applied.push(asset);
      }
      return {
        applied,
        details: dto.clear
          ? { cleared: true }
          : Object.fromEntries(set.map(([k, v]) => [k, v as unknown])),
      };
    });
  }

  /** Da de baja (retira) los assets y sus subárboles; nunca purga. */
  async retire(
    target: BulkAssetIds,
    actor: AuditActor,
  ): Promise<BulkOperationResult> {
    let withCredentials: Asset[] = [];
    const result = await this.mutate(
      'retire',
      target,
      actor,
      async (m, assets, skipped) => {
        const roots: BulkAsset[] = [];
        for (const asset of assets)
          if (asset.status === 'retired')
            skipped.push({ ...ref(asset), reason: 'Ya estaba dado de baja' });
          else roots.push(asset);
        const removed = await this.assets.removeSubtreesIn(
          m,
          roots.map((a) => a.id),
          false,
        );
        withCredentials = removed.withCredentials;
        return {
          applied: roots,
          details: { affected: removed.affectedIds.length },
        };
      },
    );
    return {
      ...result,
      revocations: await this.assets.revokeAll(withCredentials, false),
    };
  }

  /** Encola la recolección de cada asset. */
  collect(
    target: BulkAssetTarget,
    actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.enqueueEach(
      'collect',
      target,
      actor,
      async (asset, parentJobId) => [
        await this.collection.collect(asset.id, { parentJobId }),
      ],
    );
  }

  /** Encola el escaneo de cada asset (con `force`, como el botón de la ficha). */
  scan(
    target: BulkAssetTarget,
    actor: AuditActor,
  ): Promise<BulkOperationResult> {
    return this.enqueueEach(
      'scan',
      target,
      actor,
      async (asset, parentJobId) =>
        (await this.findings.scan(asset.id, true, { parentJobId })).jobs,
    );
  }

  /** Cambio de datos: todo en una transacción, con un recálculo y un evento de auditoría. */
  private async mutate(
    action: BulkAssetAction,
    target: BulkAssetTarget,
    actor: AuditActor,
    apply: (
      m: EntityManager,
      assets: BulkAsset[],
      skipped: BulkSkipped[],
    ) => Promise<Pick<Outcome, 'applied' | 'details'>>,
  ): Promise<BulkOperationResult> {
    const operationId = randomUUID();
    const outcome = await this.db.transaction(async (m) => {
      const { assets, skipped } = await this.resolve(m, target, { lock: true });
      const { applied, details } = await apply(m, assets, skipped);
      if (applied.length) await recomputePolicies(m);
      const done: Outcome = { applied, skipped, jobs: [], details };
      await this.record(m, operationId, action, done, actor);
      return done;
    });
    return this.result(operationId, action, outcome);
  }

  /** Encolado: cada asset con sus reglas; la fila de la Actividad, al final (queda encima). */
  private async enqueueEach(
    action: 'collect' | 'scan',
    target: BulkAssetTarget,
    actor: AuditActor,
    enqueue: (
      asset: BulkAsset,
      parentJobId: string,
    ) => Promise<{ id: string; deduplicated?: boolean }[]>,
  ): Promise<BulkOperationResult> {
    const operationId = randomUUID();
    const { assets, skipped } = await this.resolve(this.db.manager, target);
    const applied: BulkAsset[] = [];
    const jobs = new Set<string>();
    let reused = 0;
    for (const asset of assets) {
      try {
        const queued = await enqueue(asset, operationId);
        if (!queued.length) {
          skipped.push({ ...ref(asset), reason: 'Nada que encolar' });
          continue;
        }
        for (const job of queued) {
          // Ya en curso de antes (no el de otro asset de esta misma operación, p. ej. la misma
          // imagen en dos contenedores).
          if (job.deduplicated && !jobs.has(job.id)) reused++;
          jobs.add(job.id);
        }
        applied.push(asset);
      } catch (error) {
        // 409/404 de las reglas de cada asset: su motivo, tal cual lo daría la ficha.
        if (!(error instanceof HttpException) || error.getStatus() >= 500)
          throw error;
        skipped.push({ ...ref(asset), reason: error.message });
      }
    }
    const outcome: Outcome = {
      applied,
      skipped,
      jobs: [...jobs],
      details: reused ? { alreadyRunning: reused } : {},
    };
    await this.db.transaction((m) =>
      this.record(m, operationId, action, outcome, actor),
    );
    return this.result(operationId, action, outcome);
  }

  /**
   * Assets de la operación, en el orden pedido (los ids que no existen, a `skipped`). Con CVE,
   * los dueños de findings abiertos o aceptados (servidores, CT, imágenes) no retirados.
   */
  private async resolve(
    m: EntityManager,
    target: BulkAssetTarget,
    options: { lock?: boolean } = {},
  ): Promise<{ assets: BulkAsset[]; skipped: BulkSkipped[] }> {
    const byIds = !!target.assetIds?.length;
    const byCves = !!target.vulnerabilityIds?.length;
    if (byIds === byCves)
      throw new BadRequestException(
        'Indica assetIds o vulnerabilityIds (uno de los dos)',
      );
    let ids: string[];
    if (byIds) ids = [...new Set(target.assetIds)];
    else {
      const params: unknown[] = [
        target.vulnerabilityIds!.map((v) => v.toUpperCase()),
      ];
      let project = '';
      if (target.projectId) {
        params.push(target.projectId);
        project = 'AND o.effective_projects @> ARRAY[$2]::uuid[]';
      }
      const rows: { id: string }[] = await m.query(
        `SELECT o.id FROM findings f JOIN assets o ON o.id = f.asset_id
          WHERE upper(f.vulnerability_id) = ANY($1::text[])
            AND f.status IN ('open', 'accepted') AND o.status <> 'retired'
            -- Los mismos afectados que enseña la lista: sin los de escaneo desactivado.
            AND ${scanEnabledSql('o')} ${project}
          GROUP BY o.id, o.name ORDER BY o.name`,
        params,
      );
      ids = rows.map((r) => r.id);
      if (!ids.length)
        throw new NotFoundException('Ningún asset afectado por esos CVE');
    }
    if (ids.length > BULK_ASSETS_MAX)
      throw new BadRequestException(
        `Son ${ids.length} assets: como mucho ${BULK_ASSETS_MAX} por operación`,
      );
    const found = await m.find(Asset, {
      select: { id: true, name: true, type: true, status: true, tags: true },
      where: { id: In(ids) },
      ...(options.lock ? { lock: { mode: 'pessimistic_write' as const } } : {}),
    });
    const byId = new Map(found.map((a) => [a.id, a]));
    const assets: BulkAsset[] = [];
    const skipped: BulkSkipped[] = [];
    for (const id of ids) {
      const asset = byId.get(id);
      if (asset) assets.push(asset);
      else skipped.push({ id, name: id, type: 'unknown', reason: 'No existe' });
    }
    return { assets, skipped };
  }

  /** La fila de la Actividad (ya terminada) y el evento de auditoría, en la transacción `m`. */
  private async record(
    m: EntityManager,
    operationId: string,
    action: BulkAssetAction,
    outcome: Outcome,
    actor: AuditActor,
  ): Promise<void> {
    const label = BULK_ACTION_LABELS[action];
    const names = outcome.applied.map((a) => a.name);
    const message = [
      `${label} · ${outcome.applied.length} ${outcome.applied.length === 1 ? 'asset' : 'assets'}`,
      outcome.skipped.length
        ? `${outcome.skipped.length} ${outcome.skipped.length === 1 ? 'omitido' : 'omitidos'}`
        : null,
      outcome.jobs.length
        ? `${outcome.jobs.length} ${outcome.jobs.length === 1 ? 'tarea' : 'tareas'}`
        : null,
      typeof outcome.details['alreadyRunning'] === 'number'
        ? `${outcome.details['alreadyRunning']} ya en curso`
        : null,
      actor.actorEmail ? `por ${actor.actorEmail}` : null,
    ]
      .filter(Boolean)
      .join(' · ');
    await m.query(
      `INSERT INTO job_runs (id, name, queue, asset_id, asset_name, state, progress, message,
                             created_at, started_at, finished_at)
       VALUES ($1, $2, $3, NULL, $4, 'completed', 100, $5, now(), now(), now())`,
      [
        operationId,
        JOB_NAMES.assetsBulk,
        QUEUE_NAMES.system,
        summarizeNames(names).slice(0, 255),
        message.slice(0, 500),
      ],
    );
    await this.audit.record(actor, `asset.bulk_${action}` as AuditAction, {
      target: {
        type: 'bulk_operation',
        id: operationId,
        label: `${label} · ${outcome.applied.length} assets`,
      },
      details: {
        count: outcome.applied.length,
        assets: names.slice(0, AUDIT_NAMES_MAX),
        ...(names.length > AUDIT_NAMES_MAX
          ? { moreAssets: names.length - AUDIT_NAMES_MAX }
          : {}),
        skipped: outcome.skipped.length,
        ...(outcome.jobs.length ? { jobs: outcome.jobs.length } : {}),
        ...outcome.details,
      },
      manager: m,
    });
  }

  private result(
    operationId: string,
    action: BulkAssetAction,
    outcome: Outcome,
  ): BulkOperationResult {
    return {
      operationId,
      action,
      applied: outcome.applied.map(ref),
      skipped: outcome.skipped,
      jobs: outcome.jobs,
    };
  }
}

/** «web1, web2, web3 y 4 más» (la columna Asset de la Actividad). */
export function summarizeNames(names: readonly string[], max = 3): string {
  if (!names.length) return 'Ningún asset';
  const head = names.slice(0, max).join(', ');
  return names.length > max ? `${head} y ${names.length - max} más` : head;
}
