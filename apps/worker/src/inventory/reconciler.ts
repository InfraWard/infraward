import { Injectable, Logger, Optional } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { policyValues } from '@infraward/domain';
import {
  INVENTORY_RECONCILE_ID,
  JOB_NAMES,
  QUEUE_NAMES,
  domainsSyncDeduplicationId,
  type AssetCollectJobData,
  type AssetType,
  type DomainsSyncJobData,
  type EffectiveInventoryPolicy,
  type InventoryReconcileJobData,
  type InventoryReconcileJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import { DomainLinker } from '../domains/domain-linker.js';
import { ServiceLinker } from '../domains/service-linker.js';
import { ExpiryAlerts } from '../domains/expiry-alerts.js';
import { JobQueues } from '../jobs/job-queues.js';
import { recordQueued } from '../jobs/job-runs.js';
import { DistributedLock } from '../redis/distributed-lock.js';
import { reportProgress } from '../jobs/progress.js';

/** Nodo raíz candidato a reconciliar. */
export interface ReconcileCandidate {
  id: string;
  name: string;
  type: AssetType;
  effectivePolicy: Partial<EffectiveInventoryPolicy>;
  reconciledAt: Date | null;
}

/**
 * ¿Le toca? Con el intervalo de su política (0 = nunca) desde su última reconciliación (o
 * recolección); nunca reconciliado ⇒ sí.
 */
export function isDue(candidate: ReconcileCandidate, now: Date): boolean {
  const minutes = policyValues(
    candidate.effectivePolicy,
  ).reconcileIntervalMinutes;
  if (minutes <= 0) return false;
  if (!candidate.reconciledAt) return true;
  return now.getTime() - candidate.reconciledAt.getTime() >= minutes * 60_000;
}

/**
 * Reconciliación periódica (DESIGN §10): cada `RECONCILE_TICK` mira qué nodos raíz (sin padre
 * `contains`, con conexión, activos y no duplicados) tienen el intervalo vencido y encola su
 * recolección con `trigger: 'reconcile'`. La recolección encadena el descubrimiento, que
 * reconcilia los hijos (altas, snapshots, missing → retired) y recoge los suyos. Los conectores
 * de dominios (`dns_provider` con token) son raíces igual: se les encola `domains.sync` (§13).
 * Además, en cada tick: los enlaces de los registros DNS (por si un servidor cambió de IP o se
 * retiró) y los avisos de caducidad.
 */
@Injectable()
export class InventoryReconciler {
  private readonly logger = new Logger(InventoryReconciler.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly queues: JobQueues,
    private readonly linker: DomainLinker,
    private readonly expiry: ExpiryAlerts,
    @Optional() private readonly services?: ServiceLinker,
    @Optional() private readonly locks?: DistributedLock,
  ) {}

  private get queue() {
    return this.queues.get(QUEUE_NAMES.reconcile);
  }

  /** Raíces reconciliables (una concreta con `assetId`). */
  async candidates(assetId?: string): Promise<ReconcileCandidate[]> {
    const rows: {
      id: string;
      name: string;
      type: AssetType;
      effective_policy: Partial<EffectiveInventoryPolicy>;
      reconciled_at: Date | null;
    }[] = await this.db.query(
      `SELECT a.id, a.name, a.type, a.effective_policy, a.reconciled_at
         FROM assets a
        WHERE a.status = 'active'
          AND (a.connection IS NOT NULL
               OR (a.type = 'dns_provider' AND a.credentials ? 'apiToken'))
          AND a.duplicate_of_id IS NULL AND a.type <> 'image'
          AND NOT EXISTS (SELECT 1 FROM asset_relations r
                           WHERE r.child_id = a.id AND r.type = 'contains')
          AND ($1::uuid IS NULL OR a.id = $1)
        ORDER BY a.reconciled_at NULLS FIRST, a.name`,
      [assetId ?? null],
    );
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      type: r.type,
      effectivePolicy: r.effective_policy,
      reconciledAt: r.reconciled_at,
    }));
  }

  async run(
    job: Job<InventoryReconcileJobData, InventoryReconcileJobResult>,
  ): Promise<InventoryReconcileJobResult> {
    const { assetId } = job.data;
    // Una comprobación completa a la vez entre réplicas (la periódica y una manual de todo).
    const whole = assetId ? null : await this.locks?.tryAcquire('reconcile:all');
    if (!assetId && this.locks && !whole) {
      this.logger.log('Reconciliación: otra comprobación sigue en curso');
      await reportProgress(job, 100, 'Otra comprobación sigue en curso');
      return { queued: 0, assetIds: [], notDue: 0 };
    }
    try {
      return await this.check(job, assetId);
    } finally {
      await whole?.release();
    }
  }

  private async check(
    job: Job<InventoryReconcileJobData, InventoryReconcileJobResult>,
    assetId: string | undefined,
  ): Promise<InventoryReconcileJobResult> {
    const now = new Date();
    const candidates = await this.candidates(assetId);
    // Una concreta (manual) va aunque no le toque.
    const due = assetId ? candidates : candidates.filter((c) => isDue(c, now));
    // El del job scheduler (id `repeat:…`) no está en la Actividad: sus recolecciones, sin padre.
    const parentJobId = job.repeatJobKey ? undefined : job.id;
    const assetIds: string[] = [];
    for (const c of due) {
      // Cada nodo raíz bajo su lock: una manual y la periódica no lo encolan dos veces.
      const lock = await this.locks?.tryAcquire(`reconcile:${c.id}`);
      if (this.locks && !lock) continue;
      try {
        if (!assetId) {
          const [fresh] = await this.candidates(c.id);
          if (!fresh || !isDue(fresh, new Date())) continue;
        }
        const jobId =
          c.type === 'dns_provider'
            ? await this.enqueueDomainsSync(c.id, parentJobId)
            : await this.enqueueCollect(c.id, parentJobId);
        if (!jobId) continue;
        await this.db.query(
          `UPDATE assets SET reconciled_at = now() WHERE id = $1`,
          [c.id],
        );
        assetIds.push(c.id);
      } finally {
        await lock?.release();
      }
    }
    if (!assetId) await this.maintainDomains();
    const result: InventoryReconcileJobResult = {
      queued: assetIds.length,
      assetIds,
      notDue: candidates.length - due.length,
    };
    if (assetIds.length || !job.repeatJobKey) {
      this.logger.log(
        `Reconciliación: ${result.queued} nodos raíz encolados (${due.map((c) => c.name).join(', ') || 'ninguno'}), ${result.notDue} sin vencer`,
      );
      await reportProgress(
        job,
        100,
        `${result.queued} nodos raíz encolados, ${result.notDue} sin vencer`,
      );
    }
    return result;
  }

  /** Enlaces DNS y avisos de caducidad; un fallo aquí no hace fallar la reconciliación. */
  private async maintainDomains(): Promise<void> {
    try {
      await this.linker.link();
    } catch (error) {
      this.logger.warn(`No se pudieron enlazar los registros DNS: ${(error as Error).name}`);
    }
    try {
      await this.services?.link();
    } catch (error) {
      this.logger.warn(
        `No se pudieron calcular los caminos de los dominios: ${(error as Error).name}`,
      );
    }
    try {
      await this.expiry.run();
    } catch (error) {
      this.logger.warn(`No se pudieron revisar las caducidades: ${(error as Error).name}`);
    }
  }

  private async enqueueDomainsSync(
    assetId: string,
    parentJobId?: string,
  ): Promise<string | null> {
    try {
      const job = await this.queues.add(
        JOB_NAMES.domainsSync,
        { assetId, trigger: 'reconcile' } satisfies DomainsSyncJobData,
        {
          jobId: randomUUID(),
          deduplication: { id: domainsSyncDeduplicationId(assetId) },
        },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la sincronización de ${assetId}: ${(error as Error).name}`,
      );
      return null;
    }
  }

  private async enqueueCollect(
    assetId: string,
    parentJobId?: string,
  ): Promise<string | null> {
    try {
      const job = await this.queues.add(
        JOB_NAMES.assetCollect,
        { assetId, trigger: 'reconcile' } satisfies AssetCollectJobData,
        { jobId: randomUUID(), deduplication: { id: assetId } },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la reconciliación de ${assetId}: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /**
   * Programa la comprobación cada `seconds` (0 = apagada). Solo crea o cambia el job scheduler
   * si no existe o cambió el intervalo.
   */
  async schedule(seconds: number): Promise<void> {
    const current = await this.queue.getJobScheduler(INVENTORY_RECONCILE_ID);
    if (seconds <= 0) {
      if (current) {
        await this.queue.removeJobScheduler(INVENTORY_RECONCILE_ID);
        this.logger.log('Reconciliación periódica desactivada');
      }
      return;
    }
    const every = seconds * 1000;
    if (current && Number(current.every) === every) return;
    await this.queue.upsertJobScheduler(
      INVENTORY_RECONCILE_ID,
      { every },
      {
        name: JOB_NAMES.inventoryReconcile,
        data: {} satisfies InventoryReconcileJobData,
      },
    );
    this.logger.log(`Reconciliación comprobada cada ${seconds} s`);
  }
}
