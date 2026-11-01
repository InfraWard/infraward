import type { JobName, JobRunTrigger, QueueName } from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';

/** Lo que hace falta de un job de BullMQ para registrarlo (sin depender de bullmq). */
export interface RecordableJob {
  id?: string;
  name: string;
  queueName: string;
  data: unknown;
  /** Milisegundos (Date.now()) en que se creó. */
  timestamp: number;
}

const MESSAGE_MAX = 500;
const ERROR_MAX = 1000;

export function clip(text: string | null | undefined, max: number): string | null {
  if (!text) return null;
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export const clipMessage = (text: string | null | undefined) => clip(text, MESSAGE_MAX);
export const clipError = (text: string | null | undefined) => clip(text, ERROR_MAX);

/**
 * Asset sobre el que trabaja un job: `assetId` de sus datos; en `enrollment.verify`, el del
 * enrolamiento; en `image.scan`, el asset `image` de la imagen. null si no hay (ping).
 */
export async function jobAssetId(
  manager: EntityManager,
  name: string,
  data: unknown,
): Promise<string | null> {
  const d = (data ?? {}) as Record<string, unknown>;
  if (typeof d['assetId'] === 'string') return d['assetId'];
  if (name === 'enrollment.verify' && typeof d['enrollmentId'] === 'string') {
    const [row]: { asset_id: string }[] = await manager.query(
      'SELECT asset_id FROM enrollments WHERE id = $1',
      [d['enrollmentId']],
    );
    return row?.asset_id ?? null;
  }
  if (name === 'image.scan' && typeof d['imageId'] === 'string') {
    const [row]: { asset_id: string }[] = await manager.query(
      'SELECT asset_id FROM container_images WHERE image_id = $1',
      [d['imageId']],
    );
    return row?.asset_id ?? null;
  }
  return null;
}

/**
 * Registra un job recién encolado, con el job o lote del que cuelga o, si no cuelga de nada, qué
 * lo lanzó (`trigger`). Si ya existe (BullMQ devolvió el que estaba en cola por la deduplicación,
 * o el worker se adelantó), no lo toca.
 */
export async function recordQueuedJob(
  manager: EntityManager,
  job: RecordableJob,
  parentJobId: string | null = null,
  trigger: JobRunTrigger | null = null,
): Promise<void> {
  if (!job.id) return;
  const assetId = await jobAssetId(manager, job.name, job.data);
  await manager.query(
    `INSERT INTO job_runs (id, name, queue, asset_id, asset_name, state, parent_job_id, trigger,
                           created_at)
     SELECT $1, $2, $3, a.id, a.name, 'queued', $5, $7, to_timestamp($6 / 1000.0)
       FROM (SELECT 1) one LEFT JOIN assets a ON a.id = $4
     ON CONFLICT (id) DO NOTHING`,
    [
      job.id,
      job.name as JobName,
      job.queueName as QueueName,
      assetId,
      parentJobId,
      job.timestamp,
      parentJobId ? null : trigger,
    ],
  );
}
