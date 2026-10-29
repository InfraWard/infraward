import {
  Injectable,
  NotFoundException,
  type MessageEvent,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, Enrollment } from '@infraward/domain';
import {
  JOB_NAMES,
  enrollmentPhase,
  type EnrollmentJobProgress,
  type EnrollmentProgress,
  type JobName,
} from '@infraward/shared-types';
import {
  concatMap,
  distinctUntilChanged,
  filter,
  interval,
  map,
  merge,
  of,
  takeUntil,
  throttleTime,
  timer,
  type Observable,
} from 'rxjs';
import { DataSource } from 'typeorm';
import { JobEventsService } from '../jobs/job-events.service.js';
import { JobsService, type JobPeek } from '../jobs/jobs.service.js';
import { EnrollmentService, toEnrollment } from './enrollment.service.js';

/** Tope de jobs que se siguen en la cadena (un nodo Proxmox con muchos CT e imágenes). */
export const MAX_TRACKED_JOBS = 500;
/** Recalcula aunque no llegue ningún evento (evento perdido, otra instancia de la API). */
const FALLBACK_POLL_MS = 10_000;
/** Mantiene viva la conexión a través de proxies. */
const HEARTBEAT_MS = 15_000;
/** El cliente reconecta al cerrarse: así ninguna conexión vive indefinidamente. */
const MAX_STREAM_MS = 30 * 60_000;
/** Agrupa ráfagas de eventos (progreso de varios jobs a la vez). */
const COALESCE_MS = 200;

interface PendingJob {
  name: JobName;
  id: string;
}

/**
 * Progreso del alta en tiempo real (DESIGN §7): enrolamiento + la cadena de jobs que encadena
 * la verificación (recolección → descubrimiento → recolecciones de los hijos y escaneos),
 * siguiendo los ids que cada job deja en su resultado. Solo nombres, estados y mensajes de
 * progreso: nunca los datos ni el resultado completo de los jobs.
 */
@Injectable()
export class EnrollmentProgressService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly jobs: JobsService,
    private readonly jobEvents: JobEventsService,
    private readonly enrollment: EnrollmentService,
  ) {}

  async snapshot(assetId: string): Promise<EnrollmentProgress> {
    const asset = await this.db.getRepository(Asset).findOneBy({ id: assetId });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    const enrollment = await this.db.getRepository(Enrollment).findOne({
      where: { assetId },
      order: { createdAt: 'DESC' },
    });
    if (!enrollment)
      throw new NotFoundException('El asset no tiene enrolamientos');

    const { jobs, truncated } = enrollment.jobId
      ? await this.chain(enrollment.jobId, assetId)
      : { jobs: [], truncated: false };
    return {
      assetId,
      assetName: asset.name,
      assetStatus: asset.status,
      phase: enrollmentPhase(enrollment.status, jobs),
      enrollment: toEnrollment(enrollment),
      jobs,
      truncated,
      at: new Date().toISOString(),
    };
  }

  /**
   * Flujo SSE: un `progress` con el estado completo cada vez que cambia algo (el primero, al
   * conectar) y un `heartbeat` periódico. Falla con 404 antes de abrir el flujo.
   */
  async stream(assetId: string): Promise<Observable<MessageEvent>> {
    let current = await this.snapshot(assetId);
    let tracked = new Set(current.jobs.map((j) => j.id));

    const triggers = merge(
      this.jobEvents.events$.pipe(filter((e) => tracked.has(e.jobId))),
      this.enrollment.changes$.pipe(filter((id) => id === assetId)),
      interval(FALLBACK_POLL_MS),
    );
    const updates = triggers.pipe(
      // El primero sale al momento (si no, una verificación rápida no llega a verse) y el
      // último de cada ráfaga, también.
      throttleTime(COALESCE_MS, undefined, { leading: true, trailing: true }),
      concatMap(async () => {
        try {
          current = await this.snapshot(assetId);
        } catch {
          // Asset purgado entretanto o fallo puntual de la BD/Redis: se reintenta con el
          // siguiente evento o el sondeo.
        }
        tracked = new Set(current.jobs.map((j) => j.id));
        return current;
      }),
    );
    const progress = merge(of(current), updates).pipe(
      distinctUntilChanged((a, b) => sameProgress(a, b)),
      map((p): MessageEvent => ({ type: 'progress', data: p })),
    );
    const heartbeat = interval(HEARTBEAT_MS).pipe(
      map((): MessageEvent => ({ type: 'heartbeat', data: '' })),
    );
    return merge(progress, heartbeat).pipe(takeUntil(timer(MAX_STREAM_MS)));
  }

  /** Recorre la cadena de jobs en anchura a partir de la verificación. */
  private async chain(
    verifyJobId: string,
    assetId: string,
  ): Promise<{ jobs: EnrollmentJobProgress[]; truncated: boolean }> {
    const jobs: EnrollmentJobProgress[] = [];
    const seen = new Set<string>();
    const queue: PendingJob[] = [
      { name: JOB_NAMES.enrollmentVerify, id: verifyJobId },
    ];
    while (queue.length > 0) {
      if (jobs.length >= MAX_TRACKED_JOBS) return { jobs, truncated: true };
      const next = queue.shift()!;
      if (seen.has(next.id)) continue;
      seen.add(next.id);
      const peek = await this.jobs.peek(next.name, next.id);
      jobs.push(toJobProgress(next, peek, assetId));
      if (peek) queue.push(...followUps(peek));
    }
    return { jobs, truncated: false };
  }
}

/** Jobs que encadenó uno terminado, según su resultado. */
function followUps(peek: JobPeek): PendingJob[] {
  const r = peek.result;
  if (!r) return [];
  const pending: PendingJob[] = [];
  const add = (name: JobName, id: unknown) => {
    if (typeof id === 'string' && id) pending.push({ name, id });
  };
  if (peek.name === JOB_NAMES.enrollmentVerify && 'collectJobId' in r)
    add(JOB_NAMES.assetCollect, r.collectJobId);
  if (peek.name === JOB_NAMES.assetCollect && 'discoveryJobId' in r)
    add(JOB_NAMES.assetDiscover, r.discoveryJobId);
  if (peek.name === JOB_NAMES.assetDiscover) {
    // Resultados anteriores a esta versión no traen los ids.
    if ('collectJobIds' in r && Array.isArray(r.collectJobIds))
      for (const id of r.collectJobIds) add(JOB_NAMES.assetCollect, id);
    if ('scanJobIds' in r && Array.isArray(r.scanJobIds))
      for (const id of r.scanJobIds) add(JOB_NAMES.imageScan, id);
  }
  return pending;
}

function toJobProgress(
  job: PendingJob,
  peek: JobPeek | null,
  enrolledAssetId: string,
): EnrollmentJobProgress {
  if (!peek)
    return {
      id: job.id,
      name: job.name,
      assetId: null,
      state: 'unknown',
      progress: 0,
      message: null,
      failedReason: null,
    };
  const data = peek.data as { assetId?: unknown };
  return {
    id: job.id,
    name: job.name,
    assetId:
      job.name === JOB_NAMES.enrollmentVerify
        ? enrolledAssetId
        : typeof data.assetId === 'string'
          ? data.assetId
          : null,
    state: peek.state,
    progress: peek.progress,
    message: peek.message,
    failedReason: peek.failedReason,
  };
}

/** Igual salvo la marca de tiempo: no se reenvía si no ha cambiado nada. */
function sameProgress(a: EnrollmentProgress, b: EnrollmentProgress): boolean {
  return JSON.stringify({ ...a, at: '' }) === JSON.stringify({ ...b, at: '' });
}
