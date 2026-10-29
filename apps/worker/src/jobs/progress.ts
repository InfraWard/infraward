import type { JobProgressEvent } from '@infraward/shared-types';
import type { Job } from 'bullmq';

/** Actualiza el progreso del job y deja el evento en su log (la API lo devuelve como historial). */
export async function reportProgress(
  job: Job,
  progress: number,
  message: string,
): Promise<void> {
  const event: JobProgressEvent = {
    progress,
    message,
    at: new Date().toISOString(),
  };
  await job.log(JSON.stringify(event));
  await job.updateProgress(progress);
}
