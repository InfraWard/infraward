import type { JobProgressEvent } from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { runLog } from './run-log.js';

/**
 * Actualiza el progreso del job y deja el evento en su log de BullMQ (la API lo devuelve como
 * historial) y como paso en el log de la ejecución (DESIGN §20, «Log de cada ejecución»), salvo
 * el «Fallo: …» final, que ya escribe el runner.
 */
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
  // «Fallo: …» precede siempre al error del job, y el runner ya lo deja en el log como
  // «Fallido: …» con la duración: aquí solo sería la misma línea dos veces.
  if (!message.startsWith('Fallo')) runLog()?.step(progress, message);
  await job.log(JSON.stringify(event));
  await job.updateProgress(progress);
}
