import type { EntityManager } from 'typeorm';
import { currentJob, SupersededError } from './job-context.js';

/**
 * Fencing de las escrituras finales de un job (DESIGN §20): dentro de su transacción, bloquea su
 * fila de `job_runs` y comprueba que el intento sigue siendo el de esta ejecución. Si otra réplica
 * lo retomó (esta perdió el lock de BullMQ), lanza `SupersededError` y la transacción no escribe
 * nada. Va lo primero en la transacción. Fuera de un job o en jobs sin fila, no hace nada.
 */
export async function assertFence(m: EntityManager): Promise<void> {
  const context = currentJob();
  if (!context || context.attempt === null) return;
  const [row]: { attempt: number }[] = await m.query(
    'SELECT attempt FROM job_runs WHERE id = $1 FOR UPDATE',
    [context.job.id],
  );
  if (row && row.attempt !== context.attempt) throw new SupersededError();
}
