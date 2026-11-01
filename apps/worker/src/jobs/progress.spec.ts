import type { Job } from 'bullmq';
import { describe, expect, it, vi } from 'vitest';
import { runInJobContext } from './job-context.js';
import { reportProgress } from './progress.js';
import { RunLog } from './run-log.js';

describe('reportProgress', () => {
  it('deja los pasos en el log de la ejecución, pero no el «Fallo: …» final (lo escribe el runner)', async () => {
    const job = { log: vi.fn(), updateProgress: vi.fn() } as unknown as Job;
    const log = new RunLog(1 << 20);
    await runInJobContext(
      {
        job,
        token: undefined,
        worker: 'worker-1',
        signal: new AbortController().signal,
        attempt: 1,
        leases: [],
        log,
      },
      async () => {
        await reportProgress(job, 10, 'Leyendo la host key');
        await reportProgress(job, 100, 'Fallo: No se pudo leer la host key');
      },
    );
    expect(log.entries.map((e) => [e.level, e.message, e.progress])).toEqual([
      ['info', 'Leyendo la host key', 10],
    ]);
    // El progreso y el log de BullMQ (la API los devuelve) sí llevan el fallo.
    expect(job.log).toHaveBeenCalledTimes(2);
    expect(job.updateProgress).toHaveBeenLastCalledWith(100);
  });
});
