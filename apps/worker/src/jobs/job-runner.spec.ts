import type { Job } from 'bullmq';
import type { DistributedLock } from '../redis/distributed-lock.js';
import { HostBusy } from './job-context.js';
import type { JobRunLogs } from './job-run-logs.js';
import { JobRunner, resultWarnings, summarizeResult } from './job-runner.js';
import type { JobRuns } from './job-runs.js';
import { reportProgress } from './progress.js';
import type { RunLog } from './run-log.js';

const ID = '11111111-2222-4333-8444-555555555555';

function setup(attempt: number | null = 2) {
  const runs = {
    start: vi.fn(async () => attempt),
    track: vi.fn(async () => undefined),
  } as unknown as JobRuns;
  const locks = {} as DistributedLock;
  const saved: {
    attempt: number;
    worker: string;
    entries: RunLog['entries'];
  }[] = [];
  const logs = {
    save: vi.fn(async (_id: string, a: number, worker: string, log: RunLog) => {
      saved.push({ attempt: a, worker, entries: [...log.entries] });
    }),
  } as unknown as JobRunLogs;
  const runner = new JobRunner(runs, locks, logs);
  runner.setWorkerName('worker-1');
  const job = {
    id: ID,
    name: 'ping',
    data: {},
    log: vi.fn(async () => 0),
    updateProgress: vi.fn(async () => undefined),
    moveToDelayed: vi.fn(async () => undefined),
  } as unknown as Job;
  return { runner, job, logs, saved };
}

describe('JobRunner: log de la ejecución', () => {
  it('pasos, resultado y avisos; se guarda al terminar con su intento', async () => {
    const { runner, job, saved } = setup();
    const result = await runner.run(job, 't', async (j) => {
      await reportProgress(j, 50, 'Recogiendo facts');
      return {
        snapshotId: 's1',
        roles: ['docker', 'proxmox'],
        warnings: ['sin sudo'],
      };
    });
    expect(result).toMatchObject({ snapshotId: 's1' });
    const last = saved.at(-1)!;
    expect(last).toMatchObject({ attempt: 2, worker: 'worker-1' });
    expect(last.entries.map((e) => [e.level, e.kind, e.message])).toEqual([
      ['info', 'step', 'ping en worker-1 (intento 2)'],
      ['info', 'step', 'Recogiendo facts'],
      ['warn', 'result', 'Aviso: sin sudo'],
      ['info', 'result', 'Terminado: snapshotId: s1, roles: [docker, proxmox]'],
    ]);
    expect(last.entries[1]).toMatchObject({ progress: 50 });
  });

  it('un fallo queda como error con su mensaje', async () => {
    const { runner, job, saved } = setup();
    await expect(
      runner.run(job, 't', async () => {
        throw new Error('No se pudo leer la host key');
      }),
    ).rejects.toThrow('host key');
    expect(saved.at(-1)!.entries.at(-1)).toMatchObject({
      level: 'error',
      kind: 'result',
      message: 'Fallido: No se pudo leer la host key',
    });
  });

  it('host ocupado antes de hacer nada: no deja log', async () => {
    const { runner, job, logs } = setup();
    await expect(
      runner.run(job, 't', async () => {
        throw new HostBusy('Host ocupado', 1000);
      }),
    ).rejects.toThrow();
    expect(logs.save).not.toHaveBeenCalled();
  });

  it('sin fila en la Actividad (sin intento) no hay log', async () => {
    const { runner, job, logs } = setup(null);
    await runner.run(job, 't', async () => 'ok');
    expect(logs.save).not.toHaveBeenCalled();
  });
});

describe('summarizeResult / resultWarnings', () => {
  it('campos simples, listas y objetos con nombre; sin los avisos', () => {
    expect(
      summarizeResult({
        assetId: 'a',
        unchanged: true,
        duplicateOf: { id: 'x', name: 'srv-2' },
        findings: [{ id: 1 }, { id: 2 }],
        via: null,
        warnings: ['w'],
      }),
    ).toBe(
      'assetId: a, unchanged: true, duplicateOf: srv-2, findings: 2 elementos, via: null',
    );
    expect(summarizeResult(undefined)).toBe('sin resultado');
    expect(summarizeResult('hecho')).toBe('hecho');
    expect(resultWarnings({ warnings: ['a', 3, 'b'] })).toEqual(['a', 'b']);
    expect(resultWarnings(null)).toEqual([]);
  });
});
