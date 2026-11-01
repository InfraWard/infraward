import type { JobProgressEvent, PingJobResult } from '@infraward/shared-types';
import type { ConfigService } from '@nestjs/config';
import type { Job } from 'bullmq';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { TrivyRunner } from '../scan/trivy-runner.js';
import type { IntelUpdater } from '../intel/intel-updater.js';
import type { FindingPrioritizer } from '../intel/prioritizer.js';
import type { AlertDelivery } from '../alerts/alert-delivery.js';
import type { MetricSampler } from '../metrics/metric-sampler.js';
import { SystemProcessor } from './system.processor.js';

function fakeJob(name: string, data: unknown) {
  const logs: string[] = [];
  const progress: number[] = [];
  const job = {
    id: 'job-1',
    name,
    data,
    log: vi.fn((line: string) => Promise.resolve(logs.push(line))),
    updateProgress: vi.fn((value: number) => {
      progress.push(value);
      return Promise.resolve();
    }),
  } as unknown as Job;
  return { job, logs, progress };
}

describe('SystemProcessor', () => {
  const metrics = {
    enqueue: vi.fn().mockResolvedValue('uuid-1'),
    run: vi
      .fn()
      .mockResolvedValue({
        day: '2026-10-20',
        scopes: 2,
        compacted: 0,
        deleted: 0,
      }),
  };
  const processor = new SystemProcessor(
    {} as ConfigService<EnvironmentVariables, true>,
    { cacheDir: '/nonexistent/trivy-cache' } as TrivyRunner,
    {} as IntelUpdater,
    {} as FindingPrioritizer,
    metrics as unknown as MetricSampler,
    {} as AlertDelivery,
  );

  it('metrics.sample: el del job scheduler encola otro (Actividad); el encolado, muestrea', async () => {
    const scheduled = fakeJob('metrics.sample', { reason: 'schedule' });
    (scheduled.job as { repeatJobKey?: string }).repeatJobKey =
      'repeat:metrics-sample';
    await expect(processor.process(scheduled.job)).resolves.toEqual({
      queued: 'uuid-1',
    });
    expect(metrics.run).not.toHaveBeenCalled();
    const { job } = fakeJob('metrics.sample', { reason: 'startup' });
    await expect(processor.process(job)).resolves.toMatchObject({ scopes: 2 });
    expect(metrics.run).toHaveBeenCalledWith(job);
  });

  it('ping informa del progreso paso a paso y devuelve pong', async () => {
    const { job, logs, progress } = fakeJob('ping', {
      steps: 4,
      stepDelayMs: 0,
      message: 'hola',
    });

    const result = (await processor.process(job)) as PingJobResult;

    expect(result).toMatchObject({ pong: true, message: 'hola', steps: 4 });
    expect(progress).toEqual([0, 25, 50, 75, 100]);
    const events = logs.map((l) => JSON.parse(l) as JobProgressEvent);
    expect(events.map((e) => e.progress)).toEqual(progress);
    expect(events.at(-1)?.message).toBe('Paso 4/4');
    expect(events.every((e) => !Number.isNaN(Date.parse(e.at)))).toBe(true);
  });

  it('vulnerability.lookup sin BD de Trivy da unavailable, sin fallar', async () => {
    const { job } = fakeJob('vulnerability.lookup', {
      vulnerabilityId: 'CVE-2023-45853',
    });
    await expect(processor.process(job)).resolves.toMatchObject({
      status: 'unavailable',
      details: null,
    });
  });

  it('vulnerability.lookup rechaza un id no válido', async () => {
    const { job } = fakeJob('vulnerability.lookup', {
      vulnerabilityId: '../../etc/passwd',
    });
    await expect(processor.process(job)).rejects.toThrow(/no válido/);
  });

  it('falla con un job desconocido', async () => {
    const { job } = fakeJob('desconocido', {});
    await expect(processor.process(job)).rejects.toThrow(/desconocido/);
  });
});
