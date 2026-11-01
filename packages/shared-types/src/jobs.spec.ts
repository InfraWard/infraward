import { describe, expect, it } from 'vitest';
import { jobRunOrigin } from './jobs.js';

describe('jobRunOrigin', () => {
  const parent = (name: 'assets.bulk' | 'asset.collect') => ({ name });

  it('con padre: lote si es una operación en lote, cadena si es otra tarea', () => {
    expect(jobRunOrigin({ parentJobId: 'p', parent: parent('assets.bulk'), trigger: 'manual' })).toBe('bulk');
    expect(jobRunOrigin({ parentJobId: 'p', parent: parent('asset.collect'), trigger: null })).toBe('chain');
  });

  it('un padre ya podado cuenta como cadena', () => {
    expect(jobRunOrigin({ parentJobId: 'p', parent: null, trigger: 'manual' })).toBe('chain');
  });

  it('sin padre: lo que diga el trigger (null si no se sabe)', () => {
    expect(jobRunOrigin({ parentJobId: null, parent: null, trigger: 'schedule' })).toBe('schedule');
    expect(jobRunOrigin({ parentJobId: null, parent: null, trigger: 'manual' })).toBe('manual');
    expect(jobRunOrigin({ parentJobId: null, parent: null, trigger: null })).toBeNull();
  });
});
