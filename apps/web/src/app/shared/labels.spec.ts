import { formatDuration, isRunning } from './labels';

describe('formatDuration', () => {
  it('elige la unidad según la duración', () => {
    expect(formatDuration(850)).toBe('850 ms');
    expect(formatDuration(12_400)).toBe('12 s');
    expect(formatDuration(185_000)).toBe('3 min 05 s');
    expect(formatDuration(3_720_000)).toBe('1 h 02 min');
  });

  it('sin duración, un guion', () => {
    expect(formatDuration(null)).toBe('—');
    expect(formatDuration(-1)).toBe('—');
  });
});

describe('isRunning', () => {
  it('en cola y en curso son pendientes; terminado y fallido, no', () => {
    expect(['queued', 'active', 'completed', 'failed'].map((state) =>
      isRunning({ state: state as 'queued' }),
    )).toEqual([true, true, false, false]);
  });
});
