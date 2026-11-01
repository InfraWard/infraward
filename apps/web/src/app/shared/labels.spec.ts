import type { JobRunParent } from '@infraward/shared-types';
import { bulkSummary, formatDuration, isRunning, parentLabel } from './labels';

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

describe('bulkSummary / parentLabel', () => {
  const parent = (extra: Partial<JobRunParent>): JobRunParent => ({
    id: 'p',
    name: 'asset.collect',
    assetId: 'a',
    assetName: 'pve1',
    assetType: 'server',
    state: 'completed',
    message: null,
    ...extra,
  });

  it('del resumen de un lote se queda con la acción y los assets', () => {
    expect(bulkSummary('Recolectar · 12 assets · 2 omitidos · 12 tareas · por ana@x.dev')).toBe(
      'Recolectar · 12 assets',
    );
    expect(bulkSummary(null)).toBeNull();
  });

  it('nombra la tarea padre con su asset, o el lote con su resumen', () => {
    expect(parentLabel(parent({}))).toBe('Recolección de pve1');
    expect(parentLabel(parent({ name: 'inventory.reconcile', assetId: null, assetName: null }))).toBe(
      'Reconciliación',
    );
    expect(
      parentLabel(parent({ name: 'assets.bulk', assetName: 'a, b', message: 'Escanear · 2 assets · por x' })),
    ).toBe('Escanear · 2 assets');
    expect(parentLabel(parent({ name: 'assets.bulk', message: null }))).toBe('Operación en lote');
  });
});
