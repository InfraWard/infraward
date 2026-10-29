import { formatInterval, policySourceLabel, policyValueLabel } from './maintenance-labels';

describe('maintenance-labels', () => {
  it('intervalos legibles', () => {
    expect(formatInterval(0)).toBe('nunca');
    expect(formatInterval(5)).toBe('cada 5 min');
    expect(formatInterval(360)).toBe('cada 6 h');
    expect(formatInterval(1440)).toBe('cada 1 día');
    expect(formatInterval(10080)).toBe('cada 7 días');
    expect(formatInterval(null)).toBe('heredado');
  });

  it('valores y orígenes de la política', () => {
    expect(policyValueLabel('scanEnabled', false)).toBe('desactivado');
    expect(policyValueLabel('scanPeriodic', false)).toBe('solo bajo demanda');
    expect(policyValueLabel('scanPeriodic', null)).toBe('heredado');
    expect(policySourceLabel({ kind: 'inherited', assetId: 'x', assetName: 'pve' })).toBe(
      'heredada de pve',
    );
    expect(policySourceLabel({ kind: 'tag', tag: 'prod' })).toBe('por la etiqueta prod');
    expect(policySourceLabel({ kind: 'global' })).toBe('global');
  });
});
