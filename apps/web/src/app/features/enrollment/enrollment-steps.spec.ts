import type { EnrollmentJobProgress } from '@infraward/shared-types';
import { chainFailures, groupJobs, stepOf } from './enrollment-steps';

const job = (
  name: EnrollmentJobProgress['name'],
  state: EnrollmentJobProgress['state'],
  extra: Partial<EnrollmentJobProgress> = {},
): EnrollmentJobProgress => ({
  id: `${name}-${Math.random()}`,
  name,
  assetId: null,
  state,
  progress: 0,
  message: null,
  failedReason: null,
  ...extra,
});

describe('pasos del alta', () => {
  it('fase → paso del stepper (un fallo se queda en «Conectando»)', () => {
    expect(stepOf('waiting')).toBe(2);
    expect(stepOf('connecting')).toBe(3);
    expect(stepOf('failed')).toBe(3);
    expect(stepOf('scanning')).toBe(4);
    expect(stepOf('ready')).toBe(5);
  });

  it('agrupa los jobs por tipo con hechos, fallidos y el mensaje del que está en curso', () => {
    const groups = groupJobs([
      job('enrollment.verify', 'completed'),
      job('asset.collect', 'completed'),
      job('asset.collect', 'active', { message: 'Ejecutando Ansible' }),
      job('asset.collect', 'failed', { failedReason: 'sin python3' }),
      job('image.scan', 'unknown'),
    ]);
    expect(groups.map((g) => [g.label, g.done, g.failed, g.total])).toEqual([
      ['Verificación SSH', 1, 0, 1],
      ['Recolección', 1, 1, 3],
      ['Escaneo de imagen', 1, 0, 1],
    ]);
    expect(groups[1].active?.message).toBe('Ejecutando Ansible');
  });

  it('errores de la cadena (sin el de la verificación, que va aparte)', () => {
    expect(
      chainFailures([
        job('enrollment.verify', 'failed', { failedReason: 'host key' }),
        job('asset.collect', 'failed', { failedReason: 'sin python3' }),
      ]),
    ).toEqual(['Recolección: sin python3']);
  });
});
